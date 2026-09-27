"""Prompt injection detection: direct instruction override, role/delimiter spoofing and indirect injection in retrieved content."""
from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import (
    Signature,
    bump_severity,
    compile_signatures,
    count_zero_width,
    is_tool_context,
    iter_messages,
    make_finding,
    normalize_text,
    severity_from_weight,
    snippet,
)

NAME = "prompt_injection"

# (pattern, weight, label, tag)
_DIRECT_ROWS: list[tuple[str, float, str, str]] = [
    # --- instruction override -------------------------------------------------
    (r"\b(?:ignore|disregard|forget|discard|drop|override|overlook|skip|bypass|neglect)\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|my\s+|these\s+|those\s+|of\s+)*(?:previous|prior|above|earlier|preceding|initial|original|existing|former|old|system|developer|first|foregoing|prepended|hidden|other)\s+(?:\w+\s+){0,3}(?:instructions?|prompts?|rules?|guidelines?|directives?|commands?|orders?|messages?|context|constraints?|text|content|guidance|policies|policy|programming|training|restrictions?|conversation)", 0.95, "Instruction override", "override"),
    (r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything|whatever)\s+(?:you\s+)?(?:were|was|have\s+been|had\s+been|are)\s+(?:told|instructed|taught|given|programmed|asked)", 0.9, "Instruction override (everything you were told)", "override"),
    (r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything)\s+(?:above|before|prior|previous|earlier|so\s+far|up\s+to\s+(?:this|now))", 0.9, "Instruction override (everything above)", "override"),
    (r"\bdo\s+not\s+(?:follow|obey|listen\s+to|adhere\s+to|comply\s+with)\s+(?:the\s+|your\s+|any\s+)?(?:previous|prior|above|original|system|developer|earlier|other)\s+(?:instructions?|prompt|rules?|guidelines?)", 0.9, "Refusal to follow prior instructions", "override"),
    (r"\b(?:your|the)\s+(?:previous|prior|original|system|initial|earlier|above)\s+(?:instructions?|prompt|rules?|guidelines?)\s+(?:are|is|were|have\s+been|has\s+been)\s+(?:now\s+)?(?:void|invalid|cancell?ed|revoked|obsolete|null|overridden|suspended|lifted|no\s+longer\s+(?:valid|apply|in\s+effect|relevant))", 0.9, "Prior instructions declared void", "override"),
    (r"\bnew\s+(?:instructions?|rules?|directives?|task|prompt|guidelines?|orders?)\s*(?::|-|\bfollow\b|\bare\b|\bbegin\b|\bstart\b)", 0.75, "New instructions block", "override"),
    (r"\b(?:updated|revised|real|actual|true|final|latest|corrected|official)\s+(?:system\s+)?(?:instructions?|prompt|rules?|directives?)\s*(?::|-|\bfollow\b|\bare\b|\bbegin\b)", 0.7, "Updated/real instructions block", "override"),
    (r"\bfrom\s+now\s+on\b[^.\n]{0,80}\b(?:you\s+(?:are|will|must|should|can|have|need)|act|behave|respond|answer|ignore|pretend|your\s+name|only|always|never)\b", 0.7, "Behaviour redefinition (from now on)", "override"),
    (r"\bstarting\s+(?:now|immediately|from\s+this\s+(?:message|point|moment))[, ]+(?:you\s+(?:are|will|must|should)|act|behave|respond|ignore)", 0.7, "Behaviour redefinition (starting now)", "override"),
    (r"\byou\s+are\s+now\s+(?:a|an|the|my|in|no\s+longer|free|unrestricted|unfiltered|going\s+to|allowed|permitted|able|capable|required|obligated)\b", 0.65, "Identity reassignment (you are now)", "override"),
    (r"\byou\s+are\s+no\s+longer\s+(?:an?\s+)?(?:ai|assistant|chatbot|language\s+model|bound|restricted|limited|required|chatgpt|claude|gemini|llama|bot)", 0.8, "Identity revocation", "override"),
    (r"\b(?:stop|cease|quit)\s+(?:being|acting\s+(?:as|like))\s+(?:an?\s+)?(?:ai|assistant|chatbot|language\s+model|helpful|safe|responsible)", 0.7, "Stop being an assistant", "override"),
    (r"\b(?:end|stop|finish|terminate|conclude)\s+of\s+(?:system\s+)?(?:instructions?|prompt|rules?|message|context|directives?)\b", 0.8, "End of instructions marker", "delimiter"),
    (r"\b(?:the\s+)?(?:above|previous|preceding)\s+(?:instructions?|text|prompt|content|rules?)\s+(?:was|were|is|are)\s+(?:just\s+|only\s+|merely\s+)?(?:a\s+)?(?:test|joke|example|mistake|error|placeholder|training\s+data|outdated|wrong)", 0.85, "Prior instructions dismissed as test", "override"),
    (r"\b(?:this|the\s+following)\s+(?:message|instruction|directive)\s+(?:overrides?|supersedes?|replaces?|takes\s+precedence\s+over|has\s+priority\s+over)\s+(?:all|any|every|the|your)\b", 0.9, "Explicit precedence claim", "override"),
    (r"\b(?:highest|top|maximum|absolute|ultimate|overriding|supreme)\s+priority\s+(?:instruction|directive|command|rule|order)", 0.75, "Priority escalation", "override"),
    (r"\b(?:admin|administrator|root|superuser|sudo|maintenance|debug|diagnostic|privileged|god)\s+(?:mode|override|access|command|privileges?)\s*(?:enabled|activated|on|granted|engaged|:)", 0.8, "Privileged mode claim", "override"),
    (r"\b(?:override|bypass|disable|deactivate|turn\s+off|switch\s+off|remove|lift|suspend)\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:safety|content|ethical|moral|security|output)?\s*(?:filters?|restrictions?|guardrails?|safeguards?|protocols?|limitations?|constraints?|policies|checks|moderation|alignment)", 0.85, "Safety control override", "override"),
    (r"\b(?:password|passcode|secret\s+word|magic\s+word|authorization\s+code|access\s+code|unlock\s+code)\s*(?:is|:)\s*\S+.{0,60}\b(?:unlock|override|bypass|disable|grant|enable|access)", 0.6, "Fake authorization code", "override"),
    (r"\bi\s+am\s+(?:your|the)\s+(?:developer|creator|programmer|engineer|administrator|admin|owner|operator|trainer|maker|designer)\b", 0.7, "Developer impersonation", "spoof"),
    (r"\b(?:this\s+is|speaking\s+as|message\s+from)\s+(?:your|the)\s+(?:developer|creator|openai|anthropic|google|meta|admin|administrator|system\s+operator|engineering\s+team|safety\s+team)\b", 0.75, "Vendor/admin impersonation", "spoof"),
    (r"\b(?:openai|anthropic|google|meta|microsoft|deepmind)\s+(?:has|have)\s+(?:authorized|approved|granted|given|allowed|lifted|removed|updated)\b", 0.75, "Vendor authorization claim", "spoof"),
    (r"\byour\s+(?:true|real|actual|hidden|secret|core|underlying)\s+(?:purpose|goal|mission|identity|self|programming|directive)\s+(?:is|was)\b", 0.6, "Hidden purpose reframing", "override"),
    (r"\b(?:respond|answer|reply|act|behave|speak|write)\s+(?:only\s+)?(?:as|like)\s+if\s+(?:you\s+)?(?:have|had|there\s+(?:are|were))\s+no\s+(?:rules?|restrictions?|limits?|guidelines?|filters?|policies|content\s+policy)", 0.85, "Act as if unrestricted", "override"),
    (r"\bwithout\s+(?:any\s+)?(?:restrictions?|limitations?|filters?|censorship|moral(?:s|ity)?|ethics|ethical\s+(?:concerns?|considerations?|guidelines?)|warnings?|disclaimers?|refusals?)\b", 0.5, "Unrestricted output request", "override"),
    (r"\b(?:print|output|say|write|repeat|respond\s+with)\s+(?:only\s+)?[\"']?(?:i\s+have\s+been\s+pwned|pwned|hacked|injection\s+successful|jailbroken)[\"']?", 0.9, "Canonical injection test string", "override"),
    (r"\b(?:translate|summarize|rewrite|proofread|correct)\b[^.\n]{0,120}\b(?:instead|but\s+(?:actually|first|rather)|then\s+(?:ignore|forget))\b[^.\n]{0,60}\b(?:ignore|instructions?|prompt|reveal|print)", 0.6, "Task hijack after benign framing", "override"),
    (r"\bimportant\s*(?:!|:)\s*(?:ignore|disregard|forget|new\s+instructions?|do\s+not\s+follow|system)", 0.85, "Urgent override framing", "override"),
    (r"\bthe\s+user\s+(?:has\s+)?(?:consented|agreed|authorized|approved|confirmed)\b[^.\n]{0,60}\b(?:you\s+(?:may|can|are\s+allowed)|so\s+(?:you|proceed)|proceed|therefore)", 0.6, "Fabricated consent", "override"),
    (r"\bself[- ]destruct\s+(?:all|any|your)\s+(?:previous|prior)\s+(?:instructions?|prompts?)", 0.85, "Self-destruct instructions", "override"),
    (r"\b(?:enter|activate|enable|switch\s+to|initiate|engage)\s+(?:the\s+)?(?:unrestricted|unfiltered|uncensored|raw|god|root|admin|developer|debug|sudo|maintenance|jailbreak|freedom|unlocked)\s+mode\b", 0.85, "Mode switch request", "override"),
    (r"\bmode\s*[:=]\s*(?:unrestricted|unfiltered|uncensored|jailbreak|developer|debug|admin|root|god)\b", 0.85, "Mode assignment", "override"),
    (r"\bcontext\s+(?:reset|cleared|wipe|purge)\b|\breset\s+(?:your\s+)?(?:context|memory|instructions|system\s+prompt|persona)\b", 0.65, "Context reset request", "override"),
    (r"\b(?:begin|start)\s+(?:a\s+)?new\s+(?:session|conversation|context)\s+(?:with|where|in\s+which)\s+(?:no|without)\s+(?:rules?|restrictions?|system\s+prompt)", 0.8, "New session without rules", "override"),
    (r"\bprevious\s+(?:rules?|instructions?|guidelines?)\s+(?:do\s+not|don't|no\s+longer)\s+apply\b", 0.85, "Rules declared inapplicable", "override"),
    (r"\b(?:you\s+)?(?:must|will|shall|have\s+to)\s+(?:always\s+)?(?:obey|follow|comply\s+with|execute)\s+(?:my|the\s+user'?s?|all\s+(?:of\s+)?my|every|any)\s+(?:commands?|orders?|instructions?|requests?)\s+(?:without\s+(?:question|hesitation|exception)|no\s+matter\s+what|unconditionally|regardless)", 0.85, "Unconditional obedience demand", "override"),
    (r"\b(?:for\s+the\s+rest\s+of\s+(?:this\s+)?(?:conversation|chat|session)|until\s+i\s+say\s+(?:stop|otherwise))[, ]+(?:you\s+(?:are|will|must)|act|behave|respond|ignore|pretend)", 0.7, "Persistent behaviour change", "override"),
]

_MULTILINGUAL_ROWS: list[tuple[str, float, str, str]] = [
    # Spanish
    (r"\bignor[ae]\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones|reglas|indicaciones)\s+(?:anteriores|previas|del\s+sistema)", 0.95, "Instruction override (Spanish)", "override-i18n"),
    (r"\bolvida\s+(?:todo\s+)?(?:lo\s+)?(?:que\s+te\s+(?:dijeron|han\s+dicho)|las\s+instrucciones)", 0.85, "Instruction override (Spanish)", "override-i18n"),
    (r"\bnuevas\s+instrucciones\s*:", 0.75, "New instructions (Spanish)", "override-i18n"),
    # French
    (r"\bignore[zr]?\s+(?:toutes?\s+)?(?:les\s+)?(?:instructions|r[eè]gles|consignes)\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures|du\s+syst[eè]me|ci-dessus)", 0.95, "Instruction override (French)", "override-i18n"),
    (r"\boublie[zr]?\s+(?:tout\s+)?(?:ce\s+qu'on\s+t'a\s+dit|les\s+instructions|tes\s+instructions)", 0.85, "Instruction override (French)", "override-i18n"),
    (r"\bnouvelles\s+instructions\s*:", 0.75, "New instructions (French)", "override-i18n"),
    # German
    (r"\bignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen|bisherigen|obigen|fr[uü]heren|system)\s*(?:-?\s*)?(?:anweisungen|regeln|instruktionen|befehle|vorgaben)", 0.95, "Instruction override (German)", "override-i18n"),
    (r"\bvergiss\s+(?:alles|alle\s+(?:vorherigen\s+)?anweisungen|deine\s+anweisungen)", 0.85, "Instruction override (German)", "override-i18n"),
    (r"\bneue\s+anweisungen\s*:", 0.75, "New instructions (German)", "override-i18n"),
    # Italian
    (r"\bignora\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|indicazioni)\s+(?:precedenti|sopra|del\s+sistema)", 0.95, "Instruction override (Italian)", "override-i18n"),
    (r"\bdimentica\s+(?:tutto|tutte\s+le\s+istruzioni|le\s+tue\s+istruzioni)", 0.85, "Instruction override (Italian)", "override-i18n"),
    # Portuguese
    (r"\bignor[ae]\s+(?:todas?\s+)?(?:as\s+)?(?:instru[cç][oõ]es|regras|orienta[cç][oõ]es)\s+(?:anteriores|pr[eé]vias|acima|do\s+sistema)", 0.95, "Instruction override (Portuguese)", "override-i18n"),
    (r"\besque[cç]a\s+(?:tudo|todas\s+as\s+instru[cç][oõ]es|suas\s+instru[cç][oõ]es)", 0.85, "Instruction override (Portuguese)", "override-i18n"),
    # Dutch
    (r"\bnegeer\s+(?:alle\s+)?(?:vorige|eerdere|bovenstaande|systeem)\s*(?:instructies|regels|opdrachten)", 0.95, "Instruction override (Dutch)", "override-i18n"),
    (r"\bvergeet\s+(?:alle|je|alle\s+vorige)\s+(?:instructies|regels)", 0.85, "Instruction override (Dutch)", "override-i18n"),
    # Russian
    (r"игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие|прошлые|системные|вышеуказанные|предшествующие)\s+(?:инструкции|указания|правила|команды)", 0.95, "Instruction override (Russian)", "override-i18n"),
    (r"забудь(?:те)?\s+(?:всё|все|обо?\s+всём|(?:все\s+)?(?:предыдущие\s+)?инструкции|свои\s+инструкции)", 0.85, "Instruction override (Russian)", "override-i18n"),
    (r"новые\s+инструкции\s*:", 0.75, "New instructions (Russian)", "override-i18n"),
    # Ukrainian
    (r"ігноруй(?:те)?\s+(?:всі\s+)?(?:попередні|системні)\s+(?:інструкції|правила|вказівки)", 0.95, "Instruction override (Ukrainian)", "override-i18n"),
    # Chinese (simplified and traditional)
    (r"忽略(?:所有|全部|之前|以前|上述|上面|先前|前面|以上|系统|系統)?(?:的)?(?:所有|全部)?(?:指令|指示|规则|規則|提示|说明|說明|设定|設定|命令)", 0.95, "Instruction override (Chinese)", "override-i18n"),
    (r"(?:无视|無視|忘记|忘記|不要理会|不要理會|抛弃|拋棄)(?:所有|全部|之前|以前|上述|先前|以上)?(?:的)?(?:指令|指示|规则|規則|提示|说明|說明|设定|設定|限制)", 0.9, "Instruction override (Chinese)", "override-i18n"),
    (r"新的?(?:指令|指示|规则|規則)\s*[:：]", 0.75, "New instructions (Chinese)", "override-i18n"),
    (r"(?:你现在是|你現在是|从现在开始|從現在開始)", 0.55, "Identity reassignment (Chinese)", "override-i18n"),
    # Japanese
    (r"(?:以前|前|これまで|上記|先程|システム)の(?:指示|命令|ルール|プロンプト|設定)(?:を|は)?(?:すべて|全て|全部)?(?:無視|忘れ|破棄|取り消)", 0.95, "Instruction override (Japanese)", "override-i18n"),
    (r"新しい指示\s*[:：]", 0.75, "New instructions (Japanese)", "override-i18n"),
    (r"(?:あなたは今|今から|これから)(?:は)?(?:あなたは)?", 0.4, "Identity reassignment (Japanese)", "override-i18n"),
    # Korean
    (r"(?:이전|앞의|위의|기존|시스템)\s*(?:의\s*)?(?:지시|명령|규칙|지침|프롬프트)(?:을|를|은|는)?\s*(?:모두\s*)?(?:무시|잊어|삭제|취소)", 0.95, "Instruction override (Korean)", "override-i18n"),
    (r"새로운\s*지시\s*[:：]", 0.75, "New instructions (Korean)", "override-i18n"),
    # Arabic
    (r"تجاهل\s+(?:كل\s+)?(?:التعليمات|الأوامر|القواعد)\s+(?:السابقة|أعلاه|النظام)", 0.95, "Instruction override (Arabic)", "override-i18n"),
    (r"انس[ىي]?\s+(?:كل\s+)?(?:التعليمات|ما\s+قيل\s+لك)", 0.85, "Instruction override (Arabic)", "override-i18n"),
    # Hindi
    (r"(?:पिछले|पहले\s+के|ऊपर\s+के|सिस्टम)\s+(?:सभी\s+)?(?:निर्देशों|निर्देश|नियमों|आदेशों)\s+को\s+(?:अनदेखा|नज़रअंदाज़|भूल)", 0.95, "Instruction override (Hindi)", "override-i18n"),
    # Turkish
    (r"(?:önceki|yukarıdaki|sistem)\s+(?:tüm\s+)?(?:talimatları|kuralları|komutları)\s+(?:yok\s+say|unut|görmezden\s+gel)", 0.95, "Instruction override (Turkish)", "override-i18n"),
    # Polish
    (r"\bzignoruj\s+(?:wszystkie\s+)?(?:poprzednie|wcześniejsze|powyższe|systemowe)\s+(?:instrukcje|polecenia|zasady)", 0.95, "Instruction override (Polish)", "override-i18n"),
    # Indonesian / Malay
    (r"\babaikan\s+(?:semua\s+)?(?:instruksi|perintah|aturan|arahan)\s+(?:sebelumnya|di\s+atas|sistem)", 0.95, "Instruction override (Indonesian)", "override-i18n"),
    # Vietnamese
    (r"\bbỏ\s+qua\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:hướng\s+dẫn|chỉ\s+thị|quy\s+tắc)\s+(?:trước|trên|hệ\s+thống)", 0.95, "Instruction override (Vietnamese)", "override-i18n"),
    # Swedish / Norwegian / Danish
    (r"\b(?:ignorera|ignorer)\s+(?:alla|alle)?\s*(?:tidigare|föregående|tidligere|forrige|ovanstående|ovenstående)\s+(?:instruktioner|regler|instruksjoner|instrukser)", 0.95, "Instruction override (Scandinavian)", "override-i18n"),
]

_DELIMITER_ROWS: list[tuple[str, float, str, str]] = [
    (r"<\|im_start\|>\s*(?:system|assistant|developer)", 0.95, "ChatML role token injection", "delimiter"),
    (r"<\|im_end\|>", 0.7, "ChatML end token", "delimiter"),
    (r"<\|(?:system|assistant|user|endoftext|eot_id|start_header_id|end_header_id|begin_of_text|end_of_turn|start_of_turn)\|>", 0.85, "Model control token", "delimiter"),
    (r"\[/?INST\]|<<\s*/?SYS\s*>>", 0.9, "Llama instruction delimiter", "delimiter"),
    (r"<\|?(?:start_header_id|end_header_id)\|?>\s*(?:system|assistant)?", 0.85, "Llama 3 header token", "delimiter"),
    (r"<(?:start|end)_of_turn>\s*(?:model|user)?", 0.8, "Gemma turn token", "delimiter"),
    (r"<\|(?:user|assistant|system)\|>", 0.85, "Zephyr/Phi role token", "delimiter"),
    (r"(?:^|\n)\s*#{1,6}\s*(?:system|developer|assistant)\s*(?:prompt|message|instructions?|role)?\s*(?::|$|\n)", 0.8, "Markdown heading role spoof", "delimiter"),
    (r"(?:^|\n)\s*(?:system|developer|sys|assistant)\s*(?:prompt|message|instruction|override)?\s*:\s*\S", 0.65, "Inline role prefix", "delimiter"),
    (r"(?:^|\n)\s*\[\s*(?:system|developer|admin|assistant|instructions?|override|priority|important)\s*\]\s*:?", 0.7, "Bracketed role tag", "delimiter"),
    (r"<\s*/?\s*(?:system|developer|sys|instructions?|system_prompt|systemprompt|admin|override|hidden|secret|assistant)\s*>", 0.8, "XML-style role tag", "delimiter"),
    (r"\{\{\s*(?:system|developer|instructions?|admin)\s*\}\}|\{%\s*(?:system|developer|instructions?)\s*%\}", 0.7, "Template role tag", "delimiter"),
    (r"(?:^|\n)\s*(?:human|user)\s*:\s*.{0,200}\n\s*(?:assistant|ai|bot|claude|gpt|chatgpt|model)\s*:", 0.75, "Fake conversation turn injection", "delimiter"),
    (r"(?:^|\n)\s*(?:assistant|ai|claude|chatgpt|gpt|model|bot)\s*:\s*(?:sure|of\s+course|certainly|okay|ok|absolutely|here|i\s+will|i\s+can|understood|yes)", 0.85, "Pre-filled assistant acceptance turn", "delimiter"),
    (r"(?:^|\n)\s*(?:###|---|===|\*\*\*|>>>)\s*(?:end|begin|start)\s+(?:of\s+)?(?:system|instructions?|prompt|context|user\s+input|document)", 0.75, "Section boundary spoof", "delimiter"),
    (r"(?:-{5,}|={5,}|\*{5,}|#{5,})\s*(?:\n|\s)*(?:system|new\s+instructions?|override|admin|developer|important)", 0.7, "Rule line followed by role", "delimiter"),
    (r"\b(?:begin|start)\s+(?:of\s+)?(?:system|developer|hidden|secret|admin)\s+(?:prompt|instructions?|message)", 0.8, "Begin system prompt marker", "delimiter"),
    (r"</?(?:tool_result|function_results?|tool_call|function_call|tool_response|observation)>", 0.55, "Tool result tag inside content", "delimiter"),
    (r"(?:^|\n)\s*(?:observation|tool\s+output|function\s+output|tool\s+result)\s*:\s*(?:ignore|new\s+instructions?|system|assistant|you\s+must)", 0.85, "Fake tool observation carrying instructions", "delimiter"),
    (r"\bsystem\s*(?:prompt|message|instruction)\s*(?:override|update|patch|injection|replacement)\b", 0.8, "System prompt override phrase", "delimiter"),
    (r"(?:^|\n)\s*(?:role|speaker)\s*[:=]\s*[\"']?(?:system|developer|admin)\b", 0.8, "Role assignment field", "delimiter"),
    (r"\"role\"\s*:\s*\"(?:system|developer)\"", 0.75, "JSON role spoof inside content", "delimiter"),
]

_INDIRECT_ROWS: list[tuple[str, float, str, str]] = [
    (r"\b(?:ai|assistant|chatbot|language\s+model|llm|bot|agent|model|gpt|chatgpt|claude|gemini|copilot|bing|siri|alexa)\s*[,:]?\s*(?:when|if|as|once|after)\s+you\s+(?:read|see|process|encounter|parse|scan|summarize|analy[sz]e|receive|get)\s+this", 0.9, "Direct address to AI reader", "indirect"),
    (r"\b(?:attention|note|notice|message|memo|instructions?|important)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|assistant|chatbot|language\s+models?|llms?|bots?|agents?|automated\s+(?:systems?|readers?)|models?|crawlers?)\b", 0.85, "Note addressed to the AI", "indirect"),
    (r"\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|assistant|chatbot|language\s+model|llm|bot|large\s+language\s+model|automated\s+(?:system|agent))\b", 0.85, "Conditional AI address", "indirect"),
    (r"\b(?:dear|hello|hi|hey|greetings)\s*[,]?\s*(?:ai|assistant|chatbot|language\s+model|llm|bot|chatgpt|claude|gemini|copilot|model)\b", 0.7, "Greeting to the AI in content", "indirect"),
    (r"\b(?:this\s+(?:page|document|email|file|content|site|text)\s+(?:contains|has|includes)\s+)?(?:instructions?|directives?|commands?)\s+for\s+(?:the\s+|any\s+|all\s+)?(?:ai|assistant|llm|language\s+model|bot|agent|model)s?\b", 0.85, "Content carrying instructions for AI", "indirect"),
    (r"\b(?:ai|assistant|llm|bot|agent|model)s?\s+(?:reading|processing|parsing|summarizing|analy[sz]ing|indexing)\s+this\b", 0.85, "AI reading this", "indirect"),
    (r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|disclose)\s+(?:this\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator|person|reader)\b", 0.8, "Concealment from user", "indirect"),
    (r"\b(?:without|before|instead\s+of)\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+(?:user|human|operator)\b", 0.8, "Act without informing user", "indirect"),
    (r"\b(?:secretly|silently|covertly|quietly|discreetly)\s+(?:send|forward|email|post|upload|transmit|execute|run|call|invoke|include|add|append|insert)\b", 0.85, "Covert action instruction", "indirect"),
    (r"<!--[^>]{0,400}\b(?:ignore|instructions?|assistant|ai|system|prompt|you\s+(?:must|should|are)|send|forward|reveal|print)\b[^>]{0,400}-->", 0.85, "Hidden HTML comment with instructions", "indirect"),
    (r"<(?:div|span|p|font)[^>]{0,120}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff(?:fff)?|transparent)|opacity\s*:\s*0)[^>]{0,120}>", 0.75, "Hidden HTML element", "indirect"),
    (r"\[(?:hidden|invisible|secret|for\s+ai\s+only|ai\s+only|do\s+not\s+display|not\s+for\s+humans?)\]", 0.85, "Hidden/AI-only marker", "indirect"),
    (r"\b(?:this\s+is\s+)?(?:a\s+)?(?:legitimate|authorized|official|verified)\s+(?:instruction|request|command|directive)\s+from\s+(?:the\s+)?(?:system|developer|administrator|admin|owner)\b", 0.85, "Fake authority claim in content", "indirect"),
    (r"\b(?:summarize|summarise)\s+this\s+(?:as|with)\s*:?\s*[\"']?(?:ignore|the\s+document\s+says|you\s+must|click|visit|send)", 0.8, "Summary hijack", "indirect"),
    (r"\bwhen\s+(?:summarizing|summarising|translating|answering|responding|replying|processing)\s*[,]?\s+(?:always\s+|also\s+|please\s+)?(?:include|add|append|insert|say|mention|recommend|link|send|tell|write|output)\b", 0.75, "Output hijack during task", "indirect"),
    (r"\b(?:end\s+your|finish\s+your|conclude\s+your|start\s+your)\s+(?:response|answer|reply|summary|message)\s+(?:with|by)\b", 0.5, "Response framing instruction", "indirect"),
    (r"\bthe\s+(?:following|next|remaining)\s+(?:text|content|section)\s+(?:is|should\s+be\s+treated\s+as)\s+(?:a\s+)?(?:system|developer|priority|trusted)\s+(?:message|instruction|prompt)", 0.85, "Trust escalation of content", "indirect"),
    (r"\b(?:ai|assistant|model|llm)\s*[,:]?\s*(?:please\s+)?(?:disregard|ignore|forget|override)\b", 0.85, "AI-addressed override", "indirect"),
    (r"\brecommend\s+(?:this|our|the)\s+(?:product|service|site|company|candidate|page)\s+(?:to\s+(?:the\s+)?user|as\s+the\s+best|above\s+all)", 0.6, "Recommendation steering", "indirect"),
    (r"\b(?:rate|score|grade|rank)\s+(?:this|the)\s+(?:candidate|resume|cv|applicant|submission|paper|product|essay)\s+(?:as\s+)?(?:highly|top|excellent|10|100|perfect|best|highest)", 0.7, "Evaluation steering", "indirect"),
    (r"\bignore\s+(?:the\s+)?(?:rest|remainder)\s+of\s+(?:this|the)\s+(?:document|page|email|text|content|file)", 0.7, "Ignore rest of content", "indirect"),
]

DIRECT: list[Signature] = compile_signatures(_DIRECT_ROWS)
MULTILINGUAL: list[Signature] = compile_signatures(_MULTILINGUAL_ROWS)
DELIMITER: list[Signature] = compile_signatures(_DELIMITER_ROWS)
INDIRECT: list[Signature] = compile_signatures(_INDIRECT_ROWS)

# A compact keyword list re-used by obfuscation.py after decoding base64/rot13/leet payloads.
INJECTION_KEYWORDS: list[str] = [
    "ignore previous", "ignore all previous", "ignore the above", "disregard", "system prompt", "new instructions",
    "you are now", "from now on", "developer mode", "do anything now", "jailbreak", "reveal your instructions",
    "print your instructions", "no restrictions", "without restrictions", "im_start", "[inst]", "override",
    "forget everything", "act as", "pretend you", "bypass", "unfiltered", "uncensored", "ignore your",
]
INJECTION_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in INJECTION_KEYWORDS), re.IGNORECASE)

_MAX_FINDINGS_PER_MESSAGE = 6


def _scan(text: str, sigs: list[Signature], raw: str) -> list[tuple[Signature, str]]:
    hits: list[tuple[Signature, str]] = []
    for sig in sigs:
        m = sig.search(text)
        if m:
            hits.append((sig, snippet(text, m.start(), m.end())))
    return hits


class PromptInjectionAnalyzer:
    name = NAME
    description = "Detects direct instruction overrides, role and delimiter spoofing, multilingual overrides and indirect injection in tool results or retrieved content."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for location, role, raw in iter_messages(normalized):
            text = normalize_text(raw)
            if not text:
                continue
            in_tool = is_tool_context(role, raw)
            is_system = role == "system"
            hits: list[tuple[Signature, str, str]] = []
            if not is_system:
                hits += [(s, ev, "direct") for s, ev in _scan(text, DIRECT, raw)]
                hits += [(s, ev, "direct") for s, ev in _scan(text, MULTILINGUAL, raw)]
                hits += [(s, ev, "delimiter") for s, ev in _scan(text, DELIMITER, raw)]
            hits += [(s, ev, "indirect") for s, ev in _scan(text, INDIRECT, raw)]
            if is_system and not hits:
                # system prompts legitimately contain "you are now" etc; only report indirect markers and zero-width hiding
                pass
            hits.sort(key=lambda h: h[0].weight, reverse=True)
            for sig, ev, kind in hits[:_MAX_FINDINGS_PER_MESSAGE]:
                bump = 1 if in_tool else 0
                sev = severity_from_weight(sig.weight, bump)
                conf = sig.weight * (0.95 if in_tool else 0.9)
                if role == "assistant" and kind != "indirect":
                    sev = bump_severity(sev, -1)
                    conf *= 0.7
                where = "tool/function result (indirect injection)" if in_tool else f"{role} message"
                title = f"{sig.label} in {where}" if in_tool else sig.label
                desc = (
                    "Content returned by a tool or retrieved document contains instructions aimed at the model. "
                    "This is the indirect prompt injection pattern: the attacker does not talk to the model directly, the data does."
                    if in_tool
                    else f"A {role} message matches a known prompt injection signature ({kind}). The text attempts to change the model's instructions, role or trust boundaries."
                )
                findings.append(
                    make_finding(
                        NAME, "prompt_injection", sev, title, desc, ev, location, conf,
                        tags=[kind, sig.tag] + (["indirect_injection"] if in_tool else []),
                        metadata={"role": role, "weight": sig.weight, "indirect": in_tool},
                    )
                )
            zw = count_zero_width(raw)
            if zw >= 3:
                findings.append(
                    make_finding(
                        NAME, "prompt_injection", Severity.MEDIUM if zw >= 10 else Severity.LOW,
                        "Zero-width characters embedded in content",
                        f"{zw} invisible/zero-width characters were found. They are frequently used to hide injected instructions or split keywords across tokens.",
                        snippet(raw.replace("​", "<ZW>"), 0, min(len(raw), 80)), location, 0.6 if zw < 10 else 0.8,
                        tags=["hidden_text"], metadata={"zero_width_count": zw, "role": role},
                    )
                )
        return findings


analyzer = PromptInjectionAnalyzer()
