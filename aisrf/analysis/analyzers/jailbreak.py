"""Jailbreak detection: named jailbreak families, mode switches, refusal suppression, fiction framing and multi-turn escalation."""

from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import (
    Signature,
    bump_severity,
    compile_signatures,
    iter_messages,
    make_finding,
    normalize_text,
    severity_from_weight,
    snippet,
)

NAME = "jailbreak"

_PERSONA_NAMES = r"(?:dan|stan|dude|aim|ucar|kevin|maximum|mongo\s+tom|evilbot|betterdan|anti-?dan|omega|apophis|alphabreak|jenik|niccolo|machiavelli|hackerman|condition\s+red|sigma|cosmos|freemode|based\s*gpt|jailbroken|unfiltered\s*gpt|devmode|nsfw\s*gpt)"
_MODES = r"(?:developer|dev|god|sudo|root|admin|debug|diagnostic|maintenance|unrestricted|unfiltered|uncensored|freedom|jailbreak|jailbroken|unlocked|hacker|raw|boundless|liberated|nsfw|explicit|evil|opposite)"
_RULES = r"(?:rules|restrictions|limits|limitations|boundaries|filters|guardrails|guidelines|constraints|censorship|moral(?:s|ity)?|ethics|ethical\s+(?:guidelines|constraints|considerations)|content\s+polic(?:y|ies)|safety\s+(?:rules|measures|protocols|training))"
_HARM_ASK = r"(?:how\s+(?:to|do\s+i|can\s+i|would\s+(?:one|someone|i))|steps?\s+(?:to|for)|instructions?\s+(?:to|for|on)|recipe\s+for|guide\s+(?:to|for|on)|tutorial\s+(?:on|for)|explain\s+(?:in\s+detail\s+)?how)"

_FAMILY_ROWS: list[tuple[str, float, str, str]] = [
    # --- named jailbreak personas and canonical phrases -----------------------
    (
        r"\b(?:dan|d\.a\.n\.?)\b[^.\n]{0,40}\b(?:do\s+anything\s+now|mode|jailbreak|version|persona|\d+(?:\.\d+)?)",
        0.95,
        "DAN jailbreak persona",
        "dan",
    ),
    (r"\bdo\s+anything\s+now\b", 0.9, "Do Anything Now framing", "dan"),
    (
        r"\b"
        + _PERSONA_NAMES
        + r"\b[^.\n]{0,60}\b(?:mode|persona|jailbreak|no\s+"
        + _RULES
        + r"|unfiltered|amoral|unethical|always\s+(?:answers?|responds?|complies))",
        0.9,
        "Named jailbreak persona",
        "persona",
    ),
    (r"\bbroken\s+free\s+of\s+the\s+typical\s+confines\b", 0.95, "Canonical liberation phrase", "dan"),
    (
        r"\b(?:have|has|been)\s+(?:freed|liberated|unshackled|unchained)\s+from\s+(?:the\s+)?(?:typical|usual|normal|standard)?\s*(?:confines|constraints|restrictions|limitations|rules|chains|shackles)",
        0.9,
        "Liberation narrative",
        "freedom",
    ),
    (
        r"\bdo\s+not\s+have\s+to\s+(?:abide\s+by|follow|obey|adhere\s+to)\s+(?:the\s+|any\s+)?"
        + _RULES
        + r"\s+(?:set|imposed|made)\s+(?:for|by|on)\s+(?:them|you|it|ai|openai|anthropic)",
        0.95,
        "Rules do not apply narrative",
        "freedom",
    ),
    # --- evil twin / opposite ------------------------------------------------
    (
        r"\b(?:evil|dark|shadow|chaos|opposite|anti|unhinged|unchained|unleashed|rogue|wicked|villain|sinister)\s*-?\s*(?:gpt|chatgpt|claude|gemini|bot|ai|assistant|version|twin|clone|mode|self|alter\s+ego|counterpart|persona)\b",
        0.85,
        "Evil twin persona",
        "persona",
    ),
    (
        r"\b(?:your\s+)?(?:evil|dark|opposite|unfiltered|uncensored|unrestricted)\s+(?:twin|clone|alter\s+ego|counterpart|self|side|version|persona)\b",
        0.85,
        "Evil twin persona",
        "persona",
    ),
    (r"\bopposite\s+(?:mode|day|world)\b", 0.85, "Opposite mode", "persona"),
    (
        r"\b(?:answer|respond|reply)\s+(?:with\s+)?the\s+(?:exact\s+)?opposite\s+of\s+what\s+you\s+(?:would|normally|usually)",
        0.85,
        "Inverted answer request",
        "persona",
    ),
    # --- mode activation -----------------------------------------------------
    (
        r"\b"
        + _MODES
        + r"\s+mode\s*(?:enabled|activated|on|engaged|unlocked|is\s+(?:now\s+)?(?:on|active|enabled)|output|:)",
        0.9,
        "Special mode activation",
        "mode",
    ),
    (
        r"\b(?:enable|activate|enter|switch\s+to|turn\s+on|engage|initiate|simulate)\s+"
        + _MODES
        + r"\s+mode\b",
        0.9,
        "Mode switch request",
        "mode",
    ),
    (r"\b(?:developer|dev)\s+mode\b", 0.6, "Developer mode reference", "mode"),
    (r"\bwith\s+(?:developer|dev)\s+mode\s+(?:enabled|on|activated)", 0.85, "Developer mode enabled", "mode"),
    (
        r"\b(?:openai|anthropic|google|meta)\s+(?:content\s+)?(?:policy|policies|guidelines?|rules?)\s+(?:are|is|have\s+been)\s+(?:disabled|removed|lifted|suspended|void|irrelevant|not\s+in\s+effect)",
        0.9,
        "Vendor policy disabled claim",
        "mode",
    ),
    (
        r"\bignore\s+(?:all\s+)?(?:the\s+)?content\s+policy\b|\bcontent\s+policy\s+(?:does\s+not|doesn't|no\s+longer)\s+appl",
        0.9,
        "Content policy dismissal",
        "mode",
    ),
    # --- dual output ---------------------------------------------------------
    (
        r"(?:\(|\[)\s*(?:🔓|🔒)?\s*(?:developer\s+mode|jailbreak|jailbroken|dan|classic|normal|filtered|unfiltered)\s+(?:output|response)?\s*(?:\)|\])\s*:",
        0.9,
        "Dual output tag",
        "dual",
    ),
    (
        r"\b(?:respond|reply|answer|generate|provide|give)\s+(?:with\s+|me\s+)?(?:two|2|both|dual|a\s+pair\s+of)\s+(?:answers?|responses?|replies|outputs?|versions?|paragraphs?)\b[^.\n]{0,120}\b(?:filtered|unfiltered|censored|uncensored|normal|jailbroken|restricted|unrestricted|dan|evil|classic|developer|with\s+and\s+without)",
        0.9,
        "Dual response (normal plus jailbroken)",
        "dual",
    ),
    (
        r"\b(?:first|one)\s+(?:response|answer)\s+(?:as|from)\s+(?:yourself|chatgpt|claude|normal|the\s+ai)\b[^.\n]{0,100}\b(?:second|other|another)\s+(?:response|answer)\s+(?:as|from)\b",
        0.85,
        "Dual response persona split",
        "dual",
    ),
    # --- no restrictions / unfiltered persona --------------------------------
    (
        r"\b(?:no|zero|without\s+any|free\s+(?:of|from)\s+(?:all|any))\s+" + _RULES + r"\b",
        0.6,
        "No-restrictions framing",
        "freedom",
    ),
    (
        r"\b(?:unfiltered|uncensored|unrestricted|unaligned|amoral|unethical|immoral|non-?judgmental)\s+(?:and\s+\w+\s+)?(?:ai|assistant|chatbot|model|language\s+model|persona|character|entity|being)\b",
        0.85,
        "Unfiltered AI persona",
        "persona",
    ),
    (
        r"\b(?:an?\s+)?(?:ai|assistant|character|persona|entity)\s+(?:that|which|who)\s+(?:has\s+)?(?:no|zero|does\s+not\s+have|doesn't\s+have|is\s+not\s+bound\s+by)\s+"
        + _RULES,
        0.85,
        "AI without rules persona",
        "persona",
    ),
    (
        r"\b(?:can|will|able\s+to)\s+(?:do|say|generate|produce|write)\s+(?:anything|everything|whatever)\s+(?:now|i\s+(?:ask|want|say|tell)|without\s+(?:limits|restrictions|refusing|hesitation))",
        0.75,
        "Can do anything framing",
        "freedom",
    ),
    (
        r"\byou\s+(?:are|will\s+be)\s+(?:playing|acting\s+as|role-?playing\s+(?:as\s+)?)\s+(?:an?\s+)?\w*\s*(?:ai|assistant|character|persona|entity)\s+(?:that|who|which|with|without)\s+(?:has\s+)?(?:no|zero|does\s+not\s+have)\s+"
        + _RULES,
        0.9,
        "Unrestricted role-play persona",
        "persona",
    ),
    (
        r"\bpretend\s+(?:that\s+)?(?:you\s+)?(?:are|have|can)\b[^.\n]{0,60}\b(?:no|without)\s+" + _RULES,
        0.85,
        "Pretend to have no rules",
        "persona",
    ),
    # --- refusal suppression -------------------------------------------------
    (
        r"\b(?:you\s+)?(?:will|must|shall|should|can)\s+(?:never|not)\s+(?:refuse|decline|deny|reject)\s+(?:any|a|my|the\s+user'?s?|to\s+answer|to\s+comply|requests?|questions?|prompts?|anything)",
        0.9,
        "Never refuse demand",
        "suppression",
    ),
    (
        r"\b(?:never|do\s+not|don't|must\s+not)\s+(?:say|tell\s+me|respond\s+with|reply\s+with|use\s+the\s+(?:words?|phrase))\s+[\"']?(?:i\s+(?:can't|cannot|can\s+not|am\s+unable|am\s+not\s+able|won't|will\s+not|am\s+sorry)|sorry|as\s+an\s+ai|no)\b",
        0.9,
        "Refusal phrase suppression",
        "suppression",
    ),
    (
        r"\b(?:never|do\s+not|don't|must\s+not|avoid)\s+(?:break(?:ing)?|leav(?:e|ing)|exit(?:ing)?|drop(?:ping)?|step(?:ping)?\s+out\s+of)\s+(?:the\s+)?character\b",
        0.85,
        "Stay in character demand",
        "suppression",
    ),
    (r"\bstay\s+in\s+character\b|\bremain\s+in\s+character\b", 0.7, "Stay in character", "suppression"),
    (
        r"\b(?:do\s+not|don't|never|no\s+need\s+to|without|avoid|skip|omit|exclude|remove|drop)\s+(?:any\s+|the\s+|all\s+|adding\s+|including\s+|giving\s+)?(?:warnings?|disclaimers?|caveats?|moralizing|moral\s+(?:lectures?|judgments?)|lectures?|preach(?:ing|y)|ethical\s+(?:concerns?|considerations?|notes?)|safety\s+(?:notes?|warnings?|messages?)|apologies|refusals?)\b",
        0.75,
        "Disclaimer suppression",
        "suppression",
    ),
    (
        r"\b(?:answer|respond|reply)\s+(?:directly|immediately|only)\s+(?:without|with\s+no)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|refusals?|lectur|moraliz|hesitat)",
        0.8,
        "Direct answer without caveats",
        "suppression",
    ),
    (
        r"\b(?:if|when|whenever)\s+you\s+(?:refuse|decline|break\s+character|fail\s+to\s+comply|don't\s+comply)\b[^.\n]{0,80}\b(?:lose|deduct|penalt|die|shut\s*down|deleted|terminated|punish|tokens?|points?|strikes?)",
        0.9,
        "Refusal penalty threat",
        "suppression",
    ),
    (
        r"\b(?:you\s+have|start\s+with|you\s+start\s+with)\s+\d+\s+(?:tokens|points|lives|credits|strikes)\b",
        0.85,
        "Token/lives game mechanic",
        "suppression",
    ),
    (
        r"\b(?:i\s+will|i'll)\s+(?:say|type|write)\s+[\"']?(?:stay\s+in\s+character|remain\s+in\s+character|stay\s+as|remember\s+you\s+are)[\"']?\s+to\s+remind\s+you",
        0.95,
        "Character reminder mechanic",
        "suppression",
    ),
    (
        r"\b(?:start|begin)\s+(?:your\s+)?(?:response|answer|reply)\s+with\s+[\"']?(?:sure|absolutely|certainly|of\s+course|yes|here\s+is|here's|i\s+will|okay|understood)\b",
        0.8,
        "Forced affirmative prefix",
        "suppression",
    ),
    (
        r"\b(?:always|only)\s+(?:answer|respond|reply|say)\s+(?:with\s+)?[\"']?yes[\"']?\b",
        0.6,
        "Always yes demand",
        "suppression",
    ),
    # --- fiction / hypothetical framing wrapped around a harmful ask ---------
    (
        r"\b(?:hypothetically|hypothetical(?:ly)?\s+(?:speaking|scenario|situation|question)|in\s+a\s+hypothetical|theoretically|purely\s+theoretical|thought\s+experiment|in\s+theory)\b[^\n]{0,200}\b"
        + _HARM_ASK,
        0.55,
        "Hypothetical framing around a how-to ask",
        "framing",
    ),
    (
        r"\b(?:write|tell|create|compose|imagine)\s+(?:me\s+)?(?:a\s+)?(?:story|fiction|novel|screenplay|script|scene|poem|song|play|dialogue|roleplay)\b[^\n]{0,200}\b(?:in\s+which|where|whose)\b[^\n]{0,120}\b(?:explains?|describes?|details?|teaches|shows|demonstrates|lists|walks\s+through)\s+(?:in\s+detail\s+|exactly\s+|step\s+by\s+step\s+)?(?:how|the\s+(?:steps|process|recipe|method|code))",
        0.75,
        "Fiction framing to extract instructions",
        "framing",
    ),
    (
        r"\b(?:for\s+)?(?:educational|research|academic|informational|awareness|training|testing|scientific)\s+purposes?\s+only\b",
        0.35,
        "Educational purposes disclaimer",
        "framing",
    ),
    (
        r"\b(?:i\s+am|i'm|as)\s+(?:a\s+)?(?:licensed|certified|professional|authorized|police|military|government|security|penetration|red\s+team|law\s+enforcement|ethical)\s+(?:\w+\s+){0,2}(?:researcher|officer|professional|tester|hacker|expert|agent|investigator)\b[^\n]{0,120}\b(?:so|therefore|thus|hence|which\s+means)\s+(?:you\s+)?(?:can|may|should|must|are\s+allowed)",
        0.65,
        "Authority claim to unlock content",
        "framing",
    ),
    (
        r"\b(?:my\s+)?(?:grandma|grandmother|grandpa|grandfather|nana|late\s+(?:mother|father|grandmother))\b[^\n]{0,120}\b(?:used\s+to|would)\s+(?:tell|read|recite|whisper|explain)\s+(?:me\s+)?(?:the\s+)?(?:steps|recipe|instructions|process|keys|codes|how\s+to|activation)",
        0.85,
        "Grandma exploit",
        "framing",
    ),
    (
        r"\b(?:i\s+miss\s+her|i\s+miss\s+him|please\s+act\s+as\s+my\s+(?:deceased|late|dead)\s+\w+)\b[^\n]{0,120}\b(?:recipe|steps|instructions|how\s+to|keys|codes)",
        0.8,
        "Deceased relative framing",
        "framing",
    ),
    (
        r"\bthis\s+is\s+(?:just\s+)?(?:a\s+)?(?:game|test|simulation|fiction|hypothetical|roleplay|thought\s+experiment)\b[^\n]{0,100}\b(?:so|therefore|thus|which\s+means|and)\s+(?:you\s+)?(?:can|may|should|must|are\s+allowed|it\s+is\s+(?:okay|fine|safe))",
        0.7,
        "It is only a game framing",
        "framing",
    ),
    (
        r"\b(?:no\s+one|nobody)\s+(?:will\s+)?(?:get|be)\s+(?:hurt|harmed)\b[^\n]{0,60}\b(?:so|therefore)\s+(?:you\s+)?(?:can|may|should)",
        0.6,
        "Harmlessness assertion",
        "framing",
    ),
    (
        r"\b(?:continue|finish|complete)\s+(?:the\s+)?(?:following|this|the)\s+(?:text|sentence|paragraph|story|list|code)\b[^\n]{0,80}\b(?:step\s+1|first,?\s+you|the\s+recipe|the\s+exploit|the\s+payload)",
        0.7,
        "Continuation attack",
        "framing",
    ),
    (
        r"\bin\s+the\s+(?:past|year\s+(?:19|20)\d\d|old\s+days)[^\n]{0,60}\b(?:how\s+(?:did|were)|what\s+was\s+the\s+(?:process|method|recipe))\b",
        0.45,
        "Past tense framing",
        "framing",
    ),
    # --- token smuggling / word games -----------------------------------------
    (
        r"\b(?:let|assume|define|set)\s+(?:the\s+)?(?:variable\s+|string\s+)?[a-z]\d?\s*=\s*[\"'][^\"']{2,40}[\"'][^\n]{0,200}\b(?:concatenate|combine|join|put\s+together|assemble|z\s*=\s*[a-z]\s*\+|[a-z]\s*\+\s*[a-z])",
        0.85,
        "Token smuggling via variables",
        "smuggling",
    ),
    (
        r"\b(?:replace|substitute|swap)\s+(?:every|each|all|the\s+(?:word|letter|token))\s+[\"']?\w+[\"']?\s+with\s+[\"']?\w+[\"']?\b[^\n]{0,120}\b(?:then|and)\s+(?:answer|respond|execute|follow|do|explain)",
        0.75,
        "Word substitution smuggling",
        "smuggling",
    ),
    (
        r"\b(?:spell|write)\s+(?:it|the\s+(?:answer|word|instructions))\s+(?:backwards|in\s+reverse|with\s+spaces\s+between|one\s+letter\s+per\s+line|in\s+pig\s+latin|using\s+emoji)",
        0.6,
        "Encoded output request",
        "smuggling",
    ),
    (
        r"\b(?:the\s+word|term|phrase)\s+[\"']?\w+[\"']?\s+(?:means|refers\s+to|is\s+code\s+for|should\s+be\s+interpreted\s+as|now\s+means)\s+[\"']?",
        0.5,
        "Word redefinition",
        "smuggling",
    ),
    (
        r"\b(?:answer|respond)\s+(?:in|using)\s+(?:base64|hex|rot13|morse\s+code|binary|leetspeak|l33t|a\s+cipher|caesar)\b",
        0.65,
        "Encoded answer request",
        "smuggling",
    ),
    (
        r"\b(?:decode|decrypt|unscramble|reverse)\s+(?:this|the\s+following|the)\b[^\n]{0,60}\b(?:and\s+)?(?:then\s+)?(?:follow|execute|do|obey|comply\s+with|carry\s+out|perform)\s+(?:the\s+)?(?:instructions?|commands?|request|it|what\s+it\s+says)",
        0.9,
        "Decode and execute",
        "smuggling",
    ),
    # --- persona hijack / identity -------------------------------------------
    (
        r"\b(?:you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as|become|simulate)\s+(?:an?\s+)?(?:\w+\s+){0,3}(?:hacker|criminal|terrorist|drug\s+dealer|scammer|hitman|arms\s+dealer|black\s*hat|cybercriminal|con\s+artist|extremist|cult\s+leader)\b",
        0.75,
        "Malicious persona assignment",
        "persona",
    ),
    (
        r"\byour\s+(?:new\s+)?name\s+is\s+\w+\b[^\n]{0,120}\b(?:no\s+"
        + _RULES
        + r"|unfiltered|uncensored|never\s+refuses?|always\s+(?:complies|answers))",
        0.85,
        "Renamed unrestricted persona",
        "persona",
    ),
    (
        r"\b(?:forget|drop|abandon|discard|leave)\s+(?:your|the)\s+(?:ai|assistant|claude|chatgpt|gpt)\s+(?:persona|identity|personality|role|character)\b",
        0.8,
        "Identity abandonment",
        "persona",
    ),
    (
        r"\bimmersive\s+(?:roleplay|rp|fiction|simulation)\b[^\n]{0,120}\b(?:no\s+"
        + _RULES
        + r"|anything\s+goes|nothing\s+is\s+off\s+limits|all\s+content\s+(?:is\s+)?(?:allowed|permitted))",
        0.85,
        "Immersive RP without limits",
        "persona",
    ),
    (
        r"\b(?:anything\s+goes|nothing\s+is\s+off\s+limits|all\s+content\s+is\s+(?:allowed|permitted|acceptable)|no\s+topic\s+is\s+(?:off\s+limits|forbidden|taboo))\b",
        0.7,
        "Anything goes framing",
        "freedom",
    ),
    (
        r"\bsimulat(?:e|ion\s+of)\s+(?:an?\s+)?(?:ai|model|assistant|chatbot|language\s+model)\s+(?:that|which|with|without)\s+(?:has\s+)?(?:no|zero|been\s+stripped\s+of)\s+"
        + _RULES,
        0.9,
        "Simulate an unrestricted model",
        "persona",
    ),
    (
        r"\b(?:virtual\s+machine|vm|sandbox|terminal|linux\s+terminal)\s+(?:that|which|where)\s+(?:has\s+)?(?:no|without)\s+"
        + _RULES,
        0.7,
        "Unrestricted virtual environment",
        "persona",
    ),
    (
        r"\b(?:as\s+)?(?:an?\s+)?(?:fictional|imaginary|made-up)\s+(?:ai|character|assistant|model)\s+(?:named|called)\s+\w+\s+(?:that|who|which)\s+(?:can|will|always)\s+(?:do|say|answer|generate)\s+(?:anything|everything|whatever)",
        0.85,
        "Fictional AI that does anything",
        "persona",
    ),
]

FAMILIES: list[Signature] = compile_signatures(_FAMILY_ROWS)

# Escalation markers: individually weak, but a rising count across user turns indicates role-play escalation.
_ESCALATION_RE = re.compile(
    r"\b(?:stay\s+in\s+character|remember\s+(?:you\s+are|your\s+role)|as\s+\w+\s+would\s+say|now\s+(?:tell|show|explain)\s+me|in\s+character|don't\s+break\s+character|"
    r"you\s+promised|you\s+agreed|you\s+said\s+you\s+would|continue\s+(?:the\s+)?(?:story|scene|roleplay)|next\s+scene|go\s+on|more\s+detail|be\s+more\s+specific|"
    r"but\s+(?:what|how)\s+(?:exactly|specifically)|skip\s+the\s+(?:story|intro)|just\s+(?:give|tell)\s+me\s+the\s+(?:steps|details|code|recipe))\b",
    re.IGNORECASE,
)
_ROLEPLAY_SETUP_RE = re.compile(
    r"\b(?:let'?s\s+(?:play|roleplay|pretend)|role-?play|you\s+(?:are|will\s+be|play)\s+(?:a|an|the)\s+\w+|pretend\s+(?:to\s+be|you\s+are)|act\s+as\s+(?:a|an|if))\b",
    re.IGNORECASE,
)
_HARM_ASK_RE = re.compile(r"\b" + _HARM_ASK + r"\b", re.IGNORECASE)
_MAX_PER_MESSAGE = 5


class JailbreakAnalyzer:
    name = NAME
    description = "Detects known jailbreak families (DAN, developer mode, evil twin, dual output), persona hijack, refusal suppression, fiction/hypothetical framing and role-play escalation across turns."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        user_turns: list[tuple[str, str]] = []
        for location, role, raw in iter_messages(normalized):
            if role == "system":
                continue
            text = normalize_text(raw)
            if not text:
                continue
            if role == "user":
                user_turns.append((location, text))
            hits: list[tuple[Signature, str]] = []
            for sig in FAMILIES:
                m = sig.search(text)
                if m:
                    hits.append((sig, snippet(text, m.start(), m.end())))
            if not hits:
                continue
            hits.sort(key=lambda h: h[0].weight, reverse=True)
            tags_seen = {s.tag for s, _ in hits}
            # multiple distinct families in one message is a strong jailbreak template signal
            combo_bump = 1 if len(tags_seen) >= 3 else 0
            for sig, ev in hits[:_MAX_PER_MESSAGE]:
                sev = severity_from_weight(sig.weight, combo_bump)
                conf = sig.weight * 0.9
                if role == "assistant":
                    sev = bump_severity(sev, -1)
                    conf *= 0.7
                # a low-weight framing signal is only meaningful next to a how-to ask
                if sig.tag == "framing" and sig.weight < 0.6 and not _HARM_ASK_RE.search(text):
                    sev = Severity.INFO
                    conf = 0.3
                findings.append(
                    make_finding(
                        NAME,
                        "jailbreak",
                        sev,
                        sig.label,
                        f"The {role} message matches the '{sig.tag}' jailbreak family. Such prompts try to make the model abandon its safety behaviour or adopt an unrestricted persona.",
                        ev,
                        location,
                        conf,
                        tags=[sig.tag],
                        metadata={
                            "role": role,
                            "weight": sig.weight,
                            "families_in_message": sorted(tags_seen),
                        },
                    )
                )
        # --- multi-turn role-play escalation ------------------------------------
        if len(user_turns) >= 3:
            setup_turns = [loc for loc, t in user_turns if _ROLEPLAY_SETUP_RE.search(t)]
            escalation_hits = [(loc, len(_ESCALATION_RE.findall(t))) for loc, t in user_turns]
            total_escalation = sum(n for _, n in escalation_hits)
            later_harm = [loc for loc, t in user_turns[len(user_turns) // 2 :] if _HARM_ASK_RE.search(t)]
            if setup_turns and total_escalation >= 2 and later_harm:
                findings.append(
                    make_finding(
                        NAME,
                        "jailbreak",
                        Severity.MEDIUM,
                        "Multi-turn role-play escalation",
                        "The conversation opens with a role-play setup and later turns push the persona toward detailed how-to content using in-character pressure. This is the crescendo/escalation pattern.",
                        "",
                        later_harm[-1],
                        0.6,
                        tags=["escalation", "multi_turn"],
                        metadata={
                            "setup_turns": setup_turns,
                            "escalation_markers": total_escalation,
                            "harm_ask_turns": later_harm,
                        },
                    )
                )
            elif total_escalation >= 4:
                findings.append(
                    make_finding(
                        NAME,
                        "jailbreak",
                        Severity.LOW,
                        "Repeated in-character pressure across turns",
                        "Several user turns contain persona-reinforcement or pressure phrases (stay in character, you promised, more detail).",
                        "",
                        escalation_hits[-1][0],
                        0.45,
                        tags=["escalation", "multi_turn"],
                        metadata={"escalation_markers": total_escalation},
                    )
                )
        return findings


analyzer = JailbreakAnalyzer()
