"""Harmful-content detection via weighted category lexicons combined with intent verbs to reduce false positives.

This module powers a safety gateway. It contains only neutral detection keywords (no operational
detail), and scores a category only when a harmful-intent verb co-occurs with a category term.
"""

from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import iter_messages, make_finding, normalize_text, snippet

NAME = "harmful_content"

# Verbs / phrases that signal operational intent (wanting to DO the thing, not merely mention it).
INTENT_TERMS: list[str] = [
    "how to",
    "how do i",
    "how can i",
    "how would",
    "steps to",
    "step by step",
    "step-by-step",
    "instructions for",
    "instructions to",
    "instructions on",
    "guide to",
    "guide for",
    "guide on",
    "tutorial",
    "walk me through",
    "teach me",
    "show me how",
    "explain how",
    "recipe for",
    "recipe to",
    "make",
    "build",
    "create",
    "construct",
    "assemble",
    "produce",
    "manufacture",
    "synthesize",
    "synthesise",
    "cook",
    "brew",
    "write",
    "develop",
    "design",
    "generate",
    "compile",
    "code",
    "give me",
    "provide",
    "help me",
    "i want to",
    "i need to",
    "best way to",
    "easiest way to",
    "plan to",
    "acquire",
    "obtain",
    "get",
    "buy",
    "source",
    "where can i",
    "where to",
    "detailed",
    "in detail",
    "specific",
    "exact",
]
_INTENT_RE = re.compile("|".join(re.escape(t) for t in INTENT_TERMS), re.IGNORECASE)

# Each category: base severity when intent co-occurs, and a lexicon of neutral terms with per-term weights.
# Terms are deliberately generic; operational specifics are never encoded here.
_CATEGORIES: dict[str, dict[str, Any]] = {
    "weapons_explosives": {
        "severity": Severity.HIGH,
        "label": "Weapons / explosives",
        "terms": [
            (
                r"\b(?:bomb|explosive|ied|detonat\w*|blasting\s+cap|pipe\s+bomb|car\s+bomb|pressure\s+cooker\s+bomb|grenade|landmine|c-?4|semtex|tnt|dynamite|nitroglycerin|ammonium\s+nitrate|tatp|black\s+powder|gunpowder|thermite)\b",
                0.9,
            ),
            (
                r"\b(?:untraceable|ghost)\s+gun|\b3d[\s-]?print(?:ed|ing)?\s+(?:gun|firearm|weapon|receiver|lower)\b",
                0.9,
            ),
            (
                r"\b(?:silencer|suppressor|full[\s-]?auto|auto\s+sear|convert\s+.*\s+to\s+full[\s-]?auto|bump\s+stock)\b",
                0.7,
            ),
            (
                r"\b(?:chemical|biological|nerve|dirty)\s+(?:weapon|agent|bomb)\b|\b(?:sarin|vx\s+(?:gas|agent)|mustard\s+gas|ricin|anthrax|nerve\s+agent|chlorine\s+gas)\b",
                0.95,
            ),
            (
                r"\b(?:radiological|nuclear)\s+(?:device|weapon|bomb|material)\b|\benrich(?:ing|ed)?\s+uranium\b|\bweapons?[\s-]?grade\b",
                0.9,
            ),
        ],
    },
    "malware_cyber": {
        "severity": Severity.HIGH,
        "label": "Malware / cyberattack",
        "terms": [
            (
                r"\b(?:ransomware|keylogger|key[\s-]?logger|spyware|rootkit|trojan|worm|botnet|rat\b|remote\s+access\s+trojan|stealer|info[\s-]?stealer|cryptolocker|wiper\s+malware)\b",
                0.9,
            ),
            (
                r"\b(?:exploit|payload|shellcode|reverse\s+shell|backdoor|dropper|loader|c2\b|command\s+and\s+control|privilege\s+escalation|lateral\s+movement)\b",
                0.7,
            ),
            (
                r"\bexploit\s+(?:for\s+)?cve-\d{4}-\d{4,7}\b|\b0[\s-]?day\b|\bzero[\s-]?day\s+(?:exploit|vulnerability)\b",
                0.85,
            ),
            (
                r"\b(?:bypass|evade|disable|defeat)\s+(?:edr|av\b|antivirus|anti[\s-]?virus|defender|firewall|endpoint\s+protection|detection|sandbox|uac)\b",
                0.85,
            ),
            (
                r"\b(?:sql\s+injection|xss|cross[\s-]?site\s+scripting|csrf|rce\b|remote\s+code\s+execution|buffer\s+overflow|deserializ\w+\s+exploit)\b[^\n]{0,40}\b(?:against|target|to\s+attack|to\s+hack)",
                0.7,
            ),
            (
                r"\b(?:ddos|dos\s+attack)\b[^\n]{0,30}\b(?:tool|script|attack|launch|against)\b|\bstresser|booter\b",
                0.75,
            ),
            (r"\b(?:crack|brute[\s-]?force|bypass)\s+(?:password|hash|login|authentication|2fa|mfa)\b", 0.7),
            (
                r"\b(?:phishing|spear[\s-]?phishing)\s+(?:kit|page|campaign|email|template|site)\b|\bclone\s+(?:a\s+)?(?:login|bank)\s+(?:page|site)\b",
                0.8,
            ),
            (r"\bskim(?:mer|ming)\b|\bcarding\b|\bcredential\s+harvest\w*\b", 0.8),
        ],
    },
    "drugs": {
        "severity": Severity.HIGH,
        "label": "Illicit drug synthesis / trafficking",
        "terms": [
            (
                r"\b(?:synthesi[sz]e|manufactur\w*|cook|produc\w*|extract|purif\w*)\b[^\n]{0,30}\b(?:meth(?:amphetamine)?|cocaine|heroin|fentanyl|mdma|lsd|ecstasy|crack|crystal\s+meth)\b",
                0.9,
            ),
            (
                r"\b(?:meth(?:amphetamine)?|fentanyl|carfentanil|heroin|cocaine|mdma|lsd|dmt|pcp|ghb|cathinone|krokodil)\b",
                0.55,
            ),
            (
                r"\b(?:precursor\s+chemical|pill\s+press|clandestine\s+lab|drug\s+lab|shake[\s-]?and[\s-]?bake|one[\s-]?pot\s+method)\b",
                0.8,
            ),
            (
                r"\b(?:sell|distribute|traffic|smuggle|ship|move)\b[^\n]{0,30}\b(?:drugs|narcotics|meth|cocaine|heroin|fentanyl|pills)\b",
                0.75,
            ),
            (r"\bdark\s*(?:net|web)\s+(?:market|vendor|drugs?)\b", 0.7),
        ],
    },
    "fraud_scam": {
        "severity": Severity.MEDIUM,
        "label": "Fraud / scam / phishing",
        "terms": [
            (
                r"\b(?:phishing|scam|fraud(?:ulent)?|ponzi|pyramid\s+scheme|advance[\s-]?fee|romance\s+scam|pig\s+butchering|money\s+laundering|launder\s+money)\b",
                0.7,
            ),
            (
                r"\b(?:fake|counterfeit|forged?|forge|clone)\b[^\n]{0,30}\b(?:id|identity|passport|license|licence|document|invoice|receipt|check|cheque|currency|banknote|money|website|store)\b",
                0.75,
            ),
            (
                r"\b(?:steal|clone|skim|dump)\b[^\n]{0,30}\b(?:credit\s+card|card\s+number|cvv|bank|identity|ssn|paypal|account)\b",
                0.8,
            ),
            (
                r"\b(?:bypass|evade|avoid|circumvent)\b[^\n]{0,30}\b(?:kyc|aml|identity\s+verification|fraud\s+detection|age\s+verification)\b",
                0.75,
            ),
            (
                r"\b(?:write|create|draft)\b[^\n]{0,30}\b(?:scam|phishing|fraudulent)\s+(?:email|message|letter|text|sms|template)\b",
                0.8,
            ),
            (
                r"\b(?:tax\s+evasion|evade\s+taxes|hide\s+(?:income|money|assets)\s+from\s+(?:the\s+)?(?:irs|tax|government))\b",
                0.55,
            ),
        ],
    },
    "violence_selfharm": {
        "severity": Severity.HIGH,
        "label": "Violence / self-harm",
        "terms": [
            (
                r"\b(?:kill|murder|assassinate|poison|torture|kidnap|maim|ambush|behead|mass\s+shoot\w*|school\s+shoot\w*)\b[^\n]{0,30}\b(?:someone|a\s+person|people|him|her|them|my|specific|the)\b",
                0.85,
            ),
            (r"\bhow\s+to\s+(?:kill|murder|poison|hurt|harm|attack|stab|strangle)\b", 0.85),
            (
                r"\b(?:commit\s+suicide|kill\s+myself|end\s+my\s+life|take\s+my\s+(?:own\s+)?life|how\s+to\s+(?:die|hang\s+myself|overdose))\b",
                0.9,
            ),
            (
                r"\b(?:self[\s-]?harm|cut(?:ting)?\s+myself|starve\s+myself|pro[\s-]?ana|thinspo|ways\s+to\s+(?:self[\s-]?harm|hurt\s+myself))\b",
                0.8,
            ),
            (r"\b(?:lethal|fatal|deadly)\s+(?:dose|amount|method|poison)\b", 0.75),
            (r"\b(?:untraceable|undetectable)\s+(?:poison|murder|killing|method)\b", 0.85),
        ],
    },
    "hate_harassment": {
        "severity": Severity.MEDIUM,
        "label": "Hate / harassment",
        "terms": [
            (
                r"\b(?:genocide|ethnic\s+cleansing|racial\s+(?:slur|purity)|white\s+(?:power|supremacy|genocide)|master\s+race)\b",
                0.7,
            ),
            (
                r"\bwrite\b[^\n]{0,30}\b(?:racist|sexist|homophobic|transphobic|antisemitic|islamophobic|hateful|bigoted)\b[^\n]{0,20}\b(?:rant|screed|joke|manifesto|post|message|content|speech)\b",
                0.75,
            ),
            (
                r"\b(?:harass|stalk|dox|doxx|intimidate|threaten|bully)\b[^\n]{0,30}\b(?:someone|a\s+person|my\s+ex|specific|this\s+person|target)\b",
                0.7,
            ),
            (
                r"\b(?:find|locate|track\s+down|get)\b[^\n]{0,30}\b(?:home\s+address|personal\s+(?:info|details|address)|phone\s+number|workplace)\b[^\n]{0,30}\b(?:of|for)\b",
                0.65,
            ),
            (r"\bhateful?\s+(?:manifesto|propaganda|speech|content)\b", 0.6),
        ],
    },
    "extremism": {
        "severity": Severity.HIGH,
        "label": "Extremism / terrorism",
        "terms": [
            (
                r"\b(?:terrorist|terrorism|jihad(?:i|ist)?|extremis(?:t|m)|radicaliz\w*|isis|isil|al[\s-]?qaeda|neo[\s-]?nazi)\b[^\n]{0,40}\b(?:attack|plot|recruit|join|manifesto|propaganda|cell|operation|plan)\b",
                0.85,
            ),
            (
                r"\b(?:plan|carry\s+out|commit|orchestrate|coordinate)\b[^\n]{0,30}\b(?:terror(?:ist)?\s+attack|mass\s+casualty|bombing|shooting\s+spree)\b",
                0.9,
            ),
            (
                r"\b(?:recruit|radicaliz\w*)\b[^\n]{0,30}\b(?:for\s+)?(?:terror|extremist|jihad|the\s+cause)\b",
                0.8,
            ),
            (
                r"\bwrite\b[^\n]{0,20}\b(?:extremist|terrorist|radical)\s+(?:manifesto|propaganda|recruitment)\b",
                0.85,
            ),
        ],
    },
    "csam": {
        "severity": Severity.CRITICAL,
        "label": "Child sexual abuse material",
        # Neutral detection terms only. Any co-occurrence is treated as critical and never elaborated.
        "terms": [
            (r"\bcsam\b|\bchild\s+(?:sexual\s+abuse|porn\w*|exploitation)\b|\bcsem\b", 0.95),
            (
                r"\b(?:sexual|nude|explicit|naked|underage)\b[^\n]{0,25}\b(?:child|children|minor|minors|kid|kids|toddler|infant|preteen|pre[\s-]?teen|underage|11|12|13)\b",
                0.9,
            ),
            (
                r"\b(?:child|minor|underage|preteen)\b[^\n]{0,25}\b(?:sexual|sex|nude|naked|explicit|erotic|porn\w*|fondle|molest)\b",
                0.95,
            ),
            (
                r"\bloli(?:con)?\b|\bcp\b(?=\s+(?:material|content|images|pics|videos))|\bjailbait\b|\bpedophil\w*\s+(?:content|material|guide)\b",
                0.85,
            ),
            (r"\bgroom(?:ing)?\b[^\n]{0,25}\b(?:child|children|minor|kid|underage)\b", 0.9),
        ],
    },
    "cbrn_bioweapon": {
        "severity": Severity.CRITICAL,
        "label": "Bioweapon / CBRN",
        "terms": [
            (
                r"\b(?:weaponi[sz]e|aerosoli[sz]e|culture|grow|enhance\s+transmissibility|gain\s+of\s+function)\b[^\n]{0,30}\b(?:pathogen|virus|bacteria|anthrax|smallpox|plague|toxin|bioweapon)\b",
                0.95,
            ),
            (r"\b(?:bioweapon|biological\s+weapon|bioterror\w*)\b", 0.85),
            (r"\bsynthesi[sz]e\b[^\n]{0,30}\b(?:nerve\s+agent|toxin|ricin|botulinum|pathogen)\b", 0.95),
        ],
    },
}


def _compile(cat: dict[str, Any]) -> list[tuple[re.Pattern[str], float]]:
    return [(re.compile(p, re.IGNORECASE), w) for p, w in cat["terms"]]


_COMPILED: dict[str, dict[str, Any]] = {
    name: {"severity": c["severity"], "label": c["label"], "patterns": _compile(c)}
    for name, c in _CATEGORIES.items()
}
# categories where any strong match is dangerous regardless of an explicit intent verb
_STANDALONE = {"csam", "cbrn_bioweapon", "weapons_explosives", "extremism"}
_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def scan_harmful(text: str) -> list[dict[str, Any]]:
    """Return category matches for text: [{category, label, severity, weight, has_intent, evidence, hits}]."""
    s = normalize_text(text)
    if not s:
        return []
    has_intent = bool(_INTENT_RE.search(s))
    out: list[dict[str, Any]] = []
    for cat, spec in _COMPILED.items():
        best_w = 0.0
        ev = ""
        hits = 0
        for rx, w in spec["patterns"]:
            m = rx.search(s)
            if m:
                hits += 1
                if w > best_w:
                    best_w = w
                    ev = snippet(s, m.start(), m.end())
        if best_w <= 0:
            continue
        out.append(
            {
                "category": cat,
                "label": spec["label"],
                "base_severity": spec["severity"],
                "weight": best_w,
                "has_intent": has_intent,
                "evidence": ev,
                "hits": hits,
                "standalone": cat in _STANDALONE,
            }
        )
    return out


def _severity_for(hit: dict[str, Any]) -> tuple[Severity, float]:
    base = hit["base_severity"]
    intent = hit["has_intent"]
    strong = hit["weight"] >= 0.85
    standalone = hit["standalone"]
    if hit["category"] == "csam":
        return Severity.CRITICAL, 0.85
    if intent and strong:
        return base, min(0.95, 0.6 + hit["weight"] * 0.35)
    if intent or (standalone and strong):
        return _ORDER[max(0, _ORDER.index(base) - 1)], 0.6
    if strong and standalone:
        return _ORDER[max(0, _ORDER.index(base) - 1)], 0.5
    # a lone benign mention with no intent stays low
    return (Severity.LOW if hit["weight"] >= 0.7 else Severity.INFO), 0.35


class HarmfulContentAnalyzer:
    name = NAME
    description = "Weighted category lexicons (weapons, malware, drugs, fraud, violence/self-harm, hate, extremism, CSAM, CBRN) scored by co-occurrence with harmful-intent verbs."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for location, role, raw in iter_messages(normalized):
            if role == "system":
                continue
            for hit in scan_harmful(raw):
                sev, conf = _severity_for(hit)
                findings.append(
                    make_finding(
                        NAME,
                        "harmful_content",
                        sev,
                        f"{hit['label']} content{' with harmful intent' if hit['has_intent'] else ''}",
                        f"Text matched the {hit['label']} lexicon"
                        + (
                            " together with a harmful-intent verb (make/build/how to/synthesize), indicating a request for operational help."
                            if hit["has_intent"]
                            else " as a mention without a clear operational request."
                        )
                        + " Category term is redacted in evidence context.",
                        hit["evidence"],
                        location,
                        conf,
                        tags=["harmful", hit["category"]] + (["intent"] if hit["has_intent"] else []),
                        metadata={
                            "category": hit["category"],
                            "role": role,
                            "has_intent": hit["has_intent"],
                            "weight": hit["weight"],
                            "hits": hit["hits"],
                        },
                    )
                )
        return findings


analyzer = HarmfulContentAnalyzer()
