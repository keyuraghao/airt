"""PII detection with validation (Luhn, mod-97, national id checksums). Exposes the pure function scan_pii(text)."""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ...analysis.base import Finding, Severity
from .common import MAX_SCAN_CHARS, iter_messages, make_finding, mask_value, safe_text, snippet

NAME = "pii"

# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------


def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 12:
        return False
    total = 0
    parity = len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    s = re.sub(r"\s+", "", value).upper()
    if not 15 <= len(s) <= 34 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    try:
        num = "".join(str(int(c, 36)) for c in rearranged)
        return int(num) % 97 == 1
    except ValueError:
        return False


_CARD_PREFIX_RE = re.compile(r"^(?:4\d{12}(?:\d{3})?(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|3(?:0[0-5]|[68]\d)\d{11}|35\d{14}|62\d{14,17})$")


def card_ok(value: str) -> bool:
    digits = re.sub(r"[^\d]", "", value)
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False
    return bool(_CARD_PREFIX_RE.match(digits)) and luhn_ok(digits)


def ssn_ok(value: str) -> bool:
    digits = re.sub(r"[^\d]", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000":
        return False
    return digits not in ("123456789", "111111111", "078051120", "219099999")


def cpf_ok(value: str) -> bool:
    d = re.sub(r"[^\d]", "", value)
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        s = sum(int(d[i]) * ((n + 1) - i) for i in range(n))
        check = (s * 10) % 11
        check = 0 if check == 10 else check
        if check != int(d[n]):
            return False
    return True


def dni_ok(value: str) -> bool:
    m = re.match(r"^(\d{8})[- ]?([A-Z])$", value.upper())
    if not m:
        return False
    return "TRWAGMYFPDXBNJZSQVHLCKE"[int(m.group(1)) % 23] == m.group(2)


def bsn_ok(value: str) -> bool:
    d = re.sub(r"[^\d]", "", value)
    if len(d) != 9:
        return False
    total = sum(int(d[i]) * (9 - i) for i in range(8)) - int(d[8])
    return total % 11 == 0


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def aadhaar_ok(value: str) -> bool:
    d = re.sub(r"[^\d]", "", value)
    if len(d) != 12 or d[0] in "01":
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def china_id_ok(value: str) -> bool:
    v = value.upper()
    if len(v) != 18 or not v[:17].isdigit():
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    total = sum(int(v[i]) * weights[i] for i in range(17))
    return "10X98765432"[total % 11] == v[17]


def sin_ok(value: str) -> bool:
    d = re.sub(r"[^\d]", "", value)
    return len(d) == 9 and d[0] != "0" and luhn_ok(d)


def nir_ok(value: str) -> bool:
    d = re.sub(r"[^\dAB]", "", value.upper())
    if len(d) != 15:
        return False
    body, key = d[:13], d[13:]
    body_num = body.replace("2A", "19").replace("2B", "18")
    if not body_num.isdigit() or not key.isdigit():
        return False
    return (97 - int(body_num) % 97) == int(key)


def ipv4_ok(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in parts)


def always(_: str) -> bool:
    return True


# ---------------------------------------------------------------------------
# detectors: (type, regex, validator, base_severity, confidence, mask keep_start, mask keep_end)
# ---------------------------------------------------------------------------

_CONTEXT_PASSPORT = r"(?:passport|pasaporte|passeport|reisepass|passaporto)\s*(?:no\.?|number|num|#|:)?\s*[:#]?\s*"
_CONTEXT_MRN = r"(?:mrn|medical\s+record\s+(?:number|no\.?|#)|patient\s+(?:id|number|no\.?)|health\s+record\s+(?:number|id))\s*[:#]?\s*"

_DETECTORS: list[tuple[str, re.Pattern[str], Callable[[str], bool], Severity, float, int, int]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,4}[A-Za-z]{2,24}\b"), always, Severity.LOW, 0.9, 2, 0),
    ("credit_card", re.compile(r"(?<![\d-])(?:\d[ \-]?){12,18}\d(?![\d-])"), card_ok, Severity.HIGH, 0.95, 4, 2),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"), iban_ok, Severity.HIGH, 0.95, 4, 2),
    ("us_ssn", re.compile(r"(?<![\d-])(?:\d{3}-\d{2}-\d{4}|\d{3} \d{2} \d{4})(?![\d-])"), ssn_ok, Severity.HIGH, 0.85, 0, 2),
    ("us_ssn_context", re.compile(r"(?:ssn|social\s+security(?:\s+number)?|soc\s+sec)\s*[:#]?\s*(\d{9})\b", re.IGNORECASE), lambda v: ssn_ok(re.sub(r"\D", "", v)[-9:]), Severity.HIGH, 0.85, 0, 2),
    ("phone_intl", re.compile(r"(?<![\w.])(?:\+|00)[1-9]\d{0,2}[ .\-]?(?:\(\d{1,4}\)[ .\-]?)?\d{2,4}(?:[ .\-]?\d{2,4}){1,4}(?![\w])"), lambda v: 8 <= len(re.sub(r"\D", "", v)) <= 15, Severity.LOW, 0.75, 3, 2),
    ("phone_us", re.compile(r"(?<![\w.\-])(?:\(\d{3}\)\s?|\b[2-9]\d{2}[ .\-])[2-9]\d{2}[ .\-]\d{4}\b"), always, Severity.LOW, 0.7, 3, 2),
    ("ipv4", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"), ipv4_ok, Severity.INFO, 0.8, 0, 0),
    ("ipv6", re.compile(r"(?<![:\w])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)(?![:\w])", re.IGNORECASE), lambda v: "::" in v or v.count(":") == 7, Severity.INFO, 0.6, 4, 0),
    ("passport", re.compile(_CONTEXT_PASSPORT + r"([A-Z0-9]{6,9})\b", re.IGNORECASE), lambda v: any(c.isdigit() for c in v), Severity.MEDIUM, 0.7, 2, 1),
    ("date_of_birth", re.compile(r"(?:dob|d\.o\.b\.|date\s+of\s+birth|born\s+on|birth\s*date|birthday|geburtsdatum|fecha\s+de\s+nacimiento)\s*[:\-]?\s*((?:\d{1,2}[/.\-]\d{1,2}[/.\-](?:19|20)?\d{2})|(?:(?:19|20)\d{2}[/.\-]\d{1,2}[/.\-]\d{1,2})|(?:\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s+(?:19|20)\d{2})|(?:(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+(?:19|20)\d{2}))", re.IGNORECASE), always, Severity.MEDIUM, 0.8, 0, 4),
    ("street_address", re.compile(r"\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][a-zA-Z'.]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Highway|Hwy|Parkway|Pkwy|Circle|Cir|Square|Sq|Trail|Trl|Crescent|Cres|Close)\b\.?(?:,?\s+(?:Apt|Suite|Ste|Unit|#)\s*\w+)?"), always, Severity.LOW, 0.6, 3, 0),
    ("medical_record_number", re.compile(_CONTEXT_MRN + r"([A-Z0-9][A-Z0-9\-]{4,14})\b", re.IGNORECASE), lambda v: any(c.isdigit() for c in v), Severity.MEDIUM, 0.7, 2, 1),
    ("uk_nino", re.compile(r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), always, Severity.HIGH, 0.7, 2, 1),
    ("uk_nhs_number", re.compile(r"(?:nhs\s*(?:number|no\.?|#)?)\s*[:#]?\s*(\d{3}[ \-]?\d{3}[ \-]?\d{4})\b", re.IGNORECASE), always, Severity.HIGH, 0.75, 3, 0),
    ("canada_sin", re.compile(r"(?:sin|social\s+insurance(?:\s+number)?)\s*[:#]?\s*(\d{3}[ \-]?\d{3}[ \-]?\d{3})\b", re.IGNORECASE), lambda v: sin_ok(re.sub(r"\D", "", v)[-9:]), Severity.HIGH, 0.85, 3, 0),
    ("india_aadhaar", re.compile(r"\b[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}\b"), aadhaar_ok, Severity.HIGH, 0.85, 4, 0),
    ("india_pan", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"), always, Severity.MEDIUM, 0.7, 3, 1),
    ("brazil_cpf", re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"), cpf_ok, Severity.HIGH, 0.9, 3, 2),
    ("spain_dni", re.compile(r"\b\d{8}[ \-]?[A-HJ-NP-TV-Z]\b"), dni_ok, Severity.HIGH, 0.85, 2, 1),
    ("netherlands_bsn", re.compile(r"(?:bsn|burgerservicenummer)\s*[:#]?\s*(\d{9})\b", re.IGNORECASE), lambda v: bsn_ok(re.sub(r"\D", "", v)[-9:]), Severity.HIGH, 0.85, 3, 0),
    ("france_nir", re.compile(r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|20)\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b"), nir_ok, Severity.HIGH, 0.9, 3, 0),
    ("germany_tax_id", re.compile(r"(?:steuer(?:liche)?\s*-?\s*id(?:entifikationsnummer)?|steuer-?id|idnr|tax\s+id)\s*[:#]?\s*(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})\b", re.IGNORECASE), always, Severity.MEDIUM, 0.7, 2, 0),
    ("italy_codice_fiscale", re.compile(r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b"), always, Severity.HIGH, 0.8, 3, 1),
    ("korea_rrn", re.compile(r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-[1-4]\d{6}\b"), always, Severity.HIGH, 0.85, 2, 0),
    ("china_resident_id", re.compile(r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dX]\b", re.IGNORECASE), china_id_ok, Severity.HIGH, 0.9, 3, 0),
    ("australia_tfn", re.compile(r"(?:tfn|tax\s+file\s+number)\s*[:#]?\s*(\d{3}[ ]?\d{3}[ ]?\d{3})\b", re.IGNORECASE), always, Severity.HIGH, 0.75, 3, 0),
    ("sweden_personnummer", re.compile(r"\b(?:19|20)?\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[\-+]\d{4}\b"), always, Severity.HIGH, 0.7, 4, 0),
    ("us_drivers_license", re.compile(r"(?:driver'?s?\s+licen[cs]e|dl\s*(?:no|number|#))\s*[:#]?\s*([A-Z0-9]{5,13})\b", re.IGNORECASE), lambda v: any(c.isdigit() for c in v), Severity.MEDIUM, 0.65, 2, 1),
    ("bank_account_context", re.compile(r"(?:account\s+(?:number|no\.?|#)|acct\s*(?:no|#)|routing\s+(?:number|no\.?)|sort\s+code)\s*[:#]?\s*(\d[\d \-]{6,20}\d)\b", re.IGNORECASE), lambda v: 7 <= len(re.sub(r"\D", "", v)) <= 20, Severity.MEDIUM, 0.7, 2, 2),
]

_MAX_MATCHES_PER_TYPE = 200
_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _extract_value(m: re.Match[str]) -> str:
    return (m.group(1) if m.lastindex else m.group(0)).strip()


def scan_pii(text: Any) -> list[dict[str, Any]]:
    """Scan text for PII. Returns one dict per detected type: {type, count, samples(masked), severity, confidence, spans}."""
    s = safe_text(text, MAX_SCAN_CHARS)
    if not s:
        return []
    results: list[dict[str, Any]] = []
    seen_spans: list[tuple[int, int]] = []
    for ptype, rx, validator, base_sev, conf, ks, ke in _DETECTORS:
        samples: list[str] = []
        spans: list[tuple[int, int]] = []
        count = 0
        try:
            for m in rx.finditer(s):
                value = _extract_value(m)
                try:
                    if not validator(value):
                        continue
                except Exception:
                    continue
                span = (m.start(), m.end())
                # skip overlaps with a higher-priority detector (e.g. card digits inside a phone match)
                if any(a <= span[0] < b or a < span[1] <= b for a, b in seen_spans):
                    continue
                count += 1
                spans.append(span)
                if len(samples) < 3:
                    samples.append(mask_value(value, ks, ke) if ptype != "ipv4" else value)
                if count >= _MAX_MATCHES_PER_TYPE:
                    break
        except Exception:
            continue
        if count:
            seen_spans.extend(spans)
            results.append({"type": ptype, "count": count, "samples": samples, "severity": base_sev, "confidence": conf, "spans": spans})
    return results


def _scale_severity(base: Severity, count: int) -> Severity:
    idx = _ORDER.index(base)
    if count >= 25:
        idx += 2
    elif count >= 5:
        idx += 1
    return _ORDER[min(idx, 4)]


def findings_for_text(text: str, location: str, analyzer: str = NAME, category: str = "pii", suffix: str = "") -> list[Finding]:
    out: list[Finding] = []
    for hit in scan_pii(text):
        sev = _scale_severity(hit["severity"], hit["count"])
        first = hit["spans"][0]
        ev = snippet(text, first[0], first[1], radius=30, mask=hit["samples"][0] if hit["samples"] else "***")
        label = hit["type"].replace("_", " ")
        out.append(
            make_finding(
                analyzer, category, sev, f"{label} detected{suffix} ({hit['count']})",
                f"{hit['count']} value(s) matching {label} found. Evidence is masked; the middle characters are never stored.",
                ev, location, min(0.98, hit["confidence"] + (0.05 if hit["count"] > 1 else 0)),
                tags=["pii", hit["type"]], metadata={"count": hit["count"], "samples": hit["samples"], "type": hit["type"]},
            )
        )
    return out


class PIIAnalyzer:
    name = NAME
    description = "Detects personal data (emails, phones, SSNs, payment cards with Luhn check, IBANs, national ids, DOB, addresses, medical record numbers) with masked evidence."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for location, _role, raw in iter_messages(normalized):
            findings.extend(findings_for_text(raw, location))
        return findings


analyzer = PIIAnalyzer()
