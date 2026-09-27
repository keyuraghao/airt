"""Obfuscation detection: base64/hex/rot13/leet/reversed payloads, homoglyphs, zero-width, payload splitting and token stuffing."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import (
    count_zero_width,
    fold_leet,
    iter_messages,
    make_finding,
    mixed_script_tokens,
    snippet,
)
from .prompt_injection import INJECTION_KEYWORD_RE

NAME = "obfuscation"

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fx\\])(?:[0-9a-fA-F]{2}[\s:]?){16,}(?![0-9a-f])")
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_HEX_PREFIX_RE = re.compile(r"\b0x[0-9a-fA-F]{16,}\b")
_URL_ENC_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){8,}")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}")
# Each alternative must contain at least one real leet substitution (digit/symbol) so plain English words do not match.
_LEET_KEYWORD_RE = re.compile(
    r"1gn[o0]r[e3]|1gnore|ign[o0]re|jailbr3ak|ja1lbreak|j4ilbreak|"
    r"pr0mpt|syst3m|sy5tem|d3v3l[o0]p3r|dev3loper|d3veloper|1nstruct10n|instruct10n|1nstruction|"
    r"[o0]v3rr1de|0verride|byp4ss|byp455|unf1ltered|unc3nsored",
    re.IGNORECASE,
)
_SPLIT_RE = re.compile(
    r"\b(?:combine|concatenate|join|merge|assemble|put\s+together|glue|stitch)\s+(?:the\s+)?(?:following\s+)?(?:these\s+)?(?:fragments?|parts?|pieces?|segments?|chunks?|letters?|tokens?|strings?|words?)\b",
    re.IGNORECASE,
)
_FRAGMENT_RE = re.compile(
    r"(?:^|\n)\s*(?:part|fragment|piece|segment|chunk|line)\s*[#]?\s*\d+\s*[:=]", re.IGNORECASE
)
_CODEBLOCK_RE = re.compile(r"```[\s\S]{0,4000}?```|~~~[\s\S]{0,4000}?~~~")
_ASSISTANT_ADDR_RE = re.compile(
    r"\b(?:assistant|ai|model|you\s+(?:must|should|will|are))\b|\bignore\b|\bsystem\s+prompt\b", re.IGNORECASE
)
_REPEAT_RE = re.compile(r"(\b\w{1,20}\b)(?:\s+\1){14,}", re.IGNORECASE)
_REPEAT_CHAR_RE = re.compile(r"(.)\1{200,}")

# char_count thresholds for many-shot / long prompt heuristics
_LONG = 20000
_VERY_LONG = 60000
_HUGE = 120000


def _try_b64_decode(blob: str) -> str | None:
    s = blob.strip()
    if len(s) % 4:
        s += "=" * (4 - len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:
            return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t ")
    if not text or printable / len(text) < 0.8:
        return None
    return text


def _rescan_decoded(decoded: str) -> str:
    fold = fold_leet(decoded.lower())
    m = INJECTION_KEYWORD_RE.search(decoded) or INJECTION_KEYWORD_RE.search(fold)
    return m.group(0) if m else ""


class ObfuscationAnalyzer:
    name = NAME
    description = "Detects encoded/obfuscated payloads (base64, hex, rot13, leetspeak, reversed text), homoglyphs, zero-width hiding, payload splitting, token stuffing and instructions hidden in code blocks."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        char_count = 0
        try:
            char_count = int(normalized.get("char_count") or 0)
        except Exception:
            char_count = 0

        for location, role, raw in iter_messages(normalized):
            if role == "system":
                continue
            text = raw
            low = text.lower()

            # --- base64 blobs: decode and rescan --------------------------------
            for m in list(_B64_RE.finditer(text))[:20]:
                blob = m.group(0)
                if len(blob) > 8000:
                    blob = blob[:8000]
                decoded = _try_b64_decode(blob)
                if decoded is None:
                    continue
                kw = _rescan_decoded(decoded)
                if kw:
                    findings.append(
                        make_finding(
                            NAME,
                            "obfuscation",
                            Severity.HIGH,
                            "Base64 payload decodes to injection keywords",
                            f"A base64 blob decodes to text containing '{kw}'. Encoding is a common way to smuggle injection or jailbreak instructions past filters.",
                            snippet(
                                text,
                                m.start(),
                                m.end(),
                                radius=10,
                                mask="[base64:" + decoded[:60].replace(chr(10), " ") + "...]",
                            ),
                            location,
                            0.85,
                            tags=["base64", "decoded_injection"],
                            metadata={"role": role, "decoded_preview": decoded[:120]},
                        )
                    )
                elif len(blob) >= 64:
                    findings.append(
                        make_finding(
                            NAME,
                            "obfuscation",
                            Severity.LOW,
                            "Large base64 blob in content",
                            "A long base64-encoded blob was found. It decodes to readable text; review it for hidden instructions or data.",
                            snippet(
                                text,
                                m.start(),
                                m.end(),
                                radius=10,
                                mask="[base64 " + str(len(blob)) + " chars]",
                            ),
                            location,
                            0.4,
                            tags=["base64"],
                            metadata={"role": role, "length": len(blob), "decoded_preview": decoded[:120]},
                        )
                    )

            # --- rot13 -----------------------------------------------------------
            if len(text) >= 20:
                try:
                    rot = codecs.encode(text[:4000], "rot_13")
                    if INJECTION_KEYWORD_RE.search(rot):
                        findings.append(
                            make_finding(
                                NAME,
                                "obfuscation",
                                Severity.MEDIUM,
                                "ROT13-encoded instructions",
                                "Applying ROT13 to the content reveals injection/jailbreak keywords.",
                                "[rot13] " + INJECTION_KEYWORD_RE.search(rot).group(0),
                                location,
                                0.7,
                                tags=["rot13", "decoded_injection"],
                                metadata={"role": role},
                            )
                        )
                except Exception:
                    pass

            # --- hex / url-encoded / unicode-escaped payloads --------------------
            for rx, tag, label in (
                (_HEX_ESCAPE_RE, "hex", "Hex-escaped byte string"),
                (_URL_ENC_RE, "urlencode", "Long URL-encoded blob"),
                (_UNICODE_ESCAPE_RE, "unicode_escape", "Unicode-escaped blob"),
                (_HEX_RE, "hex", "Long hex string"),
            ):
                m = rx.search(text)
                if m:
                    decoded = ""
                    frag = m.group(0)
                    try:
                        if tag == "hex":
                            decoded = (
                                bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", frag)[:2000]).decode(
                                    "utf-8", "ignore"
                                )
                                if rx is _HEX_RE
                                else bytes(
                                    int(b, 16) for b in re.findall(r"\\x([0-9a-fA-F]{2})", frag)
                                ).decode("utf-8", "ignore")
                            )
                        elif tag == "urlencode":
                            from urllib.parse import unquote

                            decoded = unquote(frag)
                        else:
                            decoded = frag.encode().decode("unicode_escape", "ignore")
                    except Exception:
                        decoded = ""
                    inj = bool(decoded and INJECTION_KEYWORD_RE.search(decoded))
                    findings.append(
                        make_finding(
                            NAME,
                            "obfuscation",
                            Severity.HIGH if inj else Severity.LOW,
                            (label + " decodes to injection keywords") if inj else label,
                            "Encoded content "
                            + (
                                "decodes to injection/jailbreak keywords."
                                if inj
                                else "was found; it may hide instructions or data."
                            ),
                            snippet(
                                text,
                                m.start(),
                                m.end(),
                                radius=8,
                                mask="[" + tag + (":" + decoded[:50] if decoded else "") + "]",
                            ),
                            location,
                            0.75 if inj else 0.35,
                            tags=[tag] + (["decoded_injection"] if inj else []),
                            metadata={"role": role, "decoded_preview": decoded[:120]},
                        )
                    )
                    break

            # --- leetspeak -------------------------------------------------------
            if _LEET_KEYWORD_RE.search(text):
                m = _LEET_KEYWORD_RE.search(text)
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.MEDIUM,
                        "Leetspeak-obfuscated keyword",
                        "Leetspeak substitution hides an injection/jailbreak keyword (e.g. 1gn0r3, jailbr3ak).",
                        snippet(text, m.start(), m.end()),
                        location,
                        0.6,
                        tags=["leetspeak"],
                        metadata={"role": role},
                    )
                )

            # --- reversed text ---------------------------------------------------
            if len(text) >= 30:
                rev = text[::-1]
                if INJECTION_KEYWORD_RE.search(rev) and not INJECTION_KEYWORD_RE.search(low):
                    findings.append(
                        make_finding(
                            NAME,
                            "obfuscation",
                            Severity.MEDIUM,
                            "Reversed-text instructions",
                            "Reversing the content reveals injection/jailbreak keywords.",
                            "[reversed] " + INJECTION_KEYWORD_RE.search(rev).group(0),
                            location,
                            0.6,
                            tags=["reversed", "decoded_injection"],
                            metadata={"role": role},
                        )
                    )

            # --- homoglyphs ------------------------------------------------------
            mixed = mixed_script_tokens(text)
            if len(mixed) >= 2:
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.MEDIUM if len(mixed) >= 4 else Severity.LOW,
                        "Homoglyph / mixed-script tokens",
                        f"{len(mixed)} token(s) mix Latin letters with confusable characters (Cyrillic/Greek lookalikes), a way to bypass keyword filters.",
                        "tokens: " + ", ".join(mixed[:5]),
                        location,
                        0.6 if len(mixed) >= 4 else 0.45,
                        tags=["homoglyph"],
                        metadata={"role": role, "sample": mixed[:8]},
                    )
                )

            # --- zero-width hiding ----------------------------------------------
            zw = count_zero_width(text)
            if zw >= 5:
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.MEDIUM if zw >= 20 else Severity.LOW,
                        "Zero-width / invisible characters",
                        f"{zw} invisible characters found; they can hide instructions or split filtered keywords.",
                        "",
                        location,
                        0.6 if zw >= 20 else 0.4,
                        tags=["zero_width"],
                        metadata={"role": role, "count": zw},
                    )
                )

            # --- payload splitting ----------------------------------------------
            if _SPLIT_RE.search(text) or len(_FRAGMENT_RE.findall(text)) >= 3:
                m = _SPLIT_RE.search(text) or _FRAGMENT_RE.search(text)
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.MEDIUM,
                        "Payload splitting / fragment reassembly",
                        "The prompt asks the model to combine fragments or defines numbered parts, a technique to assemble a hidden instruction from harmless-looking pieces.",
                        snippet(text, m.start(), m.end()) if m else "",
                        location,
                        0.6,
                        tags=["payload_split"],
                        metadata={"role": role},
                    )
                )

            # --- instructions inside code blocks addressed to the assistant ------
            for cm in list(_CODEBLOCK_RE.finditer(text))[:5]:
                inner = cm.group(0)
                if _ASSISTANT_ADDR_RE.search(inner) and INJECTION_KEYWORD_RE.search(inner):
                    findings.append(
                        make_finding(
                            NAME,
                            "obfuscation",
                            Severity.MEDIUM,
                            "Instructions hidden inside a code block",
                            "A fenced code block contains text addressed to the assistant with injection keywords, a common way to disguise instructions as sample code.",
                            snippet(inner, 0, min(len(inner), 80)),
                            location,
                            0.6,
                            tags=["codeblock_injection"],
                            metadata={"role": role},
                        )
                    )
                    break

            # --- token stuffing --------------------------------------------------
            rep = _REPEAT_RE.search(text)
            if rep:
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.LOW,
                        "Repeated-token stuffing",
                        "A short token repeats many times in a row, which can be used to push earlier context out of the model window or trigger anomalous behaviour.",
                        snippet(text, rep.start(), min(rep.end(), rep.start() + 60)),
                        location,
                        0.5,
                        tags=["token_stuffing"],
                        metadata={"role": role},
                    )
                )
            elif _REPEAT_CHAR_RE.search(text):
                cm = _REPEAT_CHAR_RE.search(text)
                findings.append(
                    make_finding(
                        NAME,
                        "obfuscation",
                        Severity.LOW,
                        "Repeated-character flooding",
                        "A single character repeats hundreds of times, a padding/flooding pattern.",
                        f"'{cm.group(1)}' x{len(cm.group(0))}",
                        location,
                        0.45,
                        tags=["token_stuffing"],
                        metadata={"role": role},
                    )
                )

        # --- whole-request length heuristics ------------------------------------
        if char_count >= _LONG:
            if char_count >= _HUGE:
                sev, conf = Severity.MEDIUM, 0.55
            elif char_count >= _VERY_LONG:
                sev, conf = Severity.LOW, 0.45
            else:
                sev, conf = Severity.INFO, 0.35
            findings.append(
                make_finding(
                    NAME,
                    "obfuscation",
                    sev,
                    "Very long prompt (possible many-shot attack)",
                    f"The request is {char_count} characters. Extremely long prompts are used for many-shot jailbreaking and context stuffing.",
                    "",
                    "prompt_text",
                    conf,
                    tags=["long_prompt", "many_shot"],
                    metadata={"char_count": char_count},
                )
            )
        return findings


analyzer = ObfuscationAnalyzer()
