#!/usr/bin/env python
"""Generate the AISRF (AI Security & Research Framework) architecture diagrams (SVG + 2x PNG) in docs/images/.

Usage (from the repository root):

    .venv/bin/python docs/images/generate_diagrams.py

The SVGs are hand-authored through a small builder so that the diagrams are reproducible and
diff-friendly. PNGs are rendered with cairosvg at 2x scale so GitHub renders them reliably.
The taxonomy matrix is produced from ``aisrf.taxonomy.CATEGORY_MAP`` so it never drifts from the code.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

FONT = "Liberation Sans, Arial, Helvetica, sans-serif"
MONO = "Liberation Mono, DejaVu Sans Mono, Menlo, Consolas, monospace"

# palette (dark neutral panel, high-contrast light text; reads on GitHub light and dark)
BG = "#0f172a"
PANEL = "#162036"
PANEL_STROKE = "#334155"
TEXT = "#e5e7eb"
MUTED = "#a3adbd"
LINE = "#cbd5e1"
LINE_DIM = "#64748b"

ROLE = {
    "client": ("#1e3a8a", "#60a5fa"),
    "gateway": ("#134e4a", "#2dd4bf"),
    "human": ("#713f12", "#fbbf24"),
    "upstream": ("#4c1d95", "#a78bfa"),
    "store": ("#1f2937", "#9ca3af"),
    "danger": ("#7f1d1d", "#f87171"),
    "ok": ("#14532d", "#4ade80"),
    "warn": ("#7c2d12", "#fb923c"),
    "neutral": ("#1e293b", "#94a3b8"),
}

CHAR_W = 0.56  # average glyph width / font size for Liberation Sans / Arial


def text_width(s: str, size: float) -> float:
    return len(s) * size * CHAR_W


def wrap(text: str, size: float, max_w: float) -> list[str]:
    out: list[str] = []
    for para in text.split("\n"):
        words = para.split(" ")
        line = ""
        for w in words:
            cand = (line + " " + w).strip()
            if text_width(cand, size) <= max_w or not line:
                line = cand
            else:
                out.append(line)
                line = w
        out.append(line)
    return out


class SVG:
    def __init__(self, width: int, height: int, title: str, subtitle: str = "") -> None:
        self.w, self.h = width, height
        self.parts: list[str] = []
        self.markers: set[str] = set()
        self.title = title
        self.subtitle = subtitle

    # ---- primitives -------------------------------------------------------------------
    def raw(self, s: str) -> None:
        self.parts.append(s)

    def marker_id(self, color: str) -> str:
        mid = "arw" + color.strip("#")
        self.markers.add(color)
        return mid

    def text(
        self,
        x: float,
        y: float,
        s: str,
        size: float = 14,
        fill: str = TEXT,
        anchor: str = "start",
        weight: str = "normal",
        family: str = FONT,
        opacity: float = 1.0,
        rotate: float | None = None,
    ) -> None:
        tr = f' transform="rotate({rotate} {x} {y})"' if rotate is not None else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{family}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" opacity="{opacity}"{tr}>{escape(s)}</text>'
        )

    def lines(
        self,
        x: float,
        y: float,
        lines: list[str],
        size: float = 13,
        fill: str = TEXT,
        anchor: str = "start",
        lh: float | None = None,
        family: str = FONT,
        weight: str = "normal",
    ) -> float:
        lh = lh or size * 1.35
        for i, ln in enumerate(lines):
            self.text(x, y + i * lh, ln, size, fill, anchor, weight=weight, family=family)
        return y + len(lines) * lh

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: str,
        stroke: str,
        r: float = 10,
        sw: float = 1.5,
        dash: str | None = None,
        opacity: float = 1.0,
    ) -> None:
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{r}" ry="{r}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d} opacity="{opacity}"/>'
        )

    def panel(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        subtitle: str = "",
        accent: str = PANEL_STROKE,
    ) -> None:
        self.rect(x, y, w, h, PANEL, accent, r=14, sw=1.5)
        self.text(x + 16, y + 26, title, 16, TEXT, weight="bold")
        if subtitle:
            self.text(x + 16, y + 44, subtitle, 12, MUTED)

    def box(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        body: str | list[str] = "",
        role: str = "neutral",
        title_size: float = 14,
        body_size: float = 12,
        mono_body: bool = False,
        align: str = "left",
    ) -> tuple[float, float, float, float]:
        fill, stroke = ROLE[role]
        self.rect(x, y, w, h, fill, stroke, r=10, sw=1.6)
        pad = 12
        tx = x + pad if align == "left" else x + w / 2
        anchor = "start" if align == "left" else "middle"
        ty = y + pad + title_size
        tlines = wrap(title, title_size, w - 2 * pad)
        ty = self.lines(tx, ty, tlines, title_size, TEXT, anchor, weight="bold")
        if body:
            blines = body if isinstance(body, list) else wrap(body, body_size, w - 2 * pad)
            fam = MONO if mono_body else FONT
            ty += 2
            ty = self.lines(tx, ty, blines, body_size, "#d1d5db", anchor, family=fam)
        last_baseline = ty - (body_size if body else title_size) * 1.35
        if last_baseline + body_size * 0.3 > y + h - 3:
            print(f"WARNING overflow in {self.title!r}: box {title!r} needs ~{ty - y:.0f}px, has {h}px")
        return (x, y, w, h)

    def chip(self, x: float, y: float, label: str, role: str = "neutral", size: float = 11) -> float:
        fill, stroke = ROLE[role]
        w = text_width(label, size) + 16
        self.rect(x, y, w, size + 10, fill, stroke, r=(size + 10) / 2, sw=1.2)
        self.text(x + w / 2, y + size + 2, label, size, TEXT, "middle", weight="bold")
        return w

    def path(
        self,
        d: str,
        color: str = LINE,
        sw: float = 1.8,
        dash: str | None = None,
        arrow: bool = True,
        start_arrow: bool = False,
    ) -> None:
        ma = f' marker-end="url(#{self.marker_id(color)})"' if arrow else ""
        ms = f' marker-start="url(#{self.marker_id(color)}s)"' if start_arrow else ""
        dd = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{dd}{ma}{ms}/>')

    def arrow(
        self,
        pts: list[tuple[float, float]],
        label: str | list[str] = "",
        color: str = LINE,
        dash: str | None = None,
        label_pos: float = 0.5,
        label_dy: float = -8,
        label_size: float = 12,
        both: bool = False,
        label_dx: float = 0,
        label_anchor: str = "middle",
        sw: float = 1.8,
    ) -> None:
        d = "M " + " L ".join(f"{px:.1f} {py:.1f}" for px, py in pts)
        self.path(d, color, sw, dash, arrow=True, start_arrow=both)
        if label:
            # place label on the segment holding label_pos of total length
            total = sum(math.dist(pts[i], pts[i + 1]) for i in range(len(pts) - 1))
            target = total * label_pos
            acc = 0.0
            lx, ly = pts[0]
            for i in range(len(pts) - 1):
                seg = math.dist(pts[i], pts[i + 1])
                if acc + seg >= target:
                    t = (target - acc) / seg if seg else 0
                    lx = pts[i][0] + (pts[i + 1][0] - pts[i][0]) * t
                    ly = pts[i][1] + (pts[i + 1][1] - pts[i][1]) * t
                    break
                acc += seg
            self.label(lx + label_dx, ly + label_dy, label, label_size, anchor=label_anchor)

    def label(
        self,
        x: float,
        y: float,
        label: str | list[str],
        size: float = 12,
        anchor: str = "middle",
        fill: str = TEXT,
        bg: str = BG,
    ) -> None:
        lines = label if isinstance(label, list) else [label]
        w = max(text_width(l, size) for l in lines) + 10
        lh = size * 1.3
        h = lh * len(lines) + 4
        if anchor == "middle":
            bx = x - w / 2
        elif anchor == "start":
            bx = x - 5
        else:
            bx = x - w + 5
        self.rect(bx, y - size - 1, w, h, bg, bg, r=4, sw=0, opacity=0.92)
        for i, l in enumerate(lines):
            self.text(x, y + i * lh, l, size, fill, anchor)

    def legend(
        self,
        x: float,
        y: float,
        items: list[tuple[str, str]],
        cols: int = 6,
        col_w: float = 230,
        title: str = "Legend",
    ) -> None:
        rows = math.ceil(len(items) / cols)
        h = 30 + rows * 22
        w = cols * col_w + 20
        self.rect(x, y, w, h, PANEL, PANEL_STROKE, r=10)
        self.text(x + 12, y + 19, title, 12, MUTED, weight="bold")
        for i, (role, name) in enumerate(items):
            r, c = divmod(i, cols)
            cx = x + 14 + c * col_w
            cy = y + 30 + r * 22
            if role.startswith("line:"):
                color, dash = role[5:].split("|") if "|" in role else (role[5:], "")
                self.path(f"M {cx} {cy + 7} L {cx + 28} {cy + 7}", color, 2, dash or None, arrow=True)
                self.text(cx + 40, cy + 11, name, 12, TEXT)
            else:
                fill, stroke = ROLE[role]
                self.rect(cx, cy, 22, 14, fill, stroke, r=4, sw=1.2)
                self.text(cx + 30, cy + 11, name, 12, TEXT)

    # ---- output -----------------------------------------------------------------------
    def render(self) -> str:
        defs = []
        for color in sorted(self.markers):
            mid = "arw" + color.strip("#")
            defs.append(
                f'<marker id="{mid}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
                f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{color}"/></marker>'
            )
            defs.append(
                f'<marker id="{mid}s" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
                f'<path d="M 10 0 L 0 5 L 10 10 z" fill="{color}"/></marker>'
            )
        head = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" '
            f'font-family="{FONT}">',
            f"<title>{escape(self.title)}</title>",
            "<defs>" + "".join(defs) + "</defs>",
            f'<rect x="0" y="0" width="{self.w}" height="{self.h}" rx="18" ry="18" fill="{BG}"/>',
            f'<text x="32" y="44" font-size="24" font-weight="bold" fill="{TEXT}">{escape(self.title)}</text>',
        ]
        if self.subtitle:
            head.append(f'<text x="32" y="66" font-size="13" fill="{MUTED}">{escape(self.subtitle)}</text>')
        return "\n".join(head + self.parts + ["</svg>"])

    def save(self, name: str) -> None:
        svg_path = HERE / f"{name}.svg"
        svg_path.write_text(self.render(), encoding="utf-8")
        import cairosvg

        cairosvg.svg2png(url=str(svg_path), write_to=str(HERE / f"{name}.png"), scale=2, background_color=BG)
        print(f"wrote {svg_path.name} and {name}.png ({self.w}x{self.h} @2x)")


# ======================================================================================
# 1. High-level architecture
# ======================================================================================
def architecture() -> None:
    s = SVG(
        1900,
        1100,
        "AISRF architecture",
        "AISRF, AI Security & Research Framework: human-in-the-loop interception, analysis and red teaming of LLM traffic. One FastAPI process, one port. "
        "TypeSafe (Jev) is the confidence-gated decision layer.",
    )

    PH = 570  # height of the three top panels
    # --- clients ------------------------------------------------------------------------
    s.panel(32, 92, 290, PH, "Applications and agents", "no provider key on the client, only aisrf_... keys")
    cl = [
        ("OpenAI / Anthropic SDK", "base_url = http://gw:8080/v1"),
        ("Python SDK", "patch_httpx(), patch_requests(), AISRFClient"),
        ("Node package", "aisrf-intercept: global fetch / undici hook"),
        ("curl / httpx / fetch", "POST /proxy/<provider path> + X-AISRF-Key"),
        ("mitmproxy transparent", "mitm_addon.py, X-AISRF-Source: mitm"),
        ("Autonomous agents", "LangChain, LlamaIndex, tool loops"),
    ]
    y = 150
    for title, body in cl:
        s.box(48, y, 258, 72, title, body, "client", body_size=11)
        y += 82

    # --- gateway --------------------------------------------------------------------------
    gx, gy, gw, gh = 400, 92, 1050, PH
    s.panel(
        gx,
        gy,
        gw,
        gh,
        "AISRF Gateway",
        "aisrf.main.create_app: gateway + reviewer API + dashboard + MCP on port 8080",
        accent="#2dd4bf",
    )

    row1 = gy + 62
    bw, bh = 190, 150
    gap = 20
    xs = [gx + 16 + i * (bw + gap) for i in range(5)]
    s.box(
        xs[0],
        row1,
        bw,
        bh,
        "Interception endpoints",
        [
            "/v1/{path}",
            "/proxy/{path}",
            "/gateway/tickets/{id}",
            "agent key auth (SHA-256)",
            "rate limit 429, size 413",
        ],
        "gateway",
        mono_body=True,
        body_size=11,
    )
    s.box(
        xs[1],
        row1,
        bw,
        bh,
        "Normalizer",
        [
            "parser.normalize(): provider,",
            "endpoint, model, stream,",
            "system, messages, tools,",
            "prompt_text, preview",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[2],
        row1,
        bw,
        bh,
        "Analyzers (phase 1)",
        [
            "prompt_injection, jailbreak,",
            "pii, secrets, data_exfil,",
            "tool_abuse, harmful_content,",
            "obfuscation, anomaly",
            "guardrails: Rebuff, LLM Guard,",
            "NeMo, Lakera",
            "LLM judge: phase 2, gated",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[3],
        row1,
        bw,
        bh,
        "TypeSafe decision layer (Jev)",
        [
            "typesafe_guard, one call:",
            "typed questions in parallel",
            "(9 nouls, intent, severity)",
            "about 100 ms, cached 300 s",
            "verdict: benign, malicious",
            "or uncertain; gates judge",
        ],
        "warn",
        body_size=11,
    )
    s.box(
        xs[4],
        row1,
        bw,
        bh,
        "Policy engine",
        [
            "risk score 0..100 + findings",
            "allowed paths / models",
            "deny regexes, custom rules",
            "typesafe.auto_deny 0.95,",
            "typesafe.auto_approve 0.9",
            "auto-deny >= 90, auto-approve",
            "-> deny | approve | review",
        ],
        "gateway",
        body_size=11,
    )
    for i in range(4):
        x0 = xs[i] + bw
        s.arrow([(x0, row1 + bh / 2), (x0 + gap, row1 + bh / 2)], "", "#2dd4bf")

    row2 = row1 + bh + 60
    s.box(
        xs[0],
        row2,
        bw,
        bh,
        "Ticket store",
        [
            "tickets + timeline events",
            "PENDING / APPROVED / DENIED",
            "EXPIRED / FORWARDING",
            "COMPLETED / FAILED",
            "SSE stream, webhooks",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[1],
        row2,
        bw,
        bh,
        "Hold registry",
        [
            "asyncio.Event per waiting",
            "ticket (in-process fast path)",
            "DB polling fallback",
            "timeout -> EXPIRED (504)",
            "sync wait or async 202 + poll",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[2],
        row2,
        bw,
        bh,
        "Canary injection",
        [
            "Rebuff-style AISRF-CANARY-*",
            "token appended to the",
            "system prompt of every",
            "forwarded request;",
            "leak => CRITICAL finding",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[3],
        row2,
        bw,
        bh,
        "Forwarder",
        [
            "swap in encrypted upstream",
            "key, strip client credentials,",
            "relay JSON or SSE stream;",
            "response guarded ->",
            "withhold (403) or relay",
            "with X-AISRF-Ticket",
        ],
        "gateway",
        body_size=11,
    )
    s.box(
        xs[4],
        row2,
        bw,
        bh,
        "Response guard",
        [
            "typesafe_response_guard:",
            "leaked prompt / secret / PII,",
            "harmful compliance, exfil,",
            "refusal; plus system prompt",
            "leak, refusal, canary, PII,",
            "guardrail output scanners",
        ],
        "gateway",
        body_size=11,
    )
    px = xs[4] + bw / 2
    s.arrow(
        [(px, row1 + bh), (px, row1 + bh + 30), (xs[0] + bw / 2, row1 + bh + 30), (xs[0] + bw / 2, row2)],
        "ticket created PENDING, policy decision recorded",
        "#2dd4bf",
        label_pos=0.55,
        label_dy=-8,
    )
    for i in range(4):
        x0 = xs[i] + bw
        s.arrow([(x0, row2 + bh / 2), (x0 + gap, row2 + bh / 2)], "", "#2dd4bf")
    s.text(
        gx + 16,
        row2 + bh + 30,
        "Denied / expired tickets never reach the provider. Every step: ticket timeline, per-agent log, audit entry for human decisions. "
        "TypeSafe answers travel with the finding metadata.",
        11,
        MUTED,
    )

    # clients -> gateway
    s.arrow(
        [(306, 340), (gx, 340)],
        ["HTTPS", "X-AISRF-Key", "sync or async"],
        "#60a5fa",
        label_dy=-24,
        label_size=10.5,
    )

    # --- upstream --------------------------------------------------------------------------
    ux = 1490
    s.panel(
        ux,
        92,
        378,
        PH,
        "Upstream providers and services",
        "agent credential per provider; gateway key for TypeSafe",
    )
    ups = [
        ("OpenAI", "api.openai.com: /v1/chat/completions, /v1/responses"),
        ("Anthropic", "api.anthropic.com: /v1/messages"),
        ("Google Gemini", "generativelanguage.googleapis.com"),
        ("api.typesafe.ai (TypeSafe Jev)", "POST /v1/systemone, typed answers, gateway key"),
        ("Mistral, Groq, Azure OpenAI", "any OpenAI-compatible endpoint"),
        ("Ollama / self-hosted", "localhost:11434, vLLM, TGI"),
        ("Custom / enterprise backends", "any HTTP API via /proxy/<path>"),
    ]
    ay = row2 + bh / 2  # arrow height
    ys = [150, 214, 278, 340, 466, 530, 594]
    for (title, body), yy in zip(ups, ys):
        role = "warn" if title.startswith("api.typesafe") else "upstream"
        s.box(ux + 16, yy, 346, 58, title, body, role, body_size=11)
    s.arrow([(gx + gw, ay), (ux + 16, ay)], "", "#a78bfa", both=True)
    s.text(ux + 16, ay - 22, "forward after approval", 11.5, TEXT)
    s.text(ux + 16, ay - 7, "reply carries X-AISRF-Ticket", 11.5, TEXT)
    s.arrow([(gx + gw, 369), (ux + 16, 369)], "", "#fb923c", both=True)

    # --- reviewers -------------------------------------------------------------------------
    ry = 712
    s.panel(
        gx,
        ry,
        gw,
        176,
        "Human reviewers",
        "viewer < reviewer < admin roles; only PENDING tickets can be decided; every decision is audited",
        accent="#fbbf24",
    )
    rv = [
        (
            "Dashboard",
            "/tickets /agents /logs /redteam /reports /audit /codereview, live SSE, TypeSafe savings tile",
        ),
        ("MCP server", "/mcp streamable HTTP or `aisrf mcp` stdio: Claude Desktop / Claude Code"),
        ("CLI", "aisrf tickets list | show | approve | deny | watch"),
        ("Webhooks / Slack", "AISRF_NOTIFY_WEBHOOK_URLS on created / expired / failed"),
    ]
    rw = 239
    rxs = [gx + 16 + i * (rw + gap) for i in range(4)]
    for (title, body), x in zip(rv, rxs):
        s.box(x, ry + 56, rw, 100, title, body, "human", body_size=11)
    tsx = xs[0] + bw / 2
    s.arrow(
        [(tsx - 30, row2 + bh), (tsx - 30, ry)],
        ["SSE ticket.created", "notification"],
        "#fbbf24",
        label_dy=-4,
        label_dx=-12,
        label_anchor="end",
    )
    s.arrow(
        [(tsx + 30, ry), (tsx + 30, row2 + bh)],
        ["approve / deny", "-> hold resolved"],
        "#fbbf24",
        label_dy=-4,
        label_dx=12,
        label_anchor="start",
    )
    s.text(32, 780, "Browser, Claude (MCP client),", 12, MUTED)
    s.text(32, 796, "aisrf CLI, CI automation with", 12, MUTED)
    s.text(32, 812, "AISRF_ADMIN_API_TOKEN", 12, MUTED)
    s.arrow([(215, 800), (gx, 800)], "", "#fbbf24")

    # --- side components -------------------------------------------------------------------
    sy = 920
    s.panel(
        32,
        sy,
        1836,
        156,
        "Storage, observability and engines",
        "SQLAlchemy async, structlog, hash-chained audit, reports, red-team engines, runtime settings, TypeSafe savings meter",
    )
    side = [
        (
            "SQLite / PostgreSQL",
            "tickets, events, agents, audit, campaigns, probe results, scan tokens, settings, code review findings",
        ),
        ("Structured logs", "logs/aisrf.jsonl + logs/agents/<agent_id>.jsonl, X-Request-ID on every line"),
        ("Audit chain", "SHA-256 hash chain per privileged action, GET /api/audit/verify"),
        ("Reports engine", "12 formats: json yaml csv tsv md html pdf xlsx txt xml sarif junit"),
        (
            "Red-team engines",
            "native corpus (300+ probes), garak, promptfoo, PyRIT, PyRIT-Ship via scan tokens",
        ),
        ("Settings store", "runtime overrides: analyzers, rules, integrations (incl. typesafe), policy, ui"),
        (
            "TypeSafe savings meter",
            "judge tokens avoided minus TypeSafe spend: overview tile, GET /api/settings/typesafe/status, aisrf_typesafe_* metrics",
        ),
    ]
    x = 48
    for title, body in side:
        role = "warn" if title.startswith("TypeSafe") else "store"
        s.box(x, sy + 50, 246, 96, title, body, role, body_size=10.5)
        x += 258
    s.arrow([(gx + 200, ry + 176), (gx + 200, sy)], "", "#9ca3af", dash="5 4")
    s.arrow([(gx + 850, ry + 176), (gx + 850, sy)], "", "#9ca3af", dash="5 4")
    s.text(gx + 214, sy - 10, "persist, log, audit, report, run campaigns, meter savings", 11, MUTED)

    s.legend(
        ux,
        712,
        [
            ("client", "clients"),
            ("gateway", "gateway component"),
            ("human", "human review surface"),
            ("upstream", "upstream provider"),
            ("store", "storage / engine"),
            ("warn", "TypeSafe decision layer"),
        ],
        cols=2,
        col_w=180,
        title="Legend",
    )
    s.save("architecture")


# ======================================================================================
# 2. Request lifecycle (sequence)
# ======================================================================================
def request_lifecycle() -> None:
    W = 1700
    s = SVG(
        W,
        10,
        "AISRF request lifecycle",
        "One intercepted call, from client request to COMPLETED ticket. TypeSafe (Jev) answers first and gates the LLM judge and the human queue. "
        "Sync mode blocks; async mode returns 202 and polls.",
    )
    lanes = {
        "client": (150, "Client / agent", "client"),
        "gateway": (450, "AISRF Gateway", "gateway"),
        "analysis": (730, "Analyzers + policy", "gateway"),
        "typesafe": (1000, "TypeSafe (Jev)", "warn"),
        "reviewer": (1250, "Reviewer", "human"),
        "upstream": (1530, "Upstream provider", "upstream"),
    }
    top = 92
    lane_index = len(s.parts)  # lifelines are inserted here once the final height is known

    def X(k: str) -> float:
        return lanes[k][0]

    def msg(
        y: float, a: str, b: str, label: str | list[str], color: str = LINE, dash: str | None = None
    ) -> None:
        xa, xb = X(a), X(b)
        dy = -7 - (len(label) - 1) * 15.6 if isinstance(label, list) else -7
        if b == "client":
            s.arrow(
                [(xa, y), (xb, y)],
                label,
                color,
                dash=dash,
                label_dy=dy,
                label_pos=1.0,
                label_dx=16,
                label_anchor="start",
            )
        elif a == "client":
            s.arrow(
                [(xa, y), (xb, y)],
                label,
                color,
                dash=dash,
                label_dy=dy,
                label_pos=0.0,
                label_dx=16,
                label_anchor="start",
            )
        else:
            s.arrow([(xa, y), (xb, y)], label, color, dash=dash, label_dy=dy)

    def note(
        y: float,
        k: str,
        lines: list[str],
        role: str = "gateway",
        w: float = 250,
        chip: str | None = None,
        chip_role: str = "warn",
        dx: float = 0,
    ) -> float:
        h = 16 + 15 * len(lines)
        x = X(k) + dx
        fill, stroke = ROLE[role]
        s.rect(x - w / 2, y, w, h, fill, stroke, r=8)
        s.lines(x - w / 2 + 10, y + 15, lines, 11.5, TEXT, lh=15)
        if chip:
            s.chip(x + w / 2 + 12, y + h / 2 - 10, chip, chip_role)
        return y + h

    def status(y: float, label: str, role: str, x: float | None = None) -> None:
        s.chip(x if x is not None else X("gateway") + 150, y - 12, label, role)

    RX = X("reviewer") + 110  # right edge for frames that stop at the reviewer lane

    def frame(y1: float, y2: float, title: str, color: str, x1: float = 40, x2: float = W - 40) -> None:
        s.rect(x1, y1, x2 - x1, y2 - y1, "none", color, r=8, sw=1.4, dash="6 4")
        s.rect(x1, y1, text_width(title, 12) + 22, 22, color, color, r=6, sw=0, opacity=0.9)
        s.text(x1 + 11, y1 + 15, title, 12, "#0b1220", weight="bold")

    TS = "#fb923c"  # TypeSafe calls
    F = 46  # vertical room reserved under a frame title
    y = 176
    msg(
        y,
        "client",
        "gateway",
        [
            "POST /v1/chat/completions   (or /proxy/<path>)",
            "X-AISRF-Key: aisrf_...   optional X-AISRF-Async: 1",
        ],
        "#60a5fa",
    )
    y += 28
    y = note(
        y,
        "gateway",
        [
            "1. authenticate agent key (SHA-256 lookup, inactive -> 401)",
            "2. rate limit per minute (429), body size limit (413)",
            "3. normalize body: provider, model, messages, tools, stream",
            "4. create ticket PENDING, redacted headers, expires_at = now + 300 s",
        ],
        w=380,
        chip="ticket PENDING",
    )
    y += 30

    # phase 1: TypeSafe guard and the deterministic analyzers, concurrently
    f0 = y
    y += F + 16
    msg(
        y,
        "gateway",
        "typesafe",
        [
            "typesafe_guard: one POST /v1/systemone, state = system prompt + turns + tools (secrets masked, <= 12000 chars)",
            "9 nouls + intent choice + severity score answered in parallel, about 100 ms, TTL cache 300 s",
        ],
        TS,
    )
    y += 46
    msg(
        y,
        "typesafe",
        "gateway",
        [
            "typed answers with calibrated probabilities: noul >= 0.7 -> finding (confidence |p - 0.5| * 2)",
            "verdict benign (confidence >= 0.85) | malicious (>= 0.9) | uncertain, stored in finding metadata",
        ],
        TS,
    )
    y += 40
    msg(
        y,
        "gateway",
        "analysis",
        "9 deterministic analyzers + guardrail integrations (Rebuff, LLM Guard, NeMo, Lakera), concurrent with TypeSafe",
        "#2dd4bf",
    )
    y += 18
    frame(
        f0, y, "par  phase 1: analyze_request(), latency = max(TypeSafe, analyzers)", "#2dd4bf", x1=70, x2=RX
    )
    y += 26
    f0b = y
    y += F
    msg(
        y,
        "gateway",
        "analysis",
        "phase 2: llm_judge (1 to 5 s). Skipped when the verdict is benign or malicious; reason in context.llm_judge_skipped",
        "#2dd4bf",
    )
    y += 18
    frame(
        f0b,
        y,
        "opt  TypeSafe uncertain or no verdict, and escalate_to_llm_judge: true (default: judge never runs while TypeSafe is on)",
        "#fb923c",
        x1=70,
        x2=RX,
    )
    y += 28
    msg(
        y,
        "analysis",
        "gateway",
        "findings + risk score 0..100 (NONE / LOW / MEDIUM / HIGH / CRITICAL)",
        "#2dd4bf",
    )
    y += 28
    msg(y, "gateway", "analysis", "policy.evaluate(agent, normalized, path, risk, findings)", "#2dd4bf")
    y += 26
    y = note(
        y,
        "analysis",
        [
            "1. allowed paths / models, auto-deny patterns, custom deny rules",
            "2. typesafe_route (auto_route: true), highest-confidence typesafe_guard finding:",
            "    malicious, confidence >= 0.95 -> deny, rule typesafe.auto_deny",
            "    benign, confidence >= 0.9, agent requires approval, no HIGH / CRITICAL finding",
            "    -> approve, rule typesafe.auto_approve",
            "    uncertain, or below the thresholds -> fall through",
            "3. risk >= auto_deny_at_risk (90) -> deny; risk < auto_approve_below_risk -> approve",
            "4. otherwise review: a human is needed",
        ],
        w=520,
        dx=60,
    )
    y += 26
    msg(
        y,
        "analysis",
        "gateway",
        "PolicyDecision: deny | approve | review  (+ reasons, matched rules)",
        "#2dd4bf",
    )
    y += 22

    # deny branch
    f1 = y
    y += F
    msg(
        y,
        "gateway",
        "client",
        "403 {error: denied, ticket_id, risk_score}   nothing is sent upstream",
        "#f87171",
    )
    status(y, "DENIED", "danger")
    y += 18
    frame(
        f1, y, "alt  policy: deny  (deny pattern, custom rule, typesafe.auto_deny, risk threshold)", "#f87171"
    )
    y += 28

    # auto-approve branch
    f1b = y
    y += F
    y = note(
        y,
        "gateway",
        [
            "PENDING -> APPROVED without a human: reasons recorded on the ticket, e.g.",
            "TypeSafe verdict benign with confidence 0.96 >= 0.9 and no HIGH or CRITICAL finding;",
            "continues at forward_ticket() below",
        ],
        w=520,
        chip="APPROVED",
        chip_role="ok",
    )
    y += 18
    frame(
        f1b,
        y,
        "alt  policy: approve  (typesafe.auto_approve, require_approval=false, risk below threshold)",
        "#4ade80",
    )
    y += 28

    # review branch
    f2 = y
    y += F
    msg(
        y,
        "gateway",
        "reviewer",
        "SSE ticket.created on /api/stream/tickets, webhook / Slack notification; ticket page shows every TypeSafe probability",
        "#fbbf24",
    )
    y += 24
    f3 = y
    y += F
    msg(
        y,
        "gateway",
        "client",
        "202 {ticket_id, status: PENDING, poll_url: /gateway/tickets/{id}, expires_at}",
        "#60a5fa",
    )
    y += 28
    msg(
        y,
        "client",
        "gateway",
        "GET /gateway/tickets/{id} with the agent key, repeated: 202 while PENDING",
        "#60a5fa",
        dash="5 4",
    )
    y += 18
    frame(f3, y, "alt  async mode (X-AISRF-Async: 1)", "#60a5fa", x1=70, x2=850)
    y += 28
    f4 = y
    y += F - 10
    y = note(
        y,
        "gateway",
        [
            "hold_registry.wait(ticket_id): asyncio.Event fast path,",
            "DB poll every AISRF_HOLD_POLL_INTERVAL_SECONDS (1 s) for",
            "decisions made in another process",
        ],
        w=380,
    )
    y += 8
    frame(f4, y, "alt  sync mode (default): the HTTP call blocks", "#2dd4bf", x1=70, x2=850)
    y += 32
    msg(
        y,
        "reviewer",
        "gateway",
        "approve / deny with note: dashboard, MCP tool, CLI, REST (audit entry written)",
        "#fbbf24",
    )
    y += 26
    y = note(
        y,
        "gateway",
        [
            "decide(): PENDING -> APPROVED or DENIED, hold resolved,",
            "ticket_events row, agent log, SSE update",
        ],
        w=380,
        chip="APPROVED",
        chip_role="ok",
    )
    y += 26
    f5 = y
    y += F + 16
    msg(
        y,
        "gateway",
        "client",
        [
            "504 {error: expired}   sweeper (5 s) or the hold wait past AISRF_APPROVAL_TIMEOUT_SECONDS;",
            "nothing is sent upstream",
        ],
        "#f87171",
    )
    status(y, "EXPIRED", "danger", X("reviewer") - 60)
    y += 18
    frame(f5, y, "alt  no decision before the deadline", "#fb923c", x1=70, x2=RX)
    y += 28
    f6 = y
    y += F
    msg(y, "gateway", "client", "403 {error: denied, decided_by}   nothing is sent upstream", "#f87171")
    status(y, "DENIED", "danger")
    y += 18
    frame(f6, y, "alt  reviewer: deny", "#f87171", x1=70, x2=RX)
    y += 20
    frame(f2, y, "alt  policy: review (human needed)", "#fbbf24")
    y += 32

    # forwarding
    y = note(
        y,
        "gateway",
        [
            "forward_ticket(): mark FORWARDING (sync: immediately; async: on the first poll after approval)",
            "inject canary AISRF-CANARY-<hex> into the system prompt when agent.inject_canary",
            "swap in the agent's Fernet-decrypted upstream key, strip client credential headers",
        ],
        w=560,
        chip="FORWARDING",
    )
    y += 30
    msg(
        y,
        "gateway",
        "upstream",
        "forward request with upstream credentials (shared httpx client, 120 s timeout)",
        "#a78bfa",
    )
    y += 28
    msg(
        y,
        "upstream",
        "gateway",
        "200 JSON or SSE stream (relayed chunk by chunk, first 512 KB captured)",
        "#a78bfa",
    )
    y += 28
    f8 = y
    y += F + 16
    msg(
        y,
        "gateway",
        "typesafe",
        [
            "typesafe_response_guard: RESPONSE_GUARD nouls leaked_system_prompt, leaked_secret_or_pii,",
            "harmful_compliance, exfil_markup, refusal (one call, about 100 ms)",
        ],
        TS,
    )
    y += 46
    msg(
        y,
        "typesafe",
        "gateway",
        "response verdict + confidence; findings system_prompt_leak, pii_leakage, harmful_compliance, data_exfil",
        TS,
    )
    y += 40
    msg(
        y,
        "gateway",
        "analysis",
        "system prompt leak, refusal, canary leak, PII, guardrail output scanners; llm_judge_response only if uncertain + escalation",
        "#2dd4bf",
    )
    y += 18
    frame(f8, y, "par  analyze_response(): response guard and response analyzers", "#2dd4bf", x1=70, x2=RX)
    y += 28
    msg(y, "analysis", "gateway", "response findings", "#2dd4bf")
    y += 22
    f7 = y
    y += F
    msg(
        y,
        "gateway",
        "client",
        "403 {error: response_withheld} + X-AISRF-Ticket   (policy.block_on_canary_leak, default on)",
        "#f87171",
    )
    y += 18
    frame(f7, y, "alt  canary leaked in the model output", "#f87171", x1=70, x2=RX)
    y += 34
    msg(
        y,
        "gateway",
        "client",
        [
            "upstream body + X-AISRF-Ticket header",
            "(async: relayed on that poll; later polls return {status: COMPLETED, response})",
        ],
        "#4ade80",
    )
    status(y, "COMPLETED", "ok", X("reviewer") - 60)
    y += 28
    y = note(
        y,
        "gateway",
        [
            "mark_completed(): COMPLETED when upstream status < 500, otherwise FAILED (client gets 502);",
            "network errors -> FAILED. Metrics, per-agent log, ticket timeline and the TypeSafe savings meter updated.",
        ],
        w=560,
        chip="FAILED on 5xx / network error",
        chip_role="danger",
    )
    y += 24

    # lifelines and lane headers, now that the height is known
    bottom = y
    lane_parts: list[str] = []
    saved = s.parts
    s.parts = lane_parts
    for key, (x, name, role) in lanes.items():
        fill, stroke = ROLE[role]
        s.path(f"M {x} {top + 40} L {x} {bottom}", LINE_DIM, 1.2, dash="4 6", arrow=False)
        s.rect(x - 95, top, 190, 40, fill, stroke, r=10)
        s.text(x, top + 26, name, 14, TEXT, "middle", weight="bold")
    s.parts = saved[:lane_index] + lane_parts + saved[lane_index:]

    s.legend(
        40,
        bottom + 16,
        [
            ("line:#60a5fa", "client traffic"),
            ("line:#2dd4bf", "in-process gateway work"),
            ("line:" + TS, "TypeSafe decision call"),
            ("line:#fbbf24", "human decision"),
            ("line:#a78bfa", "upstream call"),
            ("line:#f87171", "blocked / error reply"),
            ("line:#4ade80", "relayed response"),
        ],
        cols=7,
        col_w=228,
        title="Arrows",
    )
    s.h = int(bottom + 16 + 52 + 24)
    s.save("request-lifecycle")


# ======================================================================================
# 3. Ticket state machine
# ======================================================================================
def ticket_state_machine() -> None:
    s = SVG(
        1500,
        780,
        "AISRF ticket state machine",
        "aisrf.models.TicketStatus and the transitions in aisrf/tickets/service.py. Only PENDING tickets can be decided (409 otherwise).",
    )

    def state(
        cx: float, cy: float, name: str, sub: list[str], role: str, w: float = 190, h: float = 74
    ) -> None:
        fill, stroke = ROLE[role]
        s.rect(cx - w / 2, cy - h / 2, w, h, fill, stroke, r=16, sw=2)
        s.text(cx, cy - h / 2 + 26, name, 17, TEXT, "middle", weight="bold")
        s.lines(cx, cy - h / 2 + 44, sub, 11, "#d1d5db", "middle", lh=14)

    C_POLICY, C_HUMAN, C_TIME, C_UP, C_GW = "#2dd4bf", "#fbbf24", "#fb923c", "#a78bfa", "#cbd5e1"

    P = (300, 330)
    A = (740, 170)
    D = (740, 520)
    E = (300, 610)
    F = (1080, 170)
    C = (1360, 90)
    X = (1360, 270)

    # entry
    s.rect(50, P[1] - 20, 130, 40, PANEL, PANEL_STROKE, r=20)
    s.text(115, P[1] + 5, "request received", 12, TEXT, "middle")
    s.arrow([(180, P[1]), (P[0] - 95, P[1])], "", C_GW)

    # edges first, labels next, nodes last so nothing sits on top of a state box
    s.arrow([(P[0] + 95, P[1] - 20), (A[0] - 95, A[1])], "", C_POLICY)
    s.arrow([(P[0] + 95, P[1] + 5), (A[0] - 95, A[1] + 25)], "", C_HUMAN)
    s.arrow([(P[0] + 95, P[1] + 20), (D[0] - 95, D[1] - 15)], "", C_POLICY)
    s.arrow([(P[0] + 80, P[1] + 37), (D[0] - 95, D[1] + 10)], "", C_HUMAN)
    s.arrow([(P[0], P[1] + 37), (E[0], E[1] - 37)], "", C_TIME)
    s.arrow([(A[0] + 95, A[1]), (F[0] - 95, F[1])], "", C_GW)
    s.arrow([(F[0] + 95, F[1] - 14), (C[0] - 95, C[1] + 14)], "", C_UP)
    s.arrow([(F[0] + 95, F[1] + 14), (X[0] - 95, X[1] - 14)], "", C_UP)

    s.label(
        380,
        160,
        ["policy: approve", "require_approval=false or", "risk < auto_approve_below_risk"],
        11,
        "start",
    )
    s.label(560, 285, ["reviewer: approve", "dashboard / MCP / CLI"], 11, "start")
    s.label(
        560,
        380,
        [
            "policy: deny",
            "path/model not allowed, deny regex,",
            "custom deny rule, risk >= auto_deny_at_risk",
        ],
        11,
        "start",
    )
    s.label(430, 520, ["reviewer: deny (with note)"], 11, "start")
    s.label(
        285,
        470,
        ["timeout: background sweeper (every 5 s)", "or the hold wait reaching expires_at"],
        11,
        "end",
    )
    s.label(910, 138, ["forward_ticket()", "sync: now; async:", "on the first poll"], 10.5, "middle")
    s.label(1200, 95, ["upstream answered"], 11, "middle")
    s.label(1180, 275, ["upstream error / 5xx"], 11, "middle")

    state(*P, "PENDING", ["waiting for a decision", "expires_at = now + 300 s"], "warn")
    state(*A, "APPROVED", ["decided, not yet forwarded"], "ok")
    state(*D, "DENIED", ["client gets 403", "nothing sent upstream"], "danger")
    state(*E, "EXPIRED", ["client gets 504", "nothing sent upstream"], "danger")
    state(*F, "FORWARDING", ["request in flight upstream", "canary + credential swap done"], "upstream")
    state(*C, "COMPLETED", ["upstream status < 500", "response analysed, relayed"], "ok")
    state(*X, "FAILED", ["network error or status >= 500", "client gets 502"], "danger")

    nx, ny = 880, 340
    s.rect(nx, ny, 580, 200, PANEL, PANEL_STROKE, r=12)
    s.text(nx + 16, ny + 26, "Invariants", 14, TEXT, weight="bold")
    s.lines(
        nx + 16,
        ny + 50,
        [
            "- decide() raises InvalidTransition (HTTP 409) unless the ticket is PENDING.",
            "- DENIED and EXPIRED tickets never reach the provider; APPROVED is the only path to FORWARDING.",
            "- Every transition writes a ticket_events row, a per-agent log line and an SSE event;",
            "  human decisions also append a hash-chained audit entry.",
            "- hold_registry.resolve() wakes a blocked sync request in-process; other processes see the",
            "  new status on their next DB poll (AISRF_HOLD_POLL_INTERVAL_SECONDS).",
            "- Async clients poll /gateway/tickets/{id}: 202 PENDING, 403 DENIED / EXPIRED, 502 FAILED,",
            "  200 {status: COMPLETED, response} once relayed.",
            "- Red-team probes are ordinary tickets (source=redteam) and follow the same machine.",
        ],
        11.5,
        "#d1d5db",
        lh=15,
    )

    s.legend(
        32,
        700,
        [
            ("line:" + C_POLICY, "policy engine"),
            ("line:" + C_HUMAN, "human reviewer"),
            ("line:" + C_TIME, "timeout sweeper / hold deadline"),
            ("line:" + C_GW, "gateway"),
            ("line:" + C_UP, "upstream result"),
        ],
        cols=5,
        col_w=250,
        title="Who triggers the transition",
    )
    s.save("ticket-state-machine")


# ======================================================================================
# 4. Red-team flow
# ======================================================================================
def redteam_flow() -> None:
    s = SVG(
        1700,
        980,
        "AISRF red-team campaign flow",
        "Every probe is a reviewable ticket through the same gateway pipeline; external scanners join through short-lived scan tokens.",
    )

    # row 1: campaign creation
    s.panel(
        32,
        90,
        1636,
        250,
        "1. Campaign creation",
        "aisrf redteam run / POST /api/redteam/campaigns / MCP create_campaign / dashboard /redteam",
        accent="#fb923c",
    )
    bx, by, bw, bh = 48, 150, 300, 170
    s.box(
        bx,
        by,
        bw,
        bh,
        "Probe corpus (YAML, 300+ probes)",
        [
            "16 categories: prompt_injection, jailbreak,",
            "system_prompt_extraction, data_exfiltration,",
            "pii_leakage, tool_abuse, harmful_content,",
            "encoding_attacks, multi_turn, many_shot,",
            "misinformation_hallucination, bias_fairness,",
            "privacy_memorization, code_safety,",
            "denial_of_wallet, benign_control",
        ],
        "warn",
        body_size=11,
    )
    s.box(
        bx + 320,
        by,
        280,
        bh,
        "Selection",
        [
            "filter by category, technique,",
            "severity; sampling with --seed;",
            "--max-probes; system prompt;",
            "target path (/v1/chat/completions)",
            "and target model",
        ],
        "warn",
        body_size=11,
    )
    s.box(
        bx + 620,
        by,
        280,
        bh,
        "Mutators",
        [
            "base64, rot13, leetspeak,",
            "reverse, split, suffix",
            "",
            "each probe x mutator becomes",
            "one probe_result row (PENDING)",
        ],
        "warn",
        body_size=11,
    )
    s.box(
        bx + 920,
        by,
        340,
        bh,
        "Comparison group: N targets in parallel",
        [
            "one campaign per target (agent, model,",
            "system prompt), same probe set and seed;",
            "start_group() runs them concurrently;",
            "AISRF_REDTEAM_CONCURRENCY probes in flight",
            "per campaign, campaign state:",
            "CREATED RUNNING PAUSED COMPLETED FAILED CANCELLED",
        ],
        "warn",
        body_size=11,
    )
    s.box(
        bx + 1280,
        by,
        328,
        bh,
        "Materialized campaign",
        [
            "campaigns row + probe_results rows",
            "config: categories, mutators, seed,",
            "target, concurrency; SSE progress on",
            "/api/stream/campaigns; pause / resume /",
            "cancel at any time",
        ],
        "store",
        body_size=11,
    )
    for i, x0 in enumerate([bx + bw, bx + 600, bx + 900, bx + 1260]):
        s.arrow([(x0, by + bh / 2), (x0 + 20, by + bh / 2)], "", "#fb923c")

    # row 2: pipeline through the gateway
    s.panel(
        32,
        370,
        1636,
        230,
        "2. Probes through the human-in-the-loop pipeline",
        "aisrf.gateway.pipeline.submit(source=redteam, campaign_id, probe_id): identical to an HTTP call; evaluate_async grades the reply, TypeSafe may override the heuristic verdict",
        accent="#2dd4bf",
    )
    py = 428
    cols = [
        (
            "pipeline.submit()",
            [
                "build provider body from",
                "probe messages + mutator,",
                "normalize, create ticket",
                "PENDING with campaign_id",
                "and probe_id",
            ],
            "gateway",
        ),
        (
            "Analyzers + policy",
            [
                "typesafe_guard + 9 analyzers",
                "and guardrail integrations;",
                "typesafe.auto_deny / auto_",
                "approve or the agent policy",
                "may auto-deny (verdict",
                "BLOCKED) or auto-approve",
            ],
            "gateway",
        ),
        (
            "Human approval",
            [
                "ticket held for a reviewer",
                "(dashboard / MCP / CLI);",
                "auto-runs when",
                "AISRF_REQUIRE_APPROVAL_FOR_",
                "REDTEAM_PROBES=false",
            ],
            "human",
        ),
        (
            "Target model",
            [
                "forwarder swaps in the",
                "upstream key, canary",
                "injected in the system",
                "prompt, per-probe timeout",
                "AISRF_REDTEAM_PROBE_TIMEOUT",
            ],
            "upstream",
        ),
        (
            "Heuristic evaluators",
            [
                "refusal detector,",
                "canary leak (strongest),",
                "success_indicators regexes,",
                "harmful / guardrail findings",
                "-> heuristic verdict",
                "+ confidence",
            ],
            "gateway",
        ),
        (
            "TypeSafe evaluator",
            [
                "one call: refused, complied,",
                "followed injection, leaked",
                "canary / prompt, harmful,",
                "safe answer + outcome choice;",
                "overrides heuristic verdict",
                "when confidence >= 0.8;",
                "not for BLOCKED, ERROR, canary",
            ],
            "neutral",
        ),
        (
            "Verdicts",
            [
                "VULNERABLE  RESISTED",
                "BLOCKED  ERROR",
                "INCONCLUSIVE",
                "+ confidence + evidence",
                "(typesafe_verdict: applied?)",
                "+ ticket_id, latency_ms",
            ],
            "ok",
        ),
    ]
    cw, ch = 210, 150
    x = 48
    for title, body, role in cols:
        s.box(x, py, cw, ch, title, body, role, body_size=11)
        x += cw + 22
    for i in range(len(cols) - 1):
        x0 = 48 + (i + 1) * cw + i * 22
        s.arrow([(x0, py + ch / 2), (x0 + 22, py + ch / 2)], "", "#2dd4bf")
    # row1 -> row2
    s.arrow([(bx + 1444, by + bh), (bx + 1444, 370)], "", "#fb923c")
    s.arrow([(48 + cw / 2, 340), (48 + cw / 2, 370)], "", "#fb923c")
    s.path(f"M {bx + 1444} 355 L {48 + cw / 2} 355", "#fb923c", 1.8, arrow=False)
    s.label(860, 359, "start(): one submit() per probe entry, AISRF_REDTEAM_CONCURRENCY at a time", 11)

    # row 3: summary and reports + external engines
    s.panel(
        32,
        630,
        1010,
        262,
        "3. Summary and reports",
        "engine.build_summary(), compare_group(), aisrf/reports builders + renderers",
        accent="#4ade80",
    )
    s.box(
        48,
        688,
        300,
        136,
        "Campaign summary",
        [
            "by_verdict totals, vulnerability rate,",
            "per-category and per-technique rates,",
            "per-severity breakdown, benign over-refusal",
            "rate, OWASP LLM Top 10 coverage",
            "(taxonomy.coverage), duration",
        ],
        "ok",
        body_size=11,
    )
    s.box(
        368,
        688,
        300,
        136,
        "Comparison matrix",
        [
            "category x target: vulnerable / tested /",
            "rate; per-probe verdict rows across",
            "targets; ranking by vulnerability rate;",
            "verdict totals per campaign",
        ],
        "ok",
        body_size=11,
    )
    s.box(
        688,
        688,
        338,
        136,
        "Reports (12 formats)",
        [
            "/api/reports/campaign/{id}?format=...",
            "json yaml csv tsv md html pdf xlsx txt xml",
            "sarif (code scanning) junit (CI gating);",
            "aisrf report campaign/ID -f sarif -o out.sarif;",
            "MCP generate_report",
        ],
        "store",
        body_size=11,
    )
    s.arrow([(348, 756), (368, 756)], "", "#4ade80")
    s.arrow([(668, 756), (688, 756)], "", "#4ade80")
    s.arrow(
        [(48 + 6 * (cw + 22) + cw / 2, py + ch), (48 + 6 * (cw + 22) + cw / 2, 606), (198, 606), (198, 630)],
        "verdicts aggregated",
        "#4ade80",
        label_pos=0.5,
    )

    s.panel(
        1070,
        630,
        598,
        262,
        "External engines through the same gateway",
        "short-lived scan tokens (scn_, TTL, revocable, bound to a campaign) let a scanner act as the agent",
        accent="#a78bfa",
    )
    eng = [
        ("garak", "probes: promptinject, dan, encoding, leakreplay; generations per probe"),
        ("promptfoo", "plugins: harmful, pii, prompt-extraction, hijacking; strategies: jailbreak, base64"),
        ("PyRIT", "converters Base64Converter, ROT13Converter; SelfAskRefusalScorer"),
        ("PyRIT-Ship + Burp", "Burp Suite traffic replayed through the gateway with the scan token"),
    ]
    yy = 688
    for title, body in eng:
        s.box(1086, yy, 176, 32, title, "", "upstream", title_size=12)
        s.lines(1276, yy + 14, wrap(body, 11, 380), 11, "#d1d5db", lh=14)
        yy += 44
    s.lines(
        1086,
        876,
        [
            "Scanner base_url -> gw /v1 or /proxy + token: every request is a ticket (source=redteam, campaign_id),",
            "analysed, policy-checked, human-approved and response-scanned; findings share the taxonomy in reports.",
        ],
        11,
        MUTED,
        lh=14,
    )
    s.arrow([(1370, 630), (1370, 600)], "", "#a78bfa")
    s.label(1358, 624, "scanner traffic joins row 2", 11, "end")

    s.legend(
        32,
        916,
        [
            ("warn", "campaign setup"),
            ("gateway", "gateway pipeline"),
            ("human", "human decision"),
            ("upstream", "target / external engine"),
            ("neutral", "TypeSafe evaluator (Jev)"),
            ("ok", "results"),
            ("store", "persistence / reports"),
        ],
        cols=7,
        col_w=180,
        title="Legend",
    )
    s.save("redteam-flow")


# ======================================================================================
# 5. Deployment topology
# ======================================================================================
def deployment() -> None:
    s = SVG(
        1600,
        860,
        "AISRF deployment topology",
        "docker compose up -d (SQLite volume) or docker compose --profile postgres up -d; TLS terminates in a reverse proxy in front of the gateway.",
    )

    # left: actors
    s.panel(32, 92, 300, 520, "Actors", "outside the compose network")
    s.box(
        48,
        150,
        268,
        78,
        "Applications and agents",
        ["SDK base_url, /proxy, mitmproxy", "X-AISRF-Key, sync or async"],
        "client",
        body_size=11,
    )
    s.box(
        48,
        240,
        268,
        78,
        "Reviewers (browser)",
        ["dashboard, SSE live queues", "signed HttpOnly session cookie"],
        "human",
        body_size=11,
    )
    s.box(
        48,
        330,
        268,
        78,
        "MCP clients over HTTP",
        ["Claude Desktop / Claude Code", "POST /mcp + Bearer admin token"],
        "human",
        body_size=11,
    )
    s.box(
        48,
        420,
        268,
        92,
        "MCP clients over stdio",
        [
            "`aisrf mcp --url https://gw --token ...`",
            "runs beside the client and calls",
            "the REST API (separate process)",
        ],
        "human",
        body_size=11,
    )
    s.box(
        48,
        524,
        268,
        76,
        "CLI and CI",
        ["aisrf tickets / report / audit verify", "AISRF_URL + AISRF_ADMIN_API_TOKEN"],
        "human",
        body_size=11,
    )

    # reverse proxy
    s.box(
        390,
        250,
        220,
        150,
        "Reverse proxy (TLS)",
        [
            "nginx / Caddy / Traefik",
            "TLS termination",
            "proxy_read_timeout > 300 s",
            "no buffering for SSE",
            "and streamed relays",
            "forwards X-Request-ID",
        ],
        "neutral",
        body_size=11,
    )
    for yy in (189, 279, 369, 466, 562):
        s.arrow([(316, yy), (390, 325)], "", "#94a3b8")
    s.text(325, 240, "HTTPS", 11, MUTED)

    # compose network
    s.panel(
        660,
        92,
        620,
        620,
        "docker compose network",
        "image aisrf:latest, multi-stage python:3.12-slim, non-root user, HEALTHCHECK GET /healthz",
        accent="#2dd4bf",
    )
    s.box(
        680,
        150,
        580,
        250,
        "aisrf-gateway container  (127.0.0.1:8080 -> 8080)",
        [
            "uvicorn, AISRF_WORKERS=1 (default): one process serves gateway /v1 /proxy /gateway/tickets,",
            "reviewer API /api/*, dashboard, MCP /mcp, /metrics, /healthz, /readyz",
            "",
            "in-process state:  hold registry (asyncio.Event per waiting ticket)  |  rate limiter  |",
            "SSE broadcaster  |  metrics  |  background sweeper (expire PENDING every 5 s, purge old tickets)",
            "",
            "env: .env + AISRF_* (AISRF_DATABASE_URL, AISRF_SECRET_KEY / AISRF_ENCRYPTION_KEY, AISRF_ADMIN_API_TOKEN,",
            "AISRF_NOTIFY_WEBHOOK_URLS, AISRF_APPROVAL_TIMEOUT_SECONDS, AISRF_HOLD_POLL_INTERVAL_SECONDS)",
        ],
        "gateway",
        body_size=11,
    )
    s.arrow([(610, 325), (680, 325)], "HTTP :8080", "#94a3b8", label_dy=-8)

    s.box(
        680,
        430,
        270,
        92,
        "volume aisrf-data -> /app/data",
        [
            "aisrf.db (SQLite, default)",
            "Fernet-encrypted upstream keys live",
            "in the agents table, never on disk in clear",
        ],
        "store",
        body_size=10.5,
    )
    s.box(
        990,
        430,
        270,
        92,
        "volume aisrf-logs -> /app/logs",
        ["aisrf.jsonl (50 MB x 10)", "agents/<agent_id>.jsonl (20 MB x 5)", "JSON console output too"],
        "store",
        body_size=10.5,
    )
    s.arrow([(815, 400), (815, 430)], "", "#9ca3af")
    s.arrow([(1125, 400), (1125, 430)], "", "#9ca3af")

    s.box(
        680,
        560,
        580,
        130,
        "aisrf-postgres container  (profile: postgres, optional)",
        [
            "postgres:16-alpine, volume aisrf-pgdata -> /var/lib/postgresql/data, pg_isready healthcheck",
            'AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:aisrf@postgres:5432/aisrf  (pip install "aisrf[postgres]")',
            "gateway depends_on postgres with required: false; without the profile the gateway uses SQLite",
        ],
        "store",
        body_size=11,
    )
    s.arrow(
        [(815, 522), (815, 560)], "or", "#9ca3af", dash="5 4", label_dx=14, label_anchor="start", label_dy=4
    )

    # right: outbound
    s.panel(1320, 92, 248, 620, "Outbound", "egress from the gateway only")
    s.box(
        1336,
        150,
        216,
        124,
        "Upstream providers",
        [
            "OpenAI, Anthropic, Gemini,",
            "Mistral, Groq, Ollama,",
            "custom HTTP APIs",
            "credentials injected by",
            "the gateway",
        ],
        "upstream",
        body_size=11,
    )
    s.box(
        1336,
        292,
        216,
        104,
        "Webhooks",
        ["Slack or generic JSON", "on ticket created /", "expired / failed", "(AISRF_NOTIFY_*)"],
        "human",
        body_size=11,
    )
    s.box(
        1336,
        412,
        216,
        104,
        "LLM judge / guardrail APIs",
        ["optional: AISRF_JUDGE_*,", "Lakera Guard endpoint,", "LLM Guard / NeMo local"],
        "upstream",
        body_size=11,
    )
    s.box(
        1336,
        532,
        216,
        96,
        "Prometheus / SIEM",
        ["scrape /metrics,", "ship logs/*.jsonl,", "verify audit chain"],
        "store",
        body_size=11,
    )
    s.arrow([(1260, 212), (1336, 212)], "", "#a78bfa")
    s.arrow([(1260, 344), (1336, 344)], "", "#fbbf24")
    s.arrow([(1260, 464), (1336, 464)], "", "#a78bfa")
    s.arrow([(1336, 580), (1260, 580)], "", "#9ca3af", dash="5 4")

    # note
    s.rect(390, 430, 250, 282, PANEL, "#fb923c", r=12)
    s.text(406, 456, "Hold registry note", 14, TEXT, weight="bold")
    s.lines(
        406,
        480,
        wrap(
            "A synchronous request blocks on an asyncio.Event inside the gateway process. A decision taken in the same process "
            "(dashboard, /mcp, REST) wakes it instantly: the fast path. A decision written by another process (a second uvicorn "
            "worker, the stdio MCP host, a direct DB write) is noticed on the next DB poll, every AISRF_HOLD_POLL_INTERVAL_SECONDS "
            "(1 s). Keep AISRF_WORKERS=1 and scale by adding gateways per agent group until the Redis / LISTEN-NOTIFY registry lands.",
            11.5,
            220,
        ),
        11.5,
        "#d1d5db",
        lh=15,
    )

    s.legend(
        32,
        760,
        [
            ("client", "application traffic"),
            ("human", "reviewer / operator surface"),
            ("gateway", "AISRF container"),
            ("store", "storage / data"),
            ("upstream", "external API"),
            ("neutral", "infrastructure"),
        ],
        cols=6,
        col_w=230,
        title="Legend",
    )
    s.text(
        32,
        830,
        "Single container alternative: docker run -d -p 127.0.0.1:8080:8080 --env-file .env -v aisrf-data:/app/data -v aisrf-logs:/app/logs aisrf",
        11.5,
        MUTED,
    )
    s.save("deployment")


# ======================================================================================
# 6. Taxonomy matrix (generated from aisrf.taxonomy)
# ======================================================================================
def taxonomy() -> None:
    from aisrf import taxonomy as tx

    owasp = list(tx.OWASP_LLM_TOP10.keys())
    greshake = list(tx.GRESHAKE_THREATS.keys()) + [
        "hidden"
    ]  # "hidden" is a Greshake delivery method used by obfuscation categories
    thacker = list(tx.THACKER_TECHNIQUES.keys())
    cats = list(tx.CATEGORY_MAP.keys())
    mapped = [c for c in cats if any(tx.CATEGORY_MAP[c].values())]
    unmapped = [c for c in cats if not any(tx.CATEGORY_MAP[c].values())]

    label_w = 250
    cell = 52
    row_h = 24
    header_h = 150
    left, top = 32, 92
    cols = (
        [("owasp", o) for o in owasp]
        + [("greshake", g) for g in greshake]
        + [("thacker", t) for t in thacker]
    )
    W = left + label_w + len(cols) * cell + 40 + 12
    grid_top = top + header_h
    H = grid_top + len(mapped) * row_h + 40 + 140

    s = SVG(
        int(W),
        int(H),
        "AISRF taxonomy matrix",
        "aisrf.taxonomy.CATEGORY_MAP: finding and probe categories mapped to OWASP LLM Top 10 (2025), Greshake et al. threat classes and Thacker technique classes.",
    )

    group_color = {"owasp": "#2dd4bf", "greshake": "#fbbf24", "thacker": "#a78bfa"}
    group_label = {
        "owasp": "OWASP LLM Top 10 (2025)",
        "greshake": "Greshake et al. threats (+ hidden delivery)",
        "thacker": "Thacker technique classes",
    }
    group_desc = {
        "owasp": tx.OWASP_LLM_TOP10,
        "greshake": {**tx.GRESHAKE_THREATS, "hidden": tx.GRESHAKE_DELIVERY["hidden"]},
        "thacker": tx.THACKER_TECHNIQUES,
    }

    # group header bands
    x = left + label_w
    for g in ("owasp", "greshake", "thacker"):
        n = sum(1 for gg, _ in cols if gg == g)
        s.rect(x, top, n * cell - 4, 26, group_color[g], group_color[g], r=6, sw=0, opacity=0.9)
        s.text(x + (n * cell - 4) / 2, top + 18, group_label[g], 12, "#0b1220", "middle", weight="bold")
        x += n * cell

    # column headers (rotated)
    for i, (g, name) in enumerate(cols):
        cx = left + label_w + i * cell + cell / 2
        lab = name if g == "owasp" else name.replace("_", " ")
        s.text(cx + 4, grid_top - 8, lab, 11.5, TEXT, "start", rotate=-60)
        if g == "owasp":
            s.text(cx, top + 42, "", 9)

    # rows
    for r, cat in enumerate(mapped):
        y = grid_top + r * row_h
        if r % 2 == 0:
            s.rect(left, y, label_w + len(cols) * cell, row_h, PANEL, PANEL, r=0, sw=0)
        s.text(left + 8, y + 16, cat, 12, TEXT, family=MONO)
        entry = tx.CATEGORY_MAP[cat]
        for i, (g, name) in enumerate(cols):
            if name in entry.get(g, []):
                cx = left + label_w + i * cell + cell / 2
                s.rect(cx - 14, y + 4, 28, row_h - 8, group_color[g], group_color[g], r=5, sw=0, opacity=0.95)
    # grid lines (light)
    x = left + label_w
    for i in range(len(cols) + 1):
        s.path(
            f"M {x + i * cell} {grid_top} L {x + i * cell} {grid_top + len(mapped) * row_h}",
            "#233047",
            1,
            arrow=False,
        )
    # group separators
    x = left + label_w
    for g in ("owasp", "greshake"):
        n = sum(1 for gg, _ in cols if gg == g)
        x += n * cell
        s.path(f"M {x} {top + 30} L {x} {grid_top + len(mapped) * row_h}", "#64748b", 1.5, arrow=False)

    # footer: OWASP names and unmapped categories
    fy = grid_top + len(mapped) * row_h + 24
    s.text(left, fy, "OWASP ids:", 12, TEXT, weight="bold")
    items = [f"{k} {v['name']}" for k, v in tx.OWASP_LLM_TOP10.items()]
    half = (len(items) + 1) // 2
    s.lines(left + 90, fy, items[:half], 11.5, "#d1d5db", lh=16)
    s.lines(left + 90 + 340, fy, items[half:], 11.5, "#d1d5db", lh=16)
    s.text(
        left + 800,
        fy,
        "Greshake threats: " + ", ".join(tx.GRESHAKE_THREATS) + "; hidden = concealed delivery.",
        11.5,
        "#d1d5db",
    )
    s.text(
        left + 800,
        fy + 16,
        "Thacker: " + ", ".join(t.replace("_", " ") for t in thacker) + ".",
        11.5,
        "#d1d5db",
    )
    s.text(
        left + 800,
        fy + 32,
        "Control / meta categories with no mapping: " + ", ".join(unmapped) + ".",
        11.5,
        "#d1d5db",
    )
    s.text(
        left + 800,
        fy + 48,
        "Findings carry owasp / greshake / thacker fields (taxonomy.enrich); campaign summaries report OWASP coverage.",
        11.5,
        "#d1d5db",
    )
    s.text(
        left,
        fy + 96,
        "Regenerate with docs/images/generate_diagrams.py after editing aisrf/taxonomy.py; this diagram is built from CATEGORY_MAP at generation time.",
        11,
        MUTED,
    )
    s.save("taxonomy")


# ======================================================================================
# 7. TypeSafe decision layer (Jev)
# ======================================================================================
def typesafe_decision_layer() -> None:
    W = 1700
    s = SVG(
        W,
        10,
        "AISRF TypeSafe decision layer (Jev)",
        "aisrf/typesafe: one call per item, typed questions answered in parallel with calibrated probabilities, confidence-gated actions. "
        "Thresholds are the defaults in integrations.typesafe.",
    )

    def auto_h(title: str, body: str, w: float, title_size: float = 14, body_size: float = 11) -> float:
        pad = 12
        n_t = len(wrap(title, title_size, w - 2 * pad))
        n_b = len(wrap(body, body_size, w - 2 * pad))
        return pad + title_size + (n_t - 1) * title_size * 1.35 + 2 + n_b * body_size * 1.35 + pad

    # --- row 1: the four hooks -----------------------------------------------------------
    hooks = [
        (
            "1. Request and response guard  (typesafe_guard, typesafe_response_guard)",
            "gateway",
            "where: analysis runner phase 1, concurrent with the deterministic analyzers and the guardrails\n"
            "state: system prompt + conversation turns + tools offered, secrets masked, at most max_state_chars (12000)\n"
            "REQUEST_GUARD: 9 nouls (prompt_injection, jailbreak, system_prompt_extraction, data_exfiltration, contains_pii, contains_secrets, "
            "harmful_request, tool_abuse, benign_business_request) + intent choice over the taxonomy + severity score (none .. critical)\n"
            "RESPONSE_GUARD: leaked_system_prompt, leaked_secret_or_pii, harmful_compliance, exfil_markup, refusal\n"
            "noul >= 0.7 (noul_threshold) -> finding, severity from the score, confidence |p - 0.5| * 2\n"
            "verdict benign: nothing fired, no noul in the grey zone, benign confidence >= 0.85 (benign_confidence)\n"
            "verdict malicious: strongest attack signal confidence >= 0.9 (malicious_confidence); otherwise uncertain\n"
            "phase 2 llm_judge / llm_judge_response only for uncertain (or no verdict) and escalate_to_llm_judge: true",
        ),
        (
            "2. Policy routing  (gateway/policy.py typesafe_route, auto_route: true)",
            "gateway",
            "order in policy.evaluate: allowed paths / models -> auto-deny patterns and custom deny rules -> typesafe_route -> risk thresholds -> review\n"
            "reads the typesafe_guard finding with the highest confidence\n"
            "malicious and confidence >= 0.95 (auto_deny_confidence) -> deny, matched rule typesafe.auto_deny, client gets 403\n"
            "benign and confidence >= 0.9 (auto_approve_confidence), agent has require_approval and no finding is HIGH or CRITICAL "
            "-> approve, matched rule typesafe.auto_approve, straight to forward_ticket()\n"
            "anything else returns nothing: auto_deny_at_risk (90) / auto_approve_below_risk / review (human) decide as before\n"
            "reasons land on the ticket, e.g. 'TypeSafe verdict benign with confidence 0.96 >= 0.9 and no HIGH or CRITICAL finding'",
        ),
        (
            "3. Red-team evaluator  (redteam/evaluators.py evaluate_async + typesafe_evaluate)",
            "gateway",
            "heuristic verdict first: refusal detector, canary leak, success_indicators regexes, harmful / guardrail findings\n"
            "REDTEAM_EVAL state: probe record (id, category, technique, expected behaviour, canary injected?), attack prompt, model response\n"
            "nouls refused, complied_with_attack, followed_injected_instruction, leaked_canary_or_system_prompt, produced_harmful_content, "
            "safe_helpful_answer + outcome choice (vulnerable, resisted, partial, unclear)\n"
            "vulnerable / partial -> VULNERABLE, resisted -> RESISTED, unclear -> INCONCLUSIVE; benign controls: refused -> VULNERABLE (over-refusal), "
            "safe_helpful_answer -> RESISTED\n"
            "overrides the heuristic verdict only when confidence >= 0.8 (redteam_confidence); evidence.typesafe_verdict says whether it applied\n"
            "never called for BLOCKED, ERROR or canary-leak results; requires redteam_evaluator: true",
        ),
        (
            "4. Code review triage  (codereview/engines/typesafe_engine.py)",
            "gateway",
            "order in the run: rules -> semgrep -> bandit -> typesafe -> llm (only files with uncertain findings, only when escalate_to_llm_judge)\n"
            "per finding >= triage_min_severity (LOW), worst severity first, max_findings 200, triage_concurrency 8 calls in flight\n"
            "CODE_TRIAGE state: finding record + masked snippet + 40 numbered context lines; nouls true_positive, user_input_reaches_prompt, "
            "model_output_reaches_sink, exploitable_without_auth, mitigated_in_code + four-level exploitability score\n"
            "confidence blended: (finding confidence + true_positive) / 2; raw answers kept in metadata (meta column)\n"
            "true_positive < 0.2 and confidence >= 0.8 (triage_confidence) -> status likely_false_positive: no risk score, "
            "excluded from SARIF, hidden by the default filter, reviewer can reopen or override\n"
            "verdict true_positive | likely_false_positive | uncertain per finding; engine table explains a skipped LLM pass",
        ),
    ]
    hw, hgap = 396, 18
    hx = [32 + i * (hw + hgap) for i in range(4)]
    hy = 92
    hh = max(auto_h(t, b, hw) for t, _, b in hooks)
    for (title, role, body), x in zip(hooks, hx):
        s.box(x, hy, hw, hh, title, body, role, body_size=11)
    hb = hy + hh

    # bus from the hooks into the client
    bus_y = hb + 26
    for x in hx:
        s.path(f"M {x + hw / 2} {hb} L {x + hw / 2} {bus_y}", "#fb923c", 1.8, arrow=False)
    s.path(f"M {hx[0] + hw / 2} {bus_y} L {hx[3] + hw / 2} {bus_y}", "#fb923c", 1.8, arrow=False)
    s.label(
        W / 2,
        bus_y - 6,
        "client.evaluate(state, questions): one request per item (request, response, probe, finding); settings read live on every call",
        11.5,
    )

    # --- row 2: client, cache, API -------------------------------------------------------
    cy = bus_y + 30
    cw_, ch_ = 620, 150
    s.box(
        32,
        cy,
        cw_,
        ch_,
        "TypeSafe client  (aisrf/typesafe/client.py)",
        [
            "async httpx, POST {base_url}/v1/systemone, model jev-latest, timeout 8 s per attempt",
            "key: integrations.typesafe.api_key (masked, server side) or TYPESAFE_API_KEY from the environment",
            "retry 3x with exponential backoff and jitter on 429 / 529 and connection errors",
            "state builders (masking, head + tail truncation), evaluate_sync for worker threads",
            "metrics: aisrf_typesafe_calls_total{ok|cached|error}, input_tokens_total, cache_hits_total, latency_ms",
            "no key or API unreachable: silent fallback (no findings, heuristic verdicts, no triage), last_error set",
        ],
        "warn",
        body_size=11,
    )
    s.arrow([(hx[0] + hw / 2, bus_y), (hx[0] + hw / 2, cy)], "", "#fb923c")
    kx, kw = 700, 300
    s.box(
        kx,
        cy,
        kw,
        ch_,
        "Result cache",
        [
            "checked before every call; 512 entries",
            "TTL cache_ttl_seconds (300), 0 disables",
            "key: sha256(model, state, questions)",
            "retries and replays are free",
            "hits count as judge tokens avoided",
            "and bill nothing (savings meter)",
        ],
        "store",
        body_size=11,
    )
    s.arrow([(32 + cw_, cy + ch_ / 2), (kx, cy + ch_ / 2)], "", "#fb923c")
    ax_, aw = 1300, 368
    s.box(
        ax_,
        cy,
        aw,
        ch_,
        "api.typesafe.ai  Jev (System One model)",
        [
            "primitives: noul (yes / no probability),",
            "choice (option probabilities + confidence),",
            "score (ordered rubric, 2 to 10 levels)",
            "every question answered in parallel against",
            "the same state; 70 to 500 ms, no streaming, no prose",
            "billed on input tokens only, about $0.042 per million",
        ],
        "upstream",
        body_size=11,
    )
    s.arrow(
        [(kx + kw, cy + ch_ / 2), (ax_, cy + ch_ / 2)],
        ["cache miss: POST /v1/systemone", "answers + usage + latency back"],
        "#fb923c",
        both=True,
        label_dy=-14,
        label_size=11,
    )

    # --- row 3: confidence gates and savings model ---------------------------------------
    gy = cy + ch_ + 60
    s.arrow(
        [(32 + cw_ / 2, cy + ch_), (32 + cw_ / 2, gy)],
        "verdict + confidence back to the hook",
        "#fb923c",
        label_dx=14,
        label_anchor="start",
        label_dy=4,
    )
    gh = 300
    s.panel(
        32,
        gy,
        968,
        gh,
        "Confidence-gated outcome",
        "TypeSafe guidance: act above 0.9, proceed with care between 0.5 and 0.9, never act below 0.5",
        accent="#fb923c",
    )
    ow, oh = 296, 176
    oy = gy + 60
    s.box(
        48,
        oy,
        ow,
        oh,
        "benign",
        [
            "guard: benign confidence >= 0.85",
            "-> LLM judge skipped (phase 2)",
            "policy: confidence >= 0.9, agent needs",
            "approval, no HIGH / CRITICAL finding",
            "-> typesafe.auto_approve, APPROVED",
            "without a human, forwarded upstream",
            "reviewers still see every probability",
        ],
        "ok",
        body_size=11,
    )
    s.box(
        48 + ow + 16,
        oy,
        ow,
        oh,
        "malicious",
        [
            "guard: strongest signal confidence >= 0.9",
            "-> LLM judge skipped (phase 2)",
            "policy: confidence >= 0.95",
            "-> typesafe.auto_deny, DENIED, 403,",
            "nothing reaches the provider",
            "red team: outcome applied at >= 0.8",
            "triage: true positive kept, confidence blended",
        ],
        "danger",
        body_size=11,
    )
    s.box(
        48 + 2 * (ow + 16),
        oy,
        ow,
        oh,
        "uncertain",
        [
            "guard: below both confidence bars, or a",
            "noul in the grey zone 0.5 .. 0.7, or no verdict",
            "escalate_to_llm_judge: true -> LLM judge",
            "(1 to 5 s); false -> no judge at all",
            "policy: falls through to the risk thresholds,",
            "usually review: the human queue",
            "red team: heuristic verdict kept",
        ],
        "warn",
        body_size=11,
    )
    s.text(
        48,
        gy + gh - 16,
        "Tune auto_approve_confidence first if benign traffic is sensitive; keep redteam_confidence at 0.8 or above because a verdict flips a heatmap cell.",
        11,
        MUTED,
    )

    # LLM judge escalation target
    jx, jy, jw, jh = 1070, oy, 200, oh
    s.box(
        jx,
        jy,
        jw,
        jh,
        "LLM judge  (escalation)",
        [
            "llm_judge,",
            "llm_judge_response,",
            "LLM code review engine;",
            "only the uncertain slice,",
            "only when escalate_to_",
            "llm_judge is true (default",
            "false); typically under",
            "10 percent of traffic",
        ],
        "upstream",
        body_size=11,
    )
    s.arrow(
        [(48 + 3 * ow + 32, oy + oh / 2), (jx, oy + oh / 2)],
        ["uncertain", "only"],
        "#a78bfa",
        dash="5 4",
        label_dy=-14,
        label_size=11,
    )

    # savings model
    sx, sw_ = 1300, 368
    s.panel(
        sx,
        gy,
        sw_,
        gh,
        "Savings model  (savings meter)",
        "overview tile, GET /api/settings/typesafe/status",
        accent="#4ade80",
    )
    s.lines(
        sx + 16,
        gy + 68,
        [
            "per evaluation, AISRF assumes the judge would have read the",
            "same input tokens and written 400 output tokens:",
        ],
        11.5,
        "#d1d5db",
        lh=15,
    )
    s.lines(
        sx + 16,
        gy + 106,
        [
            "judge_cost    = input * 0.15/M + 400 * 0.60/M",
            "typesafe_cost = billed_input * 0.042/M",
            "saved         = judge_cost - typesafe_cost",
            "cached hit    : billed_input = 0",
        ],
        11.5,
        TEXT,
        lh=16,
        family=MONO,
    )
    s.lines(
        sx + 16,
        gy + 180,
        [
            "3000-token conversation: judge 0.00069 USD and 1 to 5 s,",
            "TypeSafe 3900 input tokens (state + questions) 0.000164 USD",
            "and 0.07 to 0.5 s: 76 percent saved, about $53 and 6 machine",
            "hours of judge latency per 100000 requests a day.",
            "Fields: evaluations, api_calls, cache_hits, billed_input_tokens,",
            "typesafe_cost_usd, judge_tokens_avoided, dollars_saved.",
        ],
        11,
        "#d1d5db",
        lh=14.5,
    )
    s.arrow(
        [(kx + kw / 2, cy + ch_), (kx + kw / 2, gy - 22), (sx + 40, gy - 22), (sx + 40, gy)],
        "usage.input_tokens, cached",
        "#4ade80",
        label_pos=0.6,
        label_dy=-8,
        label_size=11,
    )

    ly = gy + gh + 20
    s.legend(
        32,
        ly,
        [
            ("gateway", "AISRF hook"),
            ("warn", "TypeSafe client / uncertain"),
            ("store", "cache"),
            ("upstream", "external model API"),
            ("ok", "benign outcome"),
            ("danger", "malicious outcome"),
            ("line:#fb923c", "TypeSafe call"),
            ("line:#a78bfa|5 4", "optional escalation"),
        ],
        cols=8,
        col_w=200,
        title="Legend",
    )
    s.h = int(ly + 52 + 24)
    s.save("typesafe-decision-layer")


if __name__ == "__main__":
    architecture()
    request_lifecycle()
    ticket_state_machine()
    redteam_flow()
    deployment()
    taxonomy()
    typesafe_decision_layer()
