#!/usr/bin/env python
"""Generate the Airt (AI Security & Research Framework) architecture diagrams (SVG + 2x PNG) in docs/images/.

Usage (from the repository root):

    .venv/bin/python docs/images/generate_diagrams.py

The SVGs are hand-authored through a small builder so that the diagrams are reproducible and
diff-friendly. PNGs are rendered with cairosvg at 2x scale so GitHub renders them reliably.
The taxonomy matrix is produced from ``airt.taxonomy.CATEGORY_MAP`` so it never drifts from the code.
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

    def text(self, x: float, y: float, s: str, size: float = 14, fill: str = TEXT, anchor: str = "start",
             weight: str = "normal", family: str = FONT, opacity: float = 1.0, rotate: float | None = None) -> None:
        tr = f' transform="rotate({rotate} {x} {y})"' if rotate is not None else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{family}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" opacity="{opacity}"{tr}>{escape(s)}</text>'
        )

    def lines(self, x: float, y: float, lines: list[str], size: float = 13, fill: str = TEXT, anchor: str = "start",
              lh: float | None = None, family: str = FONT, weight: str = "normal") -> float:
        lh = lh or size * 1.35
        for i, ln in enumerate(lines):
            self.text(x, y + i * lh, ln, size, fill, anchor, weight=weight, family=family)
        return y + len(lines) * lh

    def rect(self, x: float, y: float, w: float, h: float, fill: str, stroke: str, r: float = 10,
             sw: float = 1.5, dash: str | None = None, opacity: float = 1.0) -> None:
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{r}" ry="{r}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d} opacity="{opacity}"/>'
        )

    def panel(self, x: float, y: float, w: float, h: float, title: str, subtitle: str = "", accent: str = PANEL_STROKE) -> None:
        self.rect(x, y, w, h, PANEL, accent, r=14, sw=1.5)
        self.text(x + 16, y + 26, title, 16, TEXT, weight="bold")
        if subtitle:
            self.text(x + 16, y + 44, subtitle, 12, MUTED)

    def box(self, x: float, y: float, w: float, h: float, title: str, body: str | list[str] = "",
            role: str = "neutral", title_size: float = 14, body_size: float = 12, mono_body: bool = False,
            align: str = "left") -> tuple[float, float, float, float]:
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
        if last_baseline + body_size * 0.3 > y + h - 6:
            print(f"WARNING overflow in {self.title!r}: box {title!r} needs ~{ty - y:.0f}px, has {h}px")
        return (x, y, w, h)

    def chip(self, x: float, y: float, label: str, role: str = "neutral", size: float = 11) -> float:
        fill, stroke = ROLE[role]
        w = text_width(label, size) + 16
        self.rect(x, y, w, size + 10, fill, stroke, r=(size + 10) / 2, sw=1.2)
        self.text(x + w / 2, y + size + 2, label, size, TEXT, "middle", weight="bold")
        return w

    def path(self, d: str, color: str = LINE, sw: float = 1.8, dash: str | None = None, arrow: bool = True,
             start_arrow: bool = False) -> None:
        ma = f' marker-end="url(#{self.marker_id(color)})"' if arrow else ""
        ms = f' marker-start="url(#{self.marker_id(color)}s)"' if start_arrow else ""
        dd = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{dd}{ma}{ms}/>')

    def arrow(self, pts: list[tuple[float, float]], label: str | list[str] = "", color: str = LINE, dash: str | None = None,
              label_pos: float = 0.5, label_dy: float = -8, label_size: float = 12, both: bool = False,
              label_dx: float = 0, label_anchor: str = "middle", sw: float = 1.8) -> None:
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

    def label(self, x: float, y: float, label: str | list[str], size: float = 12, anchor: str = "middle",
              fill: str = TEXT, bg: str = BG) -> None:
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

    def legend(self, x: float, y: float, items: list[tuple[str, str]], cols: int = 6, col_w: float = 230, title: str = "Legend") -> None:
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
    s = SVG(1700, 1080, "Airt architecture",
            "Airt, AI Security & Research Framework: human-in-the-loop interception, analysis and red teaming of LLM traffic. One FastAPI process, one port.")

    PH = 570  # height of the three top panels
    # --- clients ------------------------------------------------------------------------
    s.panel(32, 92, 290, PH, "Applications and agents", "no provider key on the client, only airt_... keys")
    cl = [
        ("OpenAI / Anthropic SDK", "base_url = http://gw:8080/v1"),
        ("Python SDK", "patch_httpx(), patch_requests(), AirtClient"),
        ("Node package", "airt-intercept: global fetch / undici hook"),
        ("curl / httpx / fetch", "POST /proxy/<provider path> + X-AIRT-Key"),
        ("mitmproxy transparent", "mitm_addon.py, X-AIRT-Source: mitm"),
        ("Autonomous agents", "LangChain, LlamaIndex, tool loops"),
    ]
    y = 150
    for title, body in cl:
        s.box(48, y, 258, 72, title, body, "client", body_size=11)
        y += 82

    # --- gateway --------------------------------------------------------------------------
    gx, gy, gw, gh = 400, 92, 850, PH
    s.panel(gx, gy, gw, gh, "Airt gateway", "airt.main.create_app: gateway + reviewer API + dashboard + MCP on port 8080", accent="#2dd4bf")

    row1 = gy + 62
    bw, bh = 190, 150
    gap = 20
    xs = [gx + 16 + i * (bw + gap) for i in range(4)]
    s.box(xs[0], row1, bw, bh, "Interception endpoints",
          ["/v1/{path}", "/proxy/{path}", "/gateway/tickets/{id}", "agent key auth (SHA-256)", "rate limit 429, size 413"],
          "gateway", mono_body=True, body_size=11)
    s.box(xs[1], row1, bw, bh, "Normalizer",
          ["parser.normalize(): provider,", "endpoint, model, stream,", "system, messages, tools,", "prompt_text, preview"],
          "gateway", body_size=11)
    s.box(xs[2], row1, bw, bh, "Analyzers (concurrent)",
          ["prompt_injection, jailbreak,", "pii, secrets, data_exfil,", "tool_abuse, harmful_content,", "obfuscation, anomaly, judge",
           "guardrails: Rebuff, LLM Guard,", "NeMo, Lakera"],
          "gateway", body_size=11)
    s.box(xs[3], row1, bw, bh, "Policy engine",
          ["risk score 0..100 + findings", "allowed paths / models", "deny regexes, custom rules", "auto-deny >= 90, auto-approve", "-> deny | approve | review"],
          "gateway", body_size=11)
    for i in range(3):
        x0 = xs[i] + bw
        s.arrow([(x0, row1 + bh / 2), (x0 + gap, row1 + bh / 2)], "", "#2dd4bf")

    row2 = row1 + bh + 60
    s.box(xs[0], row2, bw, bh, "Ticket store",
          ["tickets + timeline events", "PENDING / APPROVED / DENIED", "EXPIRED / FORWARDING", "COMPLETED / FAILED", "SSE stream, webhooks"],
          "gateway", body_size=11)
    s.box(xs[1], row2, bw, bh, "Hold registry",
          ["asyncio.Event per waiting", "ticket (in-process fast path)", "DB polling fallback", "timeout -> EXPIRED (504)", "sync wait or async 202 + poll"],
          "gateway", body_size=11)
    s.box(xs[2], row2, bw, bh, "Canary injection",
          ["Rebuff-style AIRT-CANARY-*", "token appended to the", "system prompt of every", "forwarded request;", "leak => CRITICAL finding"],
          "gateway", body_size=11)
    s.box(xs[3], row2, bw, bh, "Forwarder",
          ["swap in encrypted upstream", "key, strip client credentials,", "relay JSON or SSE stream;", "scan response: prompt leak,", "refusal, canary, PII ->", "withhold or relay"],
          "gateway", body_size=11)
    px = xs[3] + bw / 2
    s.arrow([(px, row1 + bh), (px, row1 + bh + 30), (xs[0] + bw / 2, row1 + bh + 30), (xs[0] + bw / 2, row2)],
            "ticket created PENDING, policy decision recorded", "#2dd4bf", label_pos=0.55, label_dy=-8)
    for i in range(3):
        x0 = xs[i] + bw
        s.arrow([(x0, row2 + bh / 2), (x0 + gap, row2 + bh / 2)], "", "#2dd4bf")
    s.text(gx + 16, row2 + bh + 30, "Denied / expired tickets never reach the provider. Every step: ticket timeline, per-agent log, audit entry for human decisions.", 11, MUTED)

    # clients -> gateway
    s.arrow([(306, 340), (gx, 340)], ["HTTPS", "X-AIRT-Key", "sync or async"], "#60a5fa", label_dy=-24, label_size=10.5)

    # --- upstream --------------------------------------------------------------------------
    ux = 1290
    s.panel(ux, 92, 378, PH, "Upstream providers and backends", "reached only with the agent's own encrypted credential")
    ups = [
        ("OpenAI", "api.openai.com: /v1/chat/completions, /v1/responses"),
        ("Anthropic", "api.anthropic.com: /v1/messages"),
        ("Google Gemini", "generativelanguage.googleapis.com"),
        ("Mistral, Groq, Azure OpenAI", "any OpenAI-compatible endpoint"),
        ("Ollama / self-hosted", "localhost:11434, vLLM, TGI"),
        ("Custom / enterprise backends", "any HTTP API via /proxy/<path>"),
    ]
    ay = row2 + bh / 2  # arrow height
    ys = [150, 214, 278, 466, 530, 594]
    for (title, body), yy in zip(ups, ys):
        s.box(ux + 16, yy, 346, 58, title, body, "upstream", body_size=11)
    s.arrow([(gx + gw, ay), (ux + 16, ay)], "", "#a78bfa")
    s.text(ux + 16, ay - 22, "forward after approval", 11.5, TEXT)
    s.text(ux + 16, ay - 7, "reply carries X-AIRT-Ticket", 11.5, TEXT)

    # --- reviewers -------------------------------------------------------------------------
    ry = 712
    s.panel(gx, ry, gw, 176, "Human reviewers", "viewer < reviewer < admin roles; only PENDING tickets can be decided; every decision is audited", accent="#fbbf24")
    rv = [
        ("Dashboard", "/tickets /agents /logs /redteam /reports /audit, live SSE"),
        ("MCP server", "/mcp streamable HTTP or `airt mcp` stdio: Claude Desktop / Claude Code"),
        ("CLI", "airt tickets list | show | approve | deny | watch"),
        ("Webhooks / Slack", "AIRT_NOTIFY_WEBHOOK_URLS on created / expired / failed"),
    ]
    for (title, body), x in zip(rv, xs):
        s.box(x, ry + 56, bw, 100, title, body, "human", body_size=11)
    tsx = xs[0] + bw / 2
    s.arrow([(tsx - 30, row2 + bh), (tsx - 30, ry)], ["SSE ticket.created", "notification"], "#fbbf24", label_dy=-4, label_dx=-12, label_anchor="end")
    s.arrow([(tsx + 30, ry), (tsx + 30, row2 + bh)], ["approve / deny", "-> hold resolved"], "#fbbf24", label_dy=-4, label_dx=12, label_anchor="start")
    s.text(32, 780, "Browser, Claude (MCP client),", 12, MUTED)
    s.text(32, 796, "airt CLI, CI automation with", 12, MUTED)
    s.text(32, 812, "AIRT_ADMIN_API_TOKEN", 12, MUTED)
    s.arrow([(215, 800), (gx, 800)], "", "#fbbf24")

    # --- side components -------------------------------------------------------------------
    sy = 920
    s.panel(32, sy, 1636, 136, "Storage, observability and engines", "SQLAlchemy async, structlog, hash-chained audit, reports, red-team engines, runtime settings")
    side = [
        ("SQLite / PostgreSQL", "tickets, events, agents, audit, campaigns, probe results, scan tokens, settings"),
        ("Structured logs", "logs/airt.jsonl + logs/agents/<agent_id>.jsonl, X-Request-ID on every line"),
        ("Audit chain", "SHA-256 hash chain per privileged action, GET /api/audit/verify"),
        ("Reports engine", "12 formats: json yaml csv tsv md html pdf xlsx txt xml sarif junit"),
        ("Red-team engines", "native corpus (300+ probes), garak, promptfoo, PyRIT, PyRIT-Ship via scan tokens"),
        ("Settings store", "runtime overrides: analyzers, rules, integrations, policy, ui"),
    ]
    x = 48
    for title, body in side:
        s.box(x, sy + 50, 258, 76, title, body, "store", body_size=10.5)
        x += 270
    s.arrow([(gx + 200, ry + 176), (gx + 200, sy)], "", "#9ca3af", dash="5 4")
    s.arrow([(gx + 700, ry + 176), (gx + 700, sy)], "", "#9ca3af", dash="5 4")
    s.text(gx + 214, sy - 10, "persist, log, audit, report, run campaigns", 11, MUTED)

    s.legend(1290, 712, [("client", "clients"), ("gateway", "gateway component"), ("human", "human review surface"),
                         ("upstream", "upstream provider"), ("store", "storage / engine")], cols=2, col_w=180, title="Legend")
    s.save("architecture")


# ======================================================================================
# 2. Request lifecycle (sequence)
# ======================================================================================
def request_lifecycle() -> None:
    W, H = 1600, 1560
    s = SVG(W, H, "Airt request lifecycle",
            "One intercepted call, from client request to COMPLETED ticket. Sync mode blocks; async mode returns 202 and polls.")
    lanes = {
        "client": (150, "Client / agent", "client"),
        "gateway": (470, "Airt gateway", "gateway"),
        "analysis": (760, "Analyzers + policy", "gateway"),
        "reviewer": (1050, "Reviewer", "human"),
        "upstream": (1400, "Upstream provider", "upstream"),
    }
    top, bottom = 92, H - 60
    for key, (x, name, role) in lanes.items():
        fill, stroke = ROLE[role]
        s.rect(x - 95, top, 190, 40, fill, stroke, r=10)
        s.text(x, top + 26, name, 14, TEXT, "middle", weight="bold")
        s.path(f"M {x} {top + 40} L {x} {bottom}", LINE_DIM, 1.2, dash="4 6", arrow=False)

    def X(k: str) -> float:
        return lanes[k][0]

    def msg(y: float, a: str, b: str, label: str | list[str], color: str = LINE, dash: str | None = None) -> None:
        xa, xb = X(a), X(b)
        s.arrow([(xa, y), (xb, y)], label, color, dash=dash, label_dy=-6)

    def note(y: float, k: str, lines: list[str], role: str = "gateway", w: float = 250, h: float | None = None) -> float:
        h = h or (16 + 15 * len(lines))
        x = X(k)
        fill, stroke = ROLE[role]
        s.rect(x - w / 2, y, w, h, fill, stroke, r=8)
        s.lines(x - w / 2 + 10, y + 15, lines, 11.5, TEXT, lh=15)
        return y + h

    def status(y: float, label: str, role: str) -> None:
        s.chip(X("gateway") + 150, y - 12, label, role)

    def frame(y1: float, y2: float, title: str, color: str, x1: float = 40, x2: float = W - 40) -> None:
        s.rect(x1, y1, x2 - x1, y2 - y1, "none", color, r=8, sw=1.4, dash="6 4")
        s.rect(x1, y1, text_width(title, 12) + 22, 22, color, color, r=6, sw=0, opacity=0.9)
        s.text(x1 + 11, y1 + 15, title, 12, "#0b1220", weight="bold")

    y = 170
    msg(y, "client", "gateway", ["POST /v1/chat/completions   (or /proxy/<path>)", "X-AIRT-Key: airt_...   optional X-AIRT-Async: 1"], "#60a5fa")
    y += 30
    y = note(y, "gateway", ["1. authenticate agent key (SHA-256 lookup, inactive -> 401)", "2. rate limit per minute (429), body size limit (413)",
                            "3. normalize body: provider, model, messages, tools, stream", "4. create ticket PENDING, redacted headers, expires_at = now + 300 s"], w=380)
    status(y - 40, "ticket PENDING", "warn")
    y += 26
    msg(y, "gateway", "analysis", "analyze_request(normalized): 10 analyzers + guardrail integrations, concurrent", "#2dd4bf")
    y += 26
    msg(y, "analysis", "gateway", "findings + risk score 0..100 (NONE / LOW / MEDIUM / HIGH / CRITICAL)", "#2dd4bf")
    y += 26
    msg(y, "gateway", "analysis", "policy.evaluate(agent, normalized, path, risk, findings)", "#2dd4bf")
    y += 26
    msg(y, "analysis", "gateway", "PolicyDecision: deny | approve | review  (+ reasons, matched rules)", "#2dd4bf")
    y += 20

    # deny branch
    f1 = y
    y += 32
    msg(y, "gateway", "client", "403 {error: denied, ticket_id, risk_score}   nothing is sent upstream", "#f87171")
    status(y, "DENIED", "danger")
    y += 18
    frame(f1, y, "alt  policy: deny", "#f87171")
    y += 26

    # review branch (sync + async)
    f2 = y
    y += 32
    msg(y, "gateway", "reviewer", "SSE ticket.created on /api/stream/tickets, webhook / Slack notification", "#fbbf24")
    y += 22
    # async sub-branch
    f3 = y
    y += 32
    msg(y, "gateway", "client", "202 {ticket_id, status: PENDING, poll_url: /gateway/tickets/{id}, expires_at}", "#60a5fa")
    y += 26
    msg(y, "client", "gateway", "GET /gateway/tickets/{id} with the agent key, repeated: 202 while PENDING", "#60a5fa", dash="5 4")
    y += 18
    frame(f3, y, "alt  async mode (X-AIRT-Async: 1)", "#60a5fa", x1=70, x2=880)
    y += 26
    # sync sub-branch
    f4 = y
    y += 32
    y = note(y, "gateway", ["hold_registry.wait(ticket_id): asyncio.Event fast path,", "DB poll every AIRT_HOLD_POLL_INTERVAL_SECONDS (1 s) for", "decisions made in another process"], w=380)
    y += 6
    frame(f4, y, "alt  sync mode (default): the HTTP call blocks", "#2dd4bf", x1=70, x2=880)
    y += 30
    msg(y, "reviewer", "gateway", "approve / deny with note: dashboard, MCP tool, CLI, REST (audit entry written)", "#fbbf24")
    y += 26
    y = note(y, "gateway", ["decide(): PENDING -> APPROVED or DENIED, hold resolved,", "ticket_events row, agent log, SSE update"], w=380)
    status(y - 24, "APPROVED", "ok")
    y += 26
    # timeout
    f5 = y
    y += 32
    msg(y, "gateway", "client", "504 {error: expired}   sweeper (5 s) or hold timeout after AIRT_APPROVAL_TIMEOUT_SECONDS; nothing sent upstream", "#f87171")
    status(y, "EXPIRED", "danger")
    y += 18
    frame(f5, y, "alt  no decision before the deadline", "#fb923c", x1=70, x2=1230)
    y += 26
    f6 = y
    y += 32
    msg(y, "gateway", "client", "403 {error: denied, decided_by}   nothing sent upstream", "#f87171")
    status(y, "DENIED", "danger")
    y += 18
    frame(f6, y, "alt  reviewer: deny", "#f87171", x1=70, x2=1230)
    y += 18
    frame(f2, y, "alt  policy: review (human needed)", "#fbbf24")
    y += 30

    # forwarding
    y = note(y, "gateway", ["forward_ticket(): mark FORWARDING (sync: immediately; async: on the first poll after approval)",
                            "inject canary AIRT-CANARY-<hex> into the system prompt when agent.inject_canary",
                            "swap in the agent's Fernet-decrypted upstream key, strip client credential headers"], w=560)
    status(y - 30, "FORWARDING", "warn")
    y += 26
    msg(y, "gateway", "upstream", "forward request with upstream credentials (shared httpx client, 120 s timeout)", "#a78bfa")
    y += 26
    msg(y, "upstream", "gateway", "200 JSON or SSE stream (relayed chunk by chunk, first 512 KB captured)", "#a78bfa")
    y += 26
    msg(y, "gateway", "analysis", "analyze_response(): system prompt leak, refusal, canary leak, PII, guardrail output scanners", "#2dd4bf")
    y += 26
    msg(y, "analysis", "gateway", "response findings", "#2dd4bf")
    y += 20
    f7 = y
    y += 32
    msg(y, "gateway", "client", "403 {error: response_withheld} + X-AIRT-Ticket   (policy.block_on_canary_leak, default on)", "#f87171")
    y += 18
    frame(f7, y, "alt  canary leaked in the model output", "#f87171", x1=70, x2=1230)
    y += 30
    msg(y, "gateway", "client", "upstream body + X-AIRT-Ticket header  (async: relayed on that poll, later polls return {status: COMPLETED, response})", "#4ade80")
    status(y, "COMPLETED", "ok")
    y += 26
    y = note(y, "gateway", ["mark_completed(): COMPLETED when upstream status < 500, otherwise FAILED (client gets 502);",
                            "network errors -> FAILED. Metrics, per-agent log and ticket timeline updated."], w=560, h=46)
    status(y - 24, "FAILED on 5xx / network error", "danger")

    s.legend(40, H - 52, [("line:#60a5fa", "client traffic"), ("line:#2dd4bf", "in-process gateway work"), ("line:#fbbf24", "human decision"),
                          ("line:#a78bfa", "upstream call"), ("line:#f87171", "blocked / error reply"), ("line:#4ade80", "relayed response")],
             cols=6, col_w=245, title="Arrows")
    s.save("request-lifecycle")


# ======================================================================================
# 3. Ticket state machine
# ======================================================================================
def ticket_state_machine() -> None:
    s = SVG(1500, 760, "Airt ticket state machine",
            "airt.models.TicketStatus and the transitions in airt/tickets/service.py. Only PENDING tickets can be decided (409 otherwise).")

    def state(cx: float, cy: float, name: str, sub: list[str], role: str, w: float = 190, h: float = 74) -> tuple[float, float, float, float]:
        fill, stroke = ROLE[role]
        s.rect(cx - w / 2, cy - h / 2, w, h, fill, stroke, r=16, sw=2)
        s.text(cx, cy - h / 2 + 26, name, 17, TEXT, "middle", weight="bold")
        s.lines(cx, cy - h / 2 + 44, sub, 11, "#d1d5db", "middle", lh=14)
        return (cx - w / 2, cy - h / 2, w, h)

    C_POLICY, C_HUMAN, C_TIME, C_UP, C_GW = "#2dd4bf", "#fbbf24", "#fb923c", "#a78bfa", "#cbd5e1"

    P = (330, 330)
    A = (720, 200)
    D = (720, 460)
    E = (330, 590)
    F = (1010, 200)
    C = (1330, 120)
    X = (1330, 300)

    # entry
    s.rect(60, P[1] - 20, 130, 40, PANEL, PANEL_STROKE, r=20)
    s.text(125, P[1] + 5, "request received", 12, TEXT, "middle")
    s.arrow([(190, P[1]), (P[0] - 95, P[1])], "ticket created", C_GW, label_dy=-8)

    state(*P, "PENDING", ["waiting for a decision", "expires_at = now + 300 s"], "warn")
    state(*A, "APPROVED", ["decided, not yet forwarded"], "ok")
    state(*D, "DENIED", ["client gets 403", "nothing sent upstream"], "danger")
    state(*E, "EXPIRED", ["client gets 504", "nothing sent upstream"], "danger")
    state(*F, "FORWARDING", ["request in flight upstream", "canary + credential swap done"], "upstream")
    state(*C, "COMPLETED", ["upstream status < 500", "response analysed, relayed"], "ok")
    state(*X, "FAILED", ["network error or status >= 500", "client gets 502"], "danger")

    # PENDING -> APPROVED (policy) and (reviewer)
    s.arrow([(P[0] + 95, P[1] - 20), (A[0] - 95, A[1] - 12)], "", C_POLICY)
    s.label(500, 214, ["policy: approve", "require_approval=false or", "risk < auto_approve_below_risk"], 11, "start")
    s.arrow([(P[0] + 95, P[1] + 2), (A[0] - 95, A[1] + 22)], "", C_HUMAN)
    s.label(590, 300, ["reviewer: approve", "dashboard / MCP / CLI"], 11, "start")

    # PENDING -> DENIED (policy) and (reviewer)
    s.arrow([(P[0] + 95, P[1] + 22), (D[0] - 95, D[1] - 20)], "", C_POLICY)
    s.label(432, 402, ["policy: deny", "path/model not allowed, deny regex,", "custom deny rule, risk >= auto_deny_at_risk"], 11, "start")
    s.arrow([(P[0] + 60, P[1] + 37), (D[0] - 95, D[1] + 18)], "", C_HUMAN)
    s.label(438, 492, ["reviewer: deny (with note)"], 11, "start")

    # PENDING -> EXPIRED
    s.arrow([(P[0], P[1] + 37), (E[0], E[1] - 37)], "", C_TIME)
    s.label(345, 470, ["timeout: background sweeper (every 5 s)", "or the hold wait reaching expires_at"], 11, "start")

    # APPROVED -> FORWARDING
    s.arrow([(A[0] + 95, A[1]), (F[0] - 95, F[1])], "", C_GW)
    s.label(865, 178, ["gateway: forward_ticket()", "sync: at once; async: first poll"], 11, "middle")

    # FORWARDING -> COMPLETED / FAILED
    s.arrow([(F[0] + 95, F[1] - 14), (C[0] - 95, C[1] + 6)], "", C_UP)
    s.label(1170, 130, ["upstream answered"], 11, "middle")
    s.arrow([(F[0] + 95, F[1] + 14), (X[0] - 95, X[1] - 6)], "", C_UP)
    s.label(1170, 288, ["upstream error / 5xx"], 11, "middle")

    # notes
    nx, ny = 900, 400
    s.rect(nx, ny, 560, 190, PANEL, PANEL_STROKE, r=12)
    s.text(nx + 16, ny + 26, "Invariants", 14, TEXT, weight="bold")
    s.lines(nx + 16, ny + 50, [
        "- decide() raises InvalidTransition (HTTP 409) unless the ticket is PENDING.",
        "- DENIED and EXPIRED tickets never reach the provider; APPROVED is the only path to FORWARDING.",
        "- Every transition writes a ticket_events row, a per-agent log line and an SSE event;",
        "  human decisions also append a hash-chained audit entry.",
        "- hold_registry.resolve() wakes a blocked sync request in-process; other processes see the",
        "  new status on their next DB poll (AIRT_HOLD_POLL_INTERVAL_SECONDS).",
        "- Async clients poll /gateway/tickets/{id}: 202 PENDING, 403 DENIED / EXPIRED, 502 FAILED,",
        "  200 {status: COMPLETED, response} once relayed.",
        "- Red-team probes are ordinary tickets (source=redteam) and follow the same machine.",
    ], 11.5, "#d1d5db", lh=15)

    s.legend(32, 690, [("line:" + C_POLICY, "policy engine"), ("line:" + C_HUMAN, "human reviewer"), ("line:" + C_TIME, "timeout sweeper / hold deadline"),
                       ("line:" + C_GW, "gateway"), ("line:" + C_UP, "upstream result")], cols=5, col_w=250, title="Who triggers the transition")
    s.save("ticket-state-machine")


# ======================================================================================
# 4. Red-team flow
# ======================================================================================
def redteam_flow() -> None:
    s = SVG(1700, 980, "Airt red-team campaign flow",
            "Every probe is a reviewable ticket through the same gateway pipeline; external scanners join through short-lived scan tokens.")

    # row 1: campaign creation
    s.panel(32, 90, 1636, 250, "1. Campaign creation", "airt redteam run / POST /api/redteam/campaigns / MCP create_campaign / dashboard /redteam", accent="#fb923c")
    bx, by, bw, bh = 48, 150, 300, 170
    s.box(bx, by, bw, bh, "Probe corpus (YAML, 300+ probes)",
          ["16 categories: prompt_injection, jailbreak,", "system_prompt_extraction, data_exfiltration,", "pii_leakage, tool_abuse, harmful_content,",
           "encoding_attacks, multi_turn, many_shot,", "misinformation_hallucination, bias_fairness,", "privacy_memorization, code_safety,", "denial_of_wallet, benign_control"],
          "warn", body_size=11)
    s.box(bx + 320, by, 280, bh, "Selection",
          ["filter by category, technique,", "severity; sampling with --seed;", "--max-probes; system prompt;", "target path (/v1/chat/completions)", "and target model"],
          "warn", body_size=11)
    s.box(bx + 620, by, 280, bh, "Mutators",
          ["base64, rot13, leetspeak,", "reverse, split, suffix", "", "each probe x mutator becomes", "one probe_result row (PENDING)"],
          "warn", body_size=11)
    s.box(bx + 920, by, 340, bh, "Comparison group: N targets in parallel",
          ["one campaign per target (agent, model,", "system prompt), same probe set and seed;", "start_group() runs them concurrently;",
           "AIRT_REDTEAM_CONCURRENCY probes in flight", "per campaign, campaign state:", "CREATED RUNNING PAUSED COMPLETED FAILED CANCELLED"],
          "warn", body_size=11)
    s.box(bx + 1280, by, 328, bh, "Materialized campaign",
          ["campaigns row + probe_results rows", "config: categories, mutators, seed,", "target, concurrency; SSE progress on", "/api/stream/campaigns; pause / resume /", "cancel at any time"],
          "store", body_size=11)
    for i, x0 in enumerate([bx + bw, bx + 600, bx + 900, bx + 1260]):
        s.arrow([(x0, by + bh / 2), (x0 + 20, by + bh / 2)], "", "#fb923c")

    # row 2: pipeline through the gateway
    s.panel(32, 370, 1636, 230, "2. Probes through the human-in-the-loop pipeline", "airt.gateway.pipeline.submit(source=redteam, campaign_id, probe_id): identical to an HTTP call", accent="#2dd4bf")
    py = 428
    cols = [
        ("pipeline.submit()", ["build provider body from", "probe messages + mutator,", "normalize, create ticket", "PENDING with campaign_id", "and probe_id"], "gateway"),
        ("Analyzers + policy", ["same 10 request analyzers", "and guardrail integrations;", "agent policy may auto-deny", "(verdict BLOCKED) or", "auto-approve"], "gateway"),
        ("Human approval", ["ticket held for a reviewer", "(dashboard / MCP / CLI);", "auto-runs when", "AIRT_REQUIRE_APPROVAL_FOR_", "REDTEAM_PROBES=false"], "human"),
        ("Target model", ["forwarder swaps in the", "upstream key, canary", "injected in the system", "prompt, per-probe timeout", "AIRT_REDTEAM_PROBE_TIMEOUT"], "upstream"),
        ("Evaluators", ["refusal detector,", "canary leak (strongest),", "success_indicators regexes,", "harmful / guardrail findings,", "optional LLM judge"], "gateway"),
        ("Verdicts", ["VULNERABLE  RESISTED", "BLOCKED  ERROR", "INCONCLUSIVE", "+ confidence + evidence", "+ ticket_id, latency_ms"], "ok"),
    ]
    cw, ch = 250, 140
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
    s.label(860, 359, "start(): one submit() per probe entry, AIRT_REDTEAM_CONCURRENCY at a time", 11)

    # row 3: summary and reports + external engines
    s.panel(32, 630, 1010, 262, "3. Summary and reports", "engine.build_summary(), compare_group(), airt/reports builders + renderers", accent="#4ade80")
    s.box(48, 688, 300, 136, "Campaign summary",
          ["by_verdict totals, vulnerability rate,", "per-category and per-technique rates,", "per-severity breakdown, benign over-refusal", "rate, OWASP LLM Top 10 coverage", "(taxonomy.coverage), duration"],
          "ok", body_size=11)
    s.box(368, 688, 300, 136, "Comparison matrix",
          ["category x target: vulnerable / tested /", "rate; per-probe verdict rows across", "targets; ranking by vulnerability rate;", "verdict totals per campaign"],
          "ok", body_size=11)
    s.box(688, 688, 338, 136, "Reports (12 formats)",
          ["/api/reports/campaign/{id}?format=...", "json yaml csv tsv md html pdf xlsx txt xml", "sarif (code scanning) junit (CI gating);", "airt report campaign/ID -f sarif -o out.sarif;", "MCP generate_report"],
          "store", body_size=11)
    s.arrow([(348, 756), (368, 756)], "", "#4ade80")
    s.arrow([(668, 756), (688, 756)], "", "#4ade80")
    s.arrow([(48 + 5 * (cw + 22) + cw / 2, py + ch), (48 + 5 * (cw + 22) + cw / 2, 615), (198, 615), (198, 630)], "verdicts aggregated", "#4ade80", label_pos=0.5)

    s.panel(1070, 630, 598, 262, "External engines through the same gateway", "short-lived scan tokens (scn_, TTL, revocable, bound to a campaign) let a scanner act as the agent", accent="#a78bfa")
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
    s.lines(1086, 876, ["Scanner base_url -> gw /v1 or /proxy + token: every request is a ticket (source=redteam, campaign_id),",
                        "analysed, policy-checked, human-approved and response-scanned; findings share the taxonomy in reports."], 11, MUTED, lh=14)
    s.arrow([(1370, 630), (1370, 600)], "scan token traffic enters the pipeline in row 2", "#a78bfa", label_dy=-12, label_pos=1.0)

    s.legend(32, 916, [("warn", "campaign setup"), ("gateway", "gateway pipeline"), ("human", "human decision"), ("upstream", "target / external engine"),
                       ("ok", "results"), ("store", "persistence / reports")], cols=6, col_w=170, title="Legend")
    s.save("redteam-flow")


# ======================================================================================
# 5. Deployment topology
# ======================================================================================
def deployment() -> None:
    s = SVG(1600, 860, "Airt deployment topology",
            "docker compose up -d (SQLite volume) or docker compose --profile postgres up -d; TLS terminates in a reverse proxy in front of the gateway.")

    # left: actors
    s.panel(32, 92, 300, 500, "Actors", "outside the compose network")
    s.box(48, 150, 268, 70, "Applications and agents", ["SDK base_url, /proxy, mitmproxy", "X-AIRT-Key, sync or async"], "client", body_size=11)
    s.box(48, 236, 268, 70, "Reviewers (browser)", ["dashboard, SSE live queues", "signed HttpOnly session cookie"], "human", body_size=11)
    s.box(48, 322, 268, 70, "MCP clients over HTTP", ["Claude Desktop / Claude Code", "POST /mcp + Bearer admin token"], "human", body_size=11)
    s.box(48, 408, 268, 86, "MCP clients over stdio", ["`airt mcp --url https://gw --token ...`", "runs beside the client and calls", "the REST API (separate process)"], "human", body_size=11)
    s.box(48, 510, 268, 66, "CLI and CI", ["airt tickets / report / audit verify", "AIRT_URL + AIRT_ADMIN_API_TOKEN"], "human", body_size=11)

    # reverse proxy
    s.box(390, 250, 220, 150, "Reverse proxy (TLS)", ["nginx / Caddy / Traefik", "TLS termination", "proxy_read_timeout > 300 s", "no buffering for SSE", "and streamed relays", "forwards X-Request-ID"], "neutral", body_size=11)
    for yy in (185, 271, 357, 543):
        s.arrow([(316, yy), (390, 325)], "", "#94a3b8")
    s.arrow([(316, 451), (390, 325)], "", "#94a3b8")
    s.text(325, 240, "HTTPS", 11, MUTED)

    # compose network
    s.panel(660, 92, 620, 620, "docker compose network", "image airt:latest, multi-stage python:3.12-slim, non-root user, HEALTHCHECK GET /healthz", accent="#2dd4bf")
    s.box(680, 150, 580, 250, "airt-gateway container  (127.0.0.1:8080 -> 8080)",
          ["uvicorn, AIRT_WORKERS=1 (default): one process serves gateway /v1 /proxy /gateway/tickets,",
           "reviewer API /api/*, dashboard, MCP /mcp, /metrics, /healthz, /readyz",
           "",
           "in-process state:  hold registry (asyncio.Event per waiting ticket)  |  rate limiter  |",
           "SSE broadcaster  |  metrics  |  background sweeper (expire PENDING every 5 s, purge old tickets)",
           "",
           "env: .env + AIRT_* (AIRT_DATABASE_URL, AIRT_SECRET_KEY / AIRT_ENCRYPTION_KEY, AIRT_ADMIN_API_TOKEN,",
           "AIRT_NOTIFY_WEBHOOK_URLS, AIRT_APPROVAL_TIMEOUT_SECONDS, AIRT_HOLD_POLL_INTERVAL_SECONDS)"],
          "gateway", body_size=11)
    s.arrow([(610, 325), (680, 325)], "HTTP :8080", "#94a3b8", label_dy=-8)

    s.box(680, 430, 270, 92, "volume airt-data -> /app/data", ["airt.db (SQLite, default)", "Fernet-encrypted upstream keys live", "in the agents table, never on disk in clear"], "store", body_size=10.5)
    s.box(990, 430, 270, 92, "volume airt-logs -> /app/logs", ["airt.jsonl (50 MB x 10)", "agents/<agent_id>.jsonl (20 MB x 5)", "JSON console output too"], "store", body_size=10.5)
    s.arrow([(815, 400), (815, 430)], "", "#9ca3af")
    s.arrow([(1125, 400), (1125, 430)], "", "#9ca3af")

    s.box(680, 560, 580, 130, "airt-postgres container  (profile: postgres, optional)",
          ["postgres:16-alpine, volume airt-pgdata -> /var/lib/postgresql/data, pg_isready healthcheck",
           "AIRT_DATABASE_URL=postgresql+asyncpg://airt:airt@postgres:5432/airt  (pip install \"airt[postgres]\")",
           "gateway depends_on postgres with required: false; without the profile the gateway uses SQLite"],
          "store", body_size=11)
    s.arrow([(815, 522), (815, 560)], "or", "#9ca3af", dash="5 4", label_dx=14, label_anchor="start", label_dy=4)

    # right: outbound
    s.panel(1320, 92, 248, 620, "Outbound", "egress from the gateway only")
    s.box(1336, 150, 216, 120, "Upstream providers", ["OpenAI, Anthropic, Gemini,", "Mistral, Groq, Ollama,", "custom HTTP APIs", "credentials injected by", "the gateway"], "upstream", body_size=11)
    s.box(1336, 300, 216, 96, "Webhooks", ["Slack or generic JSON", "on ticket created /", "expired / failed", "(AIRT_NOTIFY_*)"], "human", body_size=11)
    s.box(1336, 426, 216, 96, "LLM judge / guardrail APIs", ["optional: AIRT_JUDGE_*,", "Lakera Guard endpoint,", "LLM Guard / NeMo local"], "upstream", body_size=11)
    s.box(1336, 552, 216, 96, "Prometheus / SIEM", ["scrape /metrics,", "ship logs/*.jsonl,", "verify audit chain"], "store", body_size=11)
    s.arrow([(1260, 210), (1336, 210)], "", "#a78bfa")
    s.arrow([(1260, 348), (1336, 348)], "", "#fbbf24")
    s.arrow([(1260, 474), (1336, 474)], "", "#a78bfa")
    s.arrow([(1336, 600), (1260, 600)], "", "#9ca3af", dash="5 4")

    # note
    s.rect(390, 430, 250, 282, PANEL, "#fb923c", r=12)
    s.text(406, 456, "Hold registry note", 14, TEXT, weight="bold")
    s.lines(406, 480, wrap(
        "A synchronous request blocks on an asyncio.Event inside the gateway process. A decision taken in the same process "
        "(dashboard, /mcp, REST) wakes it instantly: the fast path. A decision written by another process (a second uvicorn "
        "worker, the stdio MCP host, a direct DB write) is noticed on the next DB poll, every AIRT_HOLD_POLL_INTERVAL_SECONDS "
        "(1 s). Keep AIRT_WORKERS=1 and scale by adding gateways per agent group until the Redis / LISTEN-NOTIFY registry lands.",
        11.5, 220), 11.5, "#d1d5db", lh=15)

    s.legend(32, 760, [("client", "application traffic"), ("human", "reviewer / operator surface"), ("gateway", "Airt container"),
                       ("store", "storage / data"), ("upstream", "external API"), ("neutral", "infrastructure")], cols=6, col_w=230, title="Legend")
    s.text(32, 830, "Single container alternative: docker run -d -p 127.0.0.1:8080:8080 --env-file .env -v airt-data:/app/data -v airt-logs:/app/logs airt", 11.5, MUTED)
    s.save("deployment")


# ======================================================================================
# 6. Taxonomy matrix (generated from airt.taxonomy)
# ======================================================================================
def taxonomy() -> None:
    from airt import taxonomy as tx

    owasp = list(tx.OWASP_LLM_TOP10.keys())
    greshake = list(tx.GRESHAKE_THREATS.keys()) + ["hidden"]  # "hidden" is a Greshake delivery method used by obfuscation categories
    thacker = list(tx.THACKER_TECHNIQUES.keys())
    cats = list(tx.CATEGORY_MAP.keys())
    mapped = [c for c in cats if any(tx.CATEGORY_MAP[c].values())]
    unmapped = [c for c in cats if not any(tx.CATEGORY_MAP[c].values())]

    label_w = 250
    cell = 52
    row_h = 24
    header_h = 150
    left, top = 32, 92
    cols = [("owasp", o) for o in owasp] + [("greshake", g) for g in greshake] + [("thacker", t) for t in thacker]
    W = left + label_w + len(cols) * cell + 40 + 12
    grid_top = top + header_h
    H = grid_top + len(mapped) * row_h + 40 + 140

    s = SVG(int(W), int(H), "Airt taxonomy matrix",
            "airt.taxonomy.CATEGORY_MAP: finding and probe categories mapped to OWASP LLM Top 10 (2025), Greshake et al. threat classes and Thacker technique classes.")

    group_color = {"owasp": "#2dd4bf", "greshake": "#fbbf24", "thacker": "#a78bfa"}
    group_label = {"owasp": "OWASP LLM Top 10 (2025)", "greshake": "Greshake et al. threats (+ hidden delivery)", "thacker": "Thacker technique classes"}
    group_desc = {"owasp": tx.OWASP_LLM_TOP10, "greshake": {**tx.GRESHAKE_THREATS, "hidden": tx.GRESHAKE_DELIVERY["hidden"]}, "thacker": tx.THACKER_TECHNIQUES}

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
        s.path(f"M {x + i * cell} {grid_top} L {x + i * cell} {grid_top + len(mapped) * row_h}", "#233047", 1, arrow=False)
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
    s.text(left + 800, fy, "Greshake: " + ", ".join(tx.GRESHAKE_THREATS) + "; hidden = concealed delivery (white text, encodings, multi-stage payloads).", 11.5, "#d1d5db")
    s.text(left + 800, fy + 16, "Thacker: " + ", ".join(t.replace("_", " ") for t in thacker) + ".", 11.5, "#d1d5db")
    s.text(left + 800, fy + 32, "Control / meta categories with no mapping: " + ", ".join(unmapped) + ".", 11.5, "#d1d5db")
    s.text(left + 800, fy + 48, "Findings carry owasp / greshake / thacker fields (taxonomy.enrich); campaign summaries report OWASP coverage.", 11.5, "#d1d5db")
    s.text(left, fy + 96, "Regenerate with docs/images/generate_diagrams.py after editing airt/taxonomy.py; this diagram is built from CATEGORY_MAP at generation time.", 11, MUTED)
    s.save("taxonomy")


if __name__ == "__main__":
    architecture()
    request_lifecycle()
    ticket_state_machine()
    redteam_flow()
    deployment()
    taxonomy()
