"""Code review module: intake safety, rule packs, engines, persistence, API, reports, dashboard and MCP."""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
import subprocess
import zipfile
from pathlib import Path

import pytest

from aisrf.codereview import intake
from aisrf.codereview.findings import Finding, dedupe, risk_score
from aisrf.codereview.intake import IntakeError
from aisrf.codereview.rules import ALL_RULES, PACKS, RULES_BY_ID
from aisrf.codereview.secrets import mask_secrets, redact_url

# --- fixture repository ------------------------------------------------------------------------
FILES: dict[str, str] = {
    "app/chat.py": '''
import logging
from flask import Flask, request, jsonify, render_template_string
from openai import OpenAI

app = Flask(__name__)
client = OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH")
logger = logging.getLogger(__name__)
SYSTEM = "You are a support assistant for Acme."


@app.route("/chat", methods=["POST"])
def chat():
    question = request.json["question"]
    prompt = f"You are a helpful assistant. Answer the question: {question}"
    messages = [{"role": "system", "content": f"{SYSTEM} Customer id: {request.args.get('cid')}"}, {"role": "user", "content": prompt}]
    logger.info("prompt=%s", prompt)
    response = client.chat.completions.create(model="gpt-4o", messages=messages)
    answer = response.choices[0].message.content
    return render_template_string("<div>" + answer + "</div>")


@app.route("/raw", methods=["POST"])
def raw():
    body = request.get_json()
    response = client.chat.completions.create(model="gpt-4o", messages=body["messages"])
    return jsonify({"answer": response.choices[0].message.content})
''',
    "agent/tools.py": '''
import subprocess
from langchain.tools import tool
from langchain.agents import AgentExecutor


@tool
def run_diagnostic(hostname: str) -> str:
    """Ping a host chosen by the model."""
    result = subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))


@tool
def issue_refund(order_id: str, amount: float) -> str:
    """Refund an order."""
    return payments.refund(order_id, amount)


@tool
def write_note(path: str, content: str) -> str:
    """Write a note to disk."""
    open(path, "w").write(content)
    return "ok"


def agent_loop(llm, messages, tools):
    while True:
        response = llm.chat(messages, tools=tools)
        if not response.tool_calls:
            return response.content
        for call in response.tool_calls:
            fn = globals()[call.name]
            messages.append({"role": "tool", "content": fn(**call.arguments)})
''',
    "web/render.js": '''
import { marked } from "marked";
import OpenAI from "openai";

const client = new OpenAI();

export async function askAssistant(question) {
  const completion = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: question }] });
  const answer = completion.choices[0].message.content;
  document.getElementById("chat-answer").innerHTML = answer;
  document.getElementById("chat-md").innerHTML = marked(answer);
  return answer;
}
''',
    "ml/loader.py": '''
import torch
import requests
from transformers import AutoModelForCausalLM, AutoTokenizer


def fetch_and_load(url):
    download = requests.get(url).content
    path = "/tmp/model.pt"
    open(path, "wb").write(download)
    return torch.load(path)


tokenizer = AutoTokenizer.from_pretrained("acme/support-tokenizer")
model = AutoModelForCausalLM.from_pretrained("acme/support-model", trust_remote_code=True)
''',
    "rag/retrieval.py": '''
import logging
from flask import request
from langchain_community.vectorstores import Chroma

logger = logging.getLogger("rag")
store = Chroma(collection_name="docs")


def answer(llm):
    question = request.json["question"]
    where = request.json.get("filter")
    docs = store.similarity_search(question, k=5, filter=where)
    context = "\\n".join(d.page_content for d in docs)
    prompt = f"Answer the question using the context. Context: {context} Question: {question}"
    logger.info("full prompt: %s", prompt)
    return llm.invoke(prompt)
''',
    "web/Answer.jsx": '''
import React from "react";
import ReactMarkdown from "react-markdown";

export function Answer({ response }) {
  return <ReactMarkdown>{response.answer}</ReactMarkdown>;
}
''',
    "requirements.txt": "flask\nopenai>=1.0\ntorch\ntransformers==4.44.0\nlangchain\n",
    "Dockerfile": 'FROM python:latest\nRUN pip install torch transformers\nCOPY . /app\nCMD ["python", "/app/app/chat.py"]\n',
    ".env": "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH\nDATABASE_URL=postgres://user:pass@db/app\n",
    "clean/service.py": '''
"""Clean control: no model calls, no secrets, parameterised SQL."""
import os
import sqlite3


def get_user(conn: sqlite3.Connection, user_id: int) -> tuple:
    cur = conn.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def config() -> dict:
    return {"debug": False, "region": os.environ.get("REGION", "eu")}
''',
    "clean/util.js": '''
export function formatName(first, last) {
  const node = document.getElementById("name");
  node.textContent = first + " " + last;
  return node.textContent;
}
''',
    "README.md": "# Fixture\n\nA small LLM application used by the AISRF code review tests.\n",
}
EXPECTED_RULES = {
    "AISRF-PI-001": "app/chat.py",
    "AISRF-PI-003": "app/chat.py",
    "AISRF-PI-012": "app/chat.py",
    "AISRF-AT-001": "agent/tools.py",
    "AISRF-AT-002": "agent/tools.py",
    "AISRF-AT-010": "agent/tools.py",
    "AISRF-LO-002": "web/render.js",
    "AISRF-LO-003": "web/render.js",
    "AISRF-MS-001": "ml/loader.py",
    "AISRF-MS-003": "ml/loader.py",
    "AISRF-MS-004": "ml/loader.py",
    "AISRF-RG-003": "rag/retrieval.py",
    "AISRF-RG-007": "rag/retrieval.py",
    "AISRF-RG-006": "web/Answer.jsx",
    "AISRF-GN-001": "app/chat.py",
    "AISRF-MS-019": "Dockerfile",
}
HEADERS_ADMIN = {"Authorization": "Bearer test-admin-token"}


def write_tree(root: Path) -> None:
    for rel, content in FILES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content.lstrip("\n"), encoding="utf-8")


def make_zip(root: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                zf.write(path, f"fixture-main/{path.relative_to(root).as_posix()}")
    return buf.getvalue()


@pytest.fixture(scope="module")
def fixture_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("fixture-repo")
    write_tree(root)
    return root


@pytest.fixture(scope="module")
def fixture_zip(fixture_root: Path) -> bytes:
    return make_zip(fixture_root)


async def wait_for_run(client, run_id: str, timeout: float = 120) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        r = await client.get(f"/api/codereview/runs/{run_id}", headers=HEADERS_ADMIN)
        assert r.status_code == 200, r.text
        run = r.json()
        if run["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            return run
        assert asyncio.get_running_loop().time() < deadline, f"run did not finish: {run['status']} {run.get('stage')}"
        await asyncio.sleep(0.2)


# --- unit level ------------------------------------------------------------------------------
def test_catalogue_is_consistent() -> None:
    assert len(PACKS) == 6 and len(ALL_RULES) >= 90
    ids = [r.id for r in ALL_RULES]
    assert len(ids) == len(set(ids))
    for r in ALL_RULES:
        assert re.match(r"^AISRF-(PI|AT|LO|MS|RG|GN)-\d{3}$", r.id), r.id
        assert r.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert r.owasp, f"{r.id} has no OWASP mapping"
        assert r.cwe.startswith("CWE-")
        assert r.remediation and r.description and r.why
    assert RULES_BY_ID["AISRF-MS-001"].owasp == ["LLM03"]


def test_secret_masking_and_url_redaction() -> None:
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH" not in mask_secrets('key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"')
    assert mask_secrets("ghp_" + "a" * 40) == "ghp_...[masked]"
    assert redact_url("https://x-access-token:ghp_secret@github.com/org/repo.git") == "https://github.com/org/repo.git"
    f = Finding("AISRF-GN-001", "general", "rules", "CRITICAL", 0.9, "t", "d", "r", "a.py", 1, 1, 'api_key = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"')
    assert "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ12345" not in f.snippet and f.fingerprint


def test_dedupe_and_risk_score() -> None:
    a = Finding("AISRF-MS-001", "model_supply_chain", "rules", "CRITICAL", 0.7, "t", "d", "r", "m.py", 3, 3, "torch.load(p)", cwe="CWE-502")
    b = Finding("AISRF-MS-001", "model_supply_chain", "semgrep", "CRITICAL", 0.85, "t", "d", "r", "m.py", 3, 3, "torch.load(p)", cwe="CWE-502")
    c = Finding("BANDIT-B614", "general", "bandit", "MEDIUM", 0.6, "t", "d", "r", "m.py", 3, 3, "torch.load(p)", cwe="CWE-502")
    unique = dedupe([a, b, c])
    assert len(unique) == 1 and unique[0].confidence == 0.85 and set(unique[0].metadata["engines"]) == {"rules", "semgrep", "bandit"}
    assert risk_score([]) == 0
    assert risk_score([a]) >= 60 and risk_score([a, a, a]) <= 100
    assert risk_score([{"severity": "LOW", "confidence": 0.5, "status": "false_positive"}]) == 0


def test_zip_slip_and_links_are_rejected(tmp_path: Path) -> None:
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../escape.py", "print('x')")
    with pytest.raises(IntakeError, match="unsafe archive member"):
        intake.inspect_archive(evil)
    absolute = tmp_path / "abs.zip"
    with zipfile.ZipFile(absolute, "w") as zf:
        zf.writestr("/etc/passwd", "x")
    with pytest.raises(IntakeError):
        intake.inspect_archive(absolute)
    huge = tmp_path / "huge.zip"
    with zipfile.ZipFile(huge, "w") as zf:
        zf.writestr("big.txt", "a" * 2048)
    with pytest.raises(IntakeError, match="beyond"):
        intake.inspect_archive(huge, {"max_archive_bytes": 1024, "max_files": 100})


def test_local_path_allowlist(tmp_path: Path) -> None:
    with pytest.raises(IntakeError, match="outside the allowed"):
        intake.check_local_path("/etc")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    assert intake.check_local_path(str(allowed), {"path_allowlist": [str(tmp_path)]}) == allowed.resolve()
    with pytest.raises(IntakeError, match="does not exist"):
        intake.check_local_path(str(tmp_path / "missing"), {"path_allowlist": [str(tmp_path)]})


# --- full pipeline through the API -------------------------------------------------------------------
async def test_upload_run_end_to_end(client, admin_headers, fixture_zip: bytes, tmp_path: Path) -> None:
    catalogue = (await client.get("/api/codereview/rules", headers=admin_headers)).json()
    assert catalogue["total"] == len(ALL_RULES) and {p["name"] for p in catalogue["packs"]} == set(PACKS)
    assert all(r["owasp_labels"] for p in catalogue["packs"] for r in p["rules"])

    options = {"engines": ["rules", "semgrep", "bandit"]}
    r = await client.post("/api/codereview/runs/upload", headers=admin_headers, files={"file": ("fixture.zip", fixture_zip, "application/zip")}, data={"name": "fixture run", "options": json.dumps(options)})
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    run = await wait_for_run(client, run_id)
    assert run["status"] == "COMPLETED", run.get("error")
    assert run["source_type"] == "zip" and run["source_ref"] == "fixture.zip"
    assert run["file_count"] >= 10 and run["loc"] > 50
    inv = run["inventory"]
    frameworks = {f["name"] for f in inv["frameworks"]}
    assert {"openai", "langchain", "torch", "transformers"} <= frameworks
    assert inv["languages"]["python"]["files"] >= 4 and any(m["kind"] == "pip" for m in inv["manifests"])
    assert inv["dockerfiles"] == ["Dockerfile"] and ".env" in inv["secret_files"] and inv["tool_calling"]["detected"]
    summary = run["summary"]
    assert summary["risk_score"] >= 80 and summary["risk_level"] in ("HIGH", "CRITICAL")
    engines = summary["engines"]
    assert engines["rules"]["findings"] > 20
    if engines["semgrep"]["available"]:
        assert engines["semgrep"]["findings"] > 0 and engines["semgrep"]["seconds"] < 60, engines["semgrep"]
    if engines["bandit"]["available"]:
        assert engines["bandit"]["findings"] > 0, engines["bandit"]
    if not (engines["semgrep"]["available"] and engines["bandit"]["available"]):
        import warnings

        warnings.warn("semgrep or bandit not installed; external engines not exercised", stacklevel=1)
    assert set(summary["by_pack"]) == set(PACKS)

    listing = (await client.get(f"/api/codereview/runs/{run_id}/findings?limit=2000", headers=admin_headers)).json()
    findings = listing["items"]
    assert listing["total"] == run["finding_count"] == len(findings)
    seen = {(f["rule_id"], f["file"]) for f in findings}
    for rule_id, path in EXPECTED_RULES.items():
        assert (rule_id, path) in seen, f"{rule_id} not reported on {path}"
    assert not [f for f in findings if f["file"].startswith("clean/")], "clean control files must stay clean"
    assert {f["engine"] for f in findings} >= {"rules", "semgrep", "bandit"}
    assert any(f["rule_id"].startswith("BANDIT-") for f in findings)
    key_findings = [f for f in findings if f["rule_id"] == "AISRF-GN-001"]
    assert key_findings and all("abcdefghijklmnopqrstuvwxyz0123456789" not in f["snippet"] for f in key_findings)
    for f in findings:
        assert f["owasp"] and f["owasp_labels"] and f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    # filters
    high = (await client.get(f"/api/codereview/runs/{run_id}/findings?severity=CRITICAL,HIGH", headers=admin_headers)).json()["items"]
    assert high and all(f["severity"] in ("CRITICAL", "HIGH") for f in high)
    ms = (await client.get(f"/api/codereview/runs/{run_id}/findings?pack=model_supply_chain&engine=rules", headers=admin_headers)).json()["items"]
    assert ms and all(f["pack"] == "model_supply_chain" and f["engine"] == "rules" for f in ms)
    by_file = (await client.get(f"/api/codereview/runs/{run_id}/findings?file=ml/loader.py", headers=admin_headers)).json()["items"]
    assert by_file and all(f["file"] == "ml/loader.py" for f in by_file)
    searched = (await client.get(f"/api/codereview/runs/{run_id}/findings?search=trust_remote", headers=admin_headers)).json()["items"]
    assert any(f["rule_id"] == "AISRF-MS-003" for f in searched)

    # status update recomputes the summary
    target = next(f for f in findings if f["rule_id"] == "AISRF-MS-003")
    bad = await client.post(f"/api/codereview/findings/{target['id']}/status", headers=admin_headers, json={"status": "nope"})
    assert bad.status_code == 400
    r = await client.post(f"/api/codereview/findings/{target['id']}/status", headers=admin_headers, json={"status": "false_positive", "note": "vendored model"})
    assert r.status_code == 200 and r.json()["status"] == "false_positive" and r.json()["reviewer_note"] == "vendored model"
    fp = (await client.get(f"/api/codereview/runs/{run_id}/findings?status=false_positive", headers=admin_headers)).json()
    assert fp["total"] == 1 and fp["items"][0]["id"] == target["id"]
    refreshed = (await client.get(f"/api/codereview/runs/{run_id}", headers=admin_headers)).json()
    assert refreshed["summary"]["by_status"]["false_positive"] == 1 and refreshed["summary"]["open"] == summary["open"] - 1

    # file viewer
    doc = (await client.get(f"/api/codereview/runs/{run_id}/file?path=ml/loader.py", headers=admin_headers)).json()
    assert "torch.load" in doc["content"] and doc["language"] == "python" and any(f["rule_id"] == "AISRF-MS-001" for f in doc["findings"])
    assert (await client.get(f"/api/codereview/runs/{run_id}/file?path=../../etc/passwd", headers=admin_headers)).status_code == 404
    assert (await client.get(f"/api/codereview/runs/{run_id}/file?path=/etc/passwd", headers=admin_headers)).status_code == 404

    # SARIF
    sarif_resp = await client.get(f"/api/codereview/runs/{run_id}/sarif", headers=admin_headers)
    assert sarif_resp.status_code == 200 and sarif_resp.headers["content-type"].startswith("application/sarif+json")
    sarif = sarif_resp.json()
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["rules"] and all(rule["id"] and rule["shortDescription"]["text"] for rule in driver["rules"])
    results = sarif["runs"][0]["results"]
    assert results and len(results) == refreshed["summary"]["open"]
    for res in results:
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["aisrf/v1"] and res["ruleIndex"] < len(driver["rules"])
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
    with_dismissed = (await client.get(f"/api/codereview/runs/{run_id}/sarif?include_dismissed=true", headers=admin_headers)).json()
    assert len(with_dismissed["runs"][0]["results"]) == len(results) + 1

    # reports in json, html and pdf plus sarif through the reports router
    for fmt, prefix in (("json", "application/json"), ("html", "text/html"), ("pdf", "application/pdf"), ("sarif", "application/sarif+json"), ("md", "text/markdown")):
        rep = await client.get(f"/api/reports/codereview/{run_id}?format={fmt}", headers=admin_headers)
        assert rep.status_code == 200, (fmt, rep.text[:200])
        assert rep.headers["content-type"].startswith(prefix), (fmt, rep.headers["content-type"])
        assert len(rep.content) > 200
    html = (await client.get(f"/api/reports/codereview/{run_id}?format=html", headers=admin_headers)).text
    assert "AISRF-MS-001" in html and "fixture run" in html
    assert (await client.get(f"/api/reports/codereview/{run_id}?format=pdf", headers=admin_headers)).content.startswith(b"%PDF")

    # dashboard pages
    page = await client.get("/codereview", headers=admin_headers)
    assert page.status_code == 200 and 'id="run-rows"' in page.text and "/static/codereview.js" in page.text
    page = await client.get(f"/codereview/{run_id}", headers=admin_headers)
    assert page.status_code == 200 and f'data-run-id="{run_id}"' in page.text and "/static/codereview_run.js" in page.text
    anonymous = await client.get("/codereview", follow_redirects=False)
    assert anonymous.status_code == 303 and "/login" in anonymous.headers["location"]

    # live stream on channel "codereview": the generator replays the run events (ASGITransport cannot stream an endless response)
    from aisrf.codereview.router import _stream
    from aisrf.logging import broadcaster

    recent = [e for e in broadcaster.recent("codereview", 500) if e.get("run_id") == run_id]
    assert [e["event"] for e in recent][:2] == ["run.status", "run.status"] and recent[-1]["event"] == "finding.status"
    assert any(e["event"] == "run.progress" and e.get("stage") == "semgrep" for e in recent)

    class _Req:
        async def is_disconnected(self) -> bool:
            return False

    gen = _stream(_Req(), 500, run_id)
    streamed = []
    try:
        while len(streamed) < 3:
            streamed.append(await asyncio.wait_for(gen.__anext__(), timeout=5))
    finally:
        await gen.aclose()
    assert streamed[0]["event"] == "run.status" and json.loads(streamed[0]["data"])["run_id"] == run_id
    assert all(json.loads(e["data"])["run_id"] == run_id for e in streamed)

    # cancelling a finished run is a conflict, listing and deletion work
    assert (await client.post(f"/api/codereview/runs/{run_id}/cancel", headers=admin_headers)).status_code == 409
    runs = (await client.get("/api/codereview/runs?status=COMPLETED", headers=admin_headers)).json()
    assert any(item["id"] == run_id for item in runs["items"])
    work_dir = Path(refreshed["config"].get("work_dir", "")) if refreshed["config"].get("work_dir") else None
    r = await client.delete(f"/api/codereview/runs/{run_id}", headers=admin_headers)
    assert r.status_code == 200 and r.json()["deleted"] == run_id
    assert (await client.get(f"/api/codereview/runs/{run_id}", headers=admin_headers)).status_code == 404
    assert (await client.get(f"/api/codereview/runs/{run_id}/findings", headers=admin_headers)).status_code == 404
    if work_dir:
        assert not work_dir.exists()


async def test_upload_rejects_zip_slip_and_bad_options(client, admin_headers) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.py", "import os\n")
    r = await client.post("/api/codereview/runs/upload", headers=admin_headers, files={"file": ("evil.zip", buf.getvalue(), "application/zip")}, data={"options": "{}"})
    assert r.status_code == 400 and "unsafe archive member" in r.text
    r = await client.post("/api/codereview/runs/upload", headers=admin_headers, files={"file": ("x.zip", b"not a zip", "application/zip")}, data={"options": "{}"})
    assert r.status_code == 400
    r = await client.post("/api/codereview/runs/upload", headers=admin_headers, files={"file": ("x.zip", b"PK", "application/zip")}, data={"options": json.dumps({"packs": ["nope"]})})
    assert r.status_code == 400 and "unknown packs" in r.text
    assert (await client.get("/api/codereview/runs")).status_code == 401


async def test_path_intake_is_restricted_to_allowed_roots(client, admin_headers, fixture_root: Path) -> None:
    from aisrf.config import get_settings

    r = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "path", "path": "/etc"}})
    assert r.status_code == 403 and "outside" in r.text
    r = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "path", "path": str(fixture_root)}})
    assert r.status_code == 403
    inside = get_settings().data_dir / "codereview-local-src"
    inside.mkdir(parents=True, exist_ok=True)
    write_tree(inside)
    r = await client.post("/api/codereview/runs", headers=admin_headers, json={"name": "local", "source": {"type": "path", "path": str(inside)}, "options": {"engines": ["rules"], "packs": ["model_supply_chain", "general"]}})
    assert r.status_code == 201, r.text
    run = await wait_for_run(client, r.json()["id"])
    assert run["status"] == "COMPLETED" and run["source_type"] == "path"
    findings = (await client.get(f"/api/codereview/runs/{run['id']}/findings?limit=500", headers=admin_headers)).json()["items"]
    packs = {f["pack"] for f in findings}
    assert "model_supply_chain" in packs and packs <= {"model_supply_chain", "general"}
    assert run["config"]["engines"] == ["rules"] and set(run["summary"]["engines"]) == {"rules"}


async def test_git_intake_from_local_bare_repository(client, admin_headers, fixture_root: Path, tmp_path: Path) -> None:
    bare = tmp_path / "origin.git"
    work = tmp_path / "work"
    subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
    work.mkdir()
    write_tree(work)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    for args in (["init", "--quiet", "-b", "main"], ["add", "."], ["commit", "--quiet", "-m", "fixture"], ["remote", "add", "origin", str(bare)], ["push", "--quiet", "origin", "main"]):
        subprocess.run(["git", *args], cwd=work, check=True, env=env, capture_output=True)
    token = "ghp_ThisIsAVerySecretTokenValue1234567890abcd"
    payload = {"name": "git run", "source": {"type": "git", "url": f"file://{bare}", "ref": "main", "token": token}, "options": {"engines": ["rules"], "packs": ["prompt_injection", "agent_tool_abuse"]}}
    r = await client.post("/api/codereview/runs", headers=admin_headers, json=payload)
    assert r.status_code == 201, r.text
    created = r.json()
    assert token not in json.dumps(created) and created["config"]["source"].get("token") in (None, "[masked]")
    run = await wait_for_run(client, created["id"])
    assert run["status"] == "COMPLETED", run.get("error")
    assert run["source_type"] == "git" and run["source_ref"] == f"file://{bare}" and token not in json.dumps(run)
    intake_info = run["inventory"]["intake"]
    assert intake_info["method"] == "git" and re.fullmatch(r"[0-9a-f]{40}", intake_info["commit"]) and intake_info["ref"] == "main"
    findings = (await client.get(f"/api/codereview/runs/{run['id']}/findings?limit=500", headers=admin_headers)).json()["items"]
    assert {f["rule_id"] for f in findings} >= {"AISRF-PI-001", "AISRF-AT-001"}
    sarif = (await client.get(f"/api/codereview/runs/{run['id']}/sarif", headers=admin_headers)).json()
    assert sarif["runs"][0]["versionControlProvenance"][0]["revisionId"] == intake_info["commit"]
    audit = (await client.get("/api/audit?limit=50", headers=admin_headers)).json()
    assert token not in json.dumps(audit)
    missing = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "git", "url": f"file://{tmp_path}/nope.git"}, "options": {"engines": ["rules"]}})
    failed = await wait_for_run(client, missing.json()["id"])
    assert failed["status"] == "FAILED" and "intake failed" in failed["error"]


async def test_snippet_run_cancel_and_credentials(client, admin_headers) -> None:
    code = "import torch\nimport pickle\nweights = torch.load(download_path)\nobj = pickle.load(open('m.pkl', 'rb'))\n"
    r = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "snippet", "code": code, "language": "python"}, "options": {"engines": ["rules", "semgrep"]}})
    assert r.status_code == 201, r.text
    run = await wait_for_run(client, r.json()["id"])
    assert run["status"] == "COMPLETED" and run["source_type"] == "snippet"
    findings = (await client.get(f"/api/codereview/runs/{run['id']}/findings", headers=admin_headers)).json()["items"]
    ids = {f["rule_id"] for f in findings}
    assert {"AISRF-MS-001", "AISRF-MS-002"} <= ids and all(f["file"] == "snippet.py" for f in findings)
    merged = next(f for f in findings if f["rule_id"] == "AISRF-MS-001")
    assert merged["line_start"] == 3
    empty = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "snippet", "code": "   "}})
    assert empty.status_code == 400

    r = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "snippet", "code": code}, "options": {"engines": ["rules"]}})
    run_id = r.json()["id"]
    cancelled = await client.post(f"/api/codereview/runs/{run_id}/cancel", headers=admin_headers)
    assert cancelled.status_code in (200, 409)
    final = await wait_for_run(client, run_id)
    assert final["status"] in ("CANCELLED", "COMPLETED")

    assert (await client.get("/api/codereview/credentials", headers=admin_headers)).json() == []
    r = await client.post("/api/codereview/credentials", headers=admin_headers, json={"label": "ci bot", "provider": "github", "token": "ghp_" + "b" * 36})
    assert r.status_code == 201
    cred = r.json()
    assert cred["has_token"] and "token" not in cred and "token_encrypted" not in cred and cred["provider"] == "github"
    listed = (await client.get("/api/codereview/credentials", headers=admin_headers)).json()
    assert [c["id"] for c in listed] == [cred["id"]] and "b" * 36 not in json.dumps(listed)
    from aisrf.codereview import service

    assert service.resolve_credential(cred["id"])["token"] == "ghp_" + "b" * 36
    assert (await client.delete(f"/api/codereview/credentials/{cred['id']}", headers=admin_headers)).status_code == 200
    assert (await client.delete(f"/api/codereview/credentials/{cred['id']}", headers=admin_headers)).status_code == 404
    unknown = await client.post("/api/codereview/runs", headers=admin_headers, json={"source": {"type": "git", "url": "https://github.com/org/repo.git", "credential_id": "cred_missing"}})
    assert unknown.status_code == 404


async def test_mcp_codereview_tools(client, admin_headers) -> None:
    try:
        from aisrf.mcp_server import build_server
    except ImportError as exc:  # the mcp package version shim is owned by the coordinator
        pytest.skip(f"mcp server import unavailable: {exc}")
    server = build_server("http://testserver", "test-admin-token", transport_client=client)
    names = {t.name for t in await server.list_tools()}
    assert {"codereview_rules", "codereview_start", "codereview_runs", "codereview_run", "codereview_findings", "codereview_set_finding_status", "codereview_report"} <= names

    def payload(result):
        if isinstance(result, tuple):  # mcp 1.x returns (content, structured_content)
            content, structured = result
            return structured if structured is not None else json.loads(content[0].text)
        return result.structured_content if result.structured_content is not None else json.loads(result.content[0].text)

    rules = payload(await server.call_tool("codereview_rules", {"pack": "llm_output"}))
    assert [p["name"] for p in rules["packs"]] == ["llm_output"]
    started = payload(await server.call_tool("codereview_start", {"source": {"type": "snippet", "code": "import torch\nm = torch.load(path)\n"}, "options": {"engines": ["rules"]}}))
    assert started["status"] in ("CREATED", "FETCHING", "ANALYZING", "COMPLETED"), started
    run = await wait_for_run(client, started["id"])
    fetched = payload(await server.call_tool("codereview_run", {"run_id": run["id"]}))
    assert fetched["status"] == "COMPLETED" and fetched["summary"]["risk_score"] > 0
    runs = payload(await server.call_tool("codereview_runs", {"limit": 5}))
    assert any(item["id"] == run["id"] for item in runs["items"])
    findings = payload(await server.call_tool("codereview_findings", {"run_id": run["id"], "severity": "CRITICAL"}))
    assert findings["items"] and findings["items"][0]["rule_id"] == "AISRF-MS-001"
    updated = payload(await server.call_tool("codereview_set_finding_status", {"finding_id": findings["items"][0]["id"], "status": "accepted", "note": "lab only"}))
    assert updated["status"] == "accepted"
