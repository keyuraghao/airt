"""Model security and supply chain rule pack (AISRF-MS-*): model files are code, dependencies are attack surface."""

from __future__ import annotations

import ast
import os
import re
from collections.abc import Iterator

from ..inventory import AI_PACKAGES, MANIFEST_NAMES, parse_manifest
from . import pyast
from .base import ALL, CODE, PY, FileContext, Match, Rule, absence, any_of, lines, node_match, py, rule

PACK = "model_supply_chain"
UNTRUSTED_PATH = re.compile(r"(?i)(url|download|request|upload|remote|hub|tmp|temp|cache|user|input|path|file|arg|param|fetch|s3|bucket|blob)")
HUB_LOADERS = re.compile(r"(^|\.)(from_pretrained|hf_hub_download|snapshot_download|load_dataset|SentenceTransformer|pipeline|CrossEncoder|AutoModel\w*|AutoTokenizer|load_model_from_hub|hub\.load)$")
SHA = re.compile(r"^[0-9a-f]{7,40}$")
PLACEHOLDER = re.compile(r"(?i)(xxx|your[_-]|example|placeholder|\.\.\.|<[^>]+>|replace|dummy|changeme|1234567890|fake|test-?key|sample)")


def _torch_load(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if name not in ("torch.load", "load") or (name == "load" and not ctx.search(r"from torch import load")):
            continue
        wo = pyast.keyword(call, "weights_only")
        if pyast.is_true(wo):
            continue
        src = " ".join(pyast.names_in(call.args[0])) if call.args else ""
        untrusted = bool(UNTRUSTED_PATH.search(src)) or (call.args and pyast.is_dynamic_string(call.args[0]))
        note = "weights_only=False disables the pickle restrictions" if pyast.is_false(wo) else "weights_only is not set"
        yield node_match(ctx, call, boost=0.15 if untrusted else 0.0, note=note + (" and the path is derived from a download, upload or user input" if untrusted else ""))


def _unpinned_hub(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        if not HUB_LOADERS.search(name):
            continue
        target = pyast.keyword(call, "pretrained_model_name_or_path") or pyast.keyword(call, "repo_id") or pyast.keyword(call, "path") or pyast.keyword(call, "model") or (call.args[0] if call.args else None)
        if target is None or not isinstance(target, ast.Constant) or not isinstance(target.value, str):
            continue
        ident = target.value
        if "/" not in ident or ident.startswith(("./", "/", "../", "~")) or os.path.exists(ident):
            continue
        rev = pyast.keyword(call, "revision")
        if rev is None:
            yield node_match(ctx, call, note=f"{ident!r} is resolved to whatever the default branch points at")
        elif isinstance(rev, ast.Constant) and isinstance(rev.value, str) and not SHA.match(rev.value):
            yield node_match(ctx, call, boost=-0.15, note=f"revision {rev.value!r} is a moving branch or tag, not a commit hash")


def _manifest_unpinned(ctx: FileContext) -> Iterator[Match]:
    name = os.path.basename(ctx.path)
    kind = MANIFEST_NAMES.get(name)
    if kind is None:
        return
    for dep in parse_manifest(kind, ctx.text):
        if dep.get("pinned") or dep["name"].lower() not in AI_PACKAGES:
            continue
        needle = dep["name"]
        for i, line in enumerate(ctx.lines, start=1):
            if re.search(r"(?i)(^|[\"'\s])" + re.escape(needle) + r"([\"'\s\[><=~!;,:]|$)", line):
                yield Match(i, i, note=f"{needle} {dep.get('spec') or '(no version)'}".strip())
                break


def _pickle_artifacts(inventory: dict, files: list) -> Iterator[Match]:
    for art in inventory.get("model_artifacts", [])[:25]:
        if art.get("pickle_based"):
            yield Match(1, 1, file=art["path"], snippet=f"{art['path']} ({art.get('format')}, {art.get('bytes', 0)} bytes)", note="pickle-based artifact committed to the repository")


def _missing_provenance(inventory: dict, files: list) -> Iterator[Match]:
    artifacts = inventory.get("model_artifacts", [])
    if not artifacts:
        return
    names = [f.path.lower() for f in files if getattr(f, "is_text", True)]
    has_card = any(re.search(r"(model[_-]?card|MODEL_CARD|readme\.md)$", n) for n in names)
    has_sbom = any(re.search(r"(sbom|\.spdx|cyclonedx|provenance|attestation)", n) for n in names)
    if has_card and has_sbom:
        return
    first = artifacts[0]["path"]
    missing = [m for m, ok in (("model card", has_card), ("SBOM or provenance attestation", has_sbom)) if not ok]
    yield Match(1, 1, file=first, snippet=f"{len(artifacts)} model artifact(s), no {' or '.join(missing)}", note="no " + " and no ".join(missing))


RULES: list[Rule] = [
    rule(
        "AISRF-MS-001",
        PACK,
        "torch.load without weights_only=True",
        severity="CRITICAL",
        confidence=0.7,
        category="supply_chain",
        cwe="CWE-502",
        description="torch.load() unpickles the checkpoint; without weights_only=True any object in the file, including one whose __reduce__ runs os.system, is executed at load time. Checkpoints from hubs, buckets, uploads or URLs are executable code from a stranger.",
        why="Loading a model file is functionally the same as running a downloaded binary. Trojanised checkpoints work perfectly and still steal credentials on load.",
        remediation=(
            "Load state dicts with torch.load(path, weights_only=True, map_location='cpu') and define the architecture in your own code.",
            "Prefer safetensors for storage and distribution; refuse pickle-based formats at the registry.",
            "Verify a checksum or signature before loading anything obtained remotely and scan pickle files before use.",
        ),
        languages=PY,
        matcher=any_of(py(_torch_load), lines(r"torch\.load\((?![^)]*weights_only\s*=\s*True)", flag="code")),
        tags=("sink:deserialize", "pickle"),
        engines=("rules", "semgrep", "bandit"),
    ),
    rule(
        "AISRF-MS-002",
        PACK,
        "Pickle-family deserialization of model or data files",
        severity="CRITICAL",
        confidence=0.7,
        category="supply_chain",
        cwe="CWE-502",
        description="pickle, joblib, dill, cloudpickle, shelve, marshal, numpy allow_pickle=True, torch.jit.load, Keras safe_mode=False, unsafe YAML loaders or framework flags such as allow_dangerous_deserialization=True are used. Each of these executes code embedded in the file.",
        why="Serialized models and vector indexes travel between teams, buckets and hubs; a malicious file needs no exploit, only a victim who loads it.",
        remediation=(
            "Use code-free formats: safetensors, ONNX, GGUF, JSON metadata plus raw tensors.",
            "If a pickle-based format is unavoidable, verify integrity first and load inside an isolated sandbox.",
            "Never load serialized objects received from users or fetched from untrusted locations.",
        ),
        languages=ALL,
        matcher=lines(r"(\b(pickle|cPickle|_pickle|dill|cloudpickle)\.(load|loads)\s*\(|joblib\.load\s*\(|shelve\.open\s*\(|marshal\.loads?\s*\(|(numpy|np)\.load\s*\([^)]*allow_pickle\s*=\s*True|allow_dangerous_deserialization\s*=\s*True|torch\.jit\.load\s*\(|load_model\s*\([^)]*safe_mode\s*=\s*False|yaml\.(load|unsafe_load)\s*\([^)]*(Loader\s*=\s*(yaml\.)?(Unsafe)?Loader|unsafe_load)|yaml\.unsafe_load\s*\(|jsonpickle\.decode\s*\(|node-serialize|unserialize\s*\()"),
        tags=("sink:deserialize", "pickle"),
        engines=("rules", "semgrep", "bandit"),
    ),
    rule(
        "AISRF-MS-003",
        PACK,
        "trust_remote_code=True enabled",
        severity="HIGH",
        confidence=0.85,
        category="supply_chain",
        cwe="CWE-829",
        description="The hub loader is told to execute Python shipped inside the model repository. The maintainer of that repository, or anyone who compromises it, runs code in your process on every load.",
        why="Remote code is exactly what the name says; combined with unpinned revisions the code can change under you at any time.",
        remediation=(
            "Prefer models whose architecture is in the framework and load them with trust_remote_code=False.",
            "If custom code is required, vendor it into your repository after review and pin the model to a commit hash.",
            "Run such loads in an isolated environment without production credentials.",
        ),
        languages=ALL,
        matcher=lines(r"(trust_remote_code\s*[=:]\s*[Tt]rue|--trust-remote-code|trustRemoteCode\s*:\s*true)"),
        tags=("remote-code",),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-MS-004",
        PACK,
        "Hub artifact loaded without a pinned revision",
        severity="MEDIUM",
        confidence=0.55,
        category="supply_chain",
        cwe="CWE-494",
        description="A model, tokenizer or dataset is fetched from a hub by name only (or by a branch name). Whatever the default branch points at tomorrow is what you will run; a hijacked account or a force push changes the weights silently.",
        why="Pinning to a commit hash is the model equivalent of a lockfile; without it, reproducibility and integrity are both gone.",
        remediation=(
            "Pass revision='<commit sha>' to from_pretrained, hf_hub_download, snapshot_download and load_dataset.",
            "Mirror approved models into an internal registry and load from there.",
            "Record the resolved hash in your build metadata.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_unpinned_hub),
            lines(r"pipeline\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+['\"]", unless=r"revision"),
        ),
        tags=("pinning",),
    ),
    rule(
        "AISRF-MS-005",
        PACK,
        "Model or weights fetched over plain HTTP",
        severity="HIGH",
        confidence=0.7,
        category="supply_chain",
        cwe="CWE-319",
        description="Weights, checkpoints, wheels or archives are downloaded over an unencrypted http:// URL. Anyone on the path can replace the file.",
        why="A network attacker who swaps a pickle-based checkpoint gets code execution; even safe formats can be replaced with backdoored weights.",
        remediation=(
            "Use https:// and verify the certificate.",
            "Pin the expected checksum and verify it after download.",
        ),
        languages=ALL,
        matcher=lines(r"http://[^\s'\"`)]+\.(pt|pth|bin|pkl|pickle|ckpt|safetensors|gguf|onnx|h5|tar\.gz|tgz|zip|whl)\b|(load_state_dict_from_url|urlretrieve|torch\.hub\.load|download_url|wget|curl)\b[^\n]*http://"),
        tags=("transport",),
    ),
    rule(
        "AISRF-MS-006",
        PACK,
        "Remote checkpoint downloaded without integrity verification",
        severity="MEDIUM",
        confidence=0.5,
        category="supply_chain",
        cwe="CWE-494",
        description="A model file is downloaded or pulled from a hub and used without any checksum, hash or signature check in the same module.",
        why="Integrity verification is what turns 'a file from the internet' into 'the file we reviewed'.",
        remediation=(
            "Compare the download against a pinned SHA-256 (check_hash=True for torch.hub, explicit hashlib otherwise) before loading.",
            "Sign model artifacts in CI (for example with Sigstore) and verify signatures at deployment.",
            "Fail closed when verification is unavailable.",
        ),
        languages=(*CODE, "shell", "dockerfile", "yaml"),
        matcher=absence([r"(load_state_dict_from_url|urlretrieve|torch\.hub\.load|hf_hub_download|snapshot_download|download_file|urlopen|requests\.get|wget |curl )\s*\(?[^\n]*(?i:model|weights|checkpoint|ckpt|\.pt\b|\.pth\b|\.bin\b|\.safetensors|\.gguf|\.onnx|\.pkl)"], [r"(?i)(sha256|sha1|hashlib|checksum|check_hash\s*=\s*True|verify_|signature|cosign|integrity|md5|etag|blake2)"], anchor=r"(load_state_dict_from_url|urlretrieve|torch\.hub\.load|hf_hub_download|snapshot_download|download_file|urlopen|requests\.get|wget |curl )"),
        tags=("integrity",),
    ),
    rule(
        "AISRF-MS-007",
        PACK,
        "Unpinned AI or ML dependency",
        severity="MEDIUM",
        confidence=0.6,
        category="supply_chain",
        cwe="CWE-1104",
        description="An AI framework, SDK, vector store client or ML library is declared without an exact version (range, caret, wildcard or no version at all), or is installed in a container build without a pin. The next install can pull a compromised or breaking release.",
        why="ML dependency trees are deep and fast moving; typosquats, malicious updates and dependency confusion have all hit this ecosystem.",
        remediation=(
            "Pin exact versions and use a lockfile; add hash verification (pip --require-hashes, npm ci) in CI.",
            "Pull from a private mirror that blocks external packages named like internal ones.",
            "Audit dependencies regularly (pip-audit, npm audit, OSV) and pin VCS dependencies to a commit.",
        ),
        languages=("text", "toml", "json", "config", "ruby", "xml", "dockerfile", "shell", "yaml", "notebook"),
        matcher=any_of(
            _manifest_unpinned,
            lines(r"(?i)(RUN\s+|^\s*!?\s*)pip3?\s+install\b(?![^\n]*(==|--require-hashes|-r\s|--constraint|-c\s))[^\n]*\b(torch|transformers|langchain|openai|anthropic|llama-index|llama_index|vllm|diffusers|sentence-transformers|chromadb|pinecone|qdrant-client|crewai|autogen|litellm|huggingface_hub)\b"),
        ),
        tags=("pinning", "dependencies"),
    ),
    rule(
        "AISRF-MS-008",
        PACK,
        "Model serving endpoint without authentication",
        severity="MEDIUM",
        confidence=0.4,
        category="denial_of_wallet",
        cwe="CWE-306",
        description="A prediction, generation, chat or embedding route is defined in a file that shows no authentication dependency, token check or auth middleware.",
        why="Unauthenticated inference endpoints invite model extraction, denial of wallet and abuse of your provider keys by third parties.",
        remediation=(
            "Require authentication on every inference route (API keys, OAuth, session) and rate limit per identity.",
            "Return only the information the caller needs (no full probability vectors, no debug fields).",
            "Monitor query volume per client for extraction patterns.",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=any_of(
            absence([r"(@app\.(route|post|get|api_route)|@router\.(post|get|api_route)|app\.post\(|router\.post\()\s*\(?\s*['\"][^'\"]*(predict|infer|inference|generate|complet|chat|embed|classif|score|rerank|v1/)"], [r"(?i)(Depends\(|auth|api_?key|token|login_required|jwt|Authorization|Security\(|HTTPBearer|OAuth|verify_|@requires|permission|current_user|principal|passport|bearer|session\[)"], anchor=r"(@app\.(route|post|get|api_route)|@router\.(post|get|api_route)|app\.post\(|router\.post\()"),
        ),
        tags=("auth",),
    ),
    rule(
        "AISRF-MS-009",
        PACK,
        "Model weights or data published with public access",
        severity="HIGH",
        confidence=0.55,
        category="supply_chain",
        cwe="CWE-284",
        description="Storage objects or buckets are configured world-readable or world-writable (public-read ACLs, allUsers grants, wildcard principals, disabled public access blocks). Weights, fine-tuning data and vector indexes stored there can be read or replaced by anyone.",
        why="Public buckets leak proprietary models and training data; writable ones let an attacker swap the artifact your service loads next.",
        remediation=(
            "Remove public grants; serve artifacts through authenticated, signed URLs.",
            "Enable public access blocks and object versioning; verify hashes on load.",
            "Audit bucket policies as part of the ML release pipeline.",
        ),
        languages=ALL,
        matcher=lines(r"(?i)(ACL\s*[=:]\s*['\"]public-read(-write)?['\"]|--acl\s+public-read|public-read-write|['\"]allUsers['\"]|['\"]Principal['\"]\s*:\s*['\"]\*['\"]|BlockPublicAcls\s*[:=]\s*false|RestrictPublicBuckets\s*[:=]\s*false|make_public\(|predefined_acl\s*=\s*['\"]public|public_access\s*[:=]\s*(true|['\"]?blob)|allow_public_access)", boost_flag="ai"),
        tags=("storage",),
    ),
    rule(
        "AISRF-MS-010",
        PACK,
        "Unpinned base image or unverified download in a build",
        severity="MEDIUM",
        confidence=0.55,
        category="supply_chain",
        cwe="CWE-494",
        description="A Dockerfile or CI job uses a floating base image (latest or no digest), pipes a download straight into a shell, or fetches model files during the build without verifying them.",
        why="Build-time supply chain attacks land in every image you ship; ML images are large, long-lived and rarely rebuilt from verified inputs.",
        remediation=(
            "Pin base images by digest (@sha256:...) and dependencies by hash.",
            "Copy verified artifacts from an internal registry instead of downloading at build time.",
            "Never pipe curl or wget into a shell; download, verify, then execute.",
        ),
        languages=("dockerfile", "yaml", "shell", "text"),
        matcher=any_of(
            lines(r"(?i)^\s*FROM\s+(?!scratch)[^\s@]+(:latest)?\s*(AS\s+\w+)?\s*$", unless=r":[0-9][\w.\-]*(\s|$)|@sha256:"),
            lines(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b"),
            absence([r"(?i)\b(curl|wget)\b[^\n]*\.(pt|pth|bin|ckpt|safetensors|gguf|onnx|pkl)\b"], [r"(?i)(sha256sum|--checksum|sha256|verify|cosign|gpg)"], anchor=r"(?i)\b(curl|wget)\b[^\n]*\.(pt|pth|bin|ckpt|safetensors|gguf|onnx|pkl)\b"),
        ),
        tags=("build", "ci"),
    ),
    rule(
        "AISRF-MS-011",
        PACK,
        "Training or fine-tuning data ingested from untrusted sources",
        severity="MEDIUM",
        confidence=0.4,
        category="rag_poisoning",
        cwe="CWE-345",
        description="Data used for training, fine-tuning or evaluation comes from a hub dataset without a pinned revision, a remote URL, or user uploads, and the module shows no validation, deduplication or provenance tracking.",
        why="Poisoning a small fraction of training data is enough to plant triggers; web-scale and user-generated corpora are cheap to poison.",
        remediation=(
            "Pin dataset revisions and record content hashes; keep a provenance manifest per training run.",
            "Validate schema and label distributions, deduplicate and scan for trigger-like anomalies before training.",
            "Review user-contributed samples before they enter a fine-tuning set.",
        ),
        languages=PY,
        matcher=absence([r"(load_dataset\s*\(\s*['\"][^'\"]+['\"](?![^)]*revision)|pd\.read_(csv|json|parquet)\s*\(\s*['\"]https?://|read_csv\s*\(\s*(url|request|upload|user)|Dataset\.from_(pandas|dict|list)\s*\([^)]*(request|upload|user|form)|files\.create\s*\([^)]*purpose\s*=\s*['\"]fine-?tune|fine_tuning\.jobs\.create\s*\()"], [r"(?i)(validate|schema|dedup|filter_|clean_|provenance|content_hash|sha256|verify|great_expectations|review|approved|quarantine)"], anchor=r"(load_dataset\s*\(|pd\.read_(csv|json|parquet)\s*\(|read_csv\s*\(|Dataset\.from_|files\.create\s*\(|fine_tuning\.jobs\.create\s*\()"),
        tags=("training-data",),
    ),
    rule(
        "AISRF-MS-012",
        PACK,
        "Model artifacts without provenance metadata",
        severity="INFO",
        confidence=0.4,
        category="supply_chain",
        cwe="CWE-1059",
        description="The repository ships model artifacts but no model card and no SBOM or provenance attestation describing where the weights came from, how they were trained and how to verify them.",
        why="Without provenance nobody can answer 'is this the model we reviewed?' during an incident.",
        remediation=(
            "Add a model card with source, training data summary, license and the SHA-256 of each artifact.",
            "Generate an SBOM or an attestation for the model in CI and store it next to the weights.",
        ),
        languages=ALL,
        matcher=lambda ctx: iter(()),
        scope="inventory",
        tags=("provenance",),
    ),
    rule(
        "AISRF-MS-013",
        PACK,
        "Pickle-based model artifact committed to the repository",
        severity="LOW",
        confidence=0.6,
        category="supply_chain",
        cwe="CWE-502",
        description="A .pt, .pth, .pkl, .ckpt, .joblib or .bin artifact is checked in. Anyone who can push to the repository can plant code that runs when the file is loaded, and reviewers cannot inspect binary diffs.",
        why="Binary model files bypass code review; pickle-based ones are executable.",
        remediation=(
            "Convert artifacts to safetensors or ONNX and store them in an artifact registry with hashes, not in git.",
            "Scan any pickle-based file with a pickle scanner before use.",
        ),
        languages=ALL,
        matcher=lambda ctx: iter(()),
        scope="inventory",
        tags=("pickle", "repository"),
    ),
]
INVENTORY_MATCHERS = {"AISRF-MS-012": _missing_provenance, "AISRF-MS-013": _pickle_artifacts}
_ = PLACEHOLDER

from .base import ROUTE, near  # noqa: E402

EXTRA_INDEX = r"(--extra-index-url|extra-index-url\s*=|PIP_EXTRA_INDEX_URL|\[\[tool\.poetry\.source\]\]|\[\[tool\.uv\.index\]\]|--index-url\s+https?://(?!pypi\.org/)|index-url\s*=\s*https?://(?!pypi\.org/)|^\s*registry\s*=\s*https?://(?!registry\.npmjs\.org)|--trusted-host)"
UPLOAD_SOURCE = r"(request\.files|UploadFile|File\(\.\.\.\)|File\(|req\.file\b|multer|formData\.get\(\s*['\"]file|busboy|formidable)"
UPLOAD_GUARD = r"(?i)(safetensors|allowed_ext|ALLOWED_(EXT|FORMAT|TYPES)|picklescan|modelscan|fickling|scan_|approve|review|pending|quarantine|sha256|hashlib|magic\.|content_type\s*(==|in|not in)|\.suffix\s*(==|in|not in)|endswith\()"
PROBABILITY_OUTPUT = r"(return\b|jsonify\s*\(|res\.json\s*\(|JSONResponse\s*\(|['\"]predictions?['\"]\s*:)[^\n]*\b(probs|probabilities|logits|softmax|predict_proba|all_scores|class_probabilities|distribution|confidences)\b"


RULES += [
    rule(
        "AISRF-MS-014",
        PACK,
        "Hub model loaded without forcing the safetensors format",
        severity="LOW",
        confidence=0.4,
        category="supply_chain",
        cwe="CWE-502",
        description="A transformers model is loaded from a hub repository without use_safetensors=True. If the repository only offers pickle-based weights, or an attacker adds them, the loader silently falls back to unpickling.",
        why="Forcing the safe format makes the loader fail closed instead of executing whatever is in a .bin file.",
        remediation=(
            "Pass use_safetensors=True to from_pretrained and pipeline calls, and pin a revision.",
            "Mirror approved models in safetensors format in an internal registry.",
        ),
        languages=PY,
        matcher=near(r"(\w*Model\w*|\w*ForCausalLM|\w*ForSequenceClassification|\w*ForSeq2SeqLM|pipeline)\s*(\.from_pretrained)?\s*\(\s*['\"][A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+['\"]", None, window=6, unless=r"use_safetensors\s*=\s*True"),
        tags=("pickle", "hardening"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-MS-015",
        PACK,
        "Additional package index configured (dependency confusion exposure)",
        severity="MEDIUM",
        confidence=0.5,
        category="supply_chain",
        cwe="CWE-427",
        description="An extra or alternative package index is configured for pip, poetry, uv or npm. With more than one index the resolver may pick a public package that shares the name of an internal one, and --trusted-host disables TLS verification for that index.",
        why="Dependency confusion needs nothing more than a public package with the right name and a resolver that consults two indexes.",
        remediation=(
            "Use a single private index that proxies the public one and blocks external packages with internal names.",
            "Pin explicit sources per package (explicit priority in poetry or uv, scoped registries in npm) and never use --trusted-host.",
            "Register internal package names on the public index as placeholders.",
        ),
        languages=("text", "toml", "config", "dockerfile", "shell", "yaml", "notebook", "json"),
        matcher=lines(EXTRA_INDEX, unless=r"priority\s*=\s*['\"]explicit|explicit\s*=\s*true"),
        tags=("dependencies", "pinning"),
    ),
    rule(
        "AISRF-MS-016",
        PACK,
        "Model upload endpoint stores artifacts without format checks or review",
        severity="HIGH",
        confidence=0.45,
        category="supply_chain",
        cwe="CWE-434",
        description="An HTTP handler accepts an uploaded model, checkpoint or weights file and stores it, and the module shows no file type restriction, no scan and no approval step before the artifact becomes loadable.",
        why="A registry that accepts pickle-based uploads and serves them to loaders is a code execution service for anyone with upload rights.",
        remediation=(
            "Accept only code-free formats (safetensors, ONNX, GGUF) and verify the file structure, not just the extension.",
            "Scan pickle-based uploads, record a hash, and keep artifacts in a pending state until a second person approves them.",
            "Store uploads outside the web root with restrictive permissions.",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=absence([ROUTE.pattern, UPLOAD_SOURCE, r"(?i)(model|weights|checkpoint|\.pt\b|\.pth\b|\.pkl\b|\.bin\b|\.h5\b|\.ckpt\b|artifact)"], [UPLOAD_GUARD], anchor=UPLOAD_SOURCE),
        tags=("registry", "upload"),
    ),
    rule(
        "AISRF-MS-017",
        PACK,
        "Inference endpoint returns full probability vectors",
        severity="LOW",
        confidence=0.35,
        category="privacy_memorization",
        cwe="CWE-200",
        description="A prediction route returns raw probabilities, logits or per-class scores. Precise confidence values are the raw material for model extraction, membership inference and inversion attacks.",
        why="Callers rarely need more than the top labels; every extra decimal of confidence leaks information about the model and its training data.",
        remediation=(
            "Return only the top-k labels with coarse confidence buckets.",
            "Rate limit per identity and monitor for extraction patterns (high volume, random-looking inputs).",
        ),
        languages=("python", "javascript", "typescript"),
        matcher=lines(PROBABILITY_OUTPUT, flag="route"),
        tags=("inference", "extraction"),
    ),
    rule(
        "AISRF-MS-018",
        PACK,
        "Notebook committed with HTML or JavaScript cell outputs",
        severity="MEDIUM",
        confidence=0.6,
        category="supply_chain",
        cwe="CWE-79",
        description="A notebook in the repository contains rendered HTML or JavaScript outputs that include script tags, event handlers or network calls. Notebook front ends execute such outputs when the file is opened as trusted.",
        why="Shared notebooks are opened far more often than they are read as JSON; an output cell is a place to hide code that runs in the reviewer's session.",
        remediation=(
            "Strip outputs before committing (a pre-commit hook or nbstripout) and review notebook JSON, not only the rendered view.",
            "Open notebooks from other people as untrusted and keep the notebook server on a separate identity.",
        ),
        languages=("notebook",),
        matcher=near(r"\"(text/html|application/javascript)\"\s*:", r"(<script|javascript:|onerror\s*=|onload\s*=|fetch\(|XMLHttpRequest|document\.cookie|\beval\(|<iframe)", window=15),
        tags=("notebook",),
    ),
    rule(
        "AISRF-MS-019",
        PACK,
        "Container image runs as root",
        severity="LOW",
        confidence=0.6,
        category="supply_chain",
        cwe="CWE-250",
        description="The Dockerfile never switches to an unprivileged user, so the training or serving process, and anything a malicious model or dependency executes inside it, runs as root.",
        why="Root inside an ML container turns a pickle payload into a full host or cluster compromise instead of a contained incident.",
        remediation=(
            "Create a dedicated user in the image and add a USER instruction before the entrypoint.",
            "Drop capabilities, mount the filesystem read-only and set resource limits in the orchestrator.",
        ),
        languages=("dockerfile",),
        matcher=absence([r"(?i)^\s*FROM\s+"], [r"(?im)^\s*USER\s+(?!root\b)\S+"], anchor=r"(?i)^\s*FROM\s+"),
        tags=("build", "container"),
    ),
]
