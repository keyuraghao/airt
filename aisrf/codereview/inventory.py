"""Repository inventory: file walk with limits, languages and LOC, dependency manifests, AI framework
detection, model artifacts, prompt files, secrets files, CI and container configuration.

The walker is shared with the intake (copying a local directory) and the engines (what to scan).
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".ipynb": "notebook",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".vue": "vue",
    ".svelte": "svelte",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".html": "html",
    ".htm": "html",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".txt": "text",
    ".prompt": "prompt",
    ".jinja": "jinja",
    ".jinja2": "jinja",
    ".j2": "jinja",
    ".tmpl": "jinja",
    ".env": "dotenv",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".xml": "xml",
    ".cfg": "config",
    ".ini": "config",
    ".properties": "config",
}
CODE_LANGUAGES: set[str] = {
    "python",
    "javascript",
    "typescript",
    "vue",
    "svelte",
    "java",
    "go",
    "csharp",
    "ruby",
    "php",
    "rust",
    "kotlin",
    "swift",
}
MODEL_ARTIFACT_EXT: dict[str, str] = {
    ".pt": "pytorch-pickle",
    ".pth": "pytorch-pickle",
    ".bin": "binary-weights",
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".joblib": "joblib-pickle",
    ".ckpt": "checkpoint-pickle",
    ".safetensors": "safetensors",
    ".gguf": "gguf",
    ".ggml": "ggml",
    ".onnx": "onnx",
    ".h5": "keras-hdf5",
    ".hdf5": "keras-hdf5",
    ".keras": "keras",
    ".pb": "tensorflow-protobuf",
    ".tflite": "tflite",
    ".npy": "numpy",
    ".npz": "numpy",
    ".mlmodel": "coreml",
}
PICKLE_FORMATS: set[str] = {
    "pytorch-pickle",
    "pickle",
    "joblib-pickle",
    "checkpoint-pickle",
    "binary-weights",
    "numpy",
}
BINARY_EXT: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".bmp",
    ".svg",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".tar",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".jar",
    ".war",
    ".class",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".pyc",
    ".pyo",
    ".o",
    ".a",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".mp3",
    ".mp4",
    ".wav",
    ".mov",
    ".avi",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".parquet",
    ".arrow",
    ".feather",
    ".lock",
    *MODEL_ARTIFACT_EXT,
}
MANIFEST_NAMES: dict[str, str] = {
    "requirements.txt": "pip",
    "requirements-dev.txt": "pip",
    "requirements_dev.txt": "pip",
    "requirements-test.txt": "pip",
    "constraints.txt": "pip",
    "pyproject.toml": "pyproject",
    "Pipfile": "pipfile",
    "setup.py": "setup.py",
    "environment.yml": "conda",
    "package.json": "npm",
    "go.mod": "gomod",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile": "bundler",
    "Cargo.toml": "cargo",
    "composer.json": "composer",
}
AI_PACKAGES: set[str] = {
    "openai",
    "anthropic",
    "google-generativeai",
    "google-genai",
    "google-cloud-aiplatform",
    "vertexai",
    "cohere",
    "mistralai",
    "groq",
    "together",
    "replicate",
    "huggingface-hub",
    "huggingface_hub",
    "transformers",
    "diffusers",
    "accelerate",
    "peft",
    "trl",
    "datasets",
    "torch",
    "tensorflow",
    "keras",
    "jax",
    "vllm",
    "ollama",
    "litellm",
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-openai",
    "langchain-anthropic",
    "langgraph",
    "llama-index",
    "llama_index",
    "llama-index-core",
    "haystack-ai",
    "farm-haystack",
    "crewai",
    "autogen",
    "pyautogen",
    "ag2",
    "semantic-kernel",
    "dspy",
    "dspy-ai",
    "instructor",
    "guidance",
    "outlines",
    "pinecone",
    "pinecone-client",
    "chromadb",
    "weaviate-client",
    "qdrant-client",
    "pgvector",
    "faiss-cpu",
    "faiss-gpu",
    "pymilvus",
    "lancedb",
    "sentence-transformers",
    "mcp",
    "fastmcp",
    "guardrails-ai",
    "llm-guard",
    "nemoguardrails",
    "@anthropic-ai/sdk",
    "@google/generative-ai",
    "@google/genai",
    "@langchain/core",
    "@langchain/openai",
    "@langchain/anthropic",
    "@langchain/langgraph",
    "llamaindex",
    "ai",
    "@ai-sdk/openai",
    "@ai-sdk/anthropic",
    "@modelcontextprotocol/sdk",
    "@pinecone-database/pinecone",
    "weaviate-ts-client",
    "@qdrant/js-client-rest",
    "@xenova/transformers",
    "@huggingface/inference",
    "onnxruntime-node",
    "cohere-ai",
    "@mistralai/mistralai",
    "groq-sdk",
    "together-ai",
}
# Framework signatures: python import roots, npm package names and generic code markers.
FRAMEWORKS: dict[str, dict[str, Any]] = {
    "openai": {
        "kind": "llm_sdk",
        "python": ["openai"],
        "npm": ["openai"],
        "markers": [r"\bOpenAI\(", r"chat\.completions\.create\("],
    },
    "anthropic": {
        "kind": "llm_sdk",
        "python": ["anthropic"],
        "npm": ["@anthropic-ai/sdk"],
        "markers": [r"\bAnthropic\(", r"\.messages\.create\("],
    },
    "google-generativeai": {
        "kind": "llm_sdk",
        "python": ["google.generativeai", "google.genai", "vertexai"],
        "npm": ["@google/generative-ai", "@google/genai"],
        "markers": [r"GenerativeModel\("],
    },
    "cohere": {"kind": "llm_sdk", "python": ["cohere"], "npm": ["cohere-ai"], "markers": []},
    "mistral": {"kind": "llm_sdk", "python": ["mistralai"], "npm": ["@mistralai/mistralai"], "markers": []},
    "groq": {"kind": "llm_sdk", "python": ["groq"], "npm": ["groq-sdk"], "markers": []},
    "litellm": {"kind": "llm_sdk", "python": ["litellm"], "npm": [], "markers": []},
    "ollama": {"kind": "llm_sdk", "python": ["ollama"], "npm": ["ollama"], "markers": [r"localhost:11434"]},
    "vllm": {"kind": "serving", "python": ["vllm"], "npm": [], "markers": []},
    "vercel-ai-sdk": {
        "kind": "framework",
        "python": [],
        "npm": ["ai", "@ai-sdk/openai", "@ai-sdk/anthropic"],
        "markers": [r"\bgenerateText\(", r"\bstreamText\("],
    },
    "langchain": {
        "kind": "framework",
        "python": [
            "langchain",
            "langchain_core",
            "langchain_community",
            "langchain_openai",
            "langchain_anthropic",
        ],
        "npm": ["langchain", "@langchain/core", "@langchain/openai", "@langchain/anthropic"],
        "markers": [],
    },
    "langgraph": {
        "kind": "framework",
        "python": ["langgraph"],
        "npm": ["@langchain/langgraph"],
        "markers": [r"StateGraph\("],
    },
    "llama-index": {
        "kind": "framework",
        "python": ["llama_index"],
        "npm": ["llamaindex"],
        "markers": [r"VectorStoreIndex"],
    },
    "haystack": {"kind": "framework", "python": ["haystack"], "npm": [], "markers": []},
    "crewai": {"kind": "agent_framework", "python": ["crewai"], "npm": [], "markers": [r"\bCrew\("]},
    "autogen": {
        "kind": "agent_framework",
        "python": ["autogen", "autogen_agentchat", "ag2"],
        "npm": [],
        "markers": [r"AssistantAgent\("],
    },
    "semantic-kernel": {"kind": "agent_framework", "python": ["semantic_kernel"], "npm": [], "markers": []},
    "dspy": {"kind": "framework", "python": ["dspy"], "npm": [], "markers": []},
    "instructor": {"kind": "framework", "python": ["instructor"], "npm": [], "markers": []},
    "transformers": {
        "kind": "ml",
        "python": ["transformers"],
        "npm": ["@xenova/transformers", "@huggingface/transformers"],
        "markers": [r"from_pretrained\("],
    },
    "huggingface-hub": {
        "kind": "ml",
        "python": ["huggingface_hub"],
        "npm": ["@huggingface/inference"],
        "markers": [r"hf_hub_download\(", r"snapshot_download\("],
    },
    "torch": {"kind": "ml", "python": ["torch", "torchvision"], "npm": [], "markers": [r"torch\.load\("]},
    "tensorflow": {
        "kind": "ml",
        "python": ["tensorflow", "keras"],
        "npm": ["@tensorflow/tfjs"],
        "markers": [],
    },
    "sentence-transformers": {"kind": "ml", "python": ["sentence_transformers"], "npm": [], "markers": []},
    "pinecone": {
        "kind": "vector_store",
        "python": ["pinecone"],
        "npm": ["@pinecone-database/pinecone"],
        "markers": [r"\bPinecone\("],
    },
    "chromadb": {
        "kind": "vector_store",
        "python": ["chromadb"],
        "npm": ["chromadb"],
        "markers": [r"chromadb\.(Http|Persistent)?Client\("],
    },
    "weaviate": {
        "kind": "vector_store",
        "python": ["weaviate"],
        "npm": ["weaviate-ts-client", "weaviate-client"],
        "markers": [],
    },
    "qdrant": {
        "kind": "vector_store",
        "python": ["qdrant_client"],
        "npm": ["@qdrant/js-client-rest"],
        "markers": [r"QdrantClient\("],
    },
    "pgvector": {
        "kind": "vector_store",
        "python": ["pgvector"],
        "npm": ["pgvector"],
        "markers": [r"\bvector\(\d+\)", r"<=>"],
    },
    "faiss": {"kind": "vector_store", "python": ["faiss"], "npm": [], "markers": []},
    "milvus": {
        "kind": "vector_store",
        "python": ["pymilvus"],
        "npm": ["@zilliz/milvus2-sdk-node"],
        "markers": [],
    },
    "lancedb": {
        "kind": "vector_store",
        "python": ["lancedb"],
        "npm": ["@lancedb/lancedb", "vectordb"],
        "markers": [],
    },
    "mcp": {
        "kind": "mcp",
        "python": ["mcp", "fastmcp"],
        "npm": ["@modelcontextprotocol/sdk"],
        "markers": [r"FastMCP\(", r"@mcp\.tool", r"\.tool\(\s*\)", r"McpServer\("],
    },
    "guardrails": {
        "kind": "guardrails",
        "python": ["guardrails", "llm_guard", "nemoguardrails", "rebuff"],
        "npm": [],
        "markers": [],
    },
}
TOOL_CALLING_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"\btools\s*[=:]\s*\["),
    re.compile(r"\bfunctions\s*[=:]\s*\["),
    re.compile(r"\btool_choice\b"),
    re.compile(r"\btool_calls\b"),
    re.compile(r"\bfunction_call\b"),
    re.compile(r"@tool\b"),
    re.compile(r"\bStructuredTool\b"),
    re.compile(r"\bTool\("),
    re.compile(r"\bdefineTool\(|\btool\(\{"),
    re.compile(r"\bBaseTool\b"),
    re.compile(r"\bFunctionTool\b"),
    re.compile(r"\bmcp\.tool\b|@server\.tool|server\.tool\(|FastMCP\("),
]
MCP_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"^\s*(from|import)\s+(mcp|fastmcp)\b", re.M),
    re.compile(r"@modelcontextprotocol/sdk"),
    re.compile(r"\bFastMCP\(|\bMcpServer\(|\bmcp\.tool\b|@server\.tool"),
]
PROMPT_FILE_HINTS = re.compile(
    r"(?im)^\s*(system prompt|you are an? |### ?system|<\|system\|>|role:\s*[\"']?system|\[system\]|system:\s*\S)"
)
SECRET_FILE_NAMES = re.compile(
    r"(?i)^(\.env(\..+)?|secrets?\.(json|ya?ml|toml|txt)|credentials?\.(json|ya?ml)|.*\.pem|id_(rsa|ed25519|ecdsa)|.*\.p12|.*\.pfx|service[-_]account.*\.json)$"
)
CI_PATHS = re.compile(
    r"(?i)(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile|\.circleci/config\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|\.travis\.ya?ml|cloudbuild\.ya?ml|\.drone\.ya?ml)$"
)
DOCKER_PATHS = re.compile(
    r"(?i)(^|/)(Dockerfile[^/]*|[^/]+\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml)$"
)
IMPORT_PY = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
IMPORT_JS = re.compile(r"""(?:from\s+|require\(\s*|import\s*\(\s*)['"]([^'"]+)['"]""")


@dataclass
class SourceFile:
    path: str  # posix, relative to the source root
    abs_path: Path
    language: str
    size: int
    is_text: bool = True

    def read_text(self) -> str:
        try:
            return self.abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


@dataclass
class WalkStats:
    scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    skipped_excluded: int = 0
    truncated: bool = False
    bytes: int = 0


def language_of(path: str) -> str:
    name = os.path.basename(path)
    if name.startswith("Dockerfile") or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.startswith(".env"):
        return "dotenv"
    if name in ("Jenkinsfile",):
        return "groovy"
    if name in ("Gemfile", "Rakefile"):
        return "ruby"
    return LANGUAGES.get(Path(name).suffix.lower(), "")


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXT:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def _globs_match(rel: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if (
            fnmatch.fnmatch(rel, pat)
            or fnmatch.fnmatch(os.path.basename(rel), pat)
            or rel.startswith(pat.rstrip("/*") + "/")
        ):
            return True
    return False


def walk_files(
    root: Path,
    cfg: dict[str, Any],
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_files: int | None = None,
    stats: WalkStats | None = None,
) -> Iterator[SourceFile]:
    """Yield eligible files under root: excluded directories, symlinks, oversized and binary files are skipped.

    Binary files that are model artifacts are still yielded with is_text=False so the inventory sees them.
    """
    stats = stats if stats is not None else WalkStats()
    exclude_dirs = set(cfg.get("exclude_dirs") or [])
    max_bytes = int(cfg.get("max_file_bytes") or 2 * 1024 * 1024)
    limit = int(max_files or cfg.get("max_files") or 20000)
    include = [p for p in (include or []) if p]
    exclude = [p for p in (exclude or []) if p]
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames if d not in exclude_dirs and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            rel = full.relative_to(root).as_posix()
            if exclude and _globs_match(rel, exclude):
                stats.skipped_excluded += 1
                continue
            if include and not _globs_match(rel, include):
                stats.skipped_excluded += 1
                continue
            try:
                size = full.stat().st_size
            except OSError:
                continue
            artifact = full.suffix.lower() in MODEL_ARTIFACT_EXT
            if size > max_bytes and not artifact:
                stats.skipped_large += 1
                continue
            if _is_binary(full):
                stats.skipped_binary += 1
                if artifact:
                    yield SourceFile(rel, full, "", size, is_text=False)
                continue
            if stats.scanned >= limit:
                stats.truncated = True
                return
            stats.scanned += 1
            stats.bytes += size
            yield SourceFile(rel, full, language_of(rel), size, is_text=True)


# --- dependency manifests ---------------------------------------------------------------
_PIP_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*([<>=!~]=?.*)?$")
_GIT_REQ = re.compile(r"^\s*(?:-e\s+)?(git\+\S+|https?://\S+)")


def _pip_requirements(text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--")):
            continue
        m = _GIT_REQ.match(line)
        if m:
            url = m.group(1)
            pinned = bool(re.search(r"@[0-9a-f]{7,40}(#|$)", url))
            name = url.rsplit("/", 1)[-1].split("@")[0].replace(".git", "")
            deps.append({"name": name, "spec": url, "pinned": pinned, "source": "vcs"})
            continue
        m = _PIP_LINE.match(line.split(";")[0].split("\\")[0])
        if not m:
            continue
        spec = (m.group(3) or "").strip()
        pinned = spec.startswith("==") or "--hash" in raw
        deps.append({"name": m.group(1).lower(), "spec": spec, "pinned": pinned})
    return deps


def _pep508(specs: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in specs:
        if not isinstance(s, str):
            continue
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$", s.split(";")[0])
        if m:
            spec = m.group(3).strip()
            out.append({"name": m.group(1).lower(), "spec": spec, "pinned": spec.startswith("==")})
    return out


def _pyproject(text: str) -> list[dict[str, Any]]:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    deps = _pep508(list((doc.get("project") or {}).get("dependencies") or []))
    for group in ((doc.get("project") or {}).get("optional-dependencies") or {}).values():
        deps.extend(_pep508(list(group or [])))
    poetry = ((doc.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        version = spec.get("version", "") if isinstance(spec, dict) else str(spec)
        deps.append(
            {
                "name": name.lower(),
                "spec": version,
                "pinned": bool(re.match(r"^=?\d", version)) and not version.startswith(("^", "~", ">", "*")),
            }
        )
    return deps


def _package_json(text: str) -> list[dict[str, Any]]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    deps: list[dict[str, Any]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, spec in (doc.get(section) or {}).items():
            spec = str(spec)
            deps.append({"name": name, "spec": spec, "pinned": bool(re.match(r"^\d+\.\d+\.\d+", spec))})
    return deps


def _gomod(text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for m in re.finditer(r"^\s*([\w./\-]+)\s+(v[\w.\-+]+)", text, re.M):
        if m.group(1) in ("module", "go", "toolchain"):
            continue
        deps.append({"name": m.group(1), "spec": m.group(2), "pinned": True})
    return deps


def _pom(text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for m in re.finditer(r"<dependency>(.*?)</dependency>", text, re.S):
        block = m.group(1)
        art = re.search(r"<artifactId>([^<]+)</artifactId>", block)
        ver = re.search(r"<version>([^<]+)</version>", block)
        if art:
            spec = ver.group(1).strip() if ver else ""
            deps.append(
                {
                    "name": art.group(1).strip(),
                    "spec": spec,
                    "pinned": bool(spec) and not any(c in spec for c in "[(,$"),
                }
            )
    return deps


def _gemfile(text: str) -> list[dict[str, Any]]:
    deps: list[dict[str, Any]] = []
    for m in re.finditer(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", text, re.M):
        spec = m.group(2) or ""
        deps.append(
            {"name": m.group(1), "spec": spec, "pinned": spec.startswith("=") or bool(re.match(r"^\d", spec))}
        )
    return deps


def _cargo(text: str) -> list[dict[str, Any]]:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    deps: list[dict[str, Any]] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (doc.get(section) or {}).items():
            version = spec.get("version", "") if isinstance(spec, dict) else str(spec)
            deps.append({"name": name, "spec": version, "pinned": version.startswith("=")})
    return deps


MANIFEST_PARSERS = {
    "pip": _pip_requirements,
    "pyproject": _pyproject,
    "npm": _package_json,
    "gomod": _gomod,
    "maven": _pom,
    "bundler": _gemfile,
    "cargo": _cargo,
}


def parse_manifest(kind: str, text: str) -> list[dict[str, Any]]:
    parser = MANIFEST_PARSERS.get(kind)
    return parser(text) if parser else []


# --- inventory ---------------------------------------------------------------------------
@dataclass
class Inventory:
    files: int = 0
    loc: int = 0
    bytes: int = 0
    languages: dict[str, dict[str, int]] = field(default_factory=dict)
    manifests: list[dict[str, Any]] = field(default_factory=list)
    frameworks: dict[str, dict[str, Any]] = field(default_factory=dict)
    model_artifacts: list[dict[str, Any]] = field(default_factory=list)
    prompt_files: list[str] = field(default_factory=list)
    secret_files: list[str] = field(default_factory=list)
    ci_configs: list[str] = field(default_factory=list)
    dockerfiles: list[str] = field(default_factory=list)
    tool_calling_files: list[str] = field(default_factory=list)
    mcp_files: list[str] = field(default_factory=list)
    notebooks: list[str] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        frameworks = [
            {"name": name, "kind": info["kind"], "files": info["files"][:12], "count": len(info["files"])}
            for name, info in sorted(self.frameworks.items(), key=lambda kv: (-len(kv[1]["files"]), kv[0]))
        ]
        return {
            "files": self.files,
            "loc": self.loc,
            "bytes": self.bytes,
            "languages": dict(sorted(self.languages.items(), key=lambda kv: (-kv[1]["loc"], kv[0]))),
            "manifests": self.manifests,
            "frameworks": frameworks,
            "model_artifacts": self.model_artifacts,
            "prompt_files": self.prompt_files[:200],
            "secret_files": self.secret_files[:200],
            "ci_configs": self.ci_configs[:100],
            "dockerfiles": self.dockerfiles[:100],
            "tool_calling": {
                "detected": bool(self.tool_calling_files),
                "files": self.tool_calling_files[:100],
            },
            "mcp_servers": self.mcp_files[:100],
            "notebooks": self.notebooks[:100],
            "skipped": self.skipped,
            "truncated": self.truncated,
        }


def _framework_hits(text: str, language: str) -> set[str]:
    hits: set[str] = set()
    imports: set[str] = set()
    if language == "python" or language == "notebook":
        for m in IMPORT_PY.finditer(text):
            imports.add((m.group(1) or m.group(2) or "").split(".")[0])
        for name, info in FRAMEWORKS.items():
            if any(
                root in imports
                or any(i.startswith(root.split(".")[0]) for i in imports if root.startswith(i))
                for root in info["python"]
            ):
                hits.add(name)
    elif language in ("javascript", "typescript", "vue", "svelte"):
        for m in IMPORT_JS.finditer(text):
            imports.add(m.group(1))
        for name, info in FRAMEWORKS.items():
            if any(i == pkg or i.startswith(pkg + "/") for i in imports for pkg in info["npm"]):
                hits.add(name)
    for name, info in FRAMEWORKS.items():
        if name not in hits and any(re.search(p, text) for p in info["markers"]):
            hits.add(name)
    return hits


def build_inventory(root: Path, files: list[SourceFile]) -> Inventory:
    inv = Inventory()
    for f in files:
        if not f.is_text:
            fmt = MODEL_ARTIFACT_EXT.get(f.abs_path.suffix.lower(), "unknown")
            inv.model_artifacts.append(
                {"path": f.path, "format": fmt, "bytes": f.size, "pickle_based": fmt in PICKLE_FORMATS}
            )
            continue
        text = f.read_text()
        lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        loc = sum(1 for line in text.splitlines() if line.strip())
        inv.files += 1
        inv.bytes += f.size
        inv.loc += loc
        lang = f.language or "other"
        bucket = inv.languages.setdefault(lang, {"files": 0, "loc": 0})
        bucket["files"] += 1
        bucket["loc"] += loc
        name = os.path.basename(f.path)
        if name in MANIFEST_NAMES:
            kind = MANIFEST_NAMES[name]
            deps = parse_manifest(kind, text)
            inv.manifests.append(
                {
                    "path": f.path,
                    "kind": kind,
                    "dependencies": len(deps),
                    "unpinned": [d["name"] for d in deps if not d["pinned"]][:100],
                    "ai_packages": sorted({d["name"] for d in deps if d["name"].lower() in AI_PACKAGES}),
                }
            )
        if SECRET_FILE_NAMES.match(name) and not name.endswith((".example", ".sample", ".template")):
            inv.secret_files.append(f.path)
        if CI_PATHS.search(f.path):
            inv.ci_configs.append(f.path)
        if DOCKER_PATHS.search(f.path):
            inv.dockerfiles.append(f.path)
        if lang == "notebook":
            inv.notebooks.append(f.path)
        if lang in ("prompt", "jinja") or (
            lang in ("text", "markdown", "yaml") and PROMPT_FILE_HINTS.search(text[:20000])
        ):
            inv.prompt_files.append(f.path)
        if lang in CODE_LANGUAGES or lang == "notebook":
            for hit in _framework_hits(text, lang):
                inv.frameworks.setdefault(hit, {"kind": FRAMEWORKS[hit]["kind"], "files": []})[
                    "files"
                ].append(f.path)
            if any(p.search(text) for p in TOOL_CALLING_MARKERS):
                inv.tool_calling_files.append(f.path)
            if any(p.search(text) for p in MCP_MARKERS):
                inv.mcp_files.append(f.path)
        del lines
    return inv
