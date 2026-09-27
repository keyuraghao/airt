"""Single source of truth for what goes into the PyInstaller bundle.

Imported by ``aisrf.spec`` (at build time) and by ``tests/test_packaging.py`` (to check that every
package-data directory on disk is listed here). It must stay importable without PyInstaller.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE = "aisrf"

# Directories of non-Python package data, relative to the aisrf package. Every one of them is
# copied verbatim to <bundle>/_internal/aisrf/<dir> so that Path(__file__).parent lookups keep working.
PACKAGE_DATA_DIRS: tuple[str, ...] = (
    "dashboard/templates",
    "dashboard/static",
    "redteam/corpus",
    "guardrails/nemo_default",
    "codereview/rules/semgrep",
)

# Packages that are imported lazily inside functions (or resolved from strings by uvicorn,
# SQLAlchemy and pydantic) and therefore invisible to PyInstaller's static analysis.
HIDDEN_IMPORTS: tuple[str, ...] = (
    # uvicorn resolves loops, protocols and lifespan classes from strings
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.loops.uvloop",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    # database
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.dialects.sqlite.aiosqlite",
    "sqlalchemy.dialects.sqlite.pysqlite",
    "sqlalchemy.ext.asyncio",
    "aiosqlite",
    # web stack
    "anyio._backends._asyncio",
    "sse_starlette",
    "sse_starlette.sse",
    "jinja2",
    "jinja2.ext",
    "multipart",
    "python_multipart",
    "itsdangerous",
    "orjson",
    "dotenv",
    "email.mime.multipart",
    "email.mime.text",
    # logging and CLI
    "structlog",
    "structlog.dev",
    "structlog.processors",
    "structlog.contextvars",
    "typer",
    "rich",
    "rich.console",
    "rich.panel",
    "rich.table",
    "shellingham",
    # data formats and reports
    "yaml",
    "openpyxl",
    "openpyxl.styles",
    "openpyxl.utils",
    "reportlab",
    "reportlab.graphics.charts.barcharts",
    "reportlab.graphics.charts.piecharts",
    "reportlab.graphics.shapes",
    "reportlab.lib.styles",
    "reportlab.platypus",
    "reportlab.pdfbase._fontdata",
    "PIL",
    "PIL.Image",
    # MCP server (both the 1.x and 2.x module layouts are tried at import time)
    "mcp",
    "mcp.server",
    "mcp.server.fastmcp",
    "mcp.server.streamable_http_manager",
    "mcp.server.stdio",
    "mcp.client.streamable_http",
    "httpx_sse",
    "jsonschema",
    "jsonschema_specifications",
    "opentelemetry.trace",
    "opentelemetry.context",
    # crypto
    "cryptography.fernet",
    "cryptography.hazmat.backends.openssl",
)

# Whole packages collected with collect_submodules(): the aisrf tree (many modules are imported
# inside functions) and third-party packages that import their own submodules dynamically.
COLLECT_SUBMODULES: tuple[str, ...] = (
    "aisrf",
    "mcp",
    "sqlalchemy.dialects.sqlite",
    "reportlab.graphics",
    "reportlab.pdfbase",
    "reportlab.platypus",
    "openpyxl",
    "structlog",
    "uvicorn",
    "sse_starlette",
    "pydantic_settings",
)

# Third-party packages whose non-Python files must ship (fonts, templates, metadata).
COLLECT_DATA: tuple[str, ...] = (
    "reportlab",
    "openpyxl",
    "mcp",
)

# Optional and heavy dependencies. They are imported behind try/except in aisrf and stay
# opt-in (`pip install "aisrf[all]"`); excluding them keeps the binary a fraction of the size.
# Do not add PIL (reportlab.lib.utils imports it unconditionally) or opentelemetry.trace (mcp 2.x).
EXCLUDES: tuple[str, ...] = (
    "torch",
    "torchvision",
    "torchaudio",
    "triton",
    "xformers",
    "transformers",
    "tokenizers",
    "sentence_transformers",
    "huggingface_hub",
    "safetensors",
    "accelerate",
    "datasets",
    "onnxruntime",
    "fastembed",
    "numpy",
    "pandas",
    "pyarrow",
    "scipy",
    "sklearn",
    "sympy",
    "networkx",
    "spacy",
    "thinc",
    "nltk",
    "presidio_analyzer",
    "presidio_anonymizer",
    "garak",
    "pyrit",
    "llm_guard",
    "nemoguardrails",
    "rebuff",
    "semgrep",
    "bandit",
    "playwright",
    "mitmproxy",
    "langchain",
    "langchain_core",
    "langchain_openai",
    "langchain_anthropic",
    "langgraph",
    "langsmith",
    "litellm",
    "openai",
    "anthropic",
    "cohere",
    "mistralai",
    "ollama",
    "replicate",
    "tiktoken",
    "boto3",
    "botocore",
    "s3transfer",
    "google",
    "googleapiclient",
    "azure",
    "msal",
    "grpc",
    "opentelemetry.sdk",
    "opentelemetry.exporter",
    "opentelemetry.instrumentation",
    "av",
    "zstandard",
    "cairosvg",
    "cairocffi",
    "lxml",
    "docx",
    "pypdf",
    "faker",
    "pyodbc",
    "peewee",
    "sqlite_utils",
    "llm",
    "loguru",
    "cmd2",
    "prompt_toolkit",
    "IPython",
    "matplotlib",
    "tkinter",
    "_tkinter",
    "pytest",
    "_pytest",
    "coverage",
    "ruff",
    "webview",
    "PyInstaller",
    "setuptools",
    "pkg_resources",
    "watchfiles",
    "nvidia",
    "cuda",
    "wn",
)


def package_root(repo_root: Path) -> Path:
    return repo_root / PACKAGE


def data_pairs(repo_root: Path) -> list[tuple[str, str]]:
    """(source, destination) pairs in PyInstaller's ``datas`` format for every package-data directory."""
    root = package_root(repo_root)
    pairs: list[tuple[str, str]] = []
    for rel in PACKAGE_DATA_DIRS:
        src = root / rel
        if src.is_dir():
            pairs.append((str(src), f"{PACKAGE}/{rel}"))
    return pairs


def data_dirs_on_disk(repo_root: Path) -> set[str]:
    """Package directories that contain non-Python files (what the manifest must cover)."""
    root = package_root(repo_root)
    found: set[str] = set()
    for path in root.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        if path.suffix in {".py", ".pyc", ".pyo"}:
            continue
        found.add(path.parent.relative_to(root).as_posix())
    return found
