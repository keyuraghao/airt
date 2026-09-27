"""RAG poisoning and data exfiltration rule pack (AISRF-RG-*): every retrieved chunk is untrusted input."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from . import pyast
from .base import (
    CODE,
    LLM_CALL,
    PROMPT_WORDS,
    PY,
    RAG,
    UNTRUSTED_STRONG,
    FileContext,
    Match,
    Rule,
    absence,
    any_of,
    lines,
    near,
    node_match,
    py,
    rule,
)

PACK = "rag_poisoning_exfil"
INGEST = r"(add_texts\s*\(|add_documents\s*\(|aadd_documents\s*\(|\.upsert\s*\(|from_documents\s*\(|from_texts\s*\(|index\.insert\s*\(|insert_nodes\s*\(|VectorStoreIndex\.from_documents|\.add\s*\(\s*(documents|ids|embeddings|texts)\s*=|addDocuments\s*\(|addVectors\s*\(|\.index\s*\(\s*\{|write_documents\s*\()"
RETRIEVAL_CALLS = re.compile(
    r"(^|\.)(similarity_search|similarity_search_with_score|similarity_search_by_vector|asimilarity_search|max_marginal_relevance_search|as_retriever|get_relevant_documents|aget_relevant_documents|retrieve|aretrieve)$"
)
VECTOR_QUERY = re.compile(r"(^|\.)(query|search|query_points|search_points|knn_search|hybrid_search)$")
SCOPE_KW = {
    "filter",
    "filters",
    "where",
    "namespace",
    "search_kwargs",
    "pre_filter",
    "tenant",
    "metadata_filter",
    "query_filter",
    "filter_expr",
    "expr",
    "partition_names",
    "collection_name",
    "user_id",
    "tenant_id",
}
CONTEXT_NAMES = re.compile(
    r"(?i)^(context|ctx|docs?|documents?|chunks?|retrieved\w*|results?|passages?|page_content|sources?|knowledge|snippets?|evidence|references?|hits|matches|nodes?|memories|memory|search_results?)$"
)
DELIMITED = re.compile(
    r"(<context>|<document|<retrieved|<source|<reference|\[Source:|Source:|BEGIN (CONTEXT|DOCUMENT)|```|<data>|<untrusted)"
)
LOG_CALL = re.compile(
    r"(?i)\b(logger|logging|log|console|print|app\.logger|structlog\w*|logs?)\.?(info|debug|warning|warn|error|exception|log|critical)?\s*\("
)
LOG_SENSITIVE = re.compile(
    r"(?i:(\{|\(|,|\+|%s.*%|f['\"][^'\"]*\{)\s*(prompt|full_prompt|system_prompt|messages|user_message|user_input|user_query|completion|response\.choices|response\.content|response\.text|answer|conversation|transcript|raw_response|llm_response|chat_history|history)\b)"
)
CACHE_DECORATOR = re.compile(
    r"(?i)(lru_cache|functools\.cache|^cache$|\.cache$|cached|memoize|cache_data|cache_resource|st\.cache)"
)
MEMORY_TYPES = r"(ConversationBufferMemory|ConversationBufferWindowMemory|ConversationSummary\w*Memory|ConversationTokenBufferMemory|ChatMessageHistory|InMemoryChatMessageHistory|MemorySaver|InMemorySaver|ConversationChain|VectorStoreRetrieverMemory|BufferMemory|ChatMemory)"
CREDENTIAL_LITERAL = r"['\"][A-Za-z0-9_\-:/.@+=]{12,}['\"]"
ENV_REF = r"(os\.environ|getenv|process\.env|\$\{|\$[A-Z_]|secrets\.|vault|keyring|Settings\(|settings\.|config\.|<[^>]+>|your[_-]|xxx|example|changeme|placeholder|dummy|test-?)"


def _unscoped_retrieval(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    multi_tenant = ctx.search(
        r"(?i)(user_id|tenant|customer_id|org_id|workspace|account_id|current_user|principal)"
    )
    for call in pyast.iter_calls(tree):
        name = pyast.call_name(call)
        kws = {k.arg for k in call.keywords if k.arg}
        if kws & SCOPE_KW:
            continue
        if RETRIEVAL_CALLS.search(name):
            if name.endswith("as_retriever") and any(isinstance(a, ast.Dict) for a in call.args):
                continue
            yield node_match(
                ctx,
                call,
                boost=0.2 if multi_tenant or ctx.has_flag("route") else 0.0,
                note=f"{name}() runs without a filter, namespace or tenant scope",
            )
        elif VECTOR_QUERY.search(name) and (
            kws
            & {
                "vector",
                "query_embeddings",
                "query_vector",
                "embedding",
                "query_embedding",
                "query_texts",
                "data",
                "anns_field",
                "top_k",
                "n_results",
                "limit",
            }
        ):
            yield node_match(
                ctx,
                call,
                boost=0.1 if multi_tenant else -0.1,
                note=f"{name}() runs without a filter or namespace",
            )


def _filter_from_request(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for call in pyast.iter_calls(tree):
        for kw in call.keywords:
            if kw.arg not in SCOPE_KW:
                continue
            value = kw.value
            refs = pyast.names_in(value)
            try:
                src = ast.unparse(value)
            except Exception:
                src = ""
            tainted = [
                r
                for r in refs
                if UNTRUSTED_STRONG.search(r)
                or re.match(r"^(request|req|params|body|payload|form|data|args|kwargs)(\.|$)", r)
            ]
            if (
                tainted
                or re.search(r"json\.loads\(\s*(request|req|body|payload)", src)
                or pyast.is_dynamic_string(value)
            ):
                yield node_match(
                    ctx,
                    call,
                    note=f"{kw.arg}= is built from {', '.join(sorted(tainted)[:3]) or 'runtime input'}",
                )
                break


def _context_in_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("rag"):
        return
    for node in ast.walk(tree):
        if not pyast.is_dynamic_string(node):
            continue
        literal = pyast.literal_text(node)
        if not PROMPT_WORDS.search(literal) or DELIMITED.search(literal):
            continue
        names = {n.split(".")[0] for n in pyast.interpolated(node)}
        ctx_names = sorted(n for n in names if CONTEXT_NAMES.match(n))
        if ctx_names:
            yield node_match(
                ctx,
                node,
                note="retrieved content " + ", ".join(ctx_names[:3]) + " is inlined with the instructions",
            )


def _cached_retrieval(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    for func in pyast.iter_functions(tree):
        if not any(CACHE_DECORATOR.search(d) for d in pyast.decorators(func)):
            continue
        text = pyast.func_text(func, ctx.lines)
        if not (RAG.search(text) or LLM_CALL.search(text)):
            continue
        params = pyast.arg_names(func)
        if any(re.search(r"(?i)(user|tenant|session|principal|account|org)", p) for p in params):
            continue
        yield Match(
            func.lineno,
            func.lineno,
            snippet=ctx.snippet(func.lineno, func.lineno + 2),
            note=f"{func.name} caches retrieval or model results keyed only by its text arguments",
        )


def _shared_memory(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if ctx.search(
        r"(?i)(thread_id|session_id|user_id|per_user|get_session_history|RunnableWithMessageHistory|memories\[|memory_for|session\.)"
    ):
        return
    for node in tree.body:
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == "__init__":
                    for stmt in ast.walk(sub):
                        if (
                            isinstance(stmt, ast.Assign)
                            and isinstance(stmt.value, ast.Call)
                            and re.search(MEMORY_TYPES, pyast.call_name(stmt.value))
                        ):
                            yield node_match(
                                ctx,
                                stmt,
                                note="conversation memory is created once per instance and shared by every caller",
                            )
            continue
        if (
            value is None
            or not isinstance(value, ast.Call)
            or not re.search(MEMORY_TYPES, pyast.call_name(value))
        ):
            continue
        yield node_match(ctx, node, note="module-level conversation memory is shared by every user")
        del targets


RULES: list[Rule] = [
    rule(
        "AISRF-RG-001",
        PACK,
        "Documents indexed without content sanitisation or provenance",
        severity="MEDIUM",
        confidence=0.5,
        category="rag_poisoning",
        cwe="CWE-20",
        description="Text is chunked, embedded and written to the vector store with no visible cleaning step (HTML comments, hidden text, zero-width characters, control tokens) and no author, source or approval metadata.",
        why="Whatever is indexed is retrieved for every user asking a related question; one poisoned document steers answers at scale and the payload hides in comments or invisible spans.",
        remediation=(
            "Strip comments, scripts, hidden styling and zero-width characters at ingestion; normalise whitespace.",
            "Scan chunks for instruction-like patterns and quarantine hits for review.",
            "Store source, author, classification and a content hash with every chunk and require approval before it becomes retrievable.",
        ),
        languages=CODE,
        matcher=absence(
            [INGEST],
            [
                r"(?i)(sanitiz|clean_|strip_|bleach|nh3|scan_|inject|zero.?width|display\s*:\s*none|provenance|content_hash|approved|review|quarantine|moderat|Analyzer\(|guard)"
            ],
            anchor=INGEST,
        ),
        tags=("ingestion",),
    ),
    rule(
        "AISRF-RG-002",
        PACK,
        "Retrieval without a tenant or user scope",
        severity="HIGH",
        confidence=0.5,
        category="rag_poisoning",
        cwe="CWE-284",
        description="Similarity search runs against the whole collection with no metadata filter, namespace or tenant argument. Any user's question can surface chunks from any other user's or department's documents.",
        why="Cross-tenant leakage through retrieval is the most reported RAG incident class: the LLM faithfully summarises documents the caller was never allowed to see.",
        remediation=(
            "Filter every query by the caller's tenant, groups or document ACLs, enforced server side.",
            "Use per-tenant namespaces or collections in the vector store.",
            "Re-check each retrieved chunk against the caller's permissions before it enters the prompt.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_unscoped_retrieval),
            near(
                r"\.(similaritySearch|similaritySearchWithScore|asRetriever|maxMarginalRelevanceSearch)\s*\(",
                None,
                window=4,
                unless=r"(filter|namespace|where|tenant|k:\s*\d+\s*,\s*\{)",
                flag="rag",
            ),
        ),
        tags=("authorization", "retrieval"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-RG-003",
        PACK,
        "Metadata filter or namespace built from request data",
        severity="HIGH",
        confidence=0.65,
        category="rag_poisoning",
        cwe="CWE-639",
        description="The filter, where clause, namespace or collection passed to the vector store comes from request parameters or a formatted string. Callers can widen the filter to other tenants or inject operators the store interprets.",
        why="A filter is an authorisation boundary only when the server writes it; user-controlled filters are the RAG version of IDOR.",
        remediation=(
            "Derive tenant and permission filters from the authenticated session, never from the request body.",
            "Allowlist the few user-selectable filter fields and validate their values.",
            "Combine user selections with the mandatory tenant filter using AND semantics.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_filter_from_request),
            lines(
                r"\b(filter|filters|where|namespace|collection|tenant|collectionName)\s*[:=]\s*(req\.(body|query|params)|request\.(json|args|form|body|get_json)|JSON\.parse\(\s*req|json\.loads\(\s*request|params\[|body\[|payload\[|f['\"]|`[^`]*\$\{)",
                flag="rag",
            ),
        ),
        tags=("authorization", "source:http"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-RG-004",
        PACK,
        "Vector database client connected without authentication",
        severity="MEDIUM",
        confidence=0.6,
        category="rag_poisoning",
        cwe="CWE-306",
        description="A vector store client is created for a remote host without an API key, token or auth configuration. Anyone who can reach the service can read, insert or delete embeddings.",
        why="An open vector database is both a data breach and a poisoning primitive: write access to the index is write access to every future answer.",
        remediation=(
            "Enable authentication on the vector service and pass credentials from a secret store.",
            "Restrict network access to the service and separate read and write credentials.",
            "Enable audit logging on the collection.",
        ),
        languages=CODE,
        matcher=lines(
            r"(QdrantClient\s*\((?![^)\n]*api_key)[^)\n]*(url|host)\s*=\s*['\"]https?://(?!localhost|127\.0\.0\.1)|chromadb\.HttpClient\s*\((?![^)\n]*(headers|settings|auth))[^)\n]*host\s*=|weaviate\.(Client|connect_to_custom|connect_to_wcs|connect_to_weaviate_cloud)\s*\((?![^)\n]*auth)[^)\n]*(url|host|cluster_url)\s*=|MilvusClient\s*\((?![^)\n]*(token|password))[^)\n]*uri\s*=\s*['\"]https?://(?!localhost|127\.0\.0\.1)|Elasticsearch\s*\(\s*['\"]http://(?!localhost|127\.0\.0\.1)|new QdrantClient\s*\(\s*\{(?![^}\n]*apiKey)[^}\n]*url|new ChromaClient\s*\(\s*\{(?![^}\n]*auth)[^}\n]*path\s*:\s*['\"]https?://(?!localhost)|weaviate\.client\s*\(\s*\{(?![^}\n]*(apiKey|authClientSecret))[^}\n]*host)"
        ),
        tags=("auth", "vector-store"),
    ),
    rule(
        "AISRF-RG-005",
        PACK,
        "Retrieved chunks inlined into the prompt without delimiters or provenance",
        severity="HIGH",
        confidence=0.55,
        category="indirect_prompt_injection",
        cwe="CWE-74",
        description="Retrieved context is concatenated into the instruction text with no delimiter, no source label and no statement that it is reference data. Instructions hidden in a chunk read exactly like the developer's.",
        why="Delimiters do not stop injection, but without them the model has no cue at all to distinguish evidence from orders.",
        remediation=(
            "Wrap retrieved content in a clearly labelled block with the source of each chunk and tell the model it is data.",
            "Scan chunks for injection patterns before they enter the prompt and drop suspicious ones.",
            "Keep instructions in the system message and context in a separate user or tool message.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_context_in_prompt),
            lines(
                r"\$\{\s*(context|docs|documents|chunks|retrieved\w*|results|passages|sources|snippets|evidence)\w*\s*\}",
                requires=r"(?i)(you are|answer|summari[sz]e|instruction|question:|based on)",
                unless=DELIMITED.pattern,
                flag="rag",
            ),
        ),
        tags=("indirect", "sink:prompt"),
        engines=("rules", "semgrep"),
    ),
    rule(
        "AISRF-RG-006",
        PACK,
        "Answers rendered as Markdown with images or external links allowed",
        severity="HIGH",
        confidence=0.55,
        category="data_exfiltration",
        cwe="CWE-200",
        description="Assistant answers are rendered with a Markdown component that keeps images and arbitrary links. A poisoned document can make the model emit an image whose URL carries conversation data to an attacker; the browser fetches it with no click.",
        why="Markdown image exfiltration has been demonstrated against multiple production assistants; it needs only rendering, not code execution.",
        remediation=(
            "Disallow img elements (or proxy images through your own domain) in rendered answers.",
            "Rewrite links to an allowlist of hosts and show the destination on hover.",
            "Strip URLs containing long encoded query strings from model output before rendering.",
        ),
        languages=CODE,
        matcher=any_of(
            absence(
                [
                    r"(<ReactMarkdown|<Markdown\b|<MarkdownRenderer|\bremark\(|\bmarked(\.parse)?\s*\(|markdownit\s*\(|md\.render\s*\(|unified\(\)|<MDXRemote|react-markdown)",
                    r"(?i)(chat|answer|response|assistant|completion|message)",
                ],
                [
                    r"(disallowedElements|allowedElements|urlTransform|transformImageUri|transformLinkUri|skipHtml|sanitize|DOMPurify|rehypeSanitize|allowedTags|noImages|strip_images|['\"]img['\"]|linkTarget|imageProxy)"
                ],
                anchor=r"(<ReactMarkdown|<Markdown\b|<MarkdownRenderer|\bremark\(|\bmarked(\.parse)?\s*\(|markdownit\s*\(|md\.render\s*\(|unified\(\)|<MDXRemote)",
            ),
            absence(
                [
                    r"(markdown\.markdown\s*\(|markdown2\.markdown\s*\(|mistune\.(html|markdown|create_markdown)\s*\()",
                    r"(?i)(answer|response|completion|output|assistant)",
                ],
                [r"(?i)(bleach|nh3|strip_images|no_images|allowlist|['\"]img['\"]|image_proxy|linkify_safe)"],
                anchor=r"(markdown\.markdown\s*\(|markdown2\.markdown\s*\(|mistune\.(html|markdown|create_markdown)\s*\()",
            ),
        ),
        tags=("exfil", "markdown"),
    ),
    rule(
        "AISRF-RG-007",
        PACK,
        "Prompts or model responses written to logs",
        severity="MEDIUM",
        confidence=0.5,
        category="pii",
        cwe="CWE-532",
        description="Full prompts, message lists, retrieved context or model responses are passed to a logger or printed. Logs are copied to systems with weaker access control than the application database.",
        why="Prompts carry PII, secrets pasted by users and retrieved confidential documents; logging them creates a second, less protected copy.",
        remediation=(
            "Log identifiers, token counts, latency and guardrail verdicts instead of content.",
            "If content must be logged for debugging, redact PII and secrets first and restrict retention and access.",
            "Keep the debug flag off in production.",
        ),
        languages=CODE,
        matcher=lines(
            LOG_CALL.pattern + r"[^\n]*" + LOG_SENSITIVE.pattern,
            flag=("ai", "rag"),
            unless=r"(?i)(redact|mask|scrub|len\(|\.count|token|truncat|\[:\d)",
        ),
        tags=("logging", "pii"),
    ),
    rule(
        "AISRF-RG-008",
        PACK,
        "Query results or prompts cached without a user scope",
        severity="MEDIUM",
        confidence=0.5,
        category="data_exfiltration",
        cwe="CWE-524",
        description="Retrieval or completion results are memoised or cached keyed only by the query text (a cache decorator, a query-keyed cache entry or a global LLM cache). A privileged user's answer is served verbatim to the next caller with the same question.",
        why="Caches erase the authorisation that was applied when the first answer was produced.",
        remediation=(
            "Include the user or tenant identity and the permission set in every cache key.",
            "Use short TTLs and never cache answers that included restricted documents.",
            "Disable global LLM caches in multi-tenant services.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_cached_retrieval),
            lines(
                r"(cache\.(get|set)\s*\(\s*(query|question|prompt|q|text|key)\b|cache_key\s*=\s*[^\n]*(query|question|prompt)|set_llm_cache\s*\(|InMemoryCache\s*\(|SQLiteCache\s*\(|RedisCache\s*\(|GPTCache|cacheKey\s*=\s*[^\n]*(query|question|prompt))",
                unless=r"(?i)(user|tenant|session|principal|account)",
                flag=("ai", "rag"),
            ),
        ),
        tags=("cache",),
    ),
    rule(
        "AISRF-RG-009",
        PACK,
        "No PII scrubbing before indexing sensitive records",
        severity="LOW",
        confidence=0.35,
        category="pii",
        cwe="CWE-359",
        description="Records that look personal (customers, patients, employees, tickets, mail) are embedded and indexed and the module shows no de-identification step.",
        why="Once personal data is embedded it is retrievable by anyone who phrases the right question, and it is hard to delete from an index.",
        remediation=(
            "Detect and redact or pseudonymise PII before chunking (for example with a PII analyzer) and keep the mapping out of the index.",
            "Store classification metadata so retrieval can exclude sensitive chunks per caller.",
            "Implement deletion workflows for the index to honour erasure requests.",
        ),
        languages=CODE,
        matcher=absence(
            [
                INGEST,
                r"(?i)(email|phone|ssn|customer|patient|employee|user_?record|ticket|support|crm|hr_|medical|health|payroll|salary|address)",
            ],
            [r"(?i)(presidio|scrub|anonymi|redact|pii|mask|deidentif|Analyzer\(|dlp|pseudonym)"],
            anchor=INGEST,
        ),
        tags=("pii", "ingestion"),
    ),
    rule(
        "AISRF-RG-010",
        PACK,
        "Vector store or embedding service credential hardcoded",
        severity="HIGH",
        confidence=0.8,
        category="secrets",
        cwe="CWE-798",
        description="An API key, token or password for a vector database or embedding service is written into source code or configuration instead of being read from a secret store.",
        why="Anyone with repository access owns the index: they can read every embedded document and poison future answers.",
        remediation=(
            "Move the credential to environment variables or a secret manager and rotate it now.",
            "Use scoped keys (read-only for query paths) and enable audit logging on the service.",
        ),
        languages=("*",),
        matcher=lines(
            r"(?i)((pinecone|qdrant|weaviate|milvus|zilliz|chroma|pgvector|elastic|opensearch|supabase|turbopuffer|lancedb|vectara|voyage|embedding)\w*[_-]?(api[_-]?key|token|secret|password)\s*[=:]\s*"
            + CREDENTIAL_LITERAL
            + r"|AuthApiKey\s*\(\s*['\"][^'\"]{10,}['\"]|Auth\.api_key\s*\(\s*['\"][^'\"]{10,}|QdrantClient\s*\([^)]*api_key\s*=\s*['\"][^'\"]{10,}['\"]|api_key\s*[=:]\s*['\"]pcsk_[^'\"]+['\"]|postgres(ql)?://[^:\s'\"]+:[^@\s'\"]{6,}@)",
            unless=ENV_REF,
            skip_comments=False,
        ),
        tags=("secrets",),
    ),
    rule(
        "AISRF-RG-011",
        PACK,
        "Web crawl ingestion without a domain allowlist",
        severity="MEDIUM",
        confidence=0.5,
        category="rag_poisoning",
        cwe="CWE-345",
        description="Web pages are loaded into the knowledge base from URLs held in variables, and the module has no allowlist of trusted domains. Attackers only need to get a URL into the crawl list, or control a page that is already on it.",
        why="Crawled content is fully attacker controlled and is the cheapest way to plant persistent injections and phishing links.",
        remediation=(
            "Restrict crawling to an explicit allowlist of domains and paths; validate every URL before fetching.",
            "Strip hidden content and scan pages for injection patterns before indexing.",
            "Re-crawl on a schedule and diff content to catch tampering.",
        ),
        languages=CODE,
        matcher=absence(
            [
                r"(WebBaseLoader|RecursiveUrlLoader|SitemapLoader|AsyncHtmlLoader|AsyncChromiumLoader|UnstructuredURLLoader|SeleniumURLLoader|PlaywrightURLLoader|CheerioWebBaseLoader|PuppeteerWebBaseLoader|SimpleWebPageReader|BeautifulSoupWebReader|TrafilaturaWebReader|FireCrawlLoader|ApifyDatasetLoader|scrapy|crawl\w*\s*\()\s*\(?\s*[^'\")\n]*\b(url|urls|link|links|sitemap|pages|start_urls)\b"
            ],
            [
                r"(?i)(allowlist|allow_list|allowed_domains|ALLOWED|hostname in|robots|whitelist|trusted_domains|domain_filter|url_filter|same_origin)"
            ],
            anchor=r"(WebBaseLoader|RecursiveUrlLoader|SitemapLoader|AsyncHtmlLoader|AsyncChromiumLoader|UnstructuredURLLoader|SeleniumURLLoader|PlaywrightURLLoader|CheerioWebBaseLoader|PuppeteerWebBaseLoader|SimpleWebPageReader|BeautifulSoupWebReader|TrafilaturaWebReader|FireCrawlLoader|ApifyDatasetLoader|scrapy|crawl\w*\s*\()",
        ),
        tags=("ingestion", "source:web"),
    ),
    rule(
        "AISRF-RG-012",
        PACK,
        "Conversation memory shared across users",
        severity="MEDIUM",
        confidence=0.5,
        category="data_exfiltration",
        cwe="CWE-668",
        description="A conversation memory or message history object is created once (module level, singleton or per service instance) and the module never keys it by user, session or thread. Turns from one user become context for the next.",
        why="Shared memory leaks conversations across users and lets an injection planted by one user persist into everyone else's sessions.",
        remediation=(
            "Create memory per user and session (or use thread ids with a checkpointer) and cap its size.",
            "Clear memory on logout and after inactivity.",
            "Sanitise turns before saving them back into memory.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_shared_memory),
            absence(
                [
                    r"^(const|let|var)\s+(history|messages|memory|conversation|chatHistory)\s*=\s*(\[\]|new Map\(|\{\}|new (BufferMemory|ChatMessageHistory|InMemoryChatMessageHistory)\()"
                ],
                [r"(?i)(userId|sessionId|threadId|thread_id|per_user|Map<|\[userId\]|\[sessionId\])"],
                flag="ai",
                anchor=r"^(const|let|var)\s+(history|messages|memory|conversation|chatHistory)\s*=",
            ),
        ),
        tags=("memory", "isolation"),
    ),
]
_ = PY

UPLOAD_SOURCE = (
    r"(request\.files|UploadFile|File\(|req\.file\b|multer|formData\.get\(\s*['\"]file|busboy|formidable)"
)
TENANT_SCOPE = r"(?i)(namespace|tenant|user_id|owner_id|per_user|\bacl\b|visibility|collection_name\s*=\s*f|private|access_group|allowed_users)"
METADATA_NAMES = re.compile(
    r"(?i)(filename|file_name|\.name$|metadata|\.title$|\.subject$|\.author$|headers?$|attachment|page_title|doc_title|source_url)"
)


def _metadata_in_prompt(ctx: FileContext, tree: ast.Module) -> Iterator[Match]:
    if not ctx.has_flag("ai", "rag"):
        return
    for node in ast.walk(tree):
        if not pyast.is_dynamic_string(node):
            continue
        literal = pyast.literal_text(node)
        if not PROMPT_WORDS.search(literal):
            continue
        hits = sorted(n for n in pyast.interpolated(node) if METADATA_NAMES.search(n))
        if hits:
            yield node_match(
                ctx,
                node,
                note="document metadata " + ", ".join(hits[:3]) + " is interpolated into the prompt",
            )


RULES += [
    rule(
        "AISRF-RG-013",
        PACK,
        "User uploads indexed into a shared collection",
        severity="HIGH",
        confidence=0.5,
        category="rag_poisoning",
        cwe="CWE-284",
        description="Files uploaded through an HTTP handler are chunked and written to the vector store, and the module never scopes them by namespace, tenant or owner. Every user's questions can now retrieve every other user's uploads, and one upload can steer answers for everyone.",
        why="Upload plus shared index is the cheapest poisoning and cross-tenant leakage path there is: no insider access required.",
        remediation=(
            "Index uploads into a per-user or per-tenant namespace and filter retrieval by the same key.",
            "Sanitise and scan uploaded content before indexing and keep it pending until reviewed if it is shared.",
            "Record the uploader and a content hash with every chunk.",
        ),
        languages=CODE,
        matcher=absence([UPLOAD_SOURCE, INGEST], [TENANT_SCOPE], anchor=INGEST, flag="rag"),
        tags=("ingestion", "authorization"),
    ),
    rule(
        "AISRF-RG-014",
        PACK,
        "File names or document metadata interpolated into the prompt",
        severity="MEDIUM",
        confidence=0.45,
        category="indirect_prompt_injection",
        cwe="CWE-74",
        description="Titles, file names, authors, source URLs or other metadata fields are formatted into the prompt alongside the instructions. Metadata is attacker controlled just like the document body, and it is rarely sanitised.",
        why="A file name is a free text field that survives every content filter and lands right next to the instructions.",
        remediation=(
            "Treat metadata as data: place it inside the same delimited block as the chunk text and truncate it.",
            "Allowlist characters and length for names and titles at ingestion time.",
        ),
        languages=CODE,
        matcher=any_of(
            py(_metadata_in_prompt),
            lines(
                r"\$\{\s*[\w.]*(filename|fileName|metadata|title|subject|author|sourceUrl)\b",
                requires=r"(?i)(you are|answer|summari[sz]e|instruction|question:|based on|context:)",
                flag=("ai", "rag"),
            ),
        ),
        tags=("indirect", "metadata"),
    ),
]
