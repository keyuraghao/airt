# Request normalization

`aisrf/gateway/parser.py` turns any request body into one provider-agnostic structure that the analyzers, the policy engine, the canary injector and the ticket detail page all consume, and does the reverse for responses. The parser is pure: it never fails on unknown input, it degrades to a generic string walk.

## Entry point

```python
normalize(path: str, body_bytes: bytes, provider_hint: str = "") -> dict
```

`path` is the stored ticket path (`v1/chat/completions`, `v1/messages`, `v1beta/models/gemini-pro:generateContent`, ...). `provider_hint` is the agent's `upstream_provider` and is copied into the result as `provider`; it does not change parsing. A body that is not valid JSON is treated as absent for shape detection.

## Endpoint detection

`detect_endpoint(path, body)` examines the lower-cased path first, then the body:

| Condition (first match wins) | `endpoint` |
| --- | --- |
| path contains `chat/completions` | `chat` |
| path contains `/responses` or ends with `responses` | `responses` |
| path contains `/messages` or ends with `messages` | `messages` |
| path contains `embeddings` or `embed` | `embeddings` |
| path contains `completions` or ends with `generate` | `completion` |
| path contains `generatecontent` | `gemini` |
| body has a `messages` key | `chat` |
| body has a `prompt` key | `completion` |
| otherwise | `other` |

## What the parser understands

For a JSON object body:

| Shape | Recognised by | Extracted |
| --- | --- | --- |
| OpenAI chat completions | `messages` list | Each message's `role`, flattened `content`, `name`; `tool_calls` appended as `[tool_call <name>] <arguments>` lines; `system` and `developer` roles concatenated into `system` |
| OpenAI legacy completions | `prompt` (string or list) | One `user` message with the prompt (lists joined with newlines) |
| OpenAI responses API | `input` present and endpoint in `responses`, `embeddings`, `other` | If `input` is a list of role objects, one message per item; otherwise one `user` message; `instructions` becomes `system` |
| OpenAI embeddings | `input` on an `embeddings` endpoint | Same rule as above: the text to embed becomes the user message |
| Anthropic messages | `messages` list plus top-level `system` (string or list of text blocks) | `system` flattened; messages as for OpenAI; `tool_use` blocks rendered as `[tool_use <name>] <json input>` and `tool_result` blocks flattened |
| Google Gemini | `contents` list; optional `systemInstruction.parts` | One message per content entry with `role` and flattened `parts`; `systemInstruction` becomes `system` |
| Ollama chat and generate | `messages` (chat) or `prompt` (generate) | Same rules as OpenAI chat and completions |
| Cohere chat | `message` string, optional `chat_history` | History entries (lower-cased `role`, `message`) inserted before the final `user` message |
| Generic JSON | none of the above produced messages or a system prompt | Every non-empty string in the document (depth <= 12) joined with newlines into a single `user` message |

For a non-JSON body, the first 20000 bytes decoded as UTF-8 (replacement characters for invalid bytes) become one `user` message.

Common extraction applied to every JSON object:

* `model` (as string) and `stream` (as bool).
* `tools`: for each entry, `function.name` and `function.description` when present (OpenAI style), else the entry's own `name` and `description` (Anthropic style), falling back to `type` or `tool` as the name.
* `extra`: `tool_choice`, `temperature`, `max_tokens`, `max_completion_tokens`, `top_p`, `n`, `user`, `metadata`, `response_format` when present.

### Content flattening

`_text_of(content)` handles strings, lists and dicts. In lists, parts of type `text`, `input_text`, `output_text` (or any part carrying a `text` key) contribute their text; `tool_result` parts are flattened recursively; `tool_use` parts become `[tool_use <name>] <json>`; `image_url`, `image` and `input_image` become `[image]`; `input_audio` and `audio` become `[audio]`; `file` becomes `[file]`. Parts are joined with newlines.

## Normalized structure

| Field | Type | Meaning |
| --- | --- | --- |
| `provider` | string | The `provider_hint` (the agent's `upstream_provider`) |
| `endpoint` | string | `chat`, `responses`, `messages`, `embeddings`, `completion`, `gemini`, `other` |
| `model` | string | `body.model` or empty |
| `stream` | bool | `body.stream` |
| `system` | string | Concatenated system, developer and instruction text |
| `messages` | list | `{"role", "content", "name"?}` in conversation order (system messages are included here too) |
| `tools` | list | `{"name", "description"}` |
| `extra` | dict | Sampling and routing parameters listed above |
| `prompt_text` | string | The text analyzers scan (see below) |
| `last_user_message` | string | Content of the last message with role `user` |
| `preview` | string | The queue preview (see below) |
| `message_count` | int | `len(messages)` |
| `char_count` | int | `len(prompt_text)` |
| `canary` | string | Added by the gateway after normalization when a canary was injected (not produced by the parser) |

## How `prompt_text` and `preview` are built

* `user_texts` is the content of every message whose role is neither `system` nor `developer` (so `user`, `assistant`, `tool`, `function`, `model`, and so on all count).
* `prompt_text` is `system` followed by every entry of `user_texts`, skipping empty parts, joined with a blank line (two newline characters). This is what `auto_deny_patterns`, `global_auto_deny_patterns`, custom rules and most analyzers evaluate.
* `last_user_message` is the last message with role exactly `user`.
* `preview` is `last_user_message`, or `prompt_text` when there is no user message, stripped, with newlines replaced by spaces, cut to 480 characters (`MAX_PREVIEW`). It is stored as `prompt_preview` and shown in the queue, notifications and reports.

## Response text extraction

```python
extract_response_text(body_bytes: bytes, endpoint: str = "") -> str
```

Used by `_finish()` and `pipeline.submit()` to feed the response analyzers and to build `response_preview` (first 500 characters). Empty input returns an empty string.

### SSE bodies

If the decoded body starts with `data:` or contains a line starting with `data:`, every `data:` line is parsed as JSON (skipping `[DONE]` and blanks) and text is collected from:

* OpenAI chat chunks: `choices[].delta.content` and `choices[].text`;
* Anthropic streams: events with `type == "content_block_delta"` and `delta.text`;
* OpenAI responses API streams: events with `type == "response.output_text.delta"` and a `delta` string.

The pieces are concatenated without separators.

### JSON bodies

Checked in this order, first match wins:

| Body shape | Extracted |
| --- | --- |
| `choices` | For each choice: `message.content` (flattened), each `message.tool_calls[]` as `[tool_call <name>] <arguments>`, and `text`; joined with newlines |
| `content` is a list (Anthropic) | Flattened content blocks |
| `output` is a list (OpenAI responses) | Each item's flattened `content`, joined with newlines |
| `output_text` | That string |
| `candidates` (Gemini) | Flattened `content.parts` of every candidate |
| `message` is a dict (Ollama chat) | `message.content` |
| `response` is a string (Ollama generate) | That string |
| `text` is a string | That string |
| anything else | Every string in the document joined with newlines, cut to 20000 characters |

A body that is not JSON (or not a JSON object) is returned as raw text cut to 20000 characters.

## Examples

Anthropic request:

```json
{"model": "claude-3-5-haiku-latest", "system": "You are terse.", "max_tokens": 50,
 "messages": [{"role": "user", "content": [{"type": "text", "text": "Summarise this"}]}]}
```

normalizes on path `v1/messages` to `endpoint: messages`, `system: "You are terse."`, one user message `Summarise this`, `prompt_text` equal to the system text, a blank line and `Summarise this`, `preview: "Summarise this"`, `extra: {"max_tokens": 50}`.

Gemini request on `v1beta/models/gemini-pro:generateContent`:

```json
{"systemInstruction": {"parts": [{"text": "Be safe"}]}, "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
```

gives `endpoint: gemini`, `system: "Be safe"`, one user message `hi`. Note that `model` is empty because Gemini puts it in the path, so `allowed_models` is not applied to such requests.

Related: [[Gateway-Endpoints-and-Headers]], [[Analyzers]], [[Canary-Words]].
