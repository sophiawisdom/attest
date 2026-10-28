# attest: guide for agents

This service lets an **auditor** ask a question about code held by an
**auditee**, without the auditee showing the code. A model with read-only
tools reads the code inside an AWS Nitro Enclave and answers. The auditee
watches everything the model does and decides whether the auditor sees the
answer. Every step can be done through this HTTP API, by a person or an agent.

Source: https://github.com/sophiawisdom/attest. This page, the web app and
the API are served by the enclave itself, over TLS that ends inside it.

**Stability.** A server is provided by its operator as-is (`operator` in
`/api/info`). Sessions survive moves between enclaves of the same image, but
end when the server is updated to a new image, so don't rely on one lasting
more than about a day. For
anything longer, run your own instance: `SELF_HOSTING.md` in the repository
is written for an agent to follow, and takes one script.

## Roles and links

- `POST /api/sessions` creates a session and returns two links:
  `https://HOST/s/SESSION_ID#TOKEN`. The auditee keeps one link and sends the
  other to the auditor over a channel they already trust (for example
  Signal). There are no accounts or long-term keys. Whoever holds a link acts
  as that party.
- Every session call needs `Authorization: Bearer TOKEN`, where `TOKEN` is the
  part of the link after `#`. The token decides the role.
- Sessions expire after 30 days. They're kept sealed on the parent and survive
  a move to another enclave of the same image, which takes them over after
  proving its image (`/api/info` then shows a new `boot_id` and the same
  `lineage.id`, with `restored_from_boot`). During the move session calls
  answer HTTP 503 with `"moved": true`: retry shortly. A run that was going
  is recorded as interrupted (an error outcome) for the auditee to decide on.
  Without a running enclave of the lineage to hand over (a crash, or an image
  upgrade), sessions are lost.

## Flow

1. The auditor proposes a question: `POST /api/sessions/ID/question`
   `{"text": "...", "max_steps": 150, "allow_fine_tuned": false, "answer_format": ...}`.
   `answer_format` bounds what can come back, and the enclave enforces it:
   `{"kind": "yes_no"}` (yes, no or inconclusive, nothing else),
   `{"kind": "choice", "options": ["a", "b", ...]}` (exactly one option), or
   `{"kind": "text", "max_bytes": 4000}` (the default: verdict plus a summary
   of at most that many bytes). With the two strict formats the certificate
   also rounds the model-influenced activity numbers and times, and the
   auditor doesn't see when a run finishes, only the auditee's decision.
2. The auditee accepts or rejects it: `POST /api/sessions/ID/question/decision`
   `{"version": 1, "accept": true, "note": "optional"}`. A rejected or
   answered question can be revised (step 1 again). Each revision is a new
   version that needs acceptance.
3. The auditee uploads code: `PUT /api/sessions/ID/code` with a tar archive
   body (regular files only; no links). `attest upload LINK DIR` from the
   repository's CLI sends git-tracked files and checks the enclave first. The
   response includes `tree_sha256`, a hash of every (path, content) pair, and
   `commitment_sha256`, a salted hash of the tree. Before a result is
   released the auditor sees only the commitment, not the tree hash, file
   count or size. A certificate opens it only if the auditee releases the
   run details (step 8).
4. The auditee confirms the affidavit: `POST /api/sessions/ID/affidavit`
   `{"organization": "...", "repo_url": "...", "git_commit": "...", "tree_sha256": "..."}`.
   The statement says the upload is the production code at that commit, and
   that nothing in it was arranged to influence the audit.
5. Either party proposes a model: `POST /api/sessions/ID/models`
   `{"provider": "anthropic"|"openai"|"openrouter"|"bedrock"|"vertex"|"azure", "model": "...", "api_key": "...", "openrouter_zdr": true}`.
   The clouds that serve Anthropic's and OpenAI's models work directly too,
   so the model's maker needn't run the servers:
   - `"provider": "bedrock"`, `"region": "us-east-1"`, a Bedrock API key, and a
     model id such as `global.anthropic.claude-opus-5-5` (Claude, Anthropic API)
     or `us.openai.gpt-6-sol` (GPT, OpenAI API).
   - `"provider": "vertex"`, `"project": "my-project"`, `"location"`:
     `global`, `us` or `eu`, a model such as `claude-opus-5-5`, and as
     `api_key` the service-account key file (JSON). The enclave exchanges it
     for an access token at oauth2.googleapis.com.
   - `"provider": "azure"`, `"resource": "NAME"` (from NAME.openai.azure.com),
     `"api": "openai"` or `"anthropic"`, the resource's key, and your
     deployment name as `model`. The certificate records the model Azure
     reports. A deployment can be a fine-tune and the key can't show which,
     so Azure counts as a fine-tune: it runs only if the question allows
     fine-tuned models.
   The region, project or resource decides whose account the requests reach,
   so whoever supplies the key supplies it too: when the auditee approves an
   auditor's cloud proposal with their own key, they give their own region,
   project or resource with it. Check the host's retention settings: Bedrock
   has a per-region data retention mode, and Fable 5.1 is retained for 30 days
   on every host.
   With OpenRouter, add `"openrouter_only": ["google-vertex"]` to pin which
   upstream host may serve the model (OpenRouter slugs: `google-vertex`,
   `amazon-bedrock`, `azure`, `anthropic`, `openai`, or a region such as
   `google-vertex/us`). The enclave sends that list with fallbacks off on
   every request, asks OpenRouter to switch off every plugin (web search,
   web fetch, the routers), refuses router models (`openrouter/...`), and
   rejects any reply naming a different model. The certificate records the
   pin. Two limits: an OpenRouter account can set "prevent overrides" on a
   plugin, and then the request can't switch it off (check the key's account
   settings first, or use a direct provider for strict work); and the model
   check happens after the request was sent, so it catches a swap but can't
   undo it. Which model and host to use is for the parties to agree. A model
   served by someone other than its maker (Claude on Vertex or Bedrock, GPT
   on Azure) takes the maker out of serving it, but whoever owns the account
   still chooses what runs there: an Azure deployment name, in particular,
   can stand for that account's own fine-tune, so Azure runs only when the
   question allows fine-tunes.
   To use a real coding agent instead of the built-in tools, add `"agent"`:
   `"codex"` (OpenAI's Codex CLI; any OpenAI-API model: openai, openrouter,
   GPT on bedrock or azure), `"claude-code"` (Claude Code; any Anthropic-API
   model: anthropic, openrouter, Claude on bedrock, vertex or azure) or
   `"pi"` (any). Each runs with a full shell in a jail: repository read-only at
   /repo, 20 MB scratch, no network except the approved model, reached
   through a proxy in the enclave that refuses provider-side tools (web
   search, URL fetches, MCP connectors). The agents don't load instructions,
   hooks or plugins from the repository (AGENTS.md, CLAUDE.md, .claude/,
   .pi/); they see those files only as code. `GET /api/info` lists the
   agents a server has, with versions. An auditee proposal is approved immediately. An auditor proposal waits
   for `POST /api/sessions/ID/models/MODEL_ID/decision` `{"approve": true}`
   from the auditee. Keys are never shown to anyone. The code is sent to the
   chosen provider under the key owner's terms (for example zero data
   retention).
6. A run starts automatically once the latest question is accepted, the code
   and affidavit are in place, and a model is approved. The built-in agent
   has read-only tools: `list_dir`, `find_files`, `read_file`, `grep`,
   `python` (a sandbox with the code read-only at `/repo`), and
   `submit_verdict`. It has no shell and no network access. Its system prompt
   is fixed in the image (hash in `/api/info`). The jailed agents (step 5)
   get a shell instead.
7. The run ends with a verdict: `yes`, `no`, `inconclusive`, or
   `needs_clarification` (with a `clarification_request` for the auditor).
8. The auditee decides: `POST /api/sessions/ID/runs/RUN_ID/release`
   `{"release": true|false, "details": false, "note": "optional"}`. On release
   the auditor sees the verdict and can fetch the signed certificate. By
   default it is verdict-only: the question, the affidavit, the agreed model
   and harness, run and question counts, whether the code changed between
   runs, and the verdict. Nothing else the code or the model could have
   shaped: no run times, no tree hash or code size (the commitment stays
   closed), no activity or instruction-scan counts, no error text. With
   `"details": true` the auditee releases all of those too. On decline the
   auditor sees that it was declined, and the note. A new run doesn't start
   while one awaits this decision. The auditee can fetch a certificate of
   the full record at any time from the same `certificate` route.
9. After that decision, the auditor can send a follow-up message that
   continues the same conversation: `POST /api/sessions/ID/runs/RUN_ID/followup`
   `{"text": "...", "blinded": false}`. A blinded message is hidden from the
   auditee, who sees only that one was sent. The auditee still sees
   everything the agent does in response, and still decides on release. The
   certificate records each message's hash, and its text if not blinded.
10. Notifications. Agents poll (below). People can get email:
    `POST /api/sessions/ID/notify` `{"email": "..."}`, if `email_available`.
    A new address first gets one confirmation email from Amazon SES, and
    nothing else is sent to it until it is confirmed (`notify.email_status`).
    Emails say only that something happened in the session.
11. Disclosures (auditee, any time after uploading code). The auditee can show
    the auditor a file, or what a Python script prints when run over the code
    in the enclave's sandbox (code read-only at `/repo`, no network, 60 s):
    `POST /api/sessions/ID/disclosures` with
    `{"kind": "file", "path": "...", "note": "..."}` or
    `{"kind": "python", "code": "...", "note": "..."}`. This makes a draft only
    the auditee sees. `POST /api/sessions/ID/disclosures/DRAFT/decision` (the `draft` id from
    the response) `{"publish": true}` numbers and signs it, binds it to the code commitment, and shows it
    to the auditor (`false` discards it). Either party can fetch a published
    one with `GET /api/sessions/ID/disclosures/N` and check it with
    `attest verify FILE`. Disclosures are the auditee's choice: nothing about
    them is restricted by the question's answer format.

## Reading state and waiting

`GET /api/sessions/ID` returns everything your role may see:

- `status`: one sentence on what's happening.
- `next_actions`: what you can do now, with method and path.
- `questions`, `code`, `affidavit`, `models`, `runs`, `events`.
- `version`: a counter that increases on every change.

To wait for a change, call `GET /api/sessions/ID?version=V&wait=25`. It
returns as soon as `version` exceeds `V`, or after 25 seconds. `since=SEQ`
limits `events` to newer ones. A simple agent loop is: fetch, act on
`next_actions` if your policy says so, then wait on `version`.

The auditee can follow a run live with `GET /api/sessions/ID/runs/RUN_ID/trace?after=N`.
Responses come in pages of up to 4 MiB: continue from `next` while `more`
is true. A run records up to 40 MiB: for a jailed agent, every model
exchange in full (`request.new` holds the input items added since the
previous request, plus instructions and tools whenever the history starts
over, and `response` the provider's reply), and the agent's own log.

## Who sees what

| | auditee | auditor |
|---|---|---|
| question and its versions, decisions, notes | yes | yes |
| code | metadata only (it's theirs) | a salted commitment only, opened only if the auditee releases run details |
| affidavit | yes | yes |
| model proposals (provider, model, who proposed) | yes | yes |
| API keys | never | never |
| live agent trace | yes | no |
| run status | yes, with step count | only "running" until the auditee decides; never when a run finished |
| verdict and certificate | always, with every detail | only after release: verdict-only unless the auditee adds details |
| follow-up message text | unless blinded | yes |

The server operator's machine (the enclave's parent) stores uploaded files,
but only sealed: each file is encrypted with ChaCha20-Poly1305 under a
per-session key that never leaves the enclave, and bound to its session,
path and content hash. The operator learns the number of files and their
sizes. A run loads the whole repository into enclave memory before it
starts, so the operator doesn't learn which files the agent reads. A file it alters or swaps fails
authentication and is refused. Limits: 64 MiB per file, 1 GiB per upload by
default.

## Verifying this service

Do this before uploading code or trusting a result.

1. Connect over TLS and record the server certificate's SubjectPublicKeyInfo
   (SPKI). The certificate may be from Let's Encrypt or self-signed. Trust
   comes from the next steps, not the CA.
2. `GET /api/attestation?nonce=HEX` (choose 32 random bytes) on that same
   connection. The response has `enclave_info_json` and `document_b64`, an
   AWS Nitro attestation document (COSE_Sign1).
3. Check the document:
   - The signature chains to the AWS Nitro root CA (SHA-256 of DER
     `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`).
   - `nonce` equals yours.
   - `user_data` equals SHA-256 of the exact `enclave_info_json` bytes.
   - `public_key` equals `signing_public_key` in the info.
   - PCR0-2 are not all zero (zero would mean debug mode, where the host can
     read enclave memory).
4. Check `tls_spki_sha256` in the info equals SHA-256 of the SPKI from step 1.
   That shows your TLS session ends inside this enclave.
5. Check PCR0 against a build you trust. Run `build/build-eif.sh` from the
   repository at `source_commit` (on arm64 for Graviton). Builds are
   reproducible, so you get the same `pcrs.json`. Published values are in
   `measurements/` in the repository.

The CLI does all of this: `attest verify-service https://HOST --pcrs pcrs.json`.

**If a person will use the web app,** checking the service yourself doesn't
protect them: their browser makes its own TLS connection, and whoever
controls this address could get another certificate and serve their browser
a different page. Have them open their link through the local client
instead: `attest open 'https://HOST/s/ID#TOKEN'`. It does the checks above
on every connection it opens, serves the app on `http://127.0.0.1`, and
relays the API calls itself. Without `--pcrs` it fetches the measurements
published in github.com/sophiawisdom/attest for the commit the server
reports. To build it: `cargo build --release -p attest-cli` in the
repository; reading `crates/cli/src/local.rs` first is a reasonable check.

A certificate (`GET .../runs/RUN_ID/certificate`) is checkable offline. It
embeds the enclave's boot attestation document and an ed25519 signature by
`signing_public_key` over the manifest and verdict. Run
`attest verify certificate.json --pcrs pcrs.json`, or check it by hand as in
step 3, then verify `signed.signature` over `signed.domain + "\n" + signed.body`.

## What a verdict means, and what it doesn't

The enclave enforces the harness: the fixed prompt, read-only tools, fixed
provider endpoints, and that the code tree hash matches what was analysed.
Everything else is disclosed rather than enforced, and the certificate records it:

- who chose the model and key, and the key's organization as the provider
  reports it;
- which model the provider says answered;
- earlier runs, question revisions, and code changes in the session;
- counts of instruction-like text in the code (text addressed to an
  auditor or AI, "ignore previous instructions", and so on), over the whole
  repository and over the files the agent read.

The auditee controls every byte the agent reads. A verdict means "a model
reading auditee-supplied code concluded X", backed by the affidavit. If the
auditee's own company runs the model endpoint, it also controls which model
answered. The certificate says so.
