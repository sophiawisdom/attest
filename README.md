# attest

Prove it without showing it. Give an AI agent access to your information (code, Slack, email, bank data, any API) inside an attested enclave; someone else asks it questions, and every answer goes past you before it's sent.

Either party starts a session and sends the other a private link (over
Signal or whatever they already use). The **auditor** asks a question. The
**auditee** accepts it, connects what the agent may look at (Slack, email
over IMAP, Gmail, bank data through Plaid, a remote MCP server, any HTTPS
API, or a private repository the enclave fetches from GitHub itself) by
pasting tokens it makes for the purpose, and approves a model
and API key (either side can propose one). A model with read-only tools
(list, find, read, grep) reads the code inside an AWS Nitro Enclave and
answers. The auditee watches everything and decides whether the auditor sees
the result. The auditor can ask the agent to revise its answer; the auditee
sees those messages too. Only the auditee ever sees the agent's transcript. The agent can
ask the auditor to clarify. Every step is an HTTP call, so either side can be
an agent.

The web app, the API and the [agent guide](crates/enclave/web/agents.md) are
served by the enclave itself, over TLS that terminates inside it. An agent can
verify the attestation, check the TLS key binding, and compare PCR0 with a
reproducible build of this repository.

## What the enclave enforces, and what it only discloses

Enforced: the harness (fixed prompt, read-only tools, fixed provider
endpoints), the visibility rules above, and that the analysed code matches the
committed tree hash, and, for code fetched from GitHub, the repository and
commit the certificate names.

Disclosed in the signed certificate: who chose the model and key, the key's
organization as the provider reports it, which model answered and which
host served it, earlier runs, question revisions and whether the code
and whether the code changed in the session. By default that and
the verdict are all: nothing else the code or the model could have shaped
(run times, the code's hash and size, activity and instruction-scan counts,
error text). The auditee can choose to release those details too.

## Layout

- `crates/core`: shared types, Nitro attestation verification (at the
  document's own timestamp), certificate checks, instruction scan, harness prompt.
- `crates/enclave`: sessions, agent loop, provider adapters, TLS and ACME
  inside the enclave, web app (`web/index.html`), agent guide (`web/agents.md`).
- `crates/host`: untrusted parent daemon that forwards ciphertext and serves boot config.
- `crates/cli`: `attest open`, `attest verify-service`, `attest upload`, `attest verify`.
- `build/`: reproducible enclave image build. `deploy/`: AWS launch and run scripts.
- `measurements/`: published PCRs per commit.

## Use

```sh
attest open 'https://32.190.88.43/s/ID#TOKEN'
attest verify-service https://32.190.88.43   # or --pcrs measurements/<commit>.pcrs.json
attest upload 'https://32.190.88.43/s/ID#TOKEN' ~/repo --org "Example Lab" --pcrs ...
attest verify certificate.json --pcrs ...
attest verify disclosure.json --pcrs ...
```

`attest open` is the safe way to use the web app. A browser can't check
which server its TLS session reaches, so whoever controls the address could
get their own certificate and serve a page that copies links, code or keys.
`attest open` checks the attestation first (against `--pcrs`, or by default
the measurements published in this repository for the commit the server
reports), serves the app on `http://127.0.0.1`, and relays every API call
over TLS sessions it checked end inside the enclave. If a later check fails,
it stops relaying.

The auditee can also publish **disclosures**: a file from the uploaded code,
or what a Python script prints when run over it in the enclave's sandbox.
Each is signed by the enclave and bound to the code commitment, so the
auditor can check it with `attest verify`. See `/agents.md` on the server.

## Develop

```sh
cargo build && python3 tests/e2e.py
```

`tests/e2e.py` drives a whole session as two agents against a dev-mode enclave
(plain HTTP, nothing attested) with a scripted mock model.

## Deploy

Only AWS is needed. `deploy/self-host.sh` launches a Graviton Nitro instance,
builds the enclave image on it reproducibly, checks PCR0 against
`measurements/`, and starts the service. The enclave gets a Let's Encrypt
certificate for its Elastic IP, and sends email notifications through SES in
sandbox mode, so only confirmed addresses get mail. Agents poll instead. See
[SELF_HOSTING.md](SELF_HOSTING.md).

## Limits

- Sessions are written, sealed, to the parent's store a couple of seconds
  after each change, under a master key only enclaves of the same image hold.
  They survive a move to another enclave of that image (a bigger machine, a
  second region): started with the running one as its peer, the new enclave
  proves its image and takes over the key, the signing key and the latest
  state; runs that were going are recorded as interrupted. A **standby**
  (config `standby: true` with the primary as `peer`) takes the same keys
  the same way while the primary keeps serving, and copies no session data:
  it only checks every few seconds that the primary is alive. Promoted
  (`POST /api/internal/replica/promote` with a MAC under the handoff token,
  accepted only after 20 s without contact), it reads the lineage's session
  index and each session's newest state from the shared store.
  `deploy/self-host.sh --standby-for NAME` sets up such a pair in two
  availability zones; `deploy/pair.sh` on each machine promotes the standby
  and moves the Elastic IP after a minute without the primary, and turns a
  stale primary back into a standby. Changes written in the last couple of
  seconds before the primary died can be lost. The parent could serve older
  state at a promotion, or cut two healthy enclaves apart so both serve:
  a party may then miss recent changes, but none can be invented. If no
  enclave of the lineage is running (both machines lost, or an image
  upgrade), the key is gone and so are the sessions. `/api/info` shows the lineage and
  which boot it came from; the boot id still makes restarts visible.
- Capacity is set by the operator: at most `max_sessions` sessions at once
  (default 100), and a budget of enclave memory for what sessions hold
  (snapshots, traces, code indexes; default 15% of the enclave's memory, at
  most 25%). Both go in `host.json` for boot, and `deploy/limits.py` changes
  them live (a MAC under the handoff token). A full server refuses new
  sessions, uploads, questions and runs; lowering a limit never drops a
  session. (When full, the oldest session nobody has used yet, with no
  question or code, makes room.) Nothing deletes another lineage's stored
  state; an enclave deletes only its own records that were replaced, and a
  session's records once it expires.
- The auditee controls every byte the agent reads, so steering through the
  code is disclosed, not prevented. If the auditee operates the model
  endpoint, it controls which model answered. The certificate says so.
- The model provider receives the code under the key owner's terms. If the
  auditee approves the auditor's own key, the auditor can read what the
  model saw through their provider account (logs, broadcast), before any
  release. The auditee must opt in explicitly and the certificate says so;
  for the strict setting, use the auditee's key.
- The parent instance sees the size and timing of every encrypted model
  request and response. The enclave narrows this: the whole repository is
  loaded into enclave memory before a run (so the host learns nothing from
  which files are read), requests are padded to size buckets (64 KiB and up,
  1.25x apart), and a jailed harness gets at most 300 model calls. Response
  sizes come from the provider and can't be padded, so a model steered to
  vary its reply lengths could signal a few bits per call to whoever runs the
  parent. The jailed harnesses (Codex, Claude Code, pi) run arbitrary commands, so they can choose request
  sizes and timing deliberately (bounded by the call cap, one call at a
  time); the built-in harness only sends requests the enclave builds. API
  responses to the browser and agents are padded the same way. If that matters, the auditee should run the enclave themselves
  (`deploy/self-host.sh`): then the parent is theirs.
- Before release the auditor sees only a salted commitment to the code, not
  its tree hash, size or file count; a certificate opens it only if the
  auditee releases the run details. The parent stores each file sealed and
  padded to a size bucket (1 KiB and up, 1.25x apart), so it learns the
  number of files and their rough sizes, not exact ones.
- Each jailed run has its own cgroup (memory, process and CPU caps) and user
  id. Runs still share the enclave's CPUs and memory bandwidth, so a run can
  notice another's load; for the strict setting, don't share the server.
- Sessions on one server share its CPUs and run slots. Someone running other
  sessions on the same server can notice when a run frees its slot, which
  says roughly when it finished (the auditor's own view never does). The
  auditee's live trace refreshes on a fixed 5-second tick and run emails go
  out at the run's time limit, not when it ends. For the strict setting,
  self-host so no one else shares the server.
