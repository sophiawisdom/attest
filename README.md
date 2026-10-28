# attest

Ask a question about code you can't see, and get a signed answer.

An **auditee** starts a session and sends the **auditor** a private link
(over Signal or whatever they already use). The auditor asks a question. The
auditee accepts it, uploads code, confirms an affidavit, and approves a model
and API key (either side can propose one). A model with read-only tools
(list, find, read, grep) reads the code inside an AWS Nitro Enclave and
answers. The auditee watches everything and decides whether the auditor sees
the result. The auditor can send follow-ups, optionally blinded. The agent can
ask the auditor to clarify. Every step is an HTTP call, so either side can be
an agent.

The web app, the API and the [agent guide](crates/enclave/web/agents.md) are
served by the enclave itself, over TLS that terminates inside it. An agent can
verify the attestation, check the TLS key binding, and compare PCR0 with a
reproducible build of this repository.

## What the enclave enforces, and what it only discloses

Enforced: the harness (fixed prompt, read-only tools, fixed provider
endpoints), the visibility rules above, and that the analysed code matches the
tree hash in the affidavit.

Disclosed in the signed certificate: who chose the model and key, the key's
organization as the provider reports it, which model answered, earlier runs,
question revisions and code changes in the session, blinded messages (by
hash), and counts of instruction-like text in the code.

## Layout

- `crates/core`: shared types, Nitro attestation verification (at the
  document's own timestamp), certificate checks, instruction scan, harness prompt.
- `crates/enclave`: sessions, agent loop, provider adapters, TLS and ACME
  inside the enclave, web app (`web/index.html`), agent guide (`web/agents.md`).
- `crates/host`: untrusted parent daemon that forwards ciphertext and serves boot config.
- `crates/cli`: `attest verify-service`, `attest upload`, `attest verify`.
- `build/`: reproducible enclave image build. `deploy/`: AWS launch and run scripts.
- `measurements/`: published PCRs per commit.

## Use

```sh
attest verify-service https://32.190.88.43 --pcrs measurements/<commit>.pcrs.json
attest upload 'https://32.190.88.43/s/ID#TOKEN' ~/repo --org "Example Lab" --pcrs ...
attest verify certificate.json --pcrs ...
attest verify disclosure.json --pcrs ...
```

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

- Sessions live in enclave memory: a restart loses them. The boot id makes
  restarts visible.
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
  its tree hash, size or file count; each released certificate opens it.
- Sessions on one server share its CPUs and run slots. Someone running other
  sessions on the same server can notice when a run frees its slot, which
  says roughly when it finished (the auditor's own view never does). The
  auditee's live trace refreshes on a fixed 5-second tick and run emails go
  out at the run's time limit, not when it ends. For the strict setting,
  self-host so no one else shares the server.
