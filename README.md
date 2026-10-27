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
attest verify-service https://attest.sparrowsystems.co --pcrs measurements/<commit>.pcrs.json
attest upload 'https://attest.sparrowsystems.co/s/ID#TOKEN' ~/repo --org "Example Lab" --pcrs ...
attest verify certificate.json --pcrs ...
```

## Develop

```sh
cargo build && python3 tests/e2e.py
```

`tests/e2e.py` drives a whole session as two agents against a dev-mode enclave
(plain HTTP, nothing attested) with a scripted mock model.

## Deploy

`deploy/launch-graviton.sh` creates a Graviton Nitro parent. On it, run
`build/build-eif.sh` (a reproducible arm64 build plus `nitro-cli build-enclave`),
then `deploy/run.sh`. Point a DNS-only A record at the instance. The enclave
gets its own Let's Encrypt certificate once the name resolves to it.

## Limits

- Sessions live in enclave memory: a restart loses them. The boot id makes
  restarts visible.
- The auditee controls every byte the agent reads, so steering through the
  code is disclosed, not prevented. If the auditee operates the model
  endpoint, it controls which model answered. The certificate says so.
- The model provider receives the code under the key owner's terms.
