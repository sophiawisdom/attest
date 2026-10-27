# attest

Attested LLM code audits. An auditor asks a natural-language question about
code they cannot see ("does the training pipeline compute loss on
chain-of-thought tokens?"). The auditee runs a read-only LLM agent over their
code inside an AWS Nitro Enclave, sees the full transcript, and decides
whether to release the signed verdict. The auditor checks the certificate
against a reproducible enclave build.

The enclave enforces only the harness (fixed prompt; tools limited to
list/find/read/grep; fixed provider endpoints). Everything else is
**disclosed, not enforced**: the auditee picks the provider, model and API
key, and the signed manifest says what they picked so the auditor can price
it in.

## Flow

```
auditor                         auditee                          enclave (Nitro)
-------                         -------                          ---------------
attest question  ──question.json──▶
                                attest submit  ── age-encrypted ──▶ verify sigs + tree hash
                                  (code, affidavit, API key)       read/grep agent loop
                                                                   ──▶ api.openai.com / api.anthropic.com / openrouter.ai
                                attest fetch   ◀── encrypted to auditee ── certificate + full trace
                                  reads transcript.md
            ◀──certificate.json── (if they choose)
attest verify --pcrs --question
attest log    ── signed list of every run of this question text ──▶
```

The parent instance (`attest-host`) is untrusted. It forwards ciphertext:
submissions are encrypted to the enclave's attested age key, results to the
auditee's key, and provider TLS terminates inside the enclave.

## What the auditor sees (manifest)

- Question (auditor-signed) and the auditee's signed affidavit: tree hash,
  repo URL, git commit, and a clause that nothing was added with intent to
  influence the audit.
- Code: tree hash, file count, size. Never the content.
- Model: provider, fixed endpoint, requested model, models the provider
  reported, **API key's organization** (from `openai-organization` /
  `anthropic-organization-id` headers), OpenRouter upstreams and ZDR flag,
  and whether it's a fine-tune (refused unless the question allows it).
- Activity: model and tool calls, tokens, files read, and a commitment to the
  exact set of files read (the auditee can open it later).
- Instruction-text scan: counts of text addressed to an auditor/AI, override
  phrasing, self-assessment claims, verdict steering, and chat markup, over
  the whole bundle and over the files the model read. The trace is hidden
  from the auditor, so this is the only signal about steering text.
- History: earlier runs of the same question text on this boot, and whether
  the code changed between attempts (the "edit and resubmit" search loop).
  `attest log` gives the auditor the same list directly, signed, so withheld
  certificates are visible.
- Verdict: yes / no / inconclusive, confidence, and a summary written for the
  auditor (which the auditee reviews before release).

`attest verify` prints all of this, plus warnings such as self-hosted
inference (the auditee runs the model endpoint), code changed between
attempts, and instruction-shaped text in files read.

## Usage

```sh
cargo build --release
# auditor
attest keygen --out auditor.json
attest question --key auditor.json --text "Does training compute loss on CoT tokens?" --out question.json
# auditee
attest keygen --out auditee.json
ATTEST_API_KEY=sk-... attest submit --enclave https://attest.example --pcrs pcrs.json \
  --key auditee.json --question question.json --dir ~/monorepo \
  --org "Example Lab" --provider openai --model gpt-5.5 --wait
# auditor, after receiving certificate.json
attest verify --certificate certificate.json --question question.json --pcrs pcrs.json
attest log --enclave https://attest.example --pcrs pcrs.json --question question.json
```

Local dev (no hardware, nothing attested, scripted mock model):
`tests/e2e.sh`.

## Web app

```sh
attest ui --workspace ~/attest-workspace --open     # http://127.0.0.1:7717/
```

One local app for both roles, over a workspace directory that holds keys,
questions, runs and verified certificates.

- **Auditor:** sign questions and download `question.json`, drop in a
  `certificate.json` to verify it, and check a question's run log. The log
  marks finished runs you never received a certificate for.
- **Auditee:** import a question, point at a repository (Inspect shows file
  count, tree hash and commit, and warns about uncommitted changes), choose
  provider/model/key, read the generated affidavit, and sign. Runs are
  followed in the background. When one finishes you get the result as the
  auditor will see it, the full transcript, and a download for the
  certificate.

The server binds 127.0.0.1 only, rejects non-localhost Host headers, and
requires a custom header on every POST, so other web pages can't drive it.
API keys are sent to the enclave and never written to the workspace.

## Deployment (Graviton)

`deploy/launch-graviton.sh` creates a dedicated m7g.xlarge Nitro parent (2
CPUs / 10 GiB for the enclave), separate from the timelock relay. On it:
`build/build-eif.sh` (native arm64 build plus `nitro-cli build-enclave`,
which writes `build/out/pcrs.json`) and then `deploy/run.sh`. Auditors pin
that `pcrs.json` after reproducing the build themselves.

## Layout

- `crates/core`: types, signatures, tree hash, Nitro document verification,
  instruction scan, fixed harness prompt.
- `crates/enclave`: HTTP API over vsock, agent loop, tools, provider adapters.
- `crates/host`: untrusted forwarder and outbound tunnel (allowlisted hosts).
- `crates/cli`: `attest`.
- `build/`: reproducible Docker build and EIF. `deploy/run.sh`: start on EC2.

## Verification details

- Nitro documents are checked against the pinned AWS root **at the document's
  own timestamp**. Nitro signing certs expire within hours, and certificates
  must stay checkable later. Tested on a real September 2026 document from
  timelock-proxy.
- The attestation's `user_data` is sha256(enclave info JSON), which commits to
  the boot id, ed25519 signing key, age key, harness prompt hash and endpoints.
  Its `public_key` is the signing key. Zero PCRs (debug mode) are rejected.
- Builds are byte-for-byte reproducible (two clean builds checked). This
  needed the same vendored `i18n-embed-fl` patch as timelock-proxy.

## Known limits

- **Steering through the code itself** is disclosed (scan counts, files-read
  commitment, history), not prevented. The verdict means "an LLM reading
  auditee-controlled text concluded X."
- **Self-audit through your own API** (OpenAI code on api.openai.com) proves
  nothing about which model answered. The manifest flags it.
- **Run log resets on enclave restart.** Every log and certificate names its
  boot id, so a restart is visible but not prevented. Paraphrasing the
  question to get a fresh history is not detected.
- Code is held in enclave RAM (roughly 3x bundle size during submission), so
  size the enclave memory accordingly.
- Provider code goes to the inference provider under the auditee's own terms
  (ZDR etc.). That's the chosen trust model.

## Status

- Running on Nitro: dedicated Graviton parent `i-077f9745928cc406a`
  (m7g.xlarge, us-west-2, 54.202.167.71:8080, open only to the operator's IP and the
  Hetzner box). Non-debug enclave, PCR0 in
  `measurements/graviton-m7g-20261026.pcrs.json`.
- Tested on that enclave: fresh attestation checked against pinned PCRs (and
  rejected with wrong ones); encrypted submission; the enclave's own TLS to
  api.anthropic.com through the vsock tunnel (an invalid key, so the signed
  certificate records the provider's 401); offline certificate verification.
- Tested locally: unit tests, `tests/e2e.sh`, the web app end to end in a browser.
- x86 builds were checked byte-for-byte reproducible across two clean builds.
  The arm64 build has not yet been compared across machines.
- Not yet run: a real audit with a real model. The Anthropic adapter has
  only reached the authentication step.
