# Running your own attest server

Hosted attest servers are best-effort: sessions live in enclave memory and
end whenever the server is updated. If you need a server that stays up on
your schedule, run your own. It takes one script and about 15 minutes, most
of it waiting for a build.

This page is written so you can hand it to an agent: "Read SELF_HOSTING.md in
github.com/sophiawisdom/attest and deploy attest in my AWS account."

## What you need

- An AWS account and the `aws` CLI with credentials that can create EC2
  instances, key pairs, security groups, Elastic IPs and an IAM role, use
  SES, and read SSM parameters. Check with `aws sts get-caller-identity`.
- `git`, `ssh`, `curl` and `python3` locally.

That's all. No domain is needed: the enclave gets a Let's Encrypt
certificate for its Elastic IP. A domain is optional (`--domain`, with an A
record pointing at the IP, not proxied through a CDN).

## Cost

The default `m7g.xlarge` (4 vCPU, 16 GiB; the enclave gets 2 vCPU and
10 GiB) costs about $0.16/hour, roughly $120/month, plus about $3.60/month
for the Elastic IP. SES email costs $0.10 per thousand. `--type m7g.large`
halves the instance cost, with a 4 GiB enclave, of which the agent harnesses (Codex, Claude Code, pi) take about 1 GB (fine for repositories up to a few hundred MB). You also pay your model
provider for each audit.

## Deploy

```sh
git clone https://github.com/sophiawisdom/attest && cd attest
deploy/self-host.sh --region us-west-2 --operator "Example Lab" --email-from you@example.com
```

The script:

1. Creates a key pair (saved in `~/.config/attest/`), a security group
   (HTTPS from anywhere, SSH from your current IP only), an IAM role that
   can only send and verify SES email, an Elastic IP, and a Graviton
   instance with Nitro Enclaves enabled. With `--email-from`, SES emails that
   address a confirmation link; click it once.
2. Clones the repository on the instance at the newest commit with
   published measurements (or `--commit`), and builds the enclave image
   reproducibly with `build/build-eif.sh`.
3. Compares the resulting PCR0 with `measurements/<commit>.pcrs.json`. A
   match means your server runs exactly the published build.
4. Starts the untrusted host daemon and the enclave (`deploy/run.sh`) and
   checks the service answers.

A few minutes later the enclave has its own Let's Encrypt certificate for the
IP (short-lived, renewed every few days), and `https://IP` works in browsers.

**Test deploys.** Let's Encrypt issues at most 5 certificates a week for one
IP, and every deploy restarts the enclave, which requests a new one. For
repeated test deploys add `--acme-staging`: the certificate comes from
Let's Encrypt's staging CA, which browsers don't trust (use `curl -k`; the
`attest` CLI checks the enclave's TLS key through attestation either way).
Or pass `--domain` with an A record pointing at the IP, which has its own
limit.

**Email.** Notifications go through Amazon SES in sandbox mode, which only
delivers to confirmed addresses. When someone enters an address in a
session, SES sends it one confirmation email, and nothing else goes to it
until they click. That keeps the server from being usable to email
arbitrary people. The sandbox allows about 200 emails a day. Agents don't
need email; they poll.

## Check it

```sh
cargo build --release -p attest-cli
target/release/attest verify-service https://IP --pcrs measurements/<commit>.pcrs.json
```

This checks the AWS Nitro attestation, PCR0, and that TLS terminates inside
the enclave. `/agents.md` on the server describes the protocol.

## Upgrade, inspect, remove

- **Upgrade:** rerun `deploy/self-host.sh` with the same `--name` (default
  `attest`) and a newer `--commit`. This rebuilds and restarts the enclave,
  which ends every session on it.
- **Logs:** `ssh -i ~/.config/attest/attest-key.pem ec2-user@IP`. The host
  daemon logs to `~/attest-host.log`. The enclave itself has no console in
  production mode, by design.
- **Remove:** `deploy/teardown.sh --name attest` terminates the instance and
  deletes the Elastic IP, security group and IAM role.

## Notes for agents doing this

- Run the script in the foreground. It prints a `== step` line as it goes
  and exits non-zero with the reason if something fails.
- `InsufficientInstanceCapacity`: rerun with another `--region` or `--type`.
- If the PCR0 check prints a WARNING, the build did not reproduce. Report
  it rather than deploying anyway.
- The script adds SSH access from your current address on every run, so it
  keeps working if your IP changes. Old addresses stay in the security
  group; remove them by hand if you like.
- The script is safe to rerun. It reuses the instance recorded in
  `~/.config/attest/<name>.env`.
