# Running your own attest server

Hosted attest servers are best-effort: sessions live in enclave memory and
end whenever the server is updated. If you need a server that stays up on
your schedule, run your own. It takes one script and about 15 minutes, most
of it waiting for a build.

This page is written so you can hand it to an agent: "Read SELF_HOSTING.md in
github.com/sophiawisdom/attest and deploy attest in my AWS account."

## What you need

- An AWS account and the `aws` CLI with credentials that can create EC2
  instances, key pairs, security groups and Elastic IPs, and read SSM
  parameters. Check with `aws sts get-caller-identity`.
- `git`, `ssh`, `curl` and `python3` locally.
- Optional: a domain name you can add a DNS record to. Without one, the
  server works over its IP address with a self-signed certificate, which
  agents and the CLI accept (trust comes from the attestation). Browsers show
  a warning.

## Cost

The default `m7g.xlarge` (4 vCPU, 16 GiB; the enclave gets 2 vCPU and
10 GiB) costs about $0.16/hour, roughly $120/month, plus about $3.60/month
for the Elastic IP. `--type m7g.large` halves that, with a 4 GiB enclave
(fine for repositories up to a few hundred MB). You also pay your model
provider for each audit.

## Deploy

```sh
git clone https://github.com/sophiawisdom/attest && cd attest
deploy/self-host.sh --region us-west-2 --domain attest.example.com --operator "Example Lab"
```

The script:

1. Creates a key pair (saved in `~/.config/attest/`), a security group
   (HTTPS from anywhere, SSH from your current IP only), an Elastic IP and a
   Graviton instance with Nitro Enclaves enabled.
2. Clones the repository on the instance at the newest commit with
   published measurements (or `--commit`), and builds the enclave image
   reproducibly with `build/build-eif.sh`.
3. Compares the resulting PCR0 with `measurements/<commit>.pcrs.json`. A
   match means your server runs exactly the published build.
4. Starts the untrusted host daemon and the enclave (`deploy/run.sh`) and
   checks the service answers.

Then add an A record from your domain to the printed IP, **not proxied**
(TLS must end inside the enclave, not at a CDN). The enclave checks every
minute; once the name points at it, it gets its own Let's Encrypt
certificate.

## Check it

```sh
cargo build --release -p attest-cli
target/release/attest verify-service https://attest.example.com --pcrs measurements/<commit>.pcrs.json
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
- **Email notifications (optional):** put
  `"email": {"resend_api_key": "...", "from": "attest <notify@example.com>"}`
  in `/etc/attest/host.json` on the instance, then run
  `cd attest-src && deploy/run.sh`. Webhooks and polling work without it.
- **Remove:** `deploy/teardown.sh --name attest` terminates the instance and
  deletes the Elastic IP and security group.

## Notes for agents doing this

- Run the script in the foreground. It prints a `== step` line as it goes
  and exits non-zero with the reason if something fails.
- `InsufficientInstanceCapacity`: rerun with another `--region` or `--type`.
- If the PCR0 check prints a WARNING, the build did not reproduce. Report
  it rather than deploying anyway.
- The script is safe to rerun. It reuses the instance recorded in
  `~/.config/attest/<name>.env`.
