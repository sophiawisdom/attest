#!/usr/bin/env bash
# Run your own attest server on AWS Nitro Enclaves. See SELF_HOSTING.md.
#
#   deploy/self-host.sh [--name attest] [--region us-west-2] [--type m7g.xlarge]
#                       [--email-from you@example.com] [--operator "Your Name"]
#                       [--domain attest.example.com] [--commit SHA] [--repo URL]
#
# Only AWS is needed. Without --domain the server gets a Let's Encrypt
# certificate for its Elastic IP. --email-from turns on email notifications
# through Amazon SES (you confirm that address once).
#
# First run: creates a key pair, security group, IAM role (SES only), Elastic
# IP and Graviton instance; builds the enclave image on it from --commit (default: the newest
# commit with published measurements); checks PCR0 against
# measurements/<commit>.pcrs.json when that file exists; starts the service.
# Later runs with the same --name reuse the instance and redeploy (which ends
# all sessions). Undo everything with deploy/teardown.sh --name NAME.
#
# Needs: aws CLI with credentials (EC2, IAM role creation, SES, SSM read), ssh, git, curl, python3.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=attest REGION=us-west-2 TYPE=m7g.xlarge DOMAIN="" OPERATOR="" COMMIT="" REPO="" EMAIL_FROM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --region) REGION=$2; shift 2 ;;
    --type) TYPE=$2; shift 2 ;;
    --domain) DOMAIN=$2; shift 2 ;;
    --operator) OPERATOR=$2; shift 2 ;;
    --email-from) EMAIL_FROM=$2; shift 2 ;;
    --commit) COMMIT=$2; shift 2 ;;
    --repo) REPO=$2; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9-]{1,40}$ ]] || { echo "--name must be lowercase letters, digits and dashes" >&2; exit 2; }
say() { printf '\n== %s\n' "$*"; }
# Region-scoped AWS CLI. (Not `command aws` in conditions: macOS bash 3.2
# exits under set -e when a `command` builtin fails inside `if !`.)
awsr() { aws --region "$REGION" "$@"; }

STATE_DIR=${ATTEST_STATE_DIR:-$HOME/.config/attest}
STATE="$STATE_DIR/$NAME.env"
KEY="$STATE_DIR/$NAME-key.pem"
mkdir -p "$STATE_DIR"
# shellcheck disable=SC1090
[ -f "$STATE" ] && source "$STATE"
save() { printf 'REGION=%q\nINSTANCE=%q\nSG=%q\nALLOC=%q\nIP=%q\n' "$REGION" "${INSTANCE:-}" "${SG:-}" "${ALLOC:-}" "${IP:-}" > "$STATE"; }

# Enclave size per instance type: the parent keeps the rest.
case "$TYPE" in
  m7g.large|c7g.large|r7g.large) ENC_CPUS=1; ENC_MIB=$([ "$TYPE" = r7g.large ] && echo 10240 || echo 4096) ;;
  *.xlarge) ENC_CPUS=2; ENC_MIB=$([[ "$TYPE" == r* ]] && echo 24576 || echo 10240) ;;
  *.2xlarge) ENC_CPUS=4; ENC_MIB=$([[ "$TYPE" == r* ]] && echo 49152 || echo 20480) ;;
  *) echo "pick a Graviton type such as m7g.xlarge (see SELF_HOSTING.md)" >&2; exit 2 ;;
esac

say "checking AWS credentials"
aws sts get-caller-identity --query Account --output text

if [ -z "$REPO" ]; then
  REPO=$(git remote get-url origin 2>/dev/null || echo https://github.com/sophiawisdom/attest)
  REPO=${REPO/git@github.com:/https:\/\/github.com\/}
fi
if [ -z "$COMMIT" ]; then
  # The newest published build, so the PCRs can be checked against measurements/.
  M=$(git log -1 --format=%H --diff-filter=A -- 'measurements/*.pcrs.json' 2>/dev/null || true)
  COMMIT=$(git show --name-only --format= "$M" 2>/dev/null | sed -n 's#^measurements/\([0-9a-f]\{40\}\)\.pcrs\.json$#\1#p' | head -1)
  [ -n "$COMMIT" ] || COMMIT=$(git rev-parse HEAD)
fi
echo "repo $REPO @ $COMMIT"

say "IAM role for the instance (SES only)"
ROLE="$NAME-instance"
if ! aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-role --role-name "$ROLE" --description "attest enclave parent: send and verify SES email" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name ses \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ses:SendEmail","ses:VerifyEmailIdentity","ses:GetIdentityVerificationAttributes"],"Resource":"*"}]}'
if ! aws iam get-instance-profile --instance-profile-name "$ROLE" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$ROLE" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE"
  sleep 10  # IAM propagation
fi
if [ -n "$EMAIL_FROM" ]; then
  STATUS=$(awsr ses get-identity-verification-attributes --identities "$EMAIL_FROM" --query "VerificationAttributes.\"$EMAIL_FROM\".VerificationStatus" --output text 2>/dev/null || true)
  if [ "$STATUS" != Success ]; then
    awsr ses verify-email-identity --email-address "$EMAIL_FROM"
    echo "SES sent a confirmation email to $EMAIL_FROM. Click its link; notifications start once it's confirmed."
  else
    echo "$EMAIL_FROM is already confirmed in SES"
  fi
fi

if [ -z "${INSTANCE:-}" ] || [ "$(awsr ec2 describe-instances --instance-ids "$INSTANCE" --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)" != running ]; then
  say "creating key pair, security group, Elastic IP and instance in $REGION"
  if [ ! -f "$KEY" ]; then
    awsr ec2 create-key-pair --key-name "$NAME-key" --query KeyMaterial --output text > "$KEY"
    chmod 600 "$KEY"
  fi
  VPC=$(awsr ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
  [ "$VPC" != None ] || { echo "no default VPC in $REGION" >&2; exit 1; }
  AZS=$(awsr ec2 describe-instance-type-offerings --location-type availability-zone --filters "Name=instance-type,Values=$TYPE" --query 'InstanceTypeOfferings[].Location' --output text)
  SUBNET=""
  for az in $AZS; do
    SUBNET=$(awsr ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC" "Name=availability-zone,Values=$az" "Name=default-for-az,Values=true" --query 'Subnets[0].SubnetId' --output text)
    [ "$SUBNET" != None ] && break
  done
  [ -n "$SUBNET" ] && [ "$SUBNET" != None ] || { echo "$TYPE is not offered in a default subnet in $REGION" >&2; exit 1; }
  SG=$(awsr ec2 describe-security-groups --filters "Name=group-name,Values=$NAME" "Name=vpc-id,Values=$VPC" --query 'SecurityGroups[0].GroupId' --output text)
  if [ "$SG" = None ]; then
    MYIP=$(curl -s https://checkip.amazonaws.com | tr -d '[:space:]')
    SG=$(awsr ec2 create-security-group --group-name "$NAME" --vpc-id "$VPC" --description "attest: HTTPS from anywhere, SSH from the deployer" --query GroupId --output text)
    awsr ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
    awsr ec2 authorize-security-group-ingress --group-id "$SG" --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]' >/dev/null
  fi
  AMI=$(awsr ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 --query Parameter.Value --output text)
  USERDATA=$(cat <<EOF
#!/bin/bash
set -euxo pipefail
dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel git
usermod -aG ne ec2-user
usermod -aG docker ec2-user
sed -i 's/^memory_mib:.*/memory_mib: $ENC_MIB/; s/^cpu_count:.*/cpu_count: $ENC_CPUS/' /etc/nitro_enclaves/allocator.yaml
systemctl enable --now docker nitro-enclaves-allocator.service
touch /var/lib/attest-bootstrapped
EOF
)
  for _ in 1 2 3 4 5 6; do
    INSTANCE=$(awsr ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --key-name "$NAME-key" \
    --iam-instance-profile "Name=$ROLE" \
    --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET,Groups=$SG,AssociatePublicIpAddress=true" \
    --enclave-options Enabled=true --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=40,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
    --user-data "$USERDATA" --query 'Instances[0].InstanceId' --output text 2>/dev/null) && break
    sleep 10  # the new instance profile may not be visible to EC2 yet
  done
  [ -n "${INSTANCE:-}" ] || { echo "could not launch the instance" >&2; exit 1; }
  save
  echo "instance $INSTANCE ($TYPE)"
  awsr ec2 wait instance-running --instance-ids "$INSTANCE"
  if [ -z "${ALLOC:-}" ]; then
    ALLOC=$(awsr ec2 allocate-address --domain vpc --tag-specifications "ResourceType=elastic-ip,Tags=[{Key=Name,Value=$NAME}]" --query AllocationId --output text)
  fi
  awsr ec2 associate-address --allocation-id "$ALLOC" --instance-id "$INSTANCE" >/dev/null
  IP=$(awsr ec2 describe-addresses --allocation-ids "$ALLOC" --query 'Addresses[0].PublicIp' --output text)
  save
fi
echo "instance $INSTANCE at $IP"
if [ "$(awsr ec2 describe-iam-instance-profile-associations --filters "Name=instance-id,Values=$INSTANCE" --query 'IamInstanceProfileAssociations[0].State' --output text)" = None ]; then
  awsr ec2 associate-iam-instance-profile --instance-id "$INSTANCE" --iam-instance-profile "Name=$ROLE" >/dev/null
fi

SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$STATE_DIR/$NAME.known_hosts" -o ConnectTimeout=10 -o BatchMode=yes "ec2-user@$IP")
say "waiting for the instance to finish setting up (a few minutes on first boot)"
for _ in $(seq 60); do
  "${SSH[@]}" 'sudo cloud-init status --wait >/dev/null 2>&1; test -f /var/lib/attest-bootstrapped' 2>/dev/null && break
  sleep 10
done
"${SSH[@]}" 'test -f /var/lib/attest-bootstrapped' || { echo "instance setup did not finish; check /var/log/cloud-init-output.log on it" >&2; exit 1; }

say "building the enclave image on the instance (about 10 minutes)"
CONFIG=$(DOMAIN="$DOMAIN" OPERATOR="$OPERATOR" IP="$IP" EMAIL_FROM="$EMAIL_FROM" REGION="$REGION" python3 -c '
import json, os
e = lambda k: os.environ[k] or None
print(json.dumps({"domain": e("DOMAIN"), "operator": e("OPERATOR"), "public_ip": e("IP"), "email_from": e("EMAIL_FROM"), "ses_region": e("REGION")}))')
"${SSH[@]}" "set -euo pipefail
  rm -rf attest-src && git clone -q '$REPO' attest-src && cd attest-src && git checkout -q '$COMMIT'
  sudo mkdir -p /etc/attest && echo '$(printf '%s' "$CONFIG" | base64 | tr -d '\n')' | base64 -d | sudo tee /etc/attest/host.json >/dev/null
  nice -n 5 build/build-eif.sh > ~/build-eif.log 2>&1 || { tail -30 ~/build-eif.log; exit 1; }
  cat build/out/pcrs.json"
PCR0=$("${SSH[@]}" "python3 -c 'import json; print(json.load(open(\"attest-src/build/out/pcrs.json\"))[\"Measurements\"][\"PCR0\"])'")
PUBLISHED="measurements/$COMMIT.pcrs.json"
if [ -f "$PUBLISHED" ] || git show "$COMMIT:$PUBLISHED" >/dev/null 2>&1 || git show "HEAD:$PUBLISHED" >/dev/null 2>&1; then
  WANT=$( (cat "$PUBLISHED" 2>/dev/null || git show "HEAD:$PUBLISHED") | python3 -c 'import json,sys; print(json.load(sys.stdin)["Measurements"]["PCR0"])')
  if [ "$WANT" = "$PCR0" ]; then echo "PCR0 matches the published measurements for $COMMIT"; else echo "WARNING: PCR0 $PCR0 differs from published $WANT" >&2; fi
else
  echo "no published measurements for $COMMIT; your PCR0 is $PCR0"
fi

say "starting the service (this ends any sessions on the previous version)"
"${SSH[@]}" "cd attest-src && CPUS=$ENC_CPUS MEM_MIB=$ENC_MIB deploy/run.sh >/dev/null && sleep 8 && curl -sk -m 10 https://127.0.0.1/healthz" | grep -q '"ok":true' \
  || { echo "service did not come up; see ~/attest-host.log on the instance" >&2; exit 1; }

say "done"
cat <<EOF
Server:   https://${DOMAIN:-$IP}  (the enclave gets its Let's Encrypt certificate within a few minutes)
PCR0:     $PCR0
Verify:   attest verify-service https://$IP --pcrs $PUBLISHED
SSH:      ssh -i $KEY ec2-user@$IP
EOF
if [ -n "$DOMAIN" ]; then
  echo "DNS:      add an A record $DOMAIN -> $IP (not proxied). The enclave notices within a minute and gets a Let's Encrypt certificate."
fi
echo "Remove:   deploy/teardown.sh --name $NAME"
