#!/usr/bin/env bash
# Delete what deploy/self-host.sh created for --name: the instance, its
# Elastic IP, security group and IAM role. The key pair is kept unless
# --delete-key. A confirmed SES sender address is left as is.
#
#   deploy/teardown.sh --name attest [--delete-key]
set -euo pipefail
NAME=attest DELETE_KEY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --delete-key) DELETE_KEY=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
STATE_DIR=${ATTEST_STATE_DIR:-$HOME/.config/attest}
STATE="$STATE_DIR/$NAME.env"
[ -f "$STATE" ] || { echo "no deployment named $NAME ($STATE not found)" >&2; exit 1; }
# shellcheck disable=SC1090
source "$STATE"
aws() { command aws --region "$REGION" "$@"; }

echo "This deletes instance $INSTANCE, Elastic IP $IP and security group $SG in $REGION."
if [ -n "${INSTANCE:-}" ]; then
  aws ec2 terminate-instances --instance-ids "$INSTANCE" >/dev/null
  aws ec2 wait instance-terminated --instance-ids "$INSTANCE"
  echo "terminated $INSTANCE"
fi
if [ -n "${ALLOC:-}" ]; then
  aws ec2 release-address --allocation-id "$ALLOC" && echo "released $IP"
fi
if [ -n "${SG:-}" ]; then
  aws ec2 delete-security-group --group-id "$SG" && echo "deleted $SG"
fi
if [ "$DELETE_KEY" = 1 ]; then
  aws ec2 delete-key-pair --key-name "$NAME-key" && rm -f "$STATE_DIR/$NAME-key.pem" && echo "deleted key pair"
fi
ROLE="$NAME-instance"
if command aws iam get-instance-profile --instance-profile-name "$ROLE" >/dev/null 2>&1; then
  command aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE" || true
  command aws iam delete-instance-profile --instance-profile-name "$ROLE" || true
  command aws iam delete-role-policy --role-name "$ROLE" --policy-name ses || true
  command aws iam delete-role --role-name "$ROLE" && echo "deleted IAM role $ROLE"
fi
rm -f "$STATE" "$STATE_DIR/$NAME.known_hosts"
