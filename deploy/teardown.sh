#!/usr/bin/env bash
# Delete what deploy/self-host.sh created for --name: the instance, its
# Elastic IP, security group and IAM role. The key pair is kept unless
# --delete-key, and the S3 bucket of sealed files (with every version)
# unless --delete-data. A confirmed SES sender address is left as is.
#
#   deploy/teardown.sh --name attest [--delete-key] [--delete-data]
set -euo pipefail
NAME=attest DELETE_KEY=0 DELETE_DATA=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME=$2; shift 2 ;;
    --delete-key) DELETE_KEY=1; shift ;;
    --delete-data) DELETE_DATA=1; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
STATE_DIR=${ATTEST_STATE_DIR:-$HOME/.config/attest}
STATE="$STATE_DIR/$NAME.env"
[ -f "$STATE" ] || { echo "no deployment named $NAME ($STATE not found)" >&2; exit 1; }
# shellcheck disable=SC1090
source "$STATE"
# Region-scoped AWS CLI. (Not `command aws` in conditions: macOS bash 3.2
# exits under set -e when a `command` builtin fails inside `if !`.)
awsr() { aws --region "$REGION" "$@"; }

echo "This deletes instance $INSTANCE, Elastic IP $IP and security group $SG in $REGION."
if [ -n "${INSTANCE:-}" ]; then
  awsr ec2 terminate-instances --instance-ids "$INSTANCE" >/dev/null
  awsr ec2 wait instance-terminated --instance-ids "$INSTANCE"
  echo "terminated $INSTANCE"
fi
if [ -n "${ALLOC:-}" ]; then
  awsr ec2 release-address --allocation-id "$ALLOC" && echo "released $IP"
fi
if [ -n "${SG:-}" ]; then
  awsr ec2 delete-security-group --group-id "$SG" && echo "deleted $SG"
fi
if [ "$DELETE_KEY" = 1 ]; then
  awsr ec2 delete-key-pair --key-name "$NAME-key" && rm -f "$STATE_DIR/$NAME-key.pem" && echo "deleted key pair"
fi
ROLE="$NAME-instance"
if aws iam get-instance-profile --instance-profile-name "$ROLE" >/dev/null 2>&1; then
  aws iam remove-role-from-instance-profile --instance-profile-name "$ROLE" --role-name "$ROLE" || true
  aws iam delete-instance-profile --instance-profile-name "$ROLE" || true
  aws iam delete-role-policy --role-name "$ROLE" --policy-name ses || true
  aws iam delete-role-policy --role-name "$ROLE" --policy-name s3 >/dev/null 2>&1 || true
  aws iam delete-role --role-name "$ROLE" && echo "deleted IAM role $ROLE"
fi
if [ -n "${BUCKET:-}" ]; then
  if [ "$DELETE_DATA" = 1 ]; then
    # Every version and delete marker, 1000 at a time, then the bucket.
    while :; do
      BATCH=$(awsr s3api list-object-versions --bucket "$BUCKET" --max-items 1000 --output json \
        | python3 -c 'import json,sys; v=json.load(sys.stdin); o=[{"Key":x["Key"],"VersionId":x["VersionId"]} for x in (v.get("Versions") or [])+(v.get("DeleteMarkers") or [])]; print(json.dumps({"Objects":o,"Quiet":True}) if o else "")')
      [ -n "$BATCH" ] || break
      awsr s3api delete-objects --bucket "$BUCKET" --delete "$BATCH" >/dev/null
    done
    awsr s3api delete-bucket --bucket "$BUCKET" && echo "deleted s3://$BUCKET"
  else
    echo "kept s3://$BUCKET (sealed files; pass --delete-data to delete it)"
  fi
fi
rm -f "$STATE" "$STATE_DIR/$NAME.known_hosts"
