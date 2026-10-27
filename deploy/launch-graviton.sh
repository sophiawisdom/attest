#!/usr/bin/env bash
# Launch a dedicated Graviton Nitro parent for attest (separate from the
# timelock relay's production box). Prints the instance id and IP.
#
#   ALLOW_IPS="1.2.3.4/32 5.6.7.8/32" deploy/launch-graviton.sh
set -euo pipefail
REGION=${REGION:-us-west-2}
TYPE=${TYPE:-m7g.xlarge}               # 4 vCPU / 16 GiB, Nitro Enclaves supported
SUBNET=${SUBNET:-subnet-0aaaa1473e5731249}
VPC=${VPC:-vpc-0f8f62fac8d811e13}
KEY_NAME=${KEY_NAME:-attested-relay-graviton5}
NAME=attest-enclave
ALLOW_IPS=${ALLOW_IPS:?space-separated CIDRs allowed to reach SSH and the API}
aws() { command aws --region "$REGION" "$@"; }

SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$NAME Name=vpc-id,Values=$VPC \
      --query 'SecurityGroups[0].GroupId' --output text)
if [ "$SG" = None ]; then
  SG=$(aws ec2 create-security-group --group-name $NAME --vpc-id "$VPC" \
        --description "attest enclave parent: SSH and API from operator only" --query GroupId --output text)
  for cidr in $ALLOW_IPS; do
    aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr "$cidr" >/dev/null
    aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port 8080 --cidr "$cidr" >/dev/null
  done
fi
echo "security group $SG"

AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64 --query Parameter.Value --output text)
USERDATA=$(cat <<'EOF'
#!/bin/bash
set -euxo pipefail
dnf install -y docker aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel git rsync
usermod -aG ne ec2-user
usermod -aG docker ec2-user
# Enclave: 2 vCPUs, 10 GiB (code bundles are held in enclave RAM). Parent keeps 2 vCPUs, 6 GiB.
sed -i 's/^memory_mib:.*/memory_mib: 10240/; s/^cpu_count:.*/cpu_count: 2/' /etc/nitro_enclaves/allocator.yaml
systemctl enable --now docker nitro-enclaves-allocator.service
touch /var/lib/attest-bootstrapped
EOF
)
ID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --key-name "$KEY_NAME" \
  --network-interfaces "DeviceIndex=0,SubnetId=$SUBNET,Groups=$SG,AssociatePublicIpAddress=true" \
  --enclave-options Enabled=true \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=40,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
  --user-data "$USERDATA" --query 'Instances[0].InstanceId' --output text)
echo "instance $ID"
aws ec2 wait instance-running --instance-ids "$ID"
aws ec2 describe-instances --instance-ids "$ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
