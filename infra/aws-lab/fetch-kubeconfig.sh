#!/bin/bash
# Busca o kubeconfig do k3s na EC2 do lab via AWS SSM (sem SSH).
# Uso: ./fetch-kubeconfig.sh [saida.yaml]
set -euo pipefail

OUT="${1:-../../backend/kubeconfig.yaml}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

INSTANCE=$(terraform output -json k8s 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("instance_id",""))')

# fallback para state anterior (output sem instance_id): descobre pela tag
if [ -z "${INSTANCE}" ]; then
  INSTANCE=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Project,Values=graphsec-lab" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' --output text | awk '{print $1}')
fi

if [ -z "${INSTANCE}" ]; then
  echo "Não consegui descobrir o instance_id. Rode: terraform apply -auto-approve"
  exit 1
fi

echo "→ Instance: $INSTANCE   Region: $REGION"
echo "→ Aguarde o SSM agent registrar (até ~90s se a policy acabou de ser anexada)..."

until aws ssm describe-instance-information --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE" \
  --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null | grep -q Online; do
  sleep 5
  echo -n "."
done
echo " online."

CID=$(aws ssm send-command --region "$REGION" \
  --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["cat /root/kubeconfig.yaml"]' \
  --query 'Command.CommandId' --output text)

echo "→ Command: $CID"
for i in {1..30}; do
  STATUS=$(aws ssm get-command-invocation --region "$REGION" \
    --command-id "$CID" --instance-id "$INSTANCE" \
    --query 'Status' --output text 2>/dev/null || echo "Pending")
  [ "$STATUS" = "Success" ] && break
  [ "$STATUS" = "Failed" ] && { echo "SSM falhou"; exit 1; }
  sleep 2
done

aws ssm get-command-invocation --region "$REGION" \
  --command-id "$CID" --instance-id "$INSTANCE" \
  --query 'StandardOutputContent' --output text >"$OUT"

echo "✓ kubeconfig salvo em: $OUT"
echo "  (também dá para testar: KUBECONFIG=$OUT kubectl get pods -A)"
