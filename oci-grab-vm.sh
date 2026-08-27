#!/usr/bin/env bash
# Auto-retry launching an Always-Free Oracle VM until capacity opens.
# RUN THIS IN OCI CLOUD SHELL (the >_ icon, top-right of the OCI console) —
# it's already authenticated, so no API keys needed. Keep the tab open.
set -uo pipefail

C="${OCI_TENANCY:-}"
if [ -z "$C" ]; then
  echo "OCI_TENANCY not set. Paste your tenancy/compartment OCID here:"
  read -r C
fi

# วางคีย์สาธารณะของคุณเอง (cat ~/.ssh/id_ed25519.pub) หรือ export SSH_KEY ไว้ก่อนรัน
SSH_KEY="${SSH_KEY:-ssh-ed25519 AAAA...REPLACE_WITH_YOUR_PUBLIC_KEY... you@example}"
SHAPE="VM.Standard.E2.1.Micro"        # AMD Always-Free (frees up faster than ARM)

echo "Discovering availability domain, latest Ubuntu image, and a public subnet..."
AD=$(oci iam availability-domain list --compartment-id "$C" --query 'data[0].name' --raw-output)
IMG=$(oci compute image list --compartment-id "$C" \
      --operating-system "Canonical Ubuntu" --operating-system-version "22.04" \
      --shape "$SHAPE" --sort-by TIMECREATED --sort-order DESC \
      --query 'data[0].id' --raw-output)
SUBNET=$(oci network subnet list --compartment-id "$C" --all \
      --query 'data[?"prohibit-public-ip-on-vnic"==`false`] | [0].id' --raw-output)

if [ -z "$SUBNET" ] || [ "$SUBNET" = "null" ]; then
  echo "!! No PUBLIC subnet found. Create one first:"
  echo "   Networking > Virtual Cloud Networks > Start VCN Wizard >"
  echo "   'Create VCN with Internet Connectivity', then re-run this."
  exit 1
fi
echo "AD=$AD"
echo "IMAGE=$IMG"
echo "SUBNET=$SUBNET"
echo "Retrying every 60s until Oracle has free capacity. Leave this tab open. (Ctrl+C to stop.)"

n=0
while true; do
  n=$((n+1))
  OUT=$(oci compute instance launch \
    --availability-domain "$AD" --compartment-id "$C" --shape "$SHAPE" \
    --image-id "$IMG" --subnet-id "$SUBNET" --assign-public-ip true \
    --display-name devops-box \
    --metadata "{\"ssh_authorized_keys\": \"$SSH_KEY\"}" 2>&1)
  ID=$(echo "$OUT" | grep -oE 'ocid1\.instance[^"]*' | head -1)
  if [ -n "$ID" ]; then
    echo ""
    echo "SUCCESS on attempt #$n!  Instance: $ID"
    echo "Waiting ~40s for the network card + public IP..."
    sleep 40
    IP=$(oci compute instance list-vnics --instance-id "$ID" --query 'data[0]."public-ip"' --raw-output 2>/dev/null)
    echo "=================================================="
    echo " PUBLIC IP:  $IP"
    echo "=================================================="
    echo " Send this IP to Claude - we SSH in and start the ladder."
    break
  fi
  echo "[$(date +%H:%M:%S)] attempt #$n: still out of capacity, retry in 60s..."
  sleep 60
done
