#!/usr/bin/env bash
# Deploys the verifier to Cloud Run in a customer's project (docs/verifier-deploy.md).
#
#   deploy/verifier.sh setup  PROJECT REGION ENV SUBENV...
#       One-time: enables the APIs, creates the verifier's service account, a KMS key
#       ring (environment CA key, policy key, DEK key), the Artifact Registry
#       repository, one DEK and policy bundle per sub-environment and the environment
#       CA certificate. Writes deploy/out/ENV/config.json (no secrets: DEKs are KMS
#       ciphertext; the SDK token is configured as its SHA-256), deploy/out/ENV/ca.pem
#       and deploy/out/ENV/policy.pub.pem.
#   deploy/verifier.sh deploy PROJECT REGION ENV SERVICE IMAGE_TAR POLICY_JWS [CACHE_SECS]
#       Pushes the Nix-built image (verifier-image) and deploys Cloud Run service
#       SERVICE with the configuration and a signed release policy. Prints its URL.
#       CLOVELLY_VERIFIER_IMAGE (an image already pushed; IMAGE_TAR is then ignored),
#       CLOVELLY_VERIFIER_CONFIG (a configuration file other than ENV's) and
#       CLOVELLY_VERIFIER_ENV (more KEY=VALUE pairs, 1052separated) serve the test jobs.
#
#   CLOVELLY_VERIFIER_NAME  the service account and key ring (default clovelly-verifier)
#   CLOVELLY_VERIFIER_REPO  the Artifact Registry repository (default clovelly)
#   CLOVELLY_VERIFIER_OUT   where ENV's files go (default deploy/out)
#
# Needs gcloud (logged in as someone who may create these resources), docker (to push
# the image) and cargo (for the verifier's operator commands). Written for bash 3.2.
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
SA_NAME=${CLOVELLY_VERIFIER_NAME:-clovelly-verifier}
RING=$SA_NAME
REPO=${CLOVELLY_VERIFIER_REPO:-clovelly}
OUT=${CLOVELLY_VERIFIER_OUT:-$repo/deploy/out}

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
verifier() { cargo run -q --release --manifest-path "$repo/Cargo.toml" -p verifier -- "$@"; }
exists() { "$@" >/dev/null 2>&1; }

setup() {
  local project=$1 region=$2 env=$3; shift 3
  local gc="gcloud --project=$project --quiet" out=$OUT/$env
  local sa=$SA_NAME@$project.iam.gserviceaccount.com
  local keyring=projects/$project/locations/$region/keyRings/$RING
  mkdir -p "$out"
  log "enabling APIs"
  $gc services enable run.googleapis.com cloudkms.googleapis.com artifactregistry.googleapis.com >&2
  exists $gc iam service-accounts describe "$sa" \
    || $gc iam service-accounts create $SA_NAME --display-name="clovelly verifier" >&2
  exists $gc kms keyrings describe $RING --location="$region" \
    || $gc kms keyrings create $RING --location="$region" >&2
  exists $gc kms keys describe env-ca --keyring=$RING --location="$region" \
    || $gc kms keys create env-ca --keyring=$RING --location="$region" \
      --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256 >&2
  exists $gc kms keys describe policy --keyring=$RING --location="$region" \
    || $gc kms keys create policy --keyring=$RING --location="$region" \
      --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256 >&2
  exists $gc kms keys describe dek --keyring=$RING --location="$region" \
    || $gc kms keys create dek --keyring=$RING --location="$region" --purpose=encryption >&2
  # The verifier may sign with the CA key and decrypt DEKs; nothing else. The grant is
  # on this key ring only.
  for role in roles/cloudkms.signerVerifier roles/cloudkms.cryptoKeyDecrypter; do
    $gc kms keyrings add-iam-policy-binding $RING --location="$region" \
      --member="serviceAccount:$sa" --role="$role" >/dev/null
  done
  exists $gc artifacts repositories describe $REPO --location="$region" \
    || $gc artifacts repositories create $REPO --location="$region" --repository-format=docker >&2

  export CLOVELLY_ACCESS_TOKEN
  CLOVELLY_ACCESS_TOKEN=$(gcloud auth print-access-token)
  local ca_key=$keyring/cryptoKeys/env-ca/cryptoKeyVersions/1
  local policy_key=$keyring/cryptoKeys/policy/cryptoKeyVersions/1
  [ -s "$out/ca.pem" ] || verifier make-ca --kms-key "$ca_key" --env "$env" > "$out/ca.pem"
  local subenvs="{}" sub dek_file
  for sub in "$@"; do
    dek_file=$out/dek-$sub.bin
    if [ ! -s "$dek_file.kms" ]; then
      # The DEK exists in plaintext only in this pipe; KMS returns its ciphertext.
      openssl rand 32 | $gc kms encrypt --key=dek --keyring=$RING --location="$region" \
        --plaintext-file=- --ciphertext-file="$dek_file.kms"
    fi
    local bundle sig expires
    # Default deny (no destinations), version 1, valid 30 days, and the sandbox limits:
    # product default 1 vCPU and 2 GiB, at most a c3-standard-8's placeable 7 vCPU and
    # 27 GiB, 24 h. The customer publishes a new bundle by signing a newer version with
    # the policy key and redeploying (cells poll every 60 s).
    expires=$(( $(date +%s) + 30 * 86400 ))
    bundle=$(printf '{"v":1,"env":"%s","subenv":"%s","version":1,"expires":%s,"destinations":[],"sandbox":{"default":{"cpu":1,"memory":2},"max":{"cpu":7,"memory":27,"timeout":86400}}}' "$env" "$sub" "$expires")
    sig=$(printf '%s' "$bundle" | verifier sign --kms-key "$policy_key" --detached)
    subenvs=$(jq --arg s "$sub" --arg d "$(base64 < "$dek_file.kms" | tr -d '\n')" \
      --arg b "$bundle" --arg g "$sig" '. + {($s): {wrapped_dek: $d, policy_bundle: $b, policy_sig: $g}}' <<< "$subenvs")
  done
  # A re-run keeps the release keys, pins and fragments settings already configured.
  local keep='{"release_keys": [], "pinned_releases": []}'
  [ -s "$out/config.json" ] && keep=$(jq -c 'with_entries(select(.key | IN("release_keys", "pinned_releases", "fragments_url", "rekor_keys")))' "$out/config.json")
  # Cells verify every policy bundle against this key (UnlockResponse.policy_key).
  verifier public-key --kms-key "$policy_key" > "$out/policy.pub.pem"
  jq -n --arg env "$env" --argjson subenvs "$subenvs" --arg ca_key "$ca_key" \
    --rawfile ca "$out/ca.pem" --arg dek "$keyring/cryptoKeys/dek" --argjson keep "$keep" \
    --rawfile policy_key "$out/policy.pub.pem" \
    '{env: $env, subenvs: $subenvs, ca: {kms_key: $ca_key, cert_pem: $ca}, dek_kms_key: $dek,
      policy_key_pem: $policy_key, collateral_cache_secs: 3600} + $keep' > "$out/config.json"
  log "wrote $out/config.json; add the release keys you trust to release_keys"
}

deploy() {
  local project=$1 region=$2 env=$3 service=$4 image_tar=$5 policy=$6 cache=${7:-3600}
  local gc="gcloud --project=$project --quiet" out=$OUT/$env
  local digest tag config dc
  if [ -n "${CLOVELLY_VERIFIER_IMAGE:-}" ]; then
    tag=$CLOVELLY_VERIFIER_IMAGE
  else
    digest=$(tar -xzOf "$image_tar" manifest.json | jq -r '.[0].Config' | cut -c1-19)
    tag=$region-docker.pkg.dev/$project/$REPO/verifier:${digest#blobs/sha256/}
    dc=$(mktemp -d)
    log "pushing $tag"
    docker load -q -i "$image_tar" >&2
    local loaded
    loaded=$(tar -xzOf "$image_tar" manifest.json | jq -r '.[0].RepoTags[0]')
    docker tag "$loaded" "$tag"
    gcloud auth print-access-token | DOCKER_CONFIG=$dc docker login -u oauth2accesstoken --password-stdin "https://$region-docker.pkg.dev" >/dev/null 2>&1
    DOCKER_CONFIG=$dc docker push -q "$tag" >&2
    rm -rf "$dc"
  fi
  config=$(jq -c --argjson c "$cache" '.collateral_cache_secs = $c' "${CLOVELLY_VERIFIER_CONFIG:-$out/config.json}")
  log "deploying $service (collateral cache ${cache}s)"
  # Exactly one instance, kept up: the nonce store and the receipt log are in memory
  # (DECISIONS.md), so an instance scaled to zero would forget the log. 1 GiB holds the
  # log's bound (200,000 sandboxes, about 2 KB each with its cell certificate, at most
  # 512 MiB of records). No invoker IAM check: cells authenticate by attestation, and
  # GCE identity is not a security input.
  $gc run deploy "$service" --region="$region" --image="$tag" \
    --service-account="$SA_NAME@$project.iam.gserviceaccount.com" \
    --use-http2 --no-invoker-iam-check --min-instances=1 --max-instances=1 \
    --cpu=1 --memory=1Gi --timeout=60 \
    --set-env-vars="^@^CLOVELLY_CONFIG=$config@CLOVELLY_RELEASE_POLICY=$(cat "$policy")${CLOVELLY_VERIFIER_ENV:+@$CLOVELLY_VERIFIER_ENV}" >&2
  $gc run services describe "$service" --region="$region" --format='value(status.url)'
}

case ${1:-} in
  setup) shift; setup "$@" ;;
  deploy) shift; deploy "$@" ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
esac
