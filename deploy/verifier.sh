#!/usr/bin/env bash
# The Google Cloud recipe for the verifier (docs/verifier-gcp.md): a thin wrapper around the
# published images. Nothing here is needed on any other platform (docs/verifier-deploy.md).
#
#   verifier.sh init PROJECT REGION ENV SUBENV...
#       Enables the APIs, creates the verifier's service account if it is missing, and runs
#       `clovelly-keys init gcp` from the published image with your gcloud login: three keys in
#       Cloud KMS (key ring clovelly-verifier), and in ./clovelly-out/ENV the configuration, which
#       holds no secret. Prints the SDK token once.
#   verifier.sh deploy PROJECT REGION ENV [SERVICE]
#       Deploys Cloud Run service SERVICE (default verifier) from those files: the verifier and
#       the key helper as its sidecar, on that service account, one instance, always on.
#       Prints its URL.
#
#   KEYS_IMAGE, VERIFIER_IMAGE   the published images, by digest (from the release page)
#
# Needs gcloud (logged in as someone who may create these resources) and a container runtime,
# docker by default (CLOVELLY_CONTAINER_RUNTIME). Written for bash 3.2.
#
# For the test jobs, and for nothing a customer needs:
#   CLOVELLY_VERIFIER_NAME     the service account (default clovelly-verifier)
#   CLOVELLY_VERIFIER_RING     the key ring (default the same)
#   CLOVELLY_VERIFIER_OUT      where ENV's files go (default ./clovelly-out)
#   CLOVELLY_VERIFIER_CONFIG   a configuration file other than ENV's
#   CLOVELLY_RELEASE_POLICY_FILE   a signed release policy other than ENV's
#   CLOVELLY_KEYS_ALLOW        the keys the helper serves, other than ENV's
#   CLOVELLY_VERIFIER_ENV, CLOVELLY_KEYS_ENV   more KEY=VALUE pairs for each container, @-separated
#   CLOVELLY_INIT_FLAGS        more flags for `clovelly-keys init`
set -euo pipefail

SA_NAME=${CLOVELLY_VERIFIER_NAME:-clovelly-verifier}
RING=${CLOVELLY_VERIFIER_RING:-$SA_NAME}
OUT=${CLOVELLY_VERIFIER_OUT:-$PWD/clovelly-out}
RUNTIME=${CLOVELLY_CONTAINER_RUNTIME:-docker}
# The key helper's address on the loopback the two containers share.
KEYS_URL=http://127.0.0.1:8200

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
exists() { "$@" >/dev/null 2>&1; }
need() { [ -n "${!1:-}" ] || { echo "verifier.sh: set $1 to the published image, by digest (the release page lists them)" >&2; exit 2; }; }

init() {
  local project=$1 region=$2 env=$3; shift 3
  need KEYS_IMAGE
  local gc="gcloud --project=$project --quiet" out=$OUT/$env sa=$SA_NAME@$project.iam.gserviceaccount.com sub
  local subenvs=()
  for sub in "$@"; do subenvs+=(--subenv "$sub"); done
  mkdir -p "$out"
  log "enabling APIs"
  $gc services enable run.googleapis.com cloudkms.googleapis.com artifactregistry.googleapis.com >&2
  exists $gc iam service-accounts describe "$sa" \
    || $gc iam service-accounts create "$SA_NAME" --display-name="clovelly verifier" >&2
  # shellcheck disable=SC2086
  "$RUNTIME" run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -v "$out:/out" \
    -e CLOVELLY_ACCESS_TOKEN="$(gcloud auth print-access-token)" "$KEYS_IMAGE" \
    init gcp --project "$project" --location "$region" --key-ring "$RING" --service-account "$sa" \
    --env "$env" "${subenvs[@]}" --out /out ${CLOVELLY_INIT_FLAGS:-}
}

# What Cloud Run pulls: it cannot pull from ghcr.io, so a published image comes through an
# Artifact Registry remote repository in the same project, with the same digest.
pullable() {
  local project=$1 region=$2 image=$3 gc="gcloud --project=$1 --quiet"
  case $image in
    ghcr.io/*)
      exists $gc artifacts repositories describe clovelly-ghcr --location="$region" \
        || $gc artifacts repositories create clovelly-ghcr --location="$region" --repository-format=docker \
          --mode=remote-repository --remote-docker-repo=https://ghcr.io --description="ghcr.io, for the published verifier images" >&2
      printf '%s-docker.pkg.dev/%s/clovelly-ghcr/%s\n' "$region" "$project" "${image#ghcr.io/}"
      ;;
    *) printf '%s\n' "$image" ;;
  esac
}

# One entry of a container's env, as a YAML double-quoted string.
env_item() {
  local value=${2//\\/\\\\}
  value=${value//\"/\\\"}
  printf '            - name: %s\n              value: "%s"\n' "$1" "$value"
}

# KEY=VALUE pairs, @-separated.
env_pairs() {
  local pair rest=$1
  while [ -n "$rest" ]; do
    pair=${rest%%@*}
    env_item "${pair%%=*}" "${pair#*=}"
    case $rest in *@*) rest=${rest#*@} ;; *) rest="" ;; esac
  done
}

deploy() {
  local project=$1 region=$2 env=$3 service=${4:-verifier}
  need KEYS_IMAGE
  need VERIFIER_IMAGE
  local gc="gcloud --project=$project --quiet" out=$OUT/$env
  local config=${CLOVELLY_VERIFIER_CONFIG:-$out/config.json} policy=${CLOVELLY_RELEASE_POLICY_FILE:-$out/release-policy.jws}
  local allow=${CLOVELLY_KEYS_ALLOW:-$(sed -n 's/^CLOVELLY_KEYS_ALLOW=//p' "$out/keys.env")}
  local verifier_image keys_image
  verifier_image=$(pullable "$project" "$region" "$VERIFIER_IMAGE")
  keys_image=$(pullable "$project" "$region" "$KEYS_IMAGE")
  log "deploying $service"
  # The whole service as YAML, because the flags cannot move a service first deployed with one
  # unnamed container to two named ones, and this says what it is to anyone reading it.
  #
  # Exactly one instance, kept up: the nonce store and the receipt log are in its memory, so an
  # instance scaled to zero would forget the log, and a second would not know the first's nonces.
  # 1 GiB holds the log's bound (200,000 sandboxes, about 2 KB each with its cell certificate, at
  # most 512 MiB of records). No invoker IAM check: cells authenticate by attestation, and GCE
  # identity is not a security input. The verifier's port is named h2c: HTTP/2 end to end.
  local yaml
  yaml=$(mktemp)
  {
    cat <<YAML
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: $service
  annotations:
    run.googleapis.com/ingress: all
    run.googleapis.com/invoker-iam-disabled: "true"
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "1"
    spec:
      serviceAccountName: $SA_NAME@$project.iam.gserviceaccount.com
      timeoutSeconds: 60
      containers:
        - name: verifier
          image: $verifier_image
          ports:
            - { name: h2c, containerPort: 8080 }
          resources: { limits: { cpu: "1", memory: 1Gi } }
          env:
YAML
    env_item CLOVELLY_CONFIG "$(tr -d '\n' < "$config")"
    env_item CLOVELLY_KEYS_URL "$KEYS_URL"
    env_item CLOVELLY_RELEASE_POLICY "$(cat "$policy")"
    env_pairs "${CLOVELLY_VERIFIER_ENV:-}"
    cat <<YAML
        - name: keys
          image: $keys_image
          args: [serve, gcp]
          resources: { limits: { cpu: "0.5", memory: 256Mi } }
          env:
YAML
    env_item CLOVELLY_KEYS_ALLOW "$allow"
    env_pairs "${CLOVELLY_KEYS_ENV:-}"
  } > "$yaml"
  $gc run services replace "$yaml" --region="$region" >&2
  rm -f "$yaml"
  $gc run services describe "$service" --region="$region" --format='value(status.url)'
}

case ${1:-} in
  init) shift; init "$@" ;;
  deploy) shift; deploy "$@" ;;
  *) sed -n '2,29p' "$0"; exit 2 ;;
esac
