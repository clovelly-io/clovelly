# The verifier on AWS

A recipe for [the general sequence](verifier-deploy.md): your keys in AWS KMS, the verifier and key helper in one
Fargate task behind a load balancer on your certificate. You need an AWS account, the `aws` CLI logged in as someone
who may create the stack and KMS keys, a container runtime, and an ACM certificate for the name your verifier will
have. About 20 minutes.

**This recipe has not yet run against AWS: we have tested the backend against a fake of KMS's wire protocol, and
the template with `cfn-lint`.** If something here does not work, it is our bug: tell us what it said.

There is no access key anywhere in this. The helper runs as the task's role; your own login only sets it up.

The images, from the release page:

```bash
export KEYS_IMAGE=ghcr.io/clovelly-io/clovelly-keys@sha256:DIGEST VERIFIER_IMAGE=ghcr.io/clovelly-io/verifier@sha256:DIGEST
```

The stack, with nothing running yet: the task's role, the network and the load balancer. It takes about four minutes.
Replace `MY_CERTIFICATE_ARN` with your certificate's ARN, and use your own region:

```bash
curl -fsSL https://raw.githubusercontent.com/clovelly-io/clovelly/main/deploy/verifier-aws.yaml -o verifier-aws.yaml
export AWS_REGION=us-east-1
aws cloudformation deploy --stack-name clovelly-verifier-MY_ENV --template-file verifier-aws.yaml --capabilities CAPABILITY_NAMED_IAM --parameter-overrides Env=MY_ENV KeysImage="$KEYS_IMAGE" VerifierImage="$VERIFIER_IMAGE" CertificateArn=MY_CERTIFICATE_ARN DesiredCount=0
```

The keys and the configuration, from the published image with your login, for one sub-environment called `main`. This
prints your SDK token, once:

```bash
mkdir -p clovelly-out/MY_ENV
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -v "$PWD/clovelly-out/MY_ENV:/out" -e AWS_REGION --env-file <(aws configure export-credentials --format env-no-export) "$KEYS_IMAGE" init aws --role "$(aws cloudformation describe-stacks --stack-name clovelly-verifier-MY_ENV --query "Stacks[0].Outputs[?OutputKey=='TaskRoleArn'].OutputValue" --output text)" --env MY_ENV --subenv main --out /out
```

The configuration, where the task reads it. It holds no secret. It is in Parameter Store because a stack parameter is
limited to 4 KB:

```bash
aws ssm put-parameter --overwrite --type String --tier Advanced --name /clovelly/MY_ENV/config --value file://clovelly-out/MY_ENV/config.json
aws ssm put-parameter --overwrite --type String --tier Advanced --name /clovelly/MY_ENV/release-policy --value file://clovelly-out/MY_ENV/release-policy.jws
aws ssm put-parameter --overwrite --type String --tier Advanced --name /clovelly/MY_ENV/keys-allow --value "$(sed -n 's/^CLOVELLY_KEYS_ALLOW=//p' clovelly-out/MY_ENV/keys.env)"
```

The two containers:

```bash
aws cloudformation deploy --stack-name clovelly-verifier-MY_ENV --template-file verifier-aws.yaml --capabilities CAPABILITY_NAMED_IAM --parameter-overrides DesiredCount=1
```

The load balancer's name, to point your certificate's name at with a CNAME. Your verifier's address is `https://` and
that name of yours:

```bash
aws cloudformation describe-stacks --stack-name clovelly-verifier-MY_ENV --query "Stacks[0].Outputs[?OutputKey=='LoadBalancerDnsName'].OutputValue" --output text
```

## What it made

- Three KMS keys, `alias/clovelly-MY_ENV-env-ca` and `-policy` (`ECC_NIST_P256`, sign and verify) and `-dek` (symmetric).
  Each key's policy lets the task's role `kms:Sign` and `kms:GetPublicKey` on the first two and `kms:Decrypt` on the
  third, and nothing else. Your account's administrators administer them through IAM, as with any KMS key.
- `clovelly-out/MY_ENV/`: the configuration ([what is in it](verifier-deploy.md#the-sequence)).
- The stack ([`deploy/verifier-aws.yaml`](../deploy/verifier-aws.yaml)): a small VPC of its own; a network load balancer,
  whose TLS listener on your certificate speaks HTTP/2 only and passes it through to the verifier; one Fargate task with
  both containers sharing loopback, `DesiredCount: 1` with `MaximumPercent: 100`, so that there is never a second
  instance, even during a deployment; the task's role, with no policy of its own; logs in CloudWatch.

## Proving the role's limits

Run this in a task with the same role. It tries to create, delete, disable and re-key, and passes only if KMS
refuses all four:

```text
clovelly-keys check-role aws --sign-key alias/clovelly-MY_ENV-env-ca --dek-key alias/clovelly-MY_ENV-dek
```
