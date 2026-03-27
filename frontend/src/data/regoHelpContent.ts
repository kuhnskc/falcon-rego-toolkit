// Educational content and example templates for CSPM and KAC Rego policies

interface HelpRule {
  title: string;
  text: string;
}

interface HelpContent {
  rules: HelpRule[];
  patterns: string[];
  pitfalls: string[];
}

interface RegoTemplate {
  id: string;
  name: string;
  description: string;
  code: string;
}

// --- CSPM Help Content ---

export const CSPM_HELP: HelpContent = {
  rules: [
    { title: 'Package', text: 'Must be `package crowdstrike`' },
    { title: 'Result values', text: 'Must return `"pass"`, `"fail"`, or `"skip"` — no other values' },
    { title: 'Default result', text: 'Always declare a default: `default result := "fail"` (security-first) or `default result := "pass"` (detection)' },
    { title: 'Rule head operator', text: 'Use `=` in rule heads: `result = "fail" if { ... }`. Use `:=` only for locals and defaults.' },
    { title: 'Input structure', text: 'Asset data is under `input.` — use `input.configuration` for resource settings, `input.tags` for tags, `input.resource_type` to check type' },
    { title: 'Use sample data', text: 'Always fetch a real sample asset (step 3) to see exact field names — never guess' },
  ],
  patterns: [
    'Tag check: `not input.tags.Environment`',
    'Boolean config: `input.configuration.publicAccessBlockConfiguration.blockPublicAcls == false`',
    'Tag value validation: `not input.tags.Environment in ["dev", "staging", "prod"]`',
    'Skip logic: `result = "skip" if { input.tags.Exception == "approved" }`',
    'Set operations: `unauthorized := found_accounts - approved_accounts`',
    'Null safety: use `object.get(input.configuration, "field", "default")` for optional fields',
  ],
  pitfalls: [
    'Wrong package name — must be `package crowdstrike`, not `package main` or anything else',
    'Using `:=` in rule heads — write `result = "fail" if`, not `result := "fail" if`',
    'Returning boolean instead of string — result must be `"pass"`, `"fail"`, or `"skip"`, not `true`/`false`',
    'Missing `default result` — every policy must declare one or it fails audit',
    'Guessing field names — always use a sample asset to see the real JSON structure',
    'Forgetting null safety — cloud data is inconsistent, fields may be missing',
  ],
};

// --- KAC Help Content ---

export const KAC_HELP: HelpContent = {
  rules: [
    { title: 'Package', text: 'Must be `package customrule` (not `crowdstrike`)' },
    { title: 'Import', text: 'Must include `import rego.v1`' },
    { title: 'No default result', text: 'Do NOT set a default — empty result means allow, a string result means deny' },
    { title: 'Blocked keywords', text: 'Never use `http.send`, `time.now`, `crypto`, or `pattern_id` — CrowdStrike rejects them' },
    { title: 'Tabs not spaces', text: 'Indentation must use tabs — the Regal linter rejects spaces' },
    { title: 'Iteration syntax', text: 'Must use `some X in Y` — the old `array[_]` syntax is rejected' },
    { title: 'Line length', text: 'Max 120 characters per line' },
    { title: 'Rule ordering', text: 'All helper rules (like pod_spec) must come before result rules' },
  ],
  patterns: [
    'Container iteration: `some container in pod_spec.containers`',
    'Security context: `container.securityContext.privileged == true`',
    'Image check: `endswith(container.image, ":latest")`',
    'Deny message: `msg := sprintf("Container \'%s\' violated policy", [container.name])`',
    'Set comprehension: `bad contains name if { some c in containers; ... }` — use when mixing pod and container checks',
    'Pod-level check: `pod_spec.hostPID == true` — no container loop needed',
  ],
  pitfalls: [
    'Setting a default result — this would deny every admission request',
    'Using spaces instead of tabs — Regal rejects it, CrowdStrike API returns an error',
    'Using `array[_]` instead of `some X in Y` — old syntax, rejected by linter',
    'Mixing pod-level and container-level conditions in the same rule — use set comprehension to separate them',
    'Non-ASCII characters in deny messages — use hyphens `-` not em dashes',
    'Pod spec path varies by resource type — Pod uses `.spec`, Deployment uses `.spec.template.spec`, CronJob uses `.spec.jobTemplate.spec.template.spec`',
    '`hostNetwork: true` bypasses the admission webhook entirely — can only detect, not prevent',
  ],
};

// --- CSPM Example Templates ---

export const CSPM_TEMPLATES: RegoTemplate[] = [
  {
    id: 's3-security',
    name: 'S3 Bucket Security',
    description: 'Check public access block settings and required tags',
    code: `package crowdstrike

# Simple S3 Bucket Security Policy
# Checks for basic S3 security best practices

default result := "pass"

# Fail if bucket allows public read access
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == false
}

# Fail if bucket allows public write access
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == false
}

# Fail if bucket is missing Environment tag
result = "fail" if {
    input.resource_type == "AWS::S3::Bucket"
    not input.tags.Environment
}`,
  },
  {
    id: 'ec2-tagging',
    name: 'EC2 Instance Tagging',
    description: 'Enforce required tags and valid tag values on EC2 instances',
    code: `package crowdstrike

# Simple EC2 Instance Tagging Policy
# Ensures EC2 instances have proper tags for governance

default result := "pass"

# Fail if instance is missing Environment tag
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    not input.tags.Environment
}

# Fail if Environment tag has invalid value
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    input.tags.Environment
    not input.tags.Environment in ["dev", "staging", "prod"]
}

# Fail if production instance is missing Owner tag
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    input.tags.Environment == "prod"
    not input.tags.Owner
}`,
  },
  {
    id: 'ecr-cross-account',
    name: 'ECR Cross-Account Access',
    description: 'Detect unauthorized AWS accounts in ECR registry policies',
    code: `package crowdstrike

# ECR Cross-Account Access Control Policy
# Prevents unauthorized AWS accounts from accessing ECR repositories

# Define approved AWS accounts for cross-account access
approved_accounts := {
    "517716713836"  # Example account
    # Add more approved accounts here as needed
}

default result := "pass"

# Parse the ECR registry policy document
policy_doc := json.unmarshal(input.configuration.policyText)

# Extract AWS account IDs from policy principals
principal_accounts contains account_id if {
    statement := policy_doc.Statement[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS
    is_string(principal)
    startswith(principal, "arn:aws:iam::")
    parts := split(principal, ":")
    account_id := parts[4]
}

# Find accounts that are NOT approved
unauthorized_accounts := principal_accounts - approved_accounts

# Fail if any unauthorized accounts are found
result = "fail" if {
    input.resource_type == "AWS::ECR::RegistryPolicy"
    count(unauthorized_accounts) > 0
}`,
  },
];

// --- KAC Example Templates ---

export const KAC_TEMPLATES: RegoTemplate[] = [
  {
    id: 'deny-privileged',
    name: 'Deny Privileged Containers',
    description: 'Prevent containers from running in privileged mode',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tcontainer.securityContext.privileged == true\n\tmsg := sprintf(\"Container '%s' must not run in privileged mode\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tcontainer.securityContext.privileged == true\n\tmsg := sprintf(\"Init container '%s' must not run in privileged mode\", [container.name])\n}\n",
  },
  {
    id: 'require-registry',
    name: 'Require Approved Image Registry',
    description: 'Ensure all images come from an approved container registry',
    code: "package customrule\n\nimport rego.v1\n\napproved_registry := \"123456789012.dkr.ecr.us-east-1.amazonaws.com/\"\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tnot startswith(container.image, approved_registry)\n\tmsg := sprintf(\"Container '%s' uses unapproved image '%s' - only images from '%s' are allowed\", [container.name, container.image, approved_registry])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tnot startswith(container.image, approved_registry)\n\tmsg := sprintf(\"Init container '%s' uses unapproved image '%s' - only images from '%s' are allowed\", [container.name, container.image, approved_registry])\n}\n",
  },
  {
    id: 'enforce-resource-limits',
    name: 'Enforce Resource Limits',
    description: 'Require CPU and memory limits on all containers',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tnot container.resources.limits.cpu\n\tmsg := sprintf(\"Container '%s' must define CPU limits in resources.limits.cpu\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tnot container.resources.limits.memory\n\tmsg := sprintf(\"Container '%s' must define memory limits in resources.limits.memory\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tnot container.resources.limits.cpu\n\tmsg := sprintf(\"Init container '%s' must define CPU limits in resources.limits.cpu\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tnot container.resources.limits.memory\n\tmsg := sprintf(\"Init container '%s' must define memory limits in resources.limits.memory\", [container.name])\n}\n",
  },
  {
    id: 'deny-latest-tag',
    name: 'Deny Latest Image Tag',
    description: 'Prevent use of :latest tag or missing tags on container images',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tendswith(container.image, \":latest\")\n\tmsg := sprintf(\"Container '%s' uses :latest tag - use a specific version tag instead\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.containers\n\tnot contains(container.image, \":\")\n\tmsg := sprintf(\"Container '%s' image '%s' has no tag - use a specific version tag\", [container.name, container.image])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tendswith(container.image, \":latest\")\n\tmsg := sprintf(\"Init container '%s' uses :latest tag - use a specific version tag instead\", [container.name])\n}\n\nresult := msg if {\n\tsome container in pod_spec.initContainers\n\tnot contains(container.image, \":\")\n\tmsg := sprintf(\"Init container '%s' image '%s' has no tag - use a specific version tag\", [container.name, container.image])\n}\n",
  },
  {
    id: 'block-hostpath',
    name: 'Block hostPath Volumes',
    description: 'Prevent pods from mounting hostPath volumes',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := msg if {\n\tsome volume in pod_spec.volumes\n\tvolume.hostPath\n\tmsg := sprintf(\"Volume '%s' uses hostPath '%s' - not allowed\", [volume.name, volume.hostPath.path])\n}\n",
  },
  {
    id: 'deny-host-namespaces',
    name: 'Deny Host Namespaces',
    description: 'Block hostNetwork, hostPID, and hostIPC on pods',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\nresult := \"Pod must not use hostNetwork\" if {\n\tpod_spec.hostNetwork == true\n}\n\nresult := \"Pod must not use hostPID\" if {\n\tpod_spec.hostPID == true\n}\n\nresult := \"Pod must not use hostIPC\" if {\n\tpod_spec.hostIPC == true\n}\n",
  },
  {
    id: 'require-non-root',
    name: 'Require runAsNonRoot',
    description: 'Enforce that containers set runAsNonRoot in their security context',
    code: "package customrule\n\nimport rego.v1\n\npod_spec := input.request.object.spec if {\n\tinput.request.kind.kind == \"Pod\"\n}\n\npod_spec := input.request.object.spec.template.spec if {\n\tinput.request.kind.kind in [\"Deployment\", \"DaemonSet\", \"StatefulSet\", \"ReplicaSet\", \"ReplicationController\", \"Job\"]\n}\n\npod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {\n\tinput.request.kind.kind == \"CronJob\"\n}\n\ncontainers_without_non_root contains container.name if {\n\tsome container in pod_spec.containers\n\tnot container.securityContext.runAsNonRoot\n}\n\nresult := msg if {\n\tnot pod_spec.securityContext.runAsNonRoot\n\tcount(containers_without_non_root) > 0\n\tnames := concat(\", \", containers_without_non_root)\n\tmsg := sprintf(\"Containers must set runAsNonRoot to true - %s\", [names])\n}\n",
  },
];
