# Writing CrowdStrike Rego Policies — Complete Guide

This document covers everything you need to write Rego v1 policies for two CrowdStrike products:
- **CSPM Custom IOMs** — Indicators of Misconfiguration for cloud resource compliance
- **KAC Custom Rules** — Kubernetes Admission Controller rules for real-time workload admission control

---

# Part 1: CSPM Custom IOM Policies

## 1. How CrowdStrike Evaluates Custom Policies

CrowdStrike evaluates your Rego policy against individual cloud assets one at a time. For each asset:

1. The asset's enriched JSON data is injected as the `input` object.
2. Your Rego policy runs against that `input`.
3. CrowdStrike reads the value of the `result` variable.
4. Based on `result`, the asset is marked compliant (`pass`), non-compliant (`fail`), or excluded (`skip`).

There is no batch evaluation. Each policy invocation sees exactly one asset.

---

## 2. The CrowdStrike Rego Contract

Every custom policy must follow this contract exactly.

### Package Declaration
```rego
package crowdstrike
```
This is mandatory. No other package name is accepted.

### Result Variable
The policy must define a variable called `result` that evaluates to one of three string values:

| Value | Meaning | Effect in Falcon |
|-------|---------|-----------------|
| `"pass"` | Asset is compliant | No finding generated |
| `"fail"` | Asset is non-compliant | Finding/alert created |
| `"skip"` | Asset excluded from evaluation | Ignored silently |

### Default Result
You must declare a default:
```rego
default result := "fail"
```

**Security-first approach**: Use `default result := "fail"` so that if no rule matches, the asset is treated as non-compliant. This is the recommended pattern.

**Detection approach**: Use `default result := "pass"` when you are specifically looking for a bad condition. If the bad condition is not found, the asset passes.

### Minimal Valid Policy
```rego
package crowdstrike

default result := "fail"

result = "pass" if {
    # conditions that prove compliance
}
```

---

## 3. The `input` Object

The `input` object contains the full enriched asset data from CrowdStrike. The exact fields depend on the cloud provider and resource type, but the common structure is:

```
input
├── resource_id          # Unique identifier (string)
├── resource_type        # e.g., "AWS::S3::Bucket" (string)
├── service              # e.g., "aws-s3" (string)
├── region               # e.g., "us-east-1" (string)
├── account_id           # Cloud account identifier (string)
├── tags                 # Key-value tag pairs (object)
│   ├── Environment      # Example tag
│   └── Owner            # Example tag
└── configuration        # Resource-specific config (object)
    ├── ...              # Fields vary by resource type
    └── ...
```

### Key Rules for Accessing `input`
- Always access fields from `input` (e.g., `input.tags.Environment`, `input.configuration.publicAccessBlockConfiguration`).
- The `configuration` object contains the resource-specific data and varies significantly between resource types.
- The `tags` object contains cloud resource tags as key-value pairs.
- Field names are case-sensitive and follow the cloud provider's naming conventions.

---

## 4. Rego v1 Syntax Fundamentals

### Rules

A rule assigns a value when its body evaluates to true. All statements in the body are implicitly AND-ed:

```rego
# This rule assigns "pass" to result when ALL conditions are true
result = "pass" if {
    input.resource_type == "AWS::S3::Bucket"
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == true
}
```

### Multiple Rules with the Same Name

You can define multiple rules that assign different values. They act as OR — if any rule body is satisfied, its value wins. Order matters: earlier matches take priority.

```rego
# Fail if missing encryption
result = "fail" if {
    not input.configuration.serverSideEncryptionConfiguration
}

# Fail if encryption uses wrong algorithm
result = "fail" if {
    input.configuration.serverSideEncryptionConfiguration
    config := input.configuration.serverSideEncryptionConfiguration.rules[0]
    config.applyServerSideEncryptionByDefault.sseAlgorithm != "aws:kms"
}
```

### Negation with `not`

Use `not` to check that something is absent or false:

```rego
# Fail if Environment tag is missing
result = "fail" if {
    not input.tags.Environment
}
```

### Equality and Comparison
```rego
input.configuration.engine == "mysql"          # string equality
input.configuration.allocatedStorage > 100     # numeric comparison
input.tags.Environment != "prod"               # inequality
```

### String Operations
```rego
startswith(input.configuration.bucketName, "log-")
endswith(input.configuration.functionName, "-prod")
contains(input.configuration.description, "deprecated")
regex.match("^prod-.*", input.configuration.name)
lower(input.tags.Environment) == "production"
```

### The `in` Keyword (Membership Test)
```rego
# Check if value is in a set or array
input.tags.Environment in ["dev", "staging", "prod"]
"us-east-1" in input.configuration.availableRegions
```

### Sets
```rego
# Define a set of approved values
approved_regions := {"us-east-1", "us-west-2", "eu-west-1"}

# Check membership
result = "fail" if {
    not input.region in approved_regions
}
```

### Set Comprehensions
```rego
# Build a set from data
public_ports contains port if {
    rule := input.configuration.securityGroupRules[_]
    rule.direction == "INGRESS"
    rule.sourceRanges[_] == "0.0.0.0/0"
    port := rule.port
}
```

### Object Comprehensions
```rego
# Build an object from data
tag_map := {k: v |
    tag := input.tags[k]
    v := tag
}
```

### Array Iteration
```rego
# Iterate over array elements using [_] or [i]
result = "fail" if {
    rule := input.configuration.firewallRules[_]
    rule.sourceRanges[_] == "0.0.0.0/0"
    rule.allowed[_].ports[_] == "22"
}

# With index
result = "fail" if {
    some i
    rule := input.configuration.firewallRules[i]
    rule.action == "allow"
}
```

### JSON Parsing
Some fields contain JSON stored as a string. Use `json.unmarshal` to parse them:
```rego
# Parse a JSON policy document stored as a string
policy_doc := json.unmarshal(input.configuration.policyText)

# Now access fields within the parsed document
result = "fail" if {
    statement := policy_doc.Statement[_]
    statement.Effect == "Allow"
    statement.Principal == "*"
}
```

### Helper Functions with `object.get`
Safely access nested fields with a default value:
```rego
# Returns {} if "configuration" is missing from input
config := object.get(input, "configuration", {})

# Returns false if "blockPublicAcls" is missing
block_acls := object.get(config, "blockPublicAcls", false)
```

---

## 5. Common Policy Patterns

### Pattern 1: Required Tag Check
```rego
package crowdstrike

default result := "fail"

# Pass if all required tags are present
result = "pass" if {
    input.tags.Environment
    input.tags.Owner
    input.tags.CostCenter
}
```

### Pattern 2: Tag Value Validation
```rego
package crowdstrike

default result := "fail"

# Pass if Environment tag has a valid value
result = "pass" if {
    input.tags.Environment in ["dev", "staging", "prod"]
}
```

### Pattern 3: Boolean Configuration Check
```rego
package crowdstrike

default result := "fail"

# Pass if all public access blocks are enabled
result = "pass" if {
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == true
    input.configuration.publicAccessBlockConfiguration.ignorePublicAcls == true
    input.configuration.publicAccessBlockConfiguration.restrictPublicBuckets == true
}
```

### Pattern 4: Nested Field Validation with Null Safety
```rego
package crowdstrike

default result := "fail"

# Safely access nested encryption configuration
result = "pass" if {
    enc := input.configuration.serverSideEncryptionConfiguration
    enc != null
    rule := enc.rules[0]
    rule.applyServerSideEncryptionByDefault.sseAlgorithm == "aws:kms"
}
```

### Pattern 5: Allowlist / Denylist with Set Operations
```rego
package crowdstrike

approved_accounts := {
    "111111111111",
    "222222222222"
}

default result := "pass"

# Parse policy document and extract account IDs
policy_doc := json.unmarshal(input.configuration.policyText)

principal_accounts contains account_id if {
    statement := policy_doc.Statement[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS
    is_string(principal)
    startswith(principal, "arn:aws:iam::")
    parts := split(principal, ":")
    account_id := parts[4]
}

# Compute unauthorized accounts via set subtraction
unauthorized_accounts := principal_accounts - approved_accounts

# Fail if any unauthorized accounts found
result = "fail" if {
    count(unauthorized_accounts) > 0
}
```

### Pattern 6: Skip Certain Resources
```rego
package crowdstrike

default result := "fail"

# Skip evaluation for sandbox accounts
result = "skip" if {
    input.account_id == "999999999999"
}

# Skip resources tagged as exempt
result = "skip" if {
    input.tags.PolicyExempt == "true"
}

# Compliance check for non-skipped resources
result = "pass" if {
    input.configuration.encrypted == true
}
```

### Pattern 7: Multi-Condition Fail (OR logic across fail rules)
```rego
package crowdstrike

default result := "pass"

# Fail if SSH is open to the world
result = "fail" if {
    rule := input.configuration.firewallRules[_]
    rule.allowed[_].ports[_] == "22"
    rule.sourceRanges[_] == "0.0.0.0/0"
}

# Fail if RDP is open to the world
result = "fail" if {
    rule := input.configuration.firewallRules[_]
    rule.allowed[_].ports[_] == "3389"
    rule.sourceRanges[_] == "0.0.0.0/0"
}
```

### Pattern 8: Numeric Threshold Check
```rego
package crowdstrike

default result := "fail"

# Pass if log retention is at least 90 days
result = "pass" if {
    input.configuration.retentionInDays >= 90
}
```

### Pattern 9: String Pattern Matching
```rego
package crowdstrike

default result := "fail"

# Pass if resource name follows naming convention
result = "pass" if {
    regex.match("^(dev|stg|prd)-[a-z]+-[a-z0-9]+$", input.configuration.name)
}
```

### Pattern 10: Counting and Aggregation
```rego
package crowdstrike

default result := "pass"

# Count rules that allow all traffic
open_rules := [rule |
    rule := input.configuration.securityGroupRules[_]
    rule.protocol == "-1"
    rule.cidrBlock == "0.0.0.0/0"
]

# Fail if any fully open rules exist
result = "fail" if {
    count(open_rules) > 0
}
```

---

## 6. Null Safety and Defensive Coding

Cloud asset data is inconsistent. Fields can be missing, null, empty strings, or empty objects. Always code defensively.

### Checking Field Existence
```rego
# BAD: Will error if tags is missing
result = "fail" if {
    input.tags.Environment != "prod"
}

# GOOD: Check existence first
result = "fail" if {
    not input.tags.Environment
}

result = "fail" if {
    input.tags.Environment
    input.tags.Environment != "prod"
}
```

### Using `object.get` for Deep Nesting
```rego
# BAD: Will error if any intermediate field is missing
val := input.configuration.encryption.settings.enabled

# GOOD: Safe access with defaults
config := object.get(input, "configuration", {})
encryption := object.get(config, "encryption", {})
settings := object.get(encryption, "settings", {})
enabled := object.get(settings, "enabled", false)
```

### Handling Both Boolean and String Booleans
Some cloud providers return `true` (boolean) while others return `"true"` (string):
```rego
# Handle both cases
is_enabled(field) if { field == true }
is_enabled(field) if { field == "true" }
is_enabled(field) if { field == "True" }
```

---

## 7. Common Pitfalls

| Pitfall | Problem | Fix |
|---------|---------|-----|
| Wrong package name | `package mycompany` | Must be `package crowdstrike` |
| Wrong result values | `result = true` | Must be `"pass"`, `"fail"`, or `"skip"` |
| Missing default | No `default result` line | Add `default result := "fail"` |
| Accessing missing fields | `input.config.x` when `config` doesn't exist | Use `not` or `object.get` |
| Type mismatch | Comparing `true` to `"true"` | Check actual JSON types |
| Numbered alert steps | `"1. Check console\|2. Fix it"` | Use `"Check console\|Fix it"` — no numbers |
| Using `:=` in rule heads | `result := "pass" if { ... }` | Use `result = "pass" if { ... }` (single `=` for rule head assignment) |
| Array vs set confusion | Using `{}` when you need `[]` | Sets use `{}`, arrays use `[]` in Rego |

### Rule Head Assignment: `=` vs `:=`
- Use `=` when assigning a value in a rule head: `result = "pass" if { ... }`
- Use `:=` for local variable assignments inside rule bodies: `config := input.configuration`
- Use `:=` for the default declaration: `default result := "fail"`

---

## 8. When to Use Each Default

### `default result := "fail"` (Security-First)
Use when you want to **prove compliance**. The asset must satisfy specific conditions to pass. If conditions are not met (or fields are missing), it fails.

Best for:
- Encryption must be enabled
- Required tags must exist
- Public access must be blocked
- Specific configuration must be present

### `default result := "pass"` (Detection)
Use when you want to **detect a specific bad condition**. The asset passes unless a known-bad pattern is found.

Best for:
- Detect overly permissive firewall rules
- Detect unauthorized cross-account access
- Detect deprecated configurations
- Detect known-bad patterns

---

## 9. Testing Your Policy

### Via the Falcon Console
1. Go to **Cloud Security > Custom IOMs**
2. Create or edit a policy
3. Use the built-in test feature to evaluate against sample assets

### Via the CrowdStrike API
Send a POST request to the evaluation endpoint with your Rego logic and asset data:

```
POST /cloud-policies/entities/evaluation/v1
```

Query parameters:
- `cloud_provider`: `aws`, `gcp`, or `azure`
- `resource_type`: The exact resource type string
- `ids`: Array of asset IDs to test against

Request body:
```json
{
    "logic": "package crowdstrike\ndefault result := \"fail\"\nresult = \"pass\" if {\n    input.configuration.encrypted == true\n}",
    "input": { ... asset JSON ... }
}
```

The response includes the evaluation result (`pass`, `fail`, or `error`) for each tested asset.

---

## 10. Rego Policy Template

Use this as a starting point for any new policy:

```rego
package crowdstrike

# Security-first: fail unless proven compliant
default result := "fail"

# Optional: Skip resources that should be excluded
# result = "skip" if {
#     input.tags.PolicyExempt == "true"
# }

# Define what makes this resource compliant
result = "pass" if {
    # Replace with your compliance conditions
    # Example: input.configuration.encrypted == true
}
```

---
---

# Part 2: KAC (Kubernetes Admission Controller) Custom Rules

## 11. How KAC Evaluates Custom Rules

CrowdStrike KAC intercepts Kubernetes API requests in real time via an admission webhook. For each admission request:

1. The Kubernetes API server sends an **AdmissionReview** object to the KAC webhook.
2. The KAC evaluates your Rego policy against that AdmissionReview `input`.
3. If your policy produces a non-empty `result` string, the admission is **denied** with that message.
4. If your policy produces no `result` (no rule matches), the admission is **allowed**.

This is fundamentally different from CSPM: KAC is **real-time admission control** (pre-deployment), while CSPM is **post-deployment compliance scanning**.

---

## 12. The KAC Rego Contract

Every KAC custom rule must follow this contract exactly.

### Package Declaration
```rego
package customrule
```
This is mandatory. No other package name is accepted for KAC rules.

### Import
```rego
import rego.v1
```
Always include this import for Rego v1 syntax support.

### Result Variable — Deny Semantics
KAC does **not** use pass/fail/skip. Instead:

| Condition | Effect |
|-----------|--------|
| No `result` rule matches | Admission is **allowed** |
| `result` is assigned a non-empty string | Admission is **denied** with that string as the message |

There is **no `default result`** line. The absence of a result means allow.

```rego
# This denies the resource with a descriptive message
result := "Privileged containers are not allowed" if {
	# conditions that detect a violation
}
```

### No Default Result
Do NOT add `default result := "pass"` or any default. KAC is allow-by-default — if no deny rule fires, the resource is admitted.

### Minimal Valid KAC Policy
```rego
package customrule

import rego.v1

# Deny privileged containers in Pods
result := msg if {
	some container in input.request.object.spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}
```

---

## 13. KAC Input Structure — AdmissionReview

The `input` object is a Kubernetes AdmissionReview. The key path is `input.request.object`, which contains the full Kubernetes resource being admitted.

```
input
├── request
│   ├── uid                    # Unique request ID (string)
│   ├── kind
│   │   ├── group              # API group (e.g., "apps", "")
│   │   ├── version            # API version (e.g., "v1")
│   │   └── kind               # Resource kind (e.g., "Pod", "Deployment")
│   ├── resource
│   │   ├── group
│   │   ├── version
│   │   └── resource           # Plural resource name (e.g., "pods")
│   ├── namespace              # Target namespace (string)
│   ├── operation              # "CREATE", "UPDATE", "DELETE"
│   ├── userInfo
│   │   ├── username           # Who submitted the request
│   │   └── groups             # User's groups
│   └── object                 # The full K8s resource being admitted
│       ├── apiVersion
│       ├── kind
│       ├── metadata
│       │   ├── name
│       │   ├── namespace
│       │   ├── labels
│       │   └── annotations
│       └── spec               # Resource-specific spec (varies by kind)
```

### Spec Paths by Resource Type

The `spec` path to the Pod template varies by resource type:

| Resource Type | Path to Pod Spec |
|--------------|-----------------|
| Pod | `input.request.object.spec` |
| Deployment | `input.request.object.spec.template.spec` |
| DaemonSet | `input.request.object.spec.template.spec` |
| StatefulSet | `input.request.object.spec.template.spec` |
| ReplicaSet | `input.request.object.spec.template.spec` |
| ReplicationController | `input.request.object.spec.template.spec` |
| Job | `input.request.object.spec.template.spec` |
| CronJob | `input.request.object.spec.jobTemplate.spec.template.spec` |
| Service | `input.request.object.spec` (no Pod spec — has ports, selectors, etc.) |

### Container Arrays
Within the Pod spec, containers are in three possible arrays:
- `spec.containers` — regular containers (always present)
- `spec.initContainers` — init containers (optional)
- `spec.ephemeralContainers` — ephemeral debug containers (optional)

---

## 14. KAC Helper Rule Patterns

Since the spec path differs by resource type, use helper rules to extract the Pod spec uniformly.

### Pattern: Extract Pod Spec from Any Workload Type
```rego
package customrule

import rego.v1

# Pod
pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

# Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job
pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

# CronJob
pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}
```

### Pattern: Iterate Containers with `some ... in`
```rego
# Iterate regular containers — MUST use "some container in" syntax
result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' is privileged", [container.name])
}
```

### Pattern: Iterate Both Regular and Init Containers
```rego
# Regular containers
result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' must define CPU limits", [container.name])
}

# Init containers
result := msg if {
	some container in pod_spec.initContainers
	not container.resources.limits.cpu
	msg := sprintf("Init container '%s' must define CPU limits", [container.name])
}
```

### Pattern: Set Comprehension for Non-Loop Conditions

When you need to check a condition that doesn't depend on the loop variable (e.g., a pod-level setting) alongside a container-level condition, use a **set comprehension** to collect items first, then check outside the loop. This avoids the Regal `non-loop-expression` lint error.

```rego
# BAD — mixes loop and non-loop conditions (Regal rejects this):
# result := msg if {
#     some container in pod_spec.containers
#     not pod_spec.securityContext.runAsNonRoot       <-- non-loop expression
#     not container.securityContext.runAsNonRoot
#     msg := sprintf("Container '%s' must set runAsNonRoot", [container.name])
# }

# GOOD — collect non-compliant containers into a set, then check pod-level outside the loop:
containers_without_non_root contains container.name if {
	some container in pod_spec.containers
	not container.securityContext.runAsNonRoot
}

result := msg if {
	not pod_spec.securityContext.runAsNonRoot
	count(containers_without_non_root) > 0
	names := concat(", ", containers_without_non_root)
	msg := sprintf("Containers must set runAsNonRoot to true - %s", [names])
}
```

### Pattern: Get Pod-Level Metadata Labels
```rego
# For Pods, labels are on the object itself
pod_labels := input.request.object.metadata.labels if {
	input.request.kind.kind == "Pod"
}

# For workload types, check the pod template labels
pod_labels := input.request.object.spec.template.metadata.labels if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

# For CronJob, labels are deeper
pod_labels := input.request.object.spec.jobTemplate.spec.template.metadata.labels if {
	input.request.kind.kind == "CronJob"
}
```

---

## 15. Common KAC Policy Patterns

All patterns below use **linter-compliant** syntax that passes `opa fmt` and CrowdStrike's Regal linter. See Section 19 for full linter requirements.

### Pattern 1: Deny Privileged Containers
```rego
package customrule

import rego.v1

workload_kinds := {
	"Deployment", "DaemonSet", "StatefulSet",
	"ReplicaSet", "ReplicationController", "Job",
}

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in workload_kinds
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf(
		"Container '%s' must not run privileged",
		[container.name],
	)
}
```

### Pattern 2: Require Image from Approved Registry
```rego
approved_registry := "123456789012.dkr.ecr.us-east-1.amazonaws.com/"

result := msg if {
	some container in pod_spec.containers
	not startswith(container.image, approved_registry)
	msg := sprintf(
		"Container '%s' uses unapproved image '%s'",
		[container.name, container.image],
	)
}
```

### Pattern 3: Deny :latest Tag
```rego
result := msg if {
	some container in pod_spec.containers
	endswith(container.image, ":latest")
	msg := sprintf("Container '%s' uses :latest tag - use a specific version tag", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not contains(container.image, ":")
	msg := sprintf("Container '%s' has no image tag - use a specific version tag", [container.name])
}
```

### Pattern 4: Require Resource Limits
```rego
result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' must define CPU limits in resources.limits.cpu", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.memory
	msg := sprintf("Container '%s' must define memory limits in resources.limits.memory", [container.name])
}
```

### Pattern 5: Require Pod Labels
```rego
result := "Pod must have an 'owner' label" if {
	not input.request.object.metadata.labels.owner
}

result := "Pod must have a 'team' label" if {
	not input.request.object.metadata.labels.team
}
```

### Pattern 6: Block hostPath Volumes
```rego
result := msg if {
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf("Volume '%s' uses hostPath '%s' - not allowed", [volume.name, volume.hostPath.path])
}
```

### Pattern 7: Deny Host Namespaces (hostPID / hostIPC)
```rego
result := "Pod must not use hostPID" if {
	pod_spec.hostPID == true
}

result := "Pod must not use hostIPC" if {
	pod_spec.hostIPC == true
}
```

> **Note**: `hostNetwork: true` bypasses the Kubernetes admission webhook entirely — the admission request never reaches the KAC sensor. You can still write a rule for `hostNetwork` (it will fire in Alert mode or when `hostNetwork` is part of a broader workload spec), but it **cannot be enforced in Prevent mode**. `hostPID` and `hostIPC` are fully enforceable.

### Pattern 8: Require runAsNonRoot (Set Comprehension Pattern)
```rego
containers_without_non_root contains container.name if {
	some container in pod_spec.containers
	not container.securityContext.runAsNonRoot
}

result := msg if {
	not pod_spec.securityContext.runAsNonRoot
	count(containers_without_non_root) > 0
	names := concat(", ", containers_without_non_root)
	msg := sprintf("Containers must set runAsNonRoot to true - %s", [names])
}
```

This pattern avoids the Regal `non-loop-expression` lint error by separating the pod-level check from the container-level iteration.

---

## 16. Blocked Keywords in KAC

The following are **blocked** in KAC Rego policies. The platform will reject any policy containing them:

| Keyword | Reason |
|---------|--------|
| `http.send` | No external HTTP calls allowed — prevents data exfiltration and latency |
| `time.now` | No time-based operations — prevents non-deterministic behavior |
| `crypto` | No cryptographic functions — prevents abuse |
| `pattern_id` | Reserved identifier — conflicts with platform internals |

---

## 17. CSPM IOM vs KAC Comparison

| Aspect | CSPM IOM | KAC |
|--------|----------|-----|
| **Package** | `package crowdstrike` | `package customrule` |
| **Import** | Not required | `import rego.v1` |
| **Default** | `default result := "pass"` or `"fail"` | No default (allow by default) |
| **Result values** | `"pass"`, `"fail"`, `"skip"` | Empty = allow, non-empty string = deny message |
| **Input** | Cloud resource JSON (`input.configuration`, `input.tags`) | K8s AdmissionReview (`input.request.object.spec`) |
| **Evaluation scope** | Post-deployment compliance scanning | Real-time admission control (pre-deployment) |
| **API scope** | `cloud-security-policies:read/write` | `falcon-container-policies:read/write` |
| **Blocked keywords** | None | `http.send`, `time.now`, `crypto`, `pattern_id` |
| **Resource types** | AWS/GCP/Azure/OCI cloud resources | K8s Pod, Deployment, DaemonSet, StatefulSet, etc. |
| **Linter** | Not enforced | Must pass CrowdStrike's Regal linter (see Section 19) |

---

## 18. KAC Policy Template

Use this as a starting point for any new KAC policy:

```rego
package customrule

import rego.v1

# Supported workload kinds (broken out for line-length compliance)
workload_kinds := {
	"Deployment", "DaemonSet", "StatefulSet",
	"ReplicaSet", "ReplicationController", "Job",
}

# Helper: extract pod spec from any supported workload type
pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in workload_kinds
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

# Deny rule — replace with your admission check
result := msg if {
	some container in pod_spec.containers
	# Replace with your violation condition
	# Example: container.securityContext.privileged == true
	msg := sprintf(
		"Container '%s' violates policy: <describe violation>",
		[container.name],
	)
}
```

---

## 19. KAC Regal Linter Requirements

CrowdStrike validates all uploaded KAC Rego rules against the **Regal linter** (based on OPA's `opa fmt`). Rules that fail the linter are rejected at upload time. Your code must comply with the following:

### Indentation: Tabs Only
All indentation MUST use **tabs**, not spaces. This is what `opa fmt` produces.

```rego
# CORRECT — tabs
result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' is privileged", [container.name])
}

# WRONG — spaces (will be rejected)
result := msg if {
    some container in pod_spec.containers
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' is privileged", [container.name])
}
```

### Iteration: `some X in Y` Syntax Required
You MUST use `some X in collection` for iteration. The old `X := collection[_]` syntax is rejected by the linter.

```rego
# CORRECT — some ... in
result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' needs CPU limits", [container.name])
}

# WRONG — collection[_] assignment (linter rejects this)
result := msg if {
	container := pod_spec.containers[_]
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' needs CPU limits", [container.name])
}
```

### No Non-Loop Expressions Inside Loops
The linter flags `non-loop-expression` when a condition inside a `some X in Y` loop doesn't reference the loop variable. Use the **set comprehension pattern** (Section 14) to separate pod-level checks from container-level iteration.

### No Redundant Existence Checks
Do not check that a field exists before comparing its value in the same rule body. The Regal linter flags this as `redundant-existence-check`.

```rego
# WRONG — bare existence check before comparison is redundant
result := msg if {
	some container in pod_spec.containers
	some port in container.ports
	port.hostPort                    # <-- redundant, the next line implies this
	port.hostPort < 1024
	msg := sprintf("Container '%s' uses hostPort %d", [container.name, port.hostPort])
}

# CORRECT — just use the comparison directly
result := msg if {
	some container in pod_spec.containers
	some port in container.ports
	port.hostPort < 1024
	msg := sprintf("Container '%s' uses hostPort %d", [container.name, port.hostPort])
}
```

### No Messy Incremental Rules
All incremental definitions of the same rule name (e.g., multiple `result := msg if { ... }` blocks) MUST be grouped together with NO other rules, helper definitions, set comprehensions, or blank sections between them. The linter flags this as `messy-rule`.

```rego
# WRONG — helper set comprehension inserted between two result rules
result := msg if {
	some container in pod_spec.initContainers
	container.securityContext.privileged == true
	msg := sprintf("Init container '%s' must not be privileged", [container.name])
}

# This set comprehension breaks the consecutive grouping of result rules:
init_without_non_root contains container.name if {
	some container in pod_spec.initContainers
	not container.securityContext.runAsNonRoot
}

result := msg if {
	count(init_without_non_root) > 0
	msg := sprintf("Init containers must set runAsNonRoot - %s", [concat(", ", init_without_non_root)])
}

# CORRECT — all helpers BEFORE all result rules
init_without_non_root contains container.name if {
	some container in pod_spec.initContainers
	not container.securityContext.runAsNonRoot
}

result := msg if {
	some container in pod_spec.initContainers
	container.securityContext.privileged == true
	msg := sprintf("Init container '%s' must not be privileged", [container.name])
}

result := msg if {
	count(init_without_non_root) > 0
	msg := sprintf("Init containers must set runAsNonRoot - %s", [concat(", ", init_without_non_root)])
}
```

### No Multiple Outputs from Complete Rules
`result := msg if { ... }` is a **complete rule** assignment. If TWO or more `result := msg` rules match simultaneously for the same resource, OPA throws `"complete rules must not produce multiple outputs"`. This is NOT a linter error — it's a runtime OPA error.

This commonly happens when checking multiple conditions on the same container. For example, if one rule checks for missing liveness probes and another checks for missing readiness probes, a container missing BOTH will trigger two `result :=` assignments, causing the error.

**Solutions:**
1. **Combine into one rule** — Check all conditions in a single rule body and produce one combined message
2. **Make conditions mutually exclusive** — Ensure only one rule can match per container (e.g., check liveness first, and only check readiness if liveness exists)

```rego
# WRONG — both rules fire if container has neither probe
result := msg if {
	some container in pod_spec.containers
	not container.livenessProbe
	msg := sprintf("Container '%s' must define a liveness probe", [container.name])
}
result := msg if {
	some container in pod_spec.containers
	not container.readinessProbe
	msg := sprintf("Container '%s' must define a readiness probe", [container.name])
}

# CORRECT — use set comprehensions to collect all violations, then report once
containers_missing_liveness contains container.name if {
	some container in pod_spec.containers
	not container.livenessProbe
}
containers_missing_readiness contains container.name if {
	some container in pod_spec.containers
	not container.readinessProbe
}
result := msg if {
	count(containers_missing_liveness) > 0
	names := concat(", ", containers_missing_liveness)
	msg := sprintf("Containers must define a liveness probe - %s", [names])
}
result := msg if {
	count(containers_missing_liveness) == 0
	count(containers_missing_readiness) > 0
	names := concat(", ", containers_missing_readiness)
	msg := sprintf("Containers must define a readiness probe - %s", [names])
}
```

Note: The second `result` rule adds `count(containers_missing_liveness) == 0` to ensure it only fires when the first rule does NOT fire, preventing multiple outputs.

### Deny Message Strings: Avoid Special Characters
Rule names and deny messages should only use standard ASCII characters. Avoid em dashes (`—`), curly quotes, and other Unicode characters in strings that become part of the deny message, as they can cause issues with the API. Use hyphens (`-`) instead of em dashes.

### Line Length: 120-Character Maximum
**No line may exceed 120 characters.** This is the most common cause of upload failures. Long `sprintf` calls and long array literals are the usual offenders.

Break long `sprintf` calls by assigning the format string or arguments to a variable first:

```rego
# WRONG — line exceeds 120 characters
result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' in %s '%s' must not run in privileged mode - remove securityContext.privileged or set it to false", [container.name, input.request.kind.kind, input.request.object.metadata.name])
}

# CORRECT — keep deny messages short and focused
result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf(
		"Container '%s' must not run privileged",
		[container.name],
	)
}
```

Break long array literals across multiple lines:

```rego
# WRONG — line too long
pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

# CORRECT — break the array across lines
workload_kinds := {
	"Deployment", "DaemonSet", "StatefulSet",
	"ReplicaSet", "ReplicationController", "Job",
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in workload_kinds
}
```

**Best practices for staying under 120 chars:**
- Keep deny messages concise — include the container name but skip long explanations
- Use a `workload_kinds` set variable instead of inline arrays
- Break `sprintf` calls across lines using parentheses
- Assign `input.request.object.metadata.name` to a short variable like `obj_name` if needed multiple times

### Validation Before Upload
Before uploading a KAC Rego rule, validate it locally:

```bash
# Check formatting (no output = correct)
opa fmt --diff your_rule.rego

# Run Regal linter (directory-package-mismatch is safe to ignore)
regal lint your_rule.rego
```

If `opa fmt --diff` produces output, your indentation or syntax doesn't match the expected format. Apply the fix with `opa fmt -w your_rule.rego`.

---

## 20. Common KAC Pitfalls

| Pitfall | Problem | Fix |
|---------|---------|-----|
| Wrong package name | `package crowdstrike` | Must be `package customrule` for KAC |
| Adding default result | `default result := "pass"` | No default — KAC is allow-by-default |
| Using pass/fail | `result = "pass"` | Result is a deny message string, not pass/fail |
| Space indentation | 4-space indentation | Must use tabs (`opa fmt` enforces this) |
| Old iteration syntax | `container := pod_spec.containers[_]` | Must use `some container in pod_spec.containers` |
| Non-loop expression | `not pod_spec.securityContext.runAsNonRoot` inside a `some` loop | Use set comprehension pattern (Section 14) |
| Blocked keywords | `http.send`, `time.now` | Remove — these are rejected at upload |
| hostNetwork enforcement | Expecting `hostNetwork: true` to be denied | hostNetwork bypasses the webhook entirely — use Alert mode only |
| Using `:=` vs `=` in heads | `result = msg if { ... }` for incremental rules | Use `result := msg if { ... }` — KAC rules use `:=` |
| Only handling Pods | Missing Deployment/DaemonSet/Job paths | Include the pod_spec helper rules for all workload types |
| Line too long | `sprintf(...)` or `in [...]` exceeds 120 chars | Break across lines; use `workload_kinds` set variable; keep deny messages short |
| Redundant existence check | `port.hostPort` then `port.hostPort < 1024` | Remove the bare existence check — the comparison implies existence |
| Messy incremental rule | Helper rules between `result :=` definitions | Move ALL helpers before ALL `result :=` rules — group by name |
| Multiple outputs | Two `result :=` rules fire for same container | Use set comprehensions + mutually exclusive conditions (Section 19) |

---

## 21. Testing KAC Rules Locally with OPA

Before deploying a KAC rule to CrowdStrike, test it locally using the Open Policy Agent (OPA) binary. This evaluates your Rego logic against a Kubernetes manifest without affecting any live clusters. There is **no UI in the Falcon console** for testing or managing KAC custom Rego rules — all testing and deployment is done via CLI and API.

### CLI with `opa eval`

1. **Save your Rego rule** to a file:
```bash
cat > policy.rego << 'EOF'
package customrule

import rego.v1

result := msg if {
	some container in input.request.object.spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container %s must not run privileged", [container.name])
}
EOF
```

2. **Create an AdmissionReview input** wrapping your K8s manifest:
```bash
cat > input.json << 'EOF'
{
  "request": {
    "kind": {"kind": "Pod"},
    "operation": "CREATE",
    "namespace": "default",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {"name": "test-pod", "namespace": "default"},
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:latest",
            "securityContext": {"privileged": true}
          }
        ]
      }
    }
  }
}
EOF
```

3. **Run OPA eval**:
```bash
opa eval -d policy.rego -i input.json "data.customrule.result" --format json
```

4. **Interpret the result**:
   - If the output JSON contains a non-empty string in `result[0].expressions[0].value`, the rule would **DENY** with that message
   - If the value is `undefined` or the expressions array is empty, the rule would **ALLOW**

### Important Notes

- The `package` name must be `customrule` — OPA evaluates `data.customrule.result`
- The input must be an AdmissionReview structure (not raw YAML). The manifest goes inside `input.request.object`
- `input.request.kind.kind` must match the resource type for multi-kind helper rules to work
- The Regal linter (which CrowdStrike uses at upload time) is separate from OPA eval. A rule can pass OPA eval but fail linting. Run `regal lint policy.rego` separately to check lint compliance.
- Install OPA: `brew install opa` (macOS) or download from https://www.openpolicyagent.org/docs/latest/#running-opa
