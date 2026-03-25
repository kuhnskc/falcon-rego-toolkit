# CrowdStrike Custom Policy — Example Library

A collection of complete, production-ready example policies for both:
- **CSPM Custom IOMs** — Cloud resource compliance policies for AWS, GCP, and Azure
- **KAC Custom Rules** — Kubernetes admission controller rules

---

# Part 1: CSPM Custom IOM Examples

## AWS Examples

### Example 1: S3 Bucket Public Access Block

**Title:** S3 Bucket Public Access Block Required

**Description:** Ensures all S3 buckets have all four public access block settings enabled to prevent accidental public exposure of data.

**Severity:** High

**Resource Type:** `AWS::S3::Bucket`

**Rego Policy:**
```rego
package crowdstrike

# Security-first: fail unless all public access blocks are confirmed enabled
default result := "fail"

# Pass only when all four public access block settings are enabled
result = "pass" if {
    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true
    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == true
    input.configuration.publicAccessBlockConfiguration.ignorePublicAcls == true
    input.configuration.publicAccessBlockConfiguration.restrictPublicBuckets == true
}
```

**Alert Logic:**
```
S3 bucket does not have all public access block settings enabled|Public access block is a critical defense against accidental data exposure|One or more of the four public access block settings is disabled or missing
```

**Remediation:**
```
Open the S3 bucket in the AWS Console|Navigate to the Permissions tab|Click Edit under Block public access (bucket settings)|Enable all four checkboxes: Block public ACLs, Block public bucket policies, Ignore public ACLs, Restrict public buckets|Save changes
```

---

### Example 2: EC2 Instance Required Tags

**Title:** EC2 Instance Required Tagging Policy

**Description:** Ensures EC2 instances have the mandatory Environment and Owner tags for governance and cost tracking. Production instances must also have a CostCenter tag.

**Severity:** Medium

**Resource Type:** `AWS::EC2::Instance`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if Environment tag is missing
result = "fail" if {
    not input.tags.Environment
}

# Fail if Environment tag has an invalid value
result = "fail" if {
    input.tags.Environment
    not input.tags.Environment in ["dev", "staging", "prod"]
}

# Fail if Owner tag is missing
result = "fail" if {
    not input.tags.Owner
}

# Fail if production instance is missing CostCenter tag
result = "fail" if {
    input.tags.Environment == "prod"
    not input.tags.CostCenter
}
```

**Alert Logic:**
```
EC2 instance is missing one or more required tags|Required tags: Environment (dev/staging/prod), Owner|Production instances also require CostCenter tag
```

**Remediation:**
```
Open the EC2 instance in the AWS Console|Navigate to the Tags tab|Click Manage tags|Add missing required tags: Environment, Owner, and CostCenter (if production)|Save changes
```

---

### Example 3: EC2 Instance IMDSv2 Required

**Title:** EC2 Instance Metadata Service v2 Required

**Description:** Ensures EC2 instances require IMDSv2 (Instance Metadata Service v2) by enforcing HttpTokens to "required", which mitigates SSRF-based credential theft attacks.

**Severity:** High

**Resource Type:** `AWS::EC2::Instance`

**Rego Policy:**
```rego
package crowdstrike

# Fail by default — must prove IMDSv2 is enforced
default result := "fail"

# Pass if httpTokens is set to "required" (IMDSv2 enforced)
result = "pass" if {
    input.configuration.metadataOptions.httpTokens == "required"
}
```

**Alert Logic:**
```
EC2 instance is not enforcing IMDSv2|Instance Metadata Service v1 is vulnerable to SSRF attacks|Attackers can steal IAM credentials via metadata endpoint without IMDSv2
```

**Remediation:**
```
Open the EC2 instance in the AWS Console|Select Actions > Instance Settings > Modify instance metadata options|Set IMDSv2 to Required|Set Hop limit to 1|Save changes
```

---

### Example 4: ECR Cross-Account Access Control

**Title:** ECR Registry Unauthorized Cross-Account Access

**Description:** Detects ECR registry policies that grant access to AWS accounts not on the approved list. Prevents unauthorized container image access.

**Severity:** Critical

**Resource Type:** `AWS::ECR::RegistryPolicy`

**Rego Policy:**
```rego
package crowdstrike

# Define approved AWS accounts for cross-account access
approved_accounts := {
    "111111111111",
    "222222222222"
    # Add more approved account IDs here
}

default result := "pass"

# Parse the ECR registry policy document (stored as JSON string)
policy_doc := json.unmarshal(input.configuration.policyText)

# Extract AWS account IDs from Allow policy principals
principal_accounts contains account_id if {
    statement := policy_doc.Statement[_]
    statement.Effect == "Allow"
    principal := statement.Principal.AWS
    is_string(principal)
    startswith(principal, "arn:aws:iam::")
    parts := split(principal, ":")
    account_id := parts[4]
}

# Find accounts that are NOT in the approved list
unauthorized_accounts := principal_accounts - approved_accounts

# Fail if any unauthorized accounts have access
result = "fail" if {
    count(unauthorized_accounts) > 0
}
```

**Alert Logic:**
```
ECR registry policy grants access to unauthorized AWS accounts|Cross-account access should be limited to approved accounts only|Unauthorized accounts can pull container images containing sensitive code or data
```

**Remediation:**
```
Navigate to Amazon ECR in the AWS Console|Go to Private registry > Registry permissions|Review the registry policy JSON|Remove or update principals for unauthorized AWS account IDs|Verify only approved accounts are listed|Save the updated policy
```

---

### Example 5: RDS Instance Security Baseline

**Title:** RDS Instance Security Baseline

**Description:** Validates that RDS database instances meet a security baseline: encryption at rest enabled, not publicly accessible, Multi-AZ enabled, and deletion protection on.

**Severity:** High

**Resource Type:** `AWS::RDS::DBInstance`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if storage is not encrypted
result = "fail" if {
    input.configuration.storageEncrypted != true
}

# Fail if publicly accessible
result = "fail" if {
    input.configuration.publiclyAccessible == true
}

# Fail if not Multi-AZ
result = "fail" if {
    input.configuration.multiAZ != true
}

# Fail if deletion protection is not enabled
result = "fail" if {
    input.configuration.deletionProtection != true
}

# Fail if backup retention is less than 7 days
result = "fail" if {
    input.configuration.backupRetentionPeriod < 7
}
```

**Alert Logic:**
```
RDS instance does not meet the security baseline|One or more settings are non-compliant: encryption, public access, Multi-AZ, deletion protection, or backup retention|Non-compliant databases are at risk of data loss or unauthorized access
```

**Remediation:**
```
Open the RDS instance in the AWS Console|Verify Storage encryption is enabled (requires recreation if not)|Ensure Publicly accessible is set to No|Enable Multi-AZ deployment|Turn on Deletion protection|Set Backup retention period to at least 7 days|Apply changes
```

---

### Example 6: CloudWatch Log Group Retention

**Title:** CloudWatch Log Group Minimum Retention

**Description:** Ensures CloudWatch Log Groups have a retention period of at least 90 days to meet compliance requirements for log retention.

**Severity:** Medium

**Resource Type:** `AWS::Logs::LogGroup`

**Rego Policy:**
```rego
package crowdstrike

# Fail by default — must have adequate retention
default result := "fail"

# Pass if retention is at least 90 days
result = "pass" if {
    input.configuration.retentionInDays >= 90
}
```

**Alert Logic:**
```
CloudWatch Log Group retention period is less than 90 days|Insufficient log retention may violate compliance requirements|Logs may be deleted before security incidents are investigated
```

**Remediation:**
```
Open CloudWatch in the AWS Console|Navigate to Log groups|Select the non-compliant log group|Click Actions > Edit retention setting|Set retention to 90 days or greater|Save
```

---

### Example 7: Lambda Function Deprecated Runtime

**Title:** Lambda Function Deprecated Runtime Detection

**Description:** Detects Lambda functions running deprecated runtimes that no longer receive security patches.

**Severity:** High

**Resource Type:** `AWS::Lambda::Function`

**Rego Policy:**
```rego
package crowdstrike

# Set of deprecated Lambda runtimes
deprecated_runtimes := {
    "python2.7",
    "python3.6",
    "python3.7",
    "nodejs10.x",
    "nodejs12.x",
    "nodejs14.x",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "ruby2.5",
    "ruby2.7",
    "java8",
    "go1.x"
}

default result := "pass"

# Fail if the function uses a deprecated runtime
result = "fail" if {
    input.configuration.runtime in deprecated_runtimes
}
```

**Alert Logic:**
```
Lambda function is running a deprecated runtime|Deprecated runtimes no longer receive security patches|Functions on unsupported runtimes are vulnerable to known exploits
```

**Remediation:**
```
Identify the Lambda function in the AWS Console|Review the current runtime version|Update the function code to be compatible with a supported runtime|Change the runtime setting to a current version|Test the function thoroughly|Deploy the updated function
```

---

## GCP Examples

### Example 8: Compute Instance No Public IP

**Title:** GCP Compute Instance Public IP Restriction

**Description:** Detects GCP Compute instances that have external (public) IP addresses assigned, which exposes them directly to the internet.

**Severity:** High

**Resource Type:** `compute.googleapis.com/Instance`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if any network interface has an access config (external IP)
result = "fail" if {
    nic := input.configuration.networkInterfaces[_]
    nic.accessConfigs
    count(nic.accessConfigs) > 0
}
```

**Alert Logic:**
```
GCP Compute instance has a public IP address assigned|Instances with public IPs are directly exposed to internet traffic|This increases the attack surface and risk of unauthorized access
```

**Remediation:**
```
Navigate to Compute Engine in the GCP Console|Select the non-compliant instance|Click Edit|Under Network interfaces, remove the external IP|Use Cloud NAT or a load balancer for outbound/inbound traffic instead|Save changes
```

---

### Example 9: GCP Firewall No Open SSH from Internet

**Title:** GCP Firewall SSH Open to Internet

**Description:** Detects GCP firewall rules that allow SSH (port 22) ingress from any source (0.0.0.0/0), which exposes instances to brute-force attacks.

**Severity:** Critical

**Resource Type:** `compute.googleapis.com/Firewall`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if firewall allows SSH from 0.0.0.0/0
result = "fail" if {
    input.configuration.direction == "INGRESS"
    input.configuration.disabled == false
    input.configuration.sourceRanges[_] == "0.0.0.0/0"
    allowed := input.configuration.allowed[_]
    allowed.IPProtocol == "tcp"
    port := allowed.ports[_]
    # Check for port 22 directly or within a range that includes it
    port == "22"
}

# Also fail if protocol allows all ports (no port restriction)
result = "fail" if {
    input.configuration.direction == "INGRESS"
    input.configuration.disabled == false
    input.configuration.sourceRanges[_] == "0.0.0.0/0"
    allowed := input.configuration.allowed[_]
    allowed.IPProtocol == "tcp"
    not allowed.ports
}
```

**Alert Logic:**
```
GCP firewall rule allows SSH (port 22) from the entire internet (0.0.0.0/0)|Open SSH access enables brute-force attacks against all targeted instances|This is a critical exposure requiring immediate remediation
```

**Remediation:**
```
Navigate to VPC Network > Firewall in the GCP Console|Locate the non-compliant firewall rule|Edit the rule to restrict source ranges to specific trusted IP ranges or CIDR blocks|If SSH access is needed, use IAP (Identity-Aware Proxy) tunnel instead of direct access|Save the updated rule
```

---

### Example 10: GKE Cluster Security Baseline

**Title:** GKE Cluster Security Configuration

**Description:** Validates that GKE clusters have legacy ABAC disabled, network policy enabled, shielded nodes enabled, and private nodes configured.

**Severity:** High

**Resource Type:** `container.googleapis.com/Cluster`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if legacy ABAC is enabled
result = "fail" if {
    input.configuration.legacyAbac.enabled == true
}

# Fail if network policy is not enabled
result = "fail" if {
    not input.configuration.networkPolicy.enabled
}

# Fail if network policy is explicitly disabled
result = "fail" if {
    input.configuration.networkPolicy.enabled == false
}

# Fail if shielded nodes are not enabled
result = "fail" if {
    not input.configuration.shieldedNodes.enabled
}

# Fail if shielded nodes are explicitly disabled
result = "fail" if {
    input.configuration.shieldedNodes.enabled == false
}

# Fail if private nodes are not enabled
result = "fail" if {
    not input.configuration.privateClusterConfig.enablePrivateNodes
}

# Fail if private nodes are explicitly disabled
result = "fail" if {
    input.configuration.privateClusterConfig.enablePrivateNodes == false
}
```

**Alert Logic:**
```
GKE cluster does not meet the security baseline|One or more settings are non-compliant: legacy ABAC, network policy, shielded nodes, or private nodes|Non-compliant clusters have a larger attack surface and weaker isolation
```

**Remediation:**
```
Navigate to Kubernetes Engine in the GCP Console|Select the non-compliant cluster|Click Edit|Disable Legacy ABAC under Security|Enable Network policy under Networking|Enable Shielded GKE nodes under Security|Enable Private nodes under Networking|Save changes
```

---

### Example 11: GCP Service Account User-Managed Keys

**Title:** GCP Service Account User-Managed Key Detection

**Description:** Detects GCP service accounts that have user-managed keys, which are a security risk because they can be leaked and do not auto-rotate.

**Severity:** Medium

**Resource Type:** `iam.googleapis.com/ServiceAccount`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Count user-managed keys
user_managed_keys := [key |
    key := input.configuration.keys[_]
    key.keyType == "USER_MANAGED"
]

# Fail if any user-managed keys exist
result = "fail" if {
    count(user_managed_keys) > 0
}
```

**Alert Logic:**
```
GCP service account has user-managed keys|User-managed keys do not auto-rotate and can be leaked|Prefer workload identity or GCP-managed keys instead
```

**Remediation:**
```
Navigate to IAM & Admin > Service Accounts in the GCP Console|Select the service account with user-managed keys|Click Keys tab|Delete all user-managed keys|Reconfigure workloads to use Workload Identity Federation, attached service accounts, or GCP-managed keys instead
```

---

## Azure Examples

### Example 12: Storage Account HTTPS-Only

**Title:** Azure Storage Account HTTPS Required

**Description:** Ensures Azure Storage Accounts only accept HTTPS traffic and enforce a minimum TLS version of 1.2.

**Severity:** High

**Resource Type:** `Microsoft.Storage/storageAccounts`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if HTTPS-only is not enabled
result = "fail" if {
    input.configuration.properties.supportsHttpsTrafficOnly != true
}

# Fail if minimum TLS version is below 1.2
result = "fail" if {
    input.configuration.properties.minimumTlsVersion != "TLS1_2"
}

# Fail if public blob access is allowed
result = "fail" if {
    input.configuration.properties.allowBlobPublicAccess == true
}
```

**Alert Logic:**
```
Azure Storage Account does not enforce HTTPS-only or minimum TLS 1.2|Unencrypted HTTP traffic can be intercepted|Public blob access exposes data to unauthorized users
```

**Remediation:**
```
Open the Storage Account in the Azure Portal|Navigate to Configuration under Settings|Set Secure transfer required to Enabled|Set Minimum TLS version to Version 1.2|Set Allow Blob public access to Disabled|Save changes
```

---

### Example 13: Azure Storage Account Network Restriction

**Title:** Azure Storage Account Network Access Restriction

**Description:** Ensures Azure Storage Accounts deny public network access by default, requiring explicit network rules for access.

**Severity:** Medium

**Resource Type:** `Microsoft.Storage/storageAccounts`

**Rego Policy:**
```rego
package crowdstrike

default result := "fail"

# Pass if default network action is Deny
result = "pass" if {
    input.configuration.properties.networkAcls.defaultAction == "Deny"
}
```

**Alert Logic:**
```
Azure Storage Account allows public network access by default|Storage accounts without network restrictions are accessible from any network|This increases the risk of unauthorized data access
```

**Remediation:**
```
Open the Storage Account in the Azure Portal|Navigate to Networking under Security + networking|Set Public network access to Enabled from selected virtual networks and IP addresses|Or set it to Disabled entirely|Add any required virtual network rules or IP exceptions|Save changes
```

---

### Example 14: Azure Subscription Required Tags

**Title:** Azure Subscription Governance Tags

**Description:** Ensures Azure subscriptions have required governance tags: Environment, Owner, and Department.

**Severity:** Informational

**Resource Type:** `Microsoft.Resources/subscriptions`

**Rego Policy:**
```rego
package crowdstrike

default result := "pass"

# Fail if Environment tag is missing
result = "fail" if {
    not input.tags.Environment
}

# Fail if Owner tag is missing
result = "fail" if {
    not input.tags.Owner
}

# Fail if Department tag is missing
result = "fail" if {
    not input.tags.Department
}
```

**Alert Logic:**
```
Azure subscription is missing one or more required governance tags|Required tags: Environment, Owner, Department|Tags are essential for cost allocation and resource governance
```

**Remediation:**
```
Open the subscription in the Azure Portal|Navigate to Tags in the left menu|Add the missing required tags: Environment, Owner, Department|Use consistent values aligned with your organization's tagging policy|Save the tags
```

---

## Tips for Writing New CSPM Policies from These Examples

1. **Start with the closest example** — Find an example that matches your cloud provider and use case, then adapt it.
2. **Check default result** — Use `"fail"` when proving compliance, `"pass"` when detecting bad conditions.
3. **One concern per policy** — Each policy should check one logical security concern. Use multiple `result = "fail" if { ... }` blocks for sub-checks within that concern.
4. **Test with real data** — Always verify field names against actual asset JSON from your environment before deploying.
5. **Keep it simple** — Prefer straightforward field checks over complex logic. Simple policies are easier to maintain and debug.

---
---

# Part 2: KAC Custom Rule Examples

All KAC examples use `package customrule` and `import rego.v1`. They handle multiple Kubernetes resource types (Pod, Deployment, DaemonSet, StatefulSet, etc.) using helper rules to extract the Pod spec.

> **Important formatting requirements:** All Rego code uploaded to CrowdStrike is validated by the OPA Regal Linter. Code MUST:
> - Be formatted with `opa fmt` (uses **tabs** for indentation, not spaces)
> - Use `some X in Y` syntax for iteration (NOT `X := collection[_]`)
> - Avoid mixing non-loop expressions inside loop bodies (the "non-loop-expression" lint rule)
>
> All examples below are formatted to pass the Regal linter and have been tested on a live EKS cluster with KAC v7.35.

---

### Example 15: Deny Privileged Containers

**Rule Name:** Deny Privileged Containers

**Description:** Prevents any container from running in privileged mode. Privileged containers have full access to the host's devices and kernel capabilities, making them a critical security risk.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**EKS Test Result:** DENIED - `Container 'nginx' must not run in privileged mode`

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	container.securityContext.privileged == true
	msg := sprintf("Init container '%s' must not run in privileged mode", [container.name])
}
```

---

### Example 16: Require Specific Image Registry

**Rule Name:** Require Approved Container Registry

**Description:** Ensures all container images come from the organization's approved registry. Prevents use of untrusted public images that may contain vulnerabilities or malware.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**Rego Policy:**
```rego
package customrule

import rego.v1

approved_registry := "123456789012.dkr.ecr.us-east-1.amazonaws.com/"

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some container in pod_spec.containers
	not startswith(container.image, approved_registry)
	msg := sprintf("Container '%s' uses unapproved image '%s'", [container.name, container.image])
}

result := msg if {
	some container in pod_spec.initContainers
	not startswith(container.image, approved_registry)
	msg := sprintf("Init container '%s' uses unapproved image '%s'", [container.name, container.image])
}
```

**Example Deny Message:** `Container 'web-app' uses unapproved image 'nginx:latest'`

---

### Example 17: Enforce Resource Limits

**Rule Name:** Enforce Container Resource Limits

**Description:** Requires all containers to define CPU and memory limits. Without resource limits, a single container can consume all node resources, causing starvation for other workloads.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' must define CPU limits", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.memory
	msg := sprintf("Container '%s' must define memory limits", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not container.resources.limits.cpu
	msg := sprintf("Init container '%s' must define CPU limits", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not container.resources.limits.memory
	msg := sprintf("Init container '%s' must define memory limits", [container.name])
}
```

**Example Deny Message:** `Container 'web-app' must define CPU limits`

---

### Example 18: Deny Latest Tag

**Rule Name:** Deny Latest Image Tag

**Description:** Prevents containers from using the `:latest` tag or omitting a tag entirely. Using `:latest` makes deployments non-reproducible and can introduce unexpected changes when images are updated.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**EKS Test Result:** DENIED - `Container 'nginx' uses latest tag`

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some container in pod_spec.containers
	endswith(container.image, ":latest")
	msg := sprintf("Container '%s' uses :latest tag - use a specific version", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not contains(container.image, ":")
	msg := sprintf("Container '%s' image '%s' has no tag", [container.name, container.image])
}

result := msg if {
	some container in pod_spec.initContainers
	endswith(container.image, ":latest")
	msg := sprintf("Init container '%s' uses :latest tag", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not contains(container.image, ":")
	msg := sprintf("Init container '%s' image '%s' has no tag", [container.name, container.image])
}
```

---

### Example 19: Require Pod Labels

**Rule Name:** Require Mandatory Pod Labels

**Description:** Ensures all workloads have required organizational labels (`owner` and `team`) on the resource metadata. Labels are essential for resource ownership, cost tracking, and operational management.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**Rego Policy:**
```rego
package customrule

import rego.v1

result := msg if {
	not input.request.object.metadata.labels.owner
	msg := sprintf("%s '%s' must have an 'owner' label", [input.request.kind.kind, input.request.object.metadata.name])
}

result := msg if {
	not input.request.object.metadata.labels.team
	msg := sprintf("%s '%s' must have a 'team' label", [input.request.kind.kind, input.request.object.metadata.name])
}
```

**Example Deny Message:** `Deployment 'web-app' must have an 'owner' label`

---

### Example 20: Block hostPath Volumes

**Rule Name:** Block hostPath Volumes

**Description:** Prevents workloads from mounting hostPath volumes. hostPath volumes allow containers to access the host filesystem, which can be exploited to escape the container sandbox and read sensitive host data.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**EKS Test Result:** DENIED - `Volume 'host-etc' uses hostPath - not allowed`

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := msg if {
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf("Volume '%s' uses hostPath '%s' - not allowed", [volume.name, volume.hostPath.path])
}
```

---

### Example 21: Deny Host Namespace Sharing

**Rule Name:** Deny Host Namespace Sharing

**Description:** Prevents workloads from using hostNetwork, hostPID, or hostIPC. Sharing the host's namespaces allows containers to see host processes and network traffic.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**EKS Test Result:** DENIED - `Pod must not use hostPID`

> **Note:** Pods with `hostNetwork: true` bypass the Kubernetes admission webhook entirely (the request never reaches the KAC sensor). Only `hostPID` and `hostIPC` are enforceable in Prevent mode. The `hostNetwork` check is still useful in Alert mode where it generates a warning.

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

result := "Pod must not use hostNetwork" if {
	pod_spec.hostNetwork == true
}

result := "Pod must not use hostPID" if {
	pod_spec.hostPID == true
}

result := "Pod must not use hostIPC" if {
	pod_spec.hostIPC == true
}
```

---

### Example 22: Require runAsNonRoot

**Rule Name:** Require runAsNonRoot

**Description:** Enforces that all containers run as non-root users. Running containers as root (UID 0) increases the blast radius of container escapes and allows modification of sensitive files within the container filesystem. Accepts the setting at either pod-level or container-level.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**EKS Test Result:** DENIED - `Containers must set runAsNonRoot to true - nginx`

> **Pattern note:** This example demonstrates the "set comprehension" pattern to avoid the Regal "non-loop-expression" lint error. Instead of checking `not pod_level_non_root` inside a loop (which mixes a non-loop condition with a loop variable), we first collect all non-compliant container names into a set, then check the set size outside the loop.

**Rego Policy:**
```rego
package customrule

import rego.v1

pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	input.request.kind.kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}

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

---

### KAC Example 23: Init Container Security (Multi-Condition with Correct Ordering)

**Rule Name:** Require Init Container Security

**Description:** Enforces two security requirements on init containers: no privileged mode, and runAsNonRoot must be true. Demonstrates correct rule ordering to avoid "messy-rule" lint errors and "multiple outputs" OPA errors.

**Target Resource Types:** Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, ReplicationController, Job, CronJob

**Rego Policy:**
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

# Helper: collect privileged init containers
privileged_init_containers contains container.name if {
	some container in pod_spec.initContainers
	container.securityContext.privileged == true
}

# Helper: collect init containers missing runAsNonRoot
init_without_non_root contains container.name if {
	some container in pod_spec.initContainers
	not container.securityContext.runAsNonRoot
}

# IMPORTANT: All result rules are grouped together below ALL helpers.
# Inserting a helper between result rules causes "messy-rule" lint error.
# The second rule uses a guard (count == 0) to prevent "multiple outputs" OPA error.

result := msg if {
	count(privileged_init_containers) > 0
	names := concat(", ", privileged_init_containers)
	msg := sprintf(
		"Init containers must not run privileged - %s",
		[names],
	)
}

result := msg if {
	count(privileged_init_containers) == 0
	not pod_spec.securityContext.runAsNonRoot
	count(init_without_non_root) > 0
	names := concat(", ", init_without_non_root)
	msg := sprintf(
		"Init containers must set runAsNonRoot to true - %s",
		[names],
	)
}
```

**Key patterns demonstrated:**
- All helper set comprehensions (`privileged_init_containers`, `init_without_non_root`) are placed BEFORE all `result :=` rules
- The second `result` rule includes `count(privileged_init_containers) == 0` as a guard to ensure only one `result` fires at a time
- This avoids both the "messy-rule" linter error and the "multiple outputs" OPA runtime error

**Example Deny Message:** `Init containers must not run privileged - init-setup`

---

## Tips for Writing New KAC Policies from These Examples

1. **Always include the pod_spec helper rules** - These handle the different spec paths for Pod vs Deployment vs CronJob etc. Copy them from any example above.
2. **Use `some X in Y` for iteration** - The Regal linter rejects `X := collection[_]`. Always use `some container in pod_spec.containers`.
3. **Format with `opa fmt`** - The API validates formatting. Use tabs for indentation (run `opa fmt -w your_file.rego` locally to auto-format).
4. **Check both containers and initContainers** - Security rules should apply to all container types.
5. **Use `sprintf` for descriptive messages** - Include the container name or resource name so the user knows exactly what to fix.
6. **No default result needed** - KAC is allow-by-default. Only define deny rules. Adding `default result := "..."` would deny everything.
7. **Avoid the "non-loop-expression" lint error** - If you need a non-loop condition (like checking pod-level settings) inside a loop, use a set comprehension instead (see Example 22).
8. **Avoid blocked keywords** - Never use `http.send`, `time.now`, `crypto`, or `pattern_id`.
9. **Name validation** - Rule names can only contain letters, numbers, spaces, and `- _ ( ) . , ' " &`. No em dashes, colons, or special unicode.
10. **hostNetwork bypass** - Pods with `hostNetwork: true` bypass the admission webhook. Only `hostPID` and `hostIPC` are enforceable in Prevent mode.
11. **Group all result rules together** - All `result := msg if { ... }` definitions must be consecutive. Do NOT place helper set comprehensions between them — the linter flags this as "messy-rule" (see Example 23).
12. **Prevent multiple outputs** - If two `result := msg` rules can fire simultaneously (e.g., a container fails both condition A and condition B), OPA throws "complete rules must not produce multiple outputs". Add guard conditions like `count(other_violations) == 0` to make rules mutually exclusive (see Example 23).
13. **No redundant existence checks** - Do not check that a field exists before comparing its value. E.g., `port.hostPort` followed by `port.hostPort < 1024` is redundant — just use the comparison directly.
