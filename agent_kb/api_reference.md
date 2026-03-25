# CrowdStrike API Reference for Custom Policies

This document covers the CrowdStrike Falcon API endpoints for managing both:
- **CSPM Custom IOMs** — Indicators of Misconfiguration for cloud resource compliance
- **KAC Custom Rules** — Kubernetes Admission Controller rules for workload admission control

---

# Part 1: CSPM Custom IOM API

---

## Authentication

All API calls require a Bearer token obtained via OAuth2 client credentials.

### Required API Scopes
Create an API client in the Falcon console (**Support > API Clients and Keys**) with:

**For CSPM Custom IOMs:**
- **CSPM registration**: Read, Write
- **Cloud Security Assessment**: Read

**For KAC Custom Rules:**
- **Falcon Container Policies**: Read, Write (`falcon-container-policies:read`, `falcon-container-policies:write`)

### Base URLs (by Cloud Environment)

| Environment | Base URL |
|-------------|----------|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |
| US-GOV-2 | `https://api.govcloud-us-east-1.crowdstrike.com` |

### Get a Bearer Token

```
POST {base_url}/oauth2/token
```

**Headers:**
```
Accept: application/json
Content-Type: application/x-www-form-urlencoded
```

**Body (form-encoded):**
```
client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUz...",
  "expires_in": 1799
}
```

The token is valid for 30 minutes. Include it in all subsequent requests as:
```
Authorization: Bearer <access_token>
```

### Standard Headers for All API Calls
```
Authorization: Bearer <access_token>
Accept: application/json
Content-Type: application/json
```

---

## Severity Mapping

Severity is specified as an integer in all API payloads:

| Integer | Label | Description |
|---------|-------|-------------|
| 0 | Critical | Immediate action required |
| 1 | High | Important security issue |
| 2 | Medium | Moderate security concern |
| 3 | Informational | Minor issue or governance |

---

## Cloud Provider Detection

The `platform` and `provider` fields in API payloads are determined from the resource type string:

| Resource Type Pattern | Platform | Provider |
|----------------------|----------|----------|
| Starts with `AWS::` | `AWS` | `AWS` |
| Contains `googleapis.com` | `GCP` | `GCP` |
| Starts with `Microsoft.` | `Azure` | `Azure` |
| Contains `kubernetes` | `Kubernetes` | `Kubernetes` |

---

## Alert and Remediation Format

Both `alert_info` and `remediation_info` use **pipe-separated** format. CrowdStrike automatically converts pipes into numbered steps in the console.

**Correct format:**
```
Check the resource configuration|Identify the non-compliant setting|Review security implications
```

**Do NOT add numbers.** This is wrong:
```
1. Check the resource configuration|2. Identify the non-compliant setting
```

---

## CSPM API Endpoints

### 1. Create a Custom Policy

```
POST {base_url}/cloud-policies/entities/rules/v1
```

**Request Body:**
```json
{
  "name": "S3 Bucket Public Access Block Required",
  "description": "Ensures all S3 buckets have public access block enabled",
  "logic": "package crowdstrike\n\ndefault result := \"fail\"\n\nresult = \"pass\" if {\n    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true\n    input.configuration.publicAccessBlockConfiguration.blockPublicPolicy == true\n}",
  "resource_type": "AWS::S3::Bucket",
  "severity": 1,
  "platform": "AWS",
  "provider": "AWS",
  "domain": "CSPM",
  "subdomain": "IOM",
  "alert_info": "S3 bucket does not have public access block enabled|Public access block prevents accidental public exposure of data|This is a high-severity finding requiring immediate attention",
  "remediation_info": "Navigate to the S3 bucket in the AWS Console|Go to the Permissions tab|Click Edit under Block public access|Enable all four public access block settings|Save changes",
  "attack_types": "Misconfiguration"
}
```

**Field Descriptions:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name for the policy |
| `description` | Yes | What the policy checks and why |
| `logic` | Yes | Complete Rego v1 code as a string (newlines as `\n`) |
| `resource_type` | Yes | Target resource type (e.g., `AWS::S3::Bucket`) |
| `severity` | Yes | Integer 0-3 |
| `platform` | Yes | `AWS`, `GCP`, `Azure`, or `Kubernetes` |
| `provider` | Yes | Same as platform |
| `domain` | Yes | Always `"CSPM"` |
| `subdomain` | Yes | Always `"IOM"` |
| `alert_info` | Yes | Pipe-separated alert description |
| `remediation_info` | No | Pipe-separated remediation steps |
| `attack_types` | Yes | Always `"Misconfiguration"` |

**Success Response (200):**
```json
{
  "resources": [
    {
      "uuid": "abc123-def456-...",
      "name": "S3 Bucket Public Access Block Required",
      "description": "...",
      "origin": "Custom",
      "severity": 1,
      "created_at": "2024-01-15T10:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z",
      "resource_types": [
        {
          "resource_type": "AWS::S3::Bucket",
          "service": "aws-s3"
        }
      ],
      "rule_logic_list": [
        {
          "logic": "package crowdstrike\n...",
          "platform": "AWS",
          "remediation_info": "..."
        }
      ]
    }
  ]
}
```

### 2. List Custom Policies

**Step 1 — Get rule IDs:**
```
GET {base_url}/cloud-policies/queries/rules/v1?filter=rule_origin:'Custom'&limit=500
```

**Response:**
```json
{
  "resources": ["uuid-1", "uuid-2", "uuid-3"]
}
```

**Step 2 — Get rule details (batch up to 50 IDs at a time):**
```
GET {base_url}/cloud-policies/entities/rules/v1?ids=uuid-1&ids=uuid-2&ids=uuid-3
```

**Response:**
```json
{
  "resources": [
    {
      "uuid": "uuid-1",
      "name": "Policy Name",
      "description": "...",
      "origin": "Custom",
      "severity": 1,
      "created_at": "2024-01-15T10:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z",
      "resource_types": [
        {"resource_type": "AWS::S3::Bucket", "service": "aws-s3"}
      ],
      "rule_logic_list": [
        {
          "logic": "package crowdstrike\n...",
          "platform": "AWS",
          "remediation_info": "Step 1. ...\nStep 2. ..."
        }
      ]
    }
  ]
}
```

### 3. Update a Custom Policy

```
PATCH {base_url}/cloud-policies/entities/rules/v1
```

**Update description and severity:**
```json
{
  "uuid": "abc123-def456-...",
  "description": "Updated description",
  "severity": 2
}
```

**Update Rego logic:**
```json
{
  "uuid": "abc123-def456-...",
  "rule_logic_list": [
    {
      "logic": "package crowdstrike\n\ndefault result := \"fail\"\n\n... updated logic ...",
      "platform": "AWS",
      "remediation_info": "Updated step 1|Updated step 2"
    }
  ]
}
```

**Update alert and remediation info:**
```json
{
  "uuid": "abc123-def456-...",
  "alert_info": "New alert step 1|New alert step 2",
  "rule_logic_list": [
    {
      "logic": "... existing logic ...",
      "platform": "AWS",
      "remediation_info": "New remediation step 1|New remediation step 2"
    }
  ]
}
```

**Success Response (200):** Same structure as create response.

### 4. Delete a Custom Policy

```
DELETE {base_url}/cloud-policies/entities/rules/v1?ids=abc123-def456-...
```

**Success Response:** HTTP 200

### 5. Test / Evaluate a Policy

Tests your Rego logic against real cloud assets to verify correctness before deploying.

**Step 1 — Find asset IDs for the target resource type:**
```
GET {base_url}/cloud-security-assets/queries/resources/v1?filter=resource_type:'AWS::S3::Bucket'+active:'true'&limit=10
```

**Response:**
```json
{
  "resources": ["tenant-id|AWS::S3::Bucket|bucket-name-1", "tenant-id|AWS::S3::Bucket|bucket-name-2"]
}
```

**Step 2 — Get enriched asset data:**
```
GET {base_url}/cloud-policies/entities/enriched-resources/v1?ids=tenant-id|AWS::S3::Bucket|bucket-name-1
```

Include the extra header:
```
X-CS-CUSTID: <tenant-id>
```
The tenant ID is the portion of the asset ID before the first `|` character.

**Response:**
```json
{
  "resources": [
    {
      "resource_id": "tenant-id|AWS::S3::Bucket|bucket-name-1",
      "resource_type": "AWS::S3::Bucket",
      "configuration": { ... },
      "tags": { ... },
      "region": "us-east-1",
      "service": "aws-s3"
    }
  ]
}
```

**Step 3 — Evaluate the policy:**
```
POST {base_url}/cloud-policies/entities/evaluation/v1?cloud_provider=aws&resource_type=AWS::S3::Bucket&ids=tenant-id|AWS::S3::Bucket|bucket-name-1
```

**Request Body:**
```json
{
  "logic": "package crowdstrike\ndefault result := \"fail\"\nresult = \"pass\" if {\n    input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true\n}",
  "input": {
    "resource_id": "tenant-id|AWS::S3::Bucket|bucket-name-1",
    "resource_type": "AWS::S3::Bucket",
    "configuration": { ... },
    "tags": { ... },
    "region": "us-east-1",
    "service": "aws-s3"
  }
}
```

The `input` field in the body is the full enriched asset object from Step 2.

**Query Parameter Values for `cloud_provider`:**

| Resource Type Prefix | cloud_provider value |
|---------------------|---------------------|
| `AWS::` | `aws` |
| `Microsoft.` | `azure` |
| `googleapis.com` | `gcp` |

**Response:**
```json
{
  "resources": [
    {
      "result": "pass",
      "details": {}
    }
  ]
}
```

The `result` field will be `"pass"`, `"fail"`, or `"error"`.

### 6. Get Resource Type Input Schema

Returns the field schema for a given resource type — all available fields and their types (string, integer, float, date, ip, object). This includes core fields from the cloud provider response including `configuration`, relationships, and `tags`. Works even if you don't have any of that resource type in your inventory.

```
GET {base_url}/cloud-policies/combined/rules/input-schema/v1?domain=CSPM&subdomain=IOM&cloud_provider=aws&resource_type=AWS::EC2::Instance
```

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `domain` | Yes | Always `CSPM` |
| `subdomain` | Yes | Always `IOM` |
| `cloud_provider` | Yes | `aws`, `azure`, `gcp`, or `oci` |
| `resource_type` | Yes | The resource type (e.g., `AWS::EC2::Instance`, `compute.googleapis.com/Instance`) |

**Required Headers:**
```
Authorization: Bearer <token>
X-CS-CUSTID: <customer_id>
X-CS-USERUUID: <user_id>
```

- **Customer ID (CID)**: Found in the Falcon console under **Host setup and management > Deploy > Sensor downloads** (displayed at the top of the page).
- **User UUID**: Can be retrieved via `GET /users/queries/user-uuids-by-email/v1?uid=your.email@company.com` or found in User Management in the Falcon console.

**Required API Scope:** `cloud-security-policies` (Read)

**Example:**
```bash
curl -X GET 'https://api.crowdstrike.com/cloud-policies/combined/rules/input-schema/v1?domain=CSPM&subdomain=IOM&cloud_provider=aws&resource_type=AWS%3A%3AEC2%3A%3AInstance' \
  -H 'X-CS-CUSTID: <customer_id>' \
  -H 'X-CS-USERUUID: <user_id>' \
  -H 'Authorization: Bearer <token>'
```

**Response:**
Returns the schema definition describing every field available in `input` for the specified resource type, along with their data types.

**Note:** This gives you the schema (field names and types), not actual asset data. For real asset data with populated values, use the sample resource data endpoints below or the Rego editor test data in the console.

### 7. Get Sample Resource Data

If you want to see actual asset data with real values (not just the schema), you can fetch a sample resource. This is useful when writing Rego since you can see what the data actually looks like.

**Step 1 — Query resource IDs:**
```
GET {base_url}/cloud-security-assets/queries/resources/v1?filter=resource_type:'AWS::EC2::Instance'&limit=1
```

**Response:**
```json
{
  "resources": ["tenant-id|AWS::EC2::Instance|i-0abcdef1234567890"]
}
```

**Step 2 — Get the full resource:**
```
GET {base_url}/cloud-security-assets/entities/resources/v1?ids=<resource_id>
```

This returns a real asset with populated values.

### 8. Discover Cloud Resources

Find what resource types and resources exist in your CSPM environment.

**Query resources by type:**
```
GET {base_url}/cloud-security-assets/queries/resources/v1?filter=resource_type:'AWS::S3::Bucket'&limit=100
```

**Query all active resources:**
```
GET {base_url}/cloud-security-assets/queries/resources/v1?filter=active:'true'&limit=100
```

**Response:**
```json
{
  "resources": [
    "tenant-id|AWS::S3::Bucket|bucket-1",
    "tenant-id|AWS::S3::Bucket|bucket-2"
  ]
}
```

---

## Complete CSPM Workflow Example: Create and Test a Policy

1. **Authenticate** — POST to `/oauth2/token` to get a Bearer token.
2. **Fetch sample asset data** — GET resource IDs from `/cloud-security-assets/queries/resources/v1`, then GET enriched data from `/cloud-policies/entities/enriched-resources/v1`.
3. **Write the Rego policy** using the asset JSON structure as reference.
4. **Test the policy** — POST to `/cloud-policies/entities/evaluation/v1` with your logic and the asset data.
5. **Deploy the policy** — POST to `/cloud-policies/entities/rules/v1` with the full payload.
6. **Verify** — GET your policy from `/cloud-policies/entities/rules/v1` to confirm it was created.

---

## Error Handling

- **401 Unauthorized**: Token expired. Re-authenticate and retry.
- **400 Bad Request**: Usually a Rego syntax error or invalid payload field. Check the error response body for details.
- **403 Forbidden**: API client lacks required scopes.
- **429 Too Many Requests**: Rate limited. Back off and retry.
- **Timeout**: All calls should use a 30-second timeout.

---
---

# Part 2: KAC (Kubernetes Admission Controller) API

The KAC API manages Kubernetes Admission Controller policies, rule groups, custom Rego rules, host group assignments, and selectors. Custom Rego rule deployment is a **two-step process**: first upload the Rego logic via the cloud-policies API, then attach the returned rule UUID to a policy rule group.

### Required API Scopes

KAC custom rule management requires **both** of these scopes on your API client:

| Scope | Used For |
|-------|----------|
| `cloud-security-policies:read/write` | Uploading and deleting Rego logic via `/cloud-policies/entities/rules/v1` |
| `falcon-container-policies:read/write` | Managing KAC policies, rule groups, attachments, selectors, and host groups |

All KAC endpoints use the same authentication (Bearer token) and base URLs as CSPM. Standard request/response headers apply.

---

## KAC Policy Endpoints

### 1. List / Query KAC Policies

Retrieve all KAC policies or filter by query parameters.

```
GET {base_url}/admission-control-policies/combined/policies/v1
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `offset` | integer | Pagination offset |
| `limit` | integer | Maximum results to return (max 500) |
| `filter` | string | FQL filter expression |

**Response (200):**
```json
{
  "resources": [
    {
      "id": "policy-uuid-1",
      "name": "Production Security Policy",
      "description": "Enforces security standards on production workloads",
      "is_enabled": true,
      "precedence": 1,
      "created_at": "2024-06-01T10:00:00Z",
      "updated_at": "2024-06-15T14:30:00Z",
      "groups": [
        {
          "id": "rg-uuid-1",
          "name": "Container Security Rules",
          "precedence": 1,
          "custom_rules": [
            {
              "id": "cr-uuid-1",
              "name": "Deny Privileged Containers",
              "action": "Prevent"
            }
          ]
        }
      ]
    }
  ],
  "meta": {
    "pagination": {
      "offset": 0,
      "limit": 100,
      "total": 1
    }
  }
}
```

**Fallback approach** (if combined endpoint is unavailable): Query IDs first, then fetch details.

```
GET {base_url}/admission-control-policies/queries/policies/v1?limit=100&offset=0
```

Returns an array of policy IDs:
```json
{
  "resources": ["policy-uuid-1", "policy-uuid-2"]
}
```

Then fetch details:
```
GET {base_url}/admission-control-policies/entities/policies/v1?ids=policy-uuid-1&ids=policy-uuid-2
```

---

### 2. Get a Single KAC Policy

```
GET {base_url}/admission-control-policies/entities/policies/v1?ids={policy_id}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ids` | string | Policy UUID |

**Response (200):** Same structure as a single resource from the list endpoint.

---

### 3. Create a KAC Policy

```
POST {base_url}/admission-control-policies/entities/policies/v1
```

**Request Body:**
```json
{
  "name": "Production Security Policy",
  "description": "Enforces container security standards"
}
```

**Field Descriptions:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Policy display name |
| `description` | No | string | Policy description |

**Response (200/201):**
```json
{
  "resources": [
    {
      "id": "policy-uuid-new",
      "name": "Production Security Policy",
      "description": "Enforces container security standards",
      "is_enabled": false,
      "precedence": 0,
      "created_at": "2024-07-01T10:00:00Z",
      "updated_at": "2024-07-01T10:00:00Z",
      "groups": []
    }
  ]
}
```

New policies are created with `is_enabled: false` by default. A newly created policy includes a default rule group in its `groups` array.

---

### 4. Update a KAC Policy

```
PATCH {base_url}/admission-control-policies/entities/policies/v1?ids={policy_id}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ids` | string | Policy UUID |

**Request Body:**
```json
{
  "name": "Updated Policy Name",
  "description": "Updated description",
  "is_enabled": true
}
```

All fields are optional. Only include fields you want to update.

**Response (200):** Updated policy object.

---

### 5. Delete a KAC Policy

**IMPORTANT:** You must disable the policy before deleting it. If you attempt to delete an enabled policy, the API returns **403 Forbidden**.

**Step 1 — Disable the policy:**
```
PATCH {base_url}/admission-control-policies/entities/policies/v1?ids={policy_id}
```

```json
{
  "is_enabled": false
}
```

**Step 2 — Delete the policy:**
```
DELETE {base_url}/admission-control-policies/entities/policies/v1?ids={policy_id}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ids` | string | Policy UUID |

**Response (200):** Empty success response.

---

### 6. Update Policy Precedence

Sets the evaluation order for a policy relative to other policies.

```
PATCH {base_url}/admission-control-policies/entities/policy-precedence/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "precedence": 1
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | Yes | string | Policy UUID |
| `precedence` | Yes | integer | Evaluation priority (lower = higher priority) |

**Response (200):** Updated policy object.

---

## Host Group Endpoints

### 7. Add Host Groups to a Policy

Associates Kubernetes host groups (clusters) with the policy. This determines which clusters the policy applies to.

```
POST {base_url}/admission-control-policies/entities/policy-host-groups/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "host_groups": ["hg-uuid-1", "hg-uuid-2"]
}
```

**Response (200):** Updated policy object with host groups.

---

### 8. Remove Host Groups from a Policy

```
DELETE {base_url}/admission-control-policies/entities/policy-host-groups/v1?policy_id={policy_id}&host_group_ids={hg-uuid-1}&host_group_ids={hg-uuid-2}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy_id` | string | Policy UUID |
| `host_group_ids` | string (repeated) | Host group UUIDs to remove |

**Response (200):** Updated policy object.

---

## Rule Group Endpoints

### 9. Create Rule Groups within a Policy

A rule group is a logical grouping of custom Rego rules within a policy. Each policy gets a default rule group on creation; additional groups can be added here.

```
POST {base_url}/admission-control-policies/entities/policy-rule-groups/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "rule_groups": [
    {
      "name": "Container Security Rules",
      "description": "Rules enforcing container-level security"
    }
  ]
}
```

**Response (200/201):** Updated policy object with the new rule group.

---

### 10. Update a Rule Group

```
PATCH {base_url}/admission-control-policies/entities/policy-rule-groups/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "rule_groups": [
    {
      "id": "rg-uuid",
      "name": "Updated Rule Group Name",
      "description": "Updated description"
    }
  ]
}
```

**Response (200):** Updated policy object.

---

### 11. Delete Rule Groups from a Policy

```
DELETE {base_url}/admission-control-policies/entities/policy-rule-groups/v1?policy_id={policy_id}&rule_group_ids={rg-uuid-1}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy_id` | string | Policy UUID |
| `rule_group_ids` | string (repeated) | Rule group UUIDs to delete |

**Response (200):** Updated policy object.

---

### 12. Update Rule Group Precedence

Sets the evaluation order for rule groups within a policy.

```
PUT {base_url}/admission-control-policies/entities/policy-rule-group-precedence/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "rule_group_ids": ["rg-uuid-2", "rg-uuid-1", "rg-uuid-3"]
}
```

The order of IDs in the array determines the evaluation precedence (first = highest priority).

**Response (200):** Updated policy object with reordered rule groups.

---

## Custom Rego Rule Endpoints (Two-Step Deployment)

Deploying a custom Rego rule to a KAC policy is a **two-step process**:

1. **Upload** the Rego logic to the cloud-policies API (returns a rule UUID)
2. **Attach** that UUID to a policy rule group with an action (Prevent, Alert, or Disabled)

These are separate API operations against different endpoint families.

### 13. Upload Custom Rego Rule Logic (Step 1)

This endpoint uploads the Rego code to CrowdStrike and returns a rule UUID. The rule is not active until it is attached to a policy rule group in Step 2.

```
POST {base_url}/cloud-policies/entities/rules/v1
```

**Request Body:**
```json
{
  "name": "Deny Privileged Containers",
  "description": "Prevents containers from running in privileged mode",
  "logic": "package customrule\n\nimport rego.v1\n\nresult := msg if {\n\tsome container in input.request.object.spec.containers\n\tcontainer.securityContext.privileged == true\n\tmsg := sprintf(\"Container %s must not run privileged\", [container.name])\n}\n",
  "domain": "Runtime",
  "platform": "Kubernetes",
  "subdomain": "IOM",
  "severity": 3
}
```

**Field Descriptions:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Display name for the rule. Only letters, numbers, spaces, and `- _ ( ) . , ' " &` are allowed. |
| `description` | Yes | string | What the rule enforces |
| `logic` | Yes | string | Complete Rego v1 code as a string (newlines as `\n`, **tabs for indentation**) |
| `domain` | Yes | string | **Must be `"Runtime"`** |
| `platform` | Yes | string | **Must be `"Kubernetes"`** |
| `subdomain` | Yes | string | Always `"IOM"` |
| `severity` | Yes | integer | 0-3 (see Severity Mapping above) |
| `alert_info` | No | string | Pipe-separated alert description |
| `remediation_info` | No | string | Pipe-separated remediation steps |

**CRITICAL field requirements:**

- **`domain` MUST be `"Runtime"`** — The value `"KAC"` is rejected by the API with an "unsupported domain" error.
- **`platform` MUST be `"Kubernetes"`** — The value `"k8s"` is not accepted.
- **Do NOT send `resource_type` or `provider` fields** — Including either of these causes a 500 server error for KAC rules.

**Rego Logic Requirements:**
- Must use `package customrule`
- Must use `import rego.v1`
- Must NOT set a `default result` — that would deny every request
- Must not contain blocked keywords: `http.send`, `time.now`, `crypto`, `pattern_id`
- Code **must be formatted with `opa fmt`** (the API validates through the OPA Regal Linter)
- Must use tabs for indentation (not spaces)
- Must use `some X in Y` syntax for iteration (NOT `X := collection[_]`)
- Avoid `non-loop-expression` lint errors (do not mix loop variables with non-loop conditions in the same rule body)
- Result is a deny message string; empty/undefined result = allow the request

**Success Response (200):**
```json
{
  "resources": [
    {
      "uuid": "abc123-def456-...",
      "name": "Deny Privileged Containers",
      "description": "Prevents containers from running in privileged mode",
      "origin": "Custom",
      "severity": 3,
      "created_at": "2024-07-01T12:00:00Z",
      "updated_at": "2024-07-01T12:00:00Z"
    }
  ]
}
```

The `resources[0].uuid` value is the rule UUID needed for Step 2.

---

### 14. Attach Custom Rules to a Policy Rule Group (Step 2)

After uploading the Rego logic and receiving a rule UUID, attach it to a policy rule group with an enforcement action.

```
POST {base_url}/admission-control-policies/entities/policy-rule-group-custom-rules/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "rule_groups": [
    {
      "id": "rule-group-uuid",
      "custom_rules": [
        {"id": "rule-uuid-from-step-1", "action": "Prevent"},
        {"id": "another-rule-uuid", "action": "Alert"}
      ]
    }
  ]
}
```

**Field Descriptions:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` (top-level) | Yes | string | Policy UUID |
| `rule_groups[].id` | Yes | string | Rule group UUID |
| `rule_groups[].custom_rules[].id` | Yes | string | Rule UUID returned from Step 1 |
| `rule_groups[].custom_rules[].action` | Yes | string | Enforcement action (see below) |

**Valid action values:**

| Action | Behavior |
|--------|----------|
| `Prevent` | Deny the Kubernetes admission request if the rule returns a result |
| `Alert` | Allow the request but generate a warning/detection |
| `Disabled` | Rule is inactive (not evaluated) |

**IMPORTANT:** The value `"Enabled"` is NOT valid and will be rejected. Use `"Prevent"` or `"Alert"` to activate a rule.

**Response (200/201):** Updated policy object showing the rule group with attached custom rules.

---

### 15. Remove Custom Rules from a Policy

Detaches custom rules from a policy rule group. This does NOT delete the underlying Rego logic from cloud-policies.

```
DELETE {base_url}/admission-control-policies/entities/policy-rule-group-custom-rules/v1?policy_id={policy_id}&custom_rule_ids={uuid1}&custom_rule_ids={uuid2}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `policy_id` | string | Policy UUID |
| `custom_rule_ids` | string (repeated) | Rule UUIDs to detach |

**Response (200):** Updated policy object.

---

### 16. Delete Custom Rego Rule Logic

Permanently deletes the uploaded Rego logic from cloud-policies. You should detach the rule from any policy rule groups first (Step 15).

```
DELETE {base_url}/cloud-policies/entities/rules/v1?ids={uuid}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ids` | string | Rule UUID to delete |

**Response (200):** Empty success response.

---

## Selector Endpoints

### 17. Update Selectors for a Rule Group

Selectors define which Kubernetes resource types and namespaces a rule group applies to.

```
PUT {base_url}/admission-control-policies/entities/policy-rule-group-selectors/v1
```

**Request Body:**
```json
{
  "id": "policy-uuid",
  "rule_group_id": "rg-uuid",
  "labels": [
    {"key": "app", "values": ["web", "api"]}
  ],
  "namespaces": [
    {"name": "production"},
    {"name": "staging"}
  ]
}
```

**Field Descriptions:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | Yes | string | Policy UUID |
| `rule_group_id` | Yes | string | Rule group UUID |
| `labels` | No | array | Label selectors with key/values pairs |
| `namespaces` | No | array | Namespace selectors (empty = all namespaces) |

**Response (200):** Updated policy object with selectors.

---

## Complete KAC Workflow Example: Create a Policy with Custom Rules

1. **Authenticate** — POST to `/oauth2/token` to get a Bearer token. Ensure the API client has both `cloud-security-policies:read/write` and `falcon-container-policies:read/write` scopes.

2. **Create a KAC policy** — POST to `/admission-control-policies/entities/policies/v1` with a name and description. The policy is created in a disabled state.

3. **Get the default rule group ID** — The policy response includes a `groups` array. Use the `id` from the first (default) rule group. If you need additional groups, POST to `/admission-control-policies/entities/policy-rule-groups/v1`.

4. **Upload custom Rego rules** — For each rule, POST to `/cloud-policies/entities/rules/v1` with `domain: "Runtime"`, `platform: "Kubernetes"`, and the Rego logic. Save the returned `uuid` from each response.

5. **Attach rule UUIDs to the rule group** — POST to `/admission-control-policies/entities/policy-rule-group-custom-rules/v1` with the policy ID, rule group ID, and each rule UUID with `action: "Prevent"`.

6. **Enable the policy** — PATCH to `/admission-control-policies/entities/policies/v1?ids={policy_id}` with `{"is_enabled": true}`.

7. **(Optional) Assign host groups** — POST to `/admission-control-policies/entities/policy-host-groups/v1` to target specific clusters. Without host groups, the policy applies to all clusters running the KAC sensor.

### Cleanup / Teardown Workflow

To fully remove a policy and its custom rules:

1. **Disable the policy** — PATCH with `{"is_enabled": false}`.
2. **Detach custom rules from the policy** — DELETE to `/admission-control-policies/entities/policy-rule-group-custom-rules/v1` with the policy ID and rule UUIDs.
3. **Delete the policy** — DELETE to `/admission-control-policies/entities/policies/v1?ids={policy_id}`.
4. **Delete the Rego rules** — DELETE to `/cloud-policies/entities/rules/v1?ids={uuid}` for each rule.

---

## KAC Rego Linter Requirements

The CrowdStrike API validates uploaded Rego code through the **OPA Regal Linter**. Rules that fail linting are rejected with a 400 error. Key requirements:

| Requirement | Details |
|------------|---------|
| Formatting | Code **must** be formatted with `opa fmt` output style |
| Indentation | Use **tabs**, not spaces |
| Iteration syntax | Use `some X in Y` (NOT `X := collection[_]`) |
| Non-loop expressions | Do not mix loop variables with non-loop conditions in the same rule body |
| Rule name characters | Only letters, numbers, spaces, and `- _ ( ) . , ' " &` are allowed |
| No default result | Do NOT set `default result` — that would deny every request |
| Blocked keywords | `http.send`, `time.now`, `crypto`, `pattern_id` |

**Example of correct iteration:**
```rego
result := msg if {
	some container in input.request.object.spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container %s must not run privileged", [container.name])
}
```

**Example of INCORRECT iteration (will be rejected):**
```rego
result := msg if {
	container := input.request.object.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("Container %s must not run privileged", [container.name])
}
```

---

## KAC Admission Webhook Behavior

### hostNetwork Bypass

Pods with `hostNetwork: true` bypass the Kubernetes admission webhook entirely. The KAC sensor cannot intercept or enforce rules on these pods. Only `hostPID` and `hostIPC` are enforceable in Prevent mode because they do not prevent the admission webhook from being called.

### Input Paths by Resource Kind

The pod spec location in the `input` object varies by Kubernetes resource kind:

| Resource Kind | Pod Spec Path |
|--------------|---------------|
| `Pod` | `input.request.object.spec` |
| `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job` | `input.request.object.spec.template.spec` |
| `CronJob` | `input.request.object.spec.jobTemplate.spec.template.spec` |

A multi-kind rule should use conditional assignment to resolve the correct path:

```rego
pod_spec := input.request.object.spec if {
	input.request.kind.kind == "Pod"
}

pod_spec := input.request.object.spec.template.spec if {
	some kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"]
	input.request.kind.kind == kind
}

pod_spec := input.request.object.spec.jobTemplate.spec.template.spec if {
	input.request.kind.kind == "CronJob"
}
```

---

## KAC API Error Handling

- **401 Unauthorized**: Token expired or missing. Re-authenticate.
- **400 Bad Request**: Rego syntax error, Regal lint failure, blocked keyword detected, invalid rule name characters, or invalid payload. Check the error response body for details.
- **403 Forbidden**: API client lacks required scopes, OR you attempted to delete a policy that is still enabled. Disable the policy first with `{"is_enabled": false}`.
- **404 Not Found**: Policy, rule group, or custom rule ID does not exist.
- **409 Conflict**: Duplicate name or other constraint violation.
- **429 Too Many Requests**: Rate limited. Back off and retry.
- **500 Internal Server Error**: Commonly caused by sending `resource_type` or `provider` fields in a KAC custom rule creation request. These fields must be omitted for KAC rules.

---
