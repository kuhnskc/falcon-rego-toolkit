# CrowdStrike Asset & Input Data Reference

This document describes the JSON structures provided as `input` when Rego policies are evaluated for both:
- **CSPM Custom IOMs** — cloud asset JSON from AWS, GCP, Azure, and OCI
- **KAC Custom Rules** — Kubernetes AdmissionReview JSON for admission control

Understanding these structures is essential for writing accurate policies.

---

# Part 1: CSPM Cloud Asset Data

---

## How to Get Asset JSON

### Option 1: Rego Editor Test Data (Recommended)
The best source of asset JSON is the Rego editor built into the Custom IOM creation flow. This provides **enriched** data — the same data the Rego evaluation engine uses at runtime, including connected asset information (e.g., attached NAT gateways, security groups, linked resources).

1. Go to **Cloud Security > Rules and Policies > Indicators of Misconfiguration (IOM) rules**
2. Click **Create rule**
3. Enter a name, description, alert logic, and remediation steps, then click **Next**
4. In the **Rego editor**, select an asset type to generate test data
5. The generated JSON is your enriched `input` object — copy it for policy development

This is the preferred method because the enriched data matches exactly what the Rego engine evaluates against.

### Option 2: Cloud Asset Explorer (Non-Enriched)
You can also view asset data via the Falcon console's Asset Explorer, but be aware this data is **not enriched**:

1. Go to **Cloud Security > Cloud Asset Explorer**
2. Open the asset to view the **Asset Mega Panel**
3. Click the **JSON view** in the top-right corner

**Important**: This JSON is missing connected asset information that the Rego engine has access to. For example, an EC2 instance viewed here won't include attached NAT gateway data, but the same instance in the Rego editor test data will. Policies written against non-enriched data may miss fields that are available at evaluation time.

### Option 3: CrowdStrike API
Fetch enriched asset data programmatically (advanced — ask about this if needed):

1. **Discover asset IDs** by resource type:
   ```
   GET /cloud-security-assets/queries/resources/v1?filter=resource_type:'AWS::S3::Bucket'+active:'true'&limit=10
   ```

2. **Fetch enriched data** for those IDs:
   ```
   GET /cloud-policies/entities/enriched-resources/v1?ids=<asset_id>
   ```
   Include the header `X-CS-CUSTID` with the tenant ID (the portion of the asset ID before the first `|` character).

3. The response `resources[0]` object is the enriched asset data — this is your `input`.

### Option 4: Input Schema API (Field Discovery)
If you want to see what fields are available for a resource type without fetching actual asset data, you can query the input schema endpoint:

```
GET /cloud-policies/combined/rules/input-schema/v1?domain=CSPM&subdomain=IOM&cloud_provider=aws&resource_type=AWS::EC2::Instance
```

Required query parameters: `domain=CSPM`, `subdomain=IOM`, `cloud_provider` (`aws`, `azure`, `gcp`, or `oci`), and `resource_type`.

Required headers: `Authorization: Bearer <token>`, `X-CS-CUSTID: <customer_id>`, `X-CS-USERUUID: <user_id>`. Required scope: `cloud-security-policies` (Read).

This returns all available fields and their types (string, integer, float, date, ip, object) — works even if you don't have any of that resource type in your inventory. It's useful for understanding what's available, but you should still use real asset JSON from the Rego editor when writing policies to ensure accuracy.

### Option 5: Sample Resource Data via API
If you want actual asset data with real populated values (not just the schema), you can fetch a sample resource:

1. **Query resource IDs:**
   ```
   GET /cloud-security-assets/queries/resources/v1?filter=resource_type:'AWS::EC2::Instance'&limit=1
   ```

2. **Get the full resource:**
   ```
   GET /cloud-security-assets/entities/resources/v1?ids=<resource_id>
   ```

This gives you a real asset with populated values, which can be more useful when writing Rego since you can see what the actual data looks like.

---

## Common Top-Level Fields (All Providers)

Every asset, regardless of cloud provider, has these top-level fields available in `input`:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `resource_id` | string | Unique CrowdStrike identifier | `"tenant\|AWS::S3::Bucket\|my-bucket"` |
| `resource_type` | string | Cloud resource type | `"AWS::S3::Bucket"` |
| `service` | string | Service identifier | `"aws-s3"` |
| `region` | string | Cloud region | `"us-east-1"` |
| `account_id` | string | Cloud account ID | `"123456789012"` |
| `tags` | object | Key-value resource tags | `{"Environment": "prod"}` |
| `configuration` | object | Resource-specific config | *(varies by type)* |

The `configuration` object is where the resource-specific data lives. Its structure varies entirely by resource type and cloud provider.

---

## AWS Asset Structures

### AWS::S3::Bucket
```json
{
  "resource_type": "AWS::S3::Bucket",
  "service": "aws-s3",
  "region": "us-east-1",
  "tags": {
    "Environment": "prod",
    "Owner": "platform-team"
  },
  "configuration": {
    "BucketName": "my-application-bucket",
    "CreationDate": "2023-06-15T10:30:00Z",
    "publicAccessBlockConfiguration": {
      "blockPublicAcls": true,
      "blockPublicPolicy": true,
      "ignorePublicAcls": true,
      "restrictPublicBuckets": true
    },
    "serverSideEncryptionConfiguration": {
      "rules": [
        {
          "applyServerSideEncryptionByDefault": {
            "sseAlgorithm": "aws:kms",
            "kmsMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
          },
          "bucketKeyEnabled": true
        }
      ]
    },
    "versioningConfiguration": {
      "status": "Enabled"
    },
    "loggingConfiguration": {
      "targetBucket": "my-logging-bucket",
      "targetPrefix": "s3-access-logs/"
    },
    "lifecycleRules": [],
    "corsRules": [],
    "websiteConfiguration": null,
    "accelerateConfiguration": {
      "status": "Suspended"
    }
  }
}
```

**Common Rego checks for S3:**
- `input.configuration.publicAccessBlockConfiguration.blockPublicAcls == true`
- `input.configuration.serverSideEncryptionConfiguration != null`
- `input.configuration.versioningConfiguration.status == "Enabled"`
- `input.configuration.loggingConfiguration != null`

### AWS::EC2::Instance
```json
{
  "resource_type": "AWS::EC2::Instance",
  "service": "aws-ec2",
  "region": "us-west-2",
  "tags": {
    "Name": "web-server-01",
    "Environment": "prod",
    "Owner": "app-team"
  },
  "configuration": {
    "instanceId": "i-0abcdef1234567890",
    "instanceType": "t3.medium",
    "imageId": "ami-0abcdef1234567890",
    "state": {
      "name": "running",
      "code": 16
    },
    "privateDnsName": "ip-10-0-1-100.ec2.internal",
    "privateIpAddress": "10.0.1.100",
    "publicDnsName": "",
    "publicIpAddress": null,
    "subnetId": "subnet-0abcdef1234567890",
    "vpcId": "vpc-0abcdef1234567890",
    "securityGroups": [
      {
        "groupId": "sg-0abcdef1234567890",
        "groupName": "web-server-sg"
      }
    ],
    "iamInstanceProfile": {
      "arn": "arn:aws:iam::123456789012:instance-profile/web-server-role",
      "id": "AIPA1234567890EXAMPLE"
    },
    "monitoring": {
      "state": "disabled"
    },
    "ebsOptimized": true,
    "metadataOptions": {
      "httpTokens": "required",
      "httpEndpoint": "enabled",
      "httpPutResponseHopLimit": 1
    },
    "enclaveOptions": {
      "enabled": false
    },
    "platform": null,
    "launchTime": "2024-01-15T08:30:00Z"
  }
}
```

**Common Rego checks for EC2:**
- `input.tags.Environment` — tag existence
- `input.configuration.publicIpAddress == null` — no public IP
- `input.configuration.metadataOptions.httpTokens == "required"` — IMDSv2
- `input.configuration.monitoring.state == "enabled"` — detailed monitoring
- `input.configuration.iamInstanceProfile` — IAM role attached

### AWS::Lambda::Function
```json
{
  "resource_type": "AWS::Lambda::Function",
  "service": "aws-lambda",
  "region": "us-east-1",
  "tags": {
    "Application": "data-processor"
  },
  "configuration": {
    "functionName": "data-processor-handler",
    "functionArn": "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
    "runtime": "python3.12",
    "handler": "index.handler",
    "codeSize": 5242880,
    "timeout": 300,
    "memorySize": 512,
    "lastModified": "2024-06-01T12:00:00.000+0000",
    "environment": {
      "variables": {
        "TABLE_NAME": "my-table",
        "REGION": "us-east-1"
      }
    },
    "tracingConfig": {
      "mode": "Active"
    },
    "vpcConfig": {
      "subnetIds": ["subnet-abc123"],
      "securityGroupIds": ["sg-abc123"],
      "vpcId": "vpc-abc123"
    },
    "layers": [],
    "architectures": ["x86_64"],
    "ephemeralStorage": {
      "size": 512
    }
  }
}
```

**Common Rego checks for Lambda:**
- `input.configuration.runtime` — check for deprecated runtimes
- `input.configuration.vpcConfig.vpcId` — ensure VPC attachment
- `input.configuration.tracingConfig.mode == "Active"` — X-Ray tracing
- `input.configuration.timeout <= 300` — reasonable timeout

### AWS::RDS::DBInstance
```json
{
  "resource_type": "AWS::RDS::DBInstance",
  "service": "aws-rds",
  "region": "us-east-1",
  "tags": {},
  "configuration": {
    "dbInstanceIdentifier": "prod-database",
    "dbInstanceClass": "db.r5.large",
    "engine": "mysql",
    "engineVersion": "8.0.35",
    "masterUsername": "admin",
    "allocatedStorage": 100,
    "storageType": "gp3",
    "storageEncrypted": true,
    "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
    "multiAZ": true,
    "publiclyAccessible": false,
    "autoMinorVersionUpgrade": true,
    "backupRetentionPeriod": 7,
    "deletionProtection": true,
    "iamDatabaseAuthenticationEnabled": true,
    "performanceInsightsEnabled": true,
    "monitoringInterval": 60,
    "caCertificateIdentifier": "rds-ca-rsa2048-g1"
  }
}
```

**Common Rego checks for RDS:**
- `input.configuration.storageEncrypted == true`
- `input.configuration.publiclyAccessible == false`
- `input.configuration.multiAZ == true`
- `input.configuration.backupRetentionPeriod >= 7`
- `input.configuration.deletionProtection == true`

### AWS::ECR::RegistryPolicy
```json
{
  "resource_type": "AWS::ECR::RegistryPolicy",
  "service": "aws-ecr",
  "region": "us-east-1",
  "tags": {},
  "configuration": {
    "registryId": "123456789012",
    "policyText": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"CrossAccountAccess\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::444455556666:root\"},\"Action\":[\"ecr:BatchGetImage\",\"ecr:GetDownloadUrlForLayer\"]}]}"
  }
}
```

Note: `policyText` is a **JSON string** that must be parsed with `json.unmarshal` before accessing its contents.

### AWS::Logs::LogGroup
```json
{
  "resource_type": "AWS::Logs::LogGroup",
  "service": "aws-logs",
  "region": "us-east-1",
  "tags": {},
  "configuration": {
    "logGroupName": "/aws/lambda/my-function",
    "retentionInDays": 90,
    "storedBytes": 1048576,
    "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-function:*",
    "kmsKeyId": null,
    "creationTime": 1700000000000
  }
}
```

---

## GCP Asset Structures

### compute.googleapis.com/Instance
```json
{
  "resource_type": "compute.googleapis.com/Instance",
  "service": "gcp-compute",
  "region": "us-central1-a",
  "tags": {
    "environment": "production"
  },
  "configuration": {
    "name": "web-server-01",
    "machineType": "e2-medium",
    "status": "RUNNING",
    "zone": "us-central1-a",
    "canIpForward": false,
    "networkInterfaces": [
      {
        "network": "projects/my-project/global/networks/default",
        "subnetwork": "projects/my-project/regions/us-central1/subnetworks/default",
        "networkIP": "10.128.0.2",
        "accessConfigs": [
          {
            "type": "ONE_TO_ONE_NAT",
            "name": "External NAT",
            "natIP": "34.123.45.67"
          }
        ]
      }
    ],
    "disks": [
      {
        "type": "PERSISTENT",
        "mode": "READ_WRITE",
        "boot": true,
        "autoDelete": true,
        "diskSizeGb": "50",
        "diskEncryptionKey": null
      }
    ],
    "serviceAccounts": [
      {
        "email": "123456789-compute@developer.gserviceaccount.com",
        "scopes": [
          "https://www.googleapis.com/auth/cloud-platform"
        ]
      }
    ],
    "shieldedInstanceConfig": {
      "enableSecureBoot": true,
      "enableVtpm": true,
      "enableIntegrityMonitoring": true
    },
    "deletionProtection": false,
    "labels": {
      "team": "platform",
      "cost-center": "engineering"
    }
  }
}
```

**Common Rego checks for GCP Compute:**
- Check for public IP: `input.configuration.networkInterfaces[_].accessConfigs` exists
- Shielded VM: `input.configuration.shieldedInstanceConfig.enableSecureBoot == true`
- IP forwarding: `input.configuration.canIpForward == false`
- Default service account: check `serviceAccounts[_].email` does not contain `"-compute@developer.gserviceaccount.com"`

### compute.googleapis.com/Firewall
```json
{
  "resource_type": "compute.googleapis.com/Firewall",
  "service": "gcp-compute",
  "region": "global",
  "tags": {},
  "configuration": {
    "name": "allow-internal",
    "network": "projects/my-project/global/networks/default",
    "direction": "INGRESS",
    "priority": 1000,
    "disabled": false,
    "sourceRanges": ["10.0.0.0/8"],
    "allowed": [
      {
        "IPProtocol": "tcp",
        "ports": ["0-65535"]
      },
      {
        "IPProtocol": "udp",
        "ports": ["0-65535"]
      }
    ],
    "denied": [],
    "targetTags": [],
    "sourceServiceAccounts": [],
    "targetServiceAccounts": [],
    "logConfig": {
      "enable": false
    }
  }
}
```

**Common Rego checks for GCP Firewall:**
- Open to internet: `input.configuration.sourceRanges[_] == "0.0.0.0/0"`
- SSH open: check `allowed[_].ports` contains "22"
- RDP open: check `allowed[_].ports` contains "3389"
- Logging enabled: `input.configuration.logConfig.enable == true`

### container.googleapis.com/Cluster
```json
{
  "resource_type": "container.googleapis.com/Cluster",
  "service": "gcp-container",
  "region": "us-central1",
  "tags": {},
  "configuration": {
    "name": "prod-cluster",
    "location": "us-central1",
    "currentMasterVersion": "1.28.3-gke.1203000",
    "currentNodeVersion": "1.28.3-gke.1203000",
    "status": "RUNNING",
    "networkConfig": {
      "network": "projects/my-project/global/networks/default",
      "subnetwork": "projects/my-project/regions/us-central1/subnetworks/default"
    },
    "masterAuthorizedNetworksConfig": {
      "enabled": true,
      "cidrBlocks": [
        {"cidrBlock": "10.0.0.0/8", "displayName": "internal"}
      ]
    },
    "legacyAbac": {
      "enabled": false
    },
    "networkPolicy": {
      "enabled": true
    },
    "privateClusterConfig": {
      "enablePrivateNodes": true,
      "enablePrivateEndpoint": false,
      "masterIpv4CidrBlock": "172.16.0.0/28"
    },
    "addonsConfig": {
      "httpLoadBalancing": {"disabled": false},
      "networkPolicyConfig": {"disabled": false}
    },
    "loggingService": "logging.googleapis.com/kubernetes",
    "monitoringService": "monitoring.googleapis.com/kubernetes",
    "binaryAuthorization": {
      "evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"
    },
    "shieldedNodes": {
      "enabled": true
    }
  }
}
```

### iam.googleapis.com/ServiceAccount
```json
{
  "resource_type": "iam.googleapis.com/ServiceAccount",
  "service": "gcp-iam",
  "region": "global",
  "tags": {},
  "configuration": {
    "name": "projects/my-project/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com",
    "email": "my-sa@my-project.iam.gserviceaccount.com",
    "displayName": "My Service Account",
    "disabled": false,
    "uniqueId": "123456789012345678901",
    "keys": [
      {
        "name": "projects/my-project/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com/keys/abc123",
        "validAfterTime": "2024-01-01T00:00:00Z",
        "validBeforeTime": "2025-01-01T00:00:00Z",
        "keyType": "USER_MANAGED"
      }
    ]
  }
}
```

---

## Azure Asset Structures

### Microsoft.Storage/storageAccounts
```json
{
  "resource_type": "Microsoft.Storage/storageAccounts",
  "service": "azure-storage",
  "region": "eastus",
  "tags": {
    "Environment": "Production"
  },
  "configuration": {
    "name": "mystorageaccount",
    "type": "Microsoft.Storage/storageAccounts",
    "location": "eastus",
    "sku": {
      "name": "Standard_LRS",
      "tier": "Standard"
    },
    "kind": "StorageV2",
    "properties": {
      "supportsHttpsTrafficOnly": true,
      "minimumTlsVersion": "TLS1_2",
      "allowBlobPublicAccess": false,
      "networkAcls": {
        "defaultAction": "Deny",
        "bypass": "AzureServices",
        "virtualNetworkRules": [],
        "ipRules": []
      },
      "encryption": {
        "services": {
          "blob": {"enabled": true, "keyType": "Account"},
          "file": {"enabled": true, "keyType": "Account"}
        },
        "keySource": "Microsoft.Storage",
        "requireInfrastructureEncryption": false
      },
      "accessTier": "Hot",
      "provisioningState": "Succeeded"
    }
  }
}
```

**Note**: Azure resources often nest configuration under `properties` within `configuration`.

**Common Rego checks for Azure Storage:**
- `input.configuration.properties.supportsHttpsTrafficOnly == true`
- `input.configuration.properties.minimumTlsVersion == "TLS1_2"`
- `input.configuration.properties.allowBlobPublicAccess == false`
- `input.configuration.properties.networkAcls.defaultAction == "Deny"`

### Microsoft.Authorization/policyAssignments
```json
{
  "resource_type": "Microsoft.Authorization/policyAssignments",
  "service": "azure-authorization",
  "region": "global",
  "tags": {},
  "configuration": {
    "name": "security-baseline",
    "type": "Microsoft.Authorization/policyAssignments",
    "properties": {
      "displayName": "Security Baseline Policy",
      "description": "Enforces organization security baseline",
      "enforcementMode": "Default",
      "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/abc-123",
      "scope": "/subscriptions/12345678-1234-1234-1234-123456789012",
      "notScopes": [],
      "parameters": {}
    }
  }
}
```

---

## OCI Asset Structures

Oracle Cloud Infrastructure (OCI) resources follow a similar pattern to Azure. Resource types use OCI's own naming convention. Exact field structures will depend on the specific OCI resource type registered in your CrowdStrike CSPM environment. The general pattern is:

```json
{
  "resource_type": "<OCI resource type>",
  "service": "oci-<service>",
  "region": "us-ashburn-1",
  "tags": {},
  "configuration": {
    // OCI-specific fields
  }
}
```

When writing policies for OCI resources, always fetch sample asset data first to confirm the exact field names and structure.

---

## Tips for Working with Asset Data

1. **Always get sample data first** — Field names differ between providers and even between resource versions. Never guess.
2. **Check the actual types** — A field that looks boolean might be a string (`"true"` vs `true`).
3. **Watch for nested JSON strings** — Some fields (especially policy documents) are JSON-encoded strings that need `json.unmarshal`.
4. **Tags may be inconsistent** — Tag keys might be camelCase, PascalCase, or kebab-case depending on who created them.
5. **Null vs missing** — A field can be explicitly `null`, an empty string `""`, an empty array `[]`, or completely absent. Your Rego must handle all cases.
6. **Arrays use [_] for iteration** — To check any element in an array, use the `[_]` wildcard: `input.configuration.securityGroups[_].groupName == "default"`.

---
---

# Part 2: KAC (Kubernetes Admission Controller) Input Data

KAC policies receive a Kubernetes **AdmissionReview** object as `input`. Unlike CSPM cloud assets, the AdmissionReview structure is well-defined and consistent across clusters.

---

## AdmissionReview Structure Overview

The `input` for KAC is always a Kubernetes AdmissionReview. The resource being evaluated is at `input.request.object`.

```
input
├── request
│   ├── uid                         # Unique request ID
│   ├── kind
│   │   ├── group                   # API group ("apps", "batch", "")
│   │   ├── version                 # API version ("v1", "v1beta1")
│   │   └── kind                    # Resource kind ("Pod", "Deployment", etc.)
│   ├── resource
│   │   ├── group
│   │   ├── version
│   │   └── resource                # Plural name ("pods", "deployments")
│   ├── namespace                   # Target namespace
│   ├── operation                   # "CREATE", "UPDATE", "DELETE"
│   ├── userInfo
│   │   ├── username                # Submitting user
│   │   └── groups                  # User's groups
│   ├── object                      # The K8s resource being admitted
│   │   ├── apiVersion
│   │   ├── kind
│   │   ├── metadata
│   │   │   ├── name
│   │   │   ├── namespace
│   │   │   ├── labels
│   │   │   └── annotations
│   │   └── spec                    # Resource-specific (varies by kind)
│   └── oldObject                   # Previous version (UPDATE only, null on CREATE)
```

---

## Full AdmissionReview Example: Pod

```json
{
  "request": {
    "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "namespace": "default",
    "operation": "CREATE",
    "userInfo": {
      "username": "admin",
      "groups": ["system:masters", "system:authenticated"]
    },
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "nginx-pod",
        "namespace": "default",
        "labels": {
          "app": "nginx",
          "team": "platform",
          "owner": "devops"
        },
        "annotations": {
          "description": "NGINX web server"
        }
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.25.3",
            "ports": [
              {
                "containerPort": 80,
                "protocol": "TCP"
              }
            ],
            "resources": {
              "requests": {
                "cpu": "100m",
                "memory": "128Mi"
              },
              "limits": {
                "cpu": "500m",
                "memory": "256Mi"
              }
            },
            "securityContext": {
              "privileged": false,
              "readOnlyRootFilesystem": true,
              "runAsNonRoot": true,
              "runAsUser": 1000,
              "allowPrivilegeEscalation": false,
              "capabilities": {
                "drop": ["ALL"]
              }
            },
            "volumeMounts": [
              {
                "name": "html",
                "mountPath": "/usr/share/nginx/html",
                "readOnly": true
              }
            ]
          }
        ],
        "initContainers": [
          {
            "name": "init-config",
            "image": "busybox:1.36",
            "command": ["sh", "-c", "echo init"],
            "resources": {
              "limits": {
                "cpu": "100m",
                "memory": "64Mi"
              }
            },
            "securityContext": {
              "privileged": false,
              "runAsNonRoot": true
            }
          }
        ],
        "volumes": [
          {
            "name": "html",
            "configMap": {
              "name": "nginx-html"
            }
          }
        ],
        "serviceAccountName": "default",
        "hostNetwork": false,
        "hostPID": false,
        "hostIPC": false,
        "dnsPolicy": "ClusterFirst",
        "restartPolicy": "Always"
      }
    }
  }
}
```

**Key paths for Pod policies:**
- Container list: `input.request.object.spec.containers[_]`
- Init containers: `input.request.object.spec.initContainers[_]`
- Labels: `input.request.object.metadata.labels`
- Security context: `input.request.object.spec.containers[_].securityContext`
- Resource limits: `input.request.object.spec.containers[_].resources.limits`
- Volumes: `input.request.object.spec.volumes[_]`
- Host networking: `input.request.object.spec.hostNetwork`

---

## Full AdmissionReview Example: Deployment

```json
{
  "request": {
    "uid": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
    "kind": {
      "group": "apps",
      "version": "v1",
      "kind": "Deployment"
    },
    "resource": {
      "group": "apps",
      "version": "v1",
      "resource": "deployments"
    },
    "namespace": "production",
    "operation": "CREATE",
    "userInfo": {
      "username": "developer@company.com",
      "groups": ["developers", "system:authenticated"]
    },
    "object": {
      "apiVersion": "apps/v1",
      "kind": "Deployment",
      "metadata": {
        "name": "web-app",
        "namespace": "production",
        "labels": {
          "app": "web-app",
          "team": "backend",
          "owner": "backend-team",
          "version": "v2.1.0"
        },
        "annotations": {
          "deployment.kubernetes.io/revision": "1"
        }
      },
      "spec": {
        "replicas": 3,
        "selector": {
          "matchLabels": {
            "app": "web-app"
          }
        },
        "template": {
          "metadata": {
            "labels": {
              "app": "web-app",
              "team": "backend",
              "owner": "backend-team",
              "version": "v2.1.0"
            }
          },
          "spec": {
            "containers": [
              {
                "name": "web-app",
                "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/web-app:v2.1.0",
                "ports": [
                  {
                    "containerPort": 8080,
                    "protocol": "TCP"
                  }
                ],
                "resources": {
                  "requests": {
                    "cpu": "250m",
                    "memory": "512Mi"
                  },
                  "limits": {
                    "cpu": "1000m",
                    "memory": "1Gi"
                  }
                },
                "securityContext": {
                  "privileged": false,
                  "readOnlyRootFilesystem": true,
                  "runAsNonRoot": true,
                  "allowPrivilegeEscalation": false
                },
                "env": [
                  {
                    "name": "DATABASE_URL",
                    "valueFrom": {
                      "secretKeyRef": {
                        "name": "db-credentials",
                        "key": "url"
                      }
                    }
                  }
                ],
                "livenessProbe": {
                  "httpGet": {
                    "path": "/healthz",
                    "port": 8080
                  },
                  "initialDelaySeconds": 10,
                  "periodSeconds": 30
                }
              },
              {
                "name": "sidecar-proxy",
                "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/envoy-proxy:v1.28.0",
                "ports": [
                  {
                    "containerPort": 9090
                  }
                ],
                "resources": {
                  "requests": {
                    "cpu": "100m",
                    "memory": "128Mi"
                  },
                  "limits": {
                    "cpu": "500m",
                    "memory": "256Mi"
                  }
                },
                "securityContext": {
                  "privileged": false,
                  "runAsNonRoot": true
                }
              }
            ],
            "volumes": [
              {
                "name": "tmp",
                "emptyDir": {}
              }
            ],
            "serviceAccountName": "web-app-sa",
            "hostNetwork": false,
            "hostPID": false
          }
        }
      }
    }
  }
}
```

**Key paths for Deployment policies:**
- Container list: `input.request.object.spec.template.spec.containers[_]`
- Init containers: `input.request.object.spec.template.spec.initContainers[_]`
- Pod template labels: `input.request.object.spec.template.metadata.labels`
- Deployment-level labels: `input.request.object.metadata.labels`
- Security context: `input.request.object.spec.template.spec.containers[_].securityContext`
- Resource limits: `input.request.object.spec.template.spec.containers[_].resources.limits`
- Volumes: `input.request.object.spec.template.spec.volumes[_]`
- Host networking: `input.request.object.spec.template.spec.hostNetwork`

---

## Key Paths Table by Kubernetes Resource Type

| Resource Type | API Group | Path to Pod Spec | Path to Containers | Path to Pod Labels |
|--------------|-----------|-----------------|-------------------|-------------------|
| Pod | `""` (core) | `input.request.object.spec` | `input.request.object.spec.containers[_]` | `input.request.object.metadata.labels` |
| Deployment | `apps` | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| DaemonSet | `apps` | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| StatefulSet | `apps` | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| ReplicaSet | `apps` | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| ReplicationController | `""` (core) | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| Job | `batch` | `input.request.object.spec.template.spec` | `input.request.object.spec.template.spec.containers[_]` | `input.request.object.spec.template.metadata.labels` |
| CronJob | `batch` | `input.request.object.spec.jobTemplate.spec.template.spec` | `input.request.object.spec.jobTemplate.spec.template.spec.containers[_]` | `input.request.object.spec.jobTemplate.spec.template.metadata.labels` |
| Service | `""` (core) | `input.request.object.spec` (no Pod spec) | N/A — Services have ports, selectors, not containers | `input.request.object.metadata.labels` |

---

## Navigating the Input for Different Resource Types

Use the `input.request.kind.kind` field to determine the resource type and adjust your path accordingly:

```rego
# Determine resource kind
resource_kind := input.request.kind.kind

# Examples:
# resource_kind == "Pod"        -> spec is at input.request.object.spec
# resource_kind == "Deployment" -> spec is at input.request.object.spec.template.spec
# resource_kind == "CronJob"    -> spec is at input.request.object.spec.jobTemplate.spec.template.spec
```

### Common Fields Available on All KAC Resources
- `input.request.kind.kind` — Resource type (Pod, Deployment, etc.)
- `input.request.namespace` — Target namespace
- `input.request.operation` — CREATE, UPDATE, or DELETE
- `input.request.userInfo.username` — Who submitted the request
- `input.request.object.metadata.name` — Resource name
- `input.request.object.metadata.namespace` — Resource namespace
- `input.request.object.metadata.labels` — Resource-level labels
- `input.request.object.metadata.annotations` — Resource-level annotations

### Container-Level Fields (within Pod spec)
- `container.name` — Container name
- `container.image` — Container image with tag
- `container.ports` — Port mappings
- `container.resources.requests` — CPU/memory requests
- `container.resources.limits` — CPU/memory limits
- `container.securityContext` — Container security settings
- `container.securityContext.privileged` — Privileged mode flag
- `container.securityContext.runAsNonRoot` — Non-root requirement
- `container.securityContext.readOnlyRootFilesystem` — Read-only filesystem
- `container.securityContext.allowPrivilegeEscalation` — Privilege escalation flag
- `container.securityContext.capabilities` — Linux capabilities (add/drop)
- `container.volumeMounts` — Volume mount points
- `container.env` — Environment variables

### Pod-Spec-Level Fields
- `pod_spec.hostNetwork` — Whether the Pod uses host networking (**Note**: Pods with `hostNetwork: true` bypass the K8s admission webhook entirely. A KAC rule for hostNetwork will fire in Alert mode but cannot be enforced in Prevent mode.)
- `pod_spec.hostPID` — Whether the Pod uses host PID namespace (fully enforceable in Prevent mode)
- `pod_spec.hostIPC` — Whether the Pod uses host IPC namespace (fully enforceable in Prevent mode)
- `pod_spec.serviceAccountName` — Service account used by the Pod
- `pod_spec.securityContext` — Pod-level security context (applies to all containers unless overridden)
- `pod_spec.securityContext.runAsNonRoot` — Pod-level non-root requirement
- `pod_spec.volumes` — Volume definitions
- `pod_spec.volumes[_].hostPath` — hostPath volume (if present)
- `pod_spec.dnsPolicy` — DNS policy
- `pod_spec.restartPolicy` — Restart policy

---

## Iterating KAC Input Data in Rego

When writing KAC Rego rules, you MUST use `some X in Y` syntax for iteration (required by the Regal linter):

```rego
# CORRECT — iterate containers with "some ... in"
result := msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' is privileged", [container.name])
}

# CORRECT — iterate volumes with "some ... in"
result := msg if {
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf("Volume '%s' uses hostPath", [volume.name])
}
```

Do NOT use the old `X := collection[_]` pattern — it is rejected by the linter.

When checking both a pod-level condition and container-level conditions, use a **set comprehension** to avoid the `non-loop-expression` lint error:

```rego
# Collect non-compliant containers into a set
containers_without_non_root contains container.name if {
	some container in pod_spec.containers
	not container.securityContext.runAsNonRoot
}

# Then check pod-level condition outside the loop
result := msg if {
	not pod_spec.securityContext.runAsNonRoot
	count(containers_without_non_root) > 0
	names := concat(", ", containers_without_non_root)
	msg := sprintf("Containers must set runAsNonRoot - %s", [names])
}
```
