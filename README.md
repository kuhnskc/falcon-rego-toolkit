# Falcon Rego Toolkit

A web application for managing CrowdStrike Rego security policies across two products:

- **CSPM Custom IOMs** — Cloud resource compliance policies (AWS, GCP, Azure, OCI)
- **KAC Custom Rules** — Kubernetes Admission Controller policies for real-time workload admission control

> **Disclaimer:** This is an independent, community-driven project. It is **not** affiliated with, endorsed by, or officially supported by CrowdStrike. Use at your own risk.

## Quick Start

```bash
docker run -p 8000:8000 kckuhns92/falcon-rego-toolkit:latest
```

Supports **Intel (amd64)** and **Apple Silicon (arm64)**. Open **http://localhost:8000** and enter your CrowdStrike API credentials. Credentials are stored in-memory only and never persisted.

### Build from Source

```bash
git clone https://github.com/kuhnskc/falcon-rego-toolkit.git
cd falcon-rego-toolkit
cd frontend && npm install && npm run build && cd ..
docker build -t falcon-rego-toolkit .
docker run -p 8000:8000 falcon-rego-toolkit
```

### Local Development (without Docker)

```bash
git clone https://github.com/kuhnskc/falcon-rego-toolkit.git
cd falcon-rego-toolkit
./start.sh
```

This starts the backend (port 8000) and frontend dev server (port 5173). Open **http://localhost:5173**.

Requires Python 3.10+, Node.js 18+, and optionally [OPA](https://www.openpolicyagent.org/) for local KAC rule testing.

## CrowdStrike API Setup

Create an API client in your CrowdStrike console (**Support and resources > Resources and tools > API clients and keys**) with these scopes:

| Scope | Access | Used For |
|-------|--------|----------|
| `CSPM registration` | Read, Write | CSPM Custom IOM policies |
| `Cloud Security Assessment` | Read | CSPM asset discovery and testing |
| `Falcon Container Policies` | Read, Write | KAC policies, rule groups, custom rules |

### Cloud Environments

| Environment | Base URL |
|-------------|----------|
| US-1 | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

## Features

### CSPM Custom IOMs

- 8-step creation wizard — name, resource type, sample data, severity, alerts, remediation, Rego editor, test & create
- Live policy testing against real cloud assets in your environment
- Asset discovery — browse resource types and fetch enriched sample data
- Full lifecycle management — create, view, edit, delete

### KAC Custom Rules

- Policy management — create, enable/disable, delete KAC policies
- Rule groups with label and namespace selectors
- Custom Rego rules — write, view, edit, and deploy with a Monaco editor
- Local rule testing — evaluate KAC rules against K8s manifests using OPA (no deploy required)
- Rule group precedence management

### General

- Monaco Rego editor with syntax highlighting
- CrowdStrike-inspired dark theme
- Server-side auth — OAuth2 tokens managed on the backend, never exposed to the browser

## Agent Knowledge Base

The `agent_kb/` directory contains 5 markdown files designed to power a GenAI agent that helps write Rego policies for CrowdStrike. These files can be used as context for any LLM or AI coding assistant.

| File | Contents |
|------|----------|
| `system_prompt.md` | Agent system prompt with CSPM and KAC contracts |
| `rego_writing_guide.md` | Rego v1 writing guide for both products |
| `example_policies.md` | 22+ example policies (CSPM + KAC) with test results |
| `asset_data_reference.md` | Input JSON structures for cloud assets and K8s AdmissionReview |
| `api_reference.md` | CrowdStrike API reference for policy CRUD operations |

## Example Policies

The `simple_examples/` directory contains ready-to-use Rego policies:

**CSPM** — `simple_examples/cspm/`
- S3 bucket security checks
- EC2 instance tagging enforcement
- ECR cross-account access detection

**KAC** — `simple_examples/kac/`
- Block privileged containers
- Deny latest image tag
- Require resource limits
- Block hostPath volumes
- Enforce non-root execution
- Restrict image registries
- Deny host namespace access