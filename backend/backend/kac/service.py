from typing import Optional

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

from backend.common.crowdstrike_client import CrowdStrikeClient


class KacService:
    """CrowdStrike Kubernetes Admission Controller API operations."""

    BASE = "/admission-control-policies"

    def __init__(self, client: CrowdStrikeClient):
        self.client = client

    # ── Policies ────────────────────────────────────────────────────

    def list_policies(self, filter_str: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        params: dict = {"limit": limit, "offset": offset}
        if filter_str:
            params["filter"] = filter_str

        # Use combined endpoint for simplicity
        resp = self.client.get(f"{self.BASE}/combined/policies/v1", params=params)
        if resp.status_code == 200:
            return resp.json().get("resources", [])

        # Fallback to query + entities
        query_resp = self.client.get(f"{self.BASE}/queries/policies/v1", params=params)
        if query_resp.status_code != 200:
            return []
        ids = query_resp.json().get("resources", [])
        if not ids:
            return []
        entity_resp = self.client.get(f"{self.BASE}/entities/policies/v1", params={"ids": ids})
        if entity_resp.status_code == 200:
            return entity_resp.json().get("resources", [])
        return []

    def get_policy(self, policy_id: str) -> Optional[dict]:
        resp = self.client.get(f"{self.BASE}/entities/policies/v1", params={"ids": [policy_id]})
        if resp.status_code == 200:
            resources = resp.json().get("resources", [])
            return resources[0] if resources else None
        return None

    def create_policy(self, name: str, description: str = "") -> dict:
        resp = self.client.post(
            f"{self.BASE}/entities/policies/v1",
            json={"name": name, "description": description},
        )
        data = resp.json()
        if resp.status_code not in (200, 201):
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def update_policy(self, policy_id: str, updates: dict) -> dict:
        resp = self.client.patch(
            f"{self.BASE}/entities/policies/v1",
            params={"ids": policy_id},
            json=updates,
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def delete_policy(self, policy_id: str) -> dict:
        resp = self.client.delete(
            f"{self.BASE}/entities/policies/v1",
            params={"ids": [policy_id]},
        )
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": resp.json()}
        return {"deleted": True, "id": policy_id}

    def update_precedence(self, policy_id: str, precedence: int) -> dict:
        resp = self.client.patch(
            f"{self.BASE}/entities/policy-precedence/v1",
            json={"id": policy_id, "precedence": precedence},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Host groups ─────────────────────────────────────────────────

    def add_host_groups(self, policy_id: str, host_group_ids: list[str]) -> dict:
        resp = self.client.post(
            f"{self.BASE}/entities/policy-host-groups/v1",
            json={"id": policy_id, "host_groups": host_group_ids},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def remove_host_groups(self, policy_id: str, host_group_ids: list[str]) -> dict:
        resp = self.client.delete(
            f"{self.BASE}/entities/policy-host-groups/v1",
            params={"policy_id": policy_id, "host_group_ids": host_group_ids},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Rule groups ─────────────────────────────────────────────────

    def create_rule_groups(self, policy_id: str, groups: list[dict]) -> dict:
        resp = self.client.post(
            f"{self.BASE}/entities/policy-rule-groups/v1",
            json={"id": policy_id, "rule_groups": groups},
        )
        data = resp.json()
        if resp.status_code not in (200, 201):
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def update_rule_group(self, policy_id: str, rule_group: dict) -> dict:
        resp = self.client.patch(
            f"{self.BASE}/entities/policy-rule-groups/v1",
            json={"id": policy_id, "rule_groups": [rule_group]},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def delete_rule_groups(self, policy_id: str, rule_group_ids: list[str]) -> dict:
        resp = self.client.delete(
            f"{self.BASE}/entities/policy-rule-groups/v1",
            params={"policy_id": policy_id, "rule_group_ids": rule_group_ids},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Custom rules ────────────────────────────────────────────────

    def add_custom_rules(self, policy_id: str, rule_group_id: str, rules: list[dict]) -> dict:
        resp = self.client.post(
            f"{self.BASE}/entities/policy-rule-group-custom-rules/v1",
            json={
                "id": policy_id,
                "rule_groups": [
                    {
                        "id": rule_group_id,
                        "custom_rules": rules,
                    }
                ],
            },
        )
        data = resp.json()
        if resp.status_code not in (200, 201):
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def delete_custom_rules(self, policy_id: str, rule_ids: list[str]) -> dict:
        resp = self.client.delete(
            f"{self.BASE}/entities/policy-rule-group-custom-rules/v1",
            params={"policy_id": policy_id, "custom_rule_ids": rule_ids},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Selectors ───────────────────────────────────────────────────

    def update_selectors(self, policy_id: str, rule_group_id: str, selectors: dict) -> dict:
        resp = self.client.put(
            f"{self.BASE}/entities/policy-rule-group-selectors/v1",
            json={
                "id": policy_id,
                "rule_group_id": rule_group_id,
                **selectors,
            },
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Custom Rego rule creation (upload logic) ─────────────────────

    def create_custom_rego_rule(
        self,
        name: str,
        description: str,
        logic: str,
        severity: int = 3,
        alert_info: str = "",
        remediation_info: str = "",
    ) -> dict:
        """Create a custom Rego rule via cloud-policies API (domain=Runtime).

        This uploads the Rego logic to CrowdStrike and returns a rule UUID
        that can then be attached to a KAC policy rule group.

        Per the KAC authoring guide, the minimal required fields are:
        name, description, logic, domain=Runtime, platform=Kubernetes,
        subdomain=IOM, and severity. Do NOT send resource_type or provider
        for KAC rules — those cause a 500 server error.
        """
        payload = {
            "name": name,
            "description": description,
            "logic": logic,
            "severity": severity,
            "platform": "Kubernetes",
            "domain": "Runtime",
            "subdomain": "IOM",
        }
        if alert_info:
            payload["alert_info"] = alert_info
        if remediation_info:
            payload["remediation_info"] = remediation_info

        resp = self.client.post("/cloud-policies/entities/rules/v1", json=payload)
        data = resp.json()
        if resp.status_code not in (200, 201):
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    def delete_custom_rego_rule(self, rule_uuid: str) -> dict:
        """Delete a custom Rego rule by UUID from cloud-policies."""
        resp = self.client.delete(
            "/cloud-policies/entities/rules/v1",
            params={"ids": [rule_uuid]},
        )
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": resp.json()}
        return {"deleted": True, "uuid": rule_uuid}

    def get_custom_rego_rule(self, rule_uuid: str) -> Optional[dict]:
        """Get a custom Rego rule by UUID, including the Rego logic."""
        resp = self.client.get(
            "/cloud-policies/entities/rules/v1",
            params={"ids": [rule_uuid]},
        )
        if resp.status_code == 200:
            resources = resp.json().get("resources", [])
            return resources[0] if resources else None
        return None

    def update_custom_rego_rule(self, rule_uuid: str, updates: dict) -> dict:
        """Update a custom Rego rule (name, description, severity, logic)."""
        payload = {"uuid": rule_uuid}
        if "logic" in updates:
            payload["rule_logic_list"] = [{
                "logic": updates.pop("logic"),
                "platform": "Kubernetes",
            }]
        payload.update(updates)
        resp = self.client.patch("/cloud-policies/entities/rules/v1", json=payload)
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Rule group precedence ───────────────────────────────────────

    def set_rule_group_precedence(self, policy_id: str, rule_group_ids: list[str]) -> dict:
        resp = self.client.put(
            f"{self.BASE}/entities/policy-rule-group-precedence/v1",
            json={"id": policy_id, "rule_group_ids": rule_group_ids},
        )
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Local OPA evaluation (no CrowdStrike API needed) ───────────

    KIND_TO_RESOURCE = {
        "Pod": "pods",
        "Deployment": "deployments",
        "DaemonSet": "daemonsets",
        "StatefulSet": "statefulsets",
        "ReplicaSet": "replicasets",
        "ReplicationController": "replicationcontrollers",
        "Job": "jobs",
        "CronJob": "cronjobs",
        "Service": "services",
    }

    @staticmethod
    def _build_admission_review(manifest: dict) -> dict:
        """Wrap a K8s manifest in an AdmissionReview structure."""
        kind = manifest.get("kind", "Unknown")
        api_version = manifest.get("apiVersion", "v1")
        metadata = manifest.get("metadata", {})

        if "/" in api_version:
            group, version = api_version.split("/", 1)
        else:
            group = ""
            version = api_version

        resource_name = KacService.KIND_TO_RESOURCE.get(kind, kind.lower() + "s")

        return {
            "request": {
                "uid": "eval-00000000-0000-0000-0000-000000000000",
                "kind": {"group": group, "version": version, "kind": kind},
                "resource": {"group": group, "version": version, "resource": resource_name},
                "namespace": metadata.get("namespace", "default"),
                "operation": "CREATE",
                "userInfo": {
                    "username": "rego-toolkit-evaluator",
                    "groups": ["system:authenticated"],
                },
                "object": manifest,
            }
        }

    @staticmethod
    def evaluate_rule(logic: str, manifest_yaml: str) -> dict:
        """Evaluate a KAC Rego rule locally using the OPA binary."""
        opa_path = shutil.which("opa")
        if not opa_path:
            return {
                "decision": "ERROR",
                "message": "OPA binary not found. Install OPA: brew install opa",
                "opa_available": False,
                "manifest_kind": "",
                "manifest_name": "",
                "raw_output": None,
                "error": "OPA not installed",
            }

        # Parse YAML manifest
        try:
            manifest = yaml.safe_load(manifest_yaml)
        except yaml.YAMLError as e:
            return {
                "decision": "ERROR",
                "message": f"Invalid YAML: {e}",
                "opa_available": True,
                "manifest_kind": "",
                "manifest_name": "",
                "raw_output": None,
                "error": str(e),
            }

        if not isinstance(manifest, dict):
            return {
                "decision": "ERROR",
                "message": "YAML must parse to a JSON object (got a scalar or list)",
                "opa_available": True,
                "manifest_kind": "",
                "manifest_name": "",
                "raw_output": None,
                "error": "Manifest is not a dict",
            }

        kind = manifest.get("kind", "Unknown")
        name = manifest.get("metadata", {}).get("name", "unknown")

        # Wrap in AdmissionReview
        admission_review = KacService._build_admission_review(manifest)

        # Write temp files and run OPA
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.rego"
            input_path = Path(tmpdir) / "input.json"

            policy_path.write_text(logic)
            input_path.write_text(json.dumps(admission_review, indent=2))

            try:
                proc = subprocess.run(
                    [
                        opa_path, "eval",
                        "-d", str(policy_path),
                        "-i", str(input_path),
                        "data.customrule.result",
                        "--format", "json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except subprocess.TimeoutExpired:
                return {
                    "decision": "ERROR",
                    "message": "OPA evaluation timed out (10s limit)",
                    "opa_available": True,
                    "manifest_kind": kind,
                    "manifest_name": name,
                    "raw_output": None,
                    "error": "Timeout",
                }

            if proc.returncode != 0:
                error_msg = proc.stderr.strip() or proc.stdout.strip()
                return {
                    "decision": "ERROR",
                    "message": f"OPA error: {error_msg}",
                    "opa_available": True,
                    "manifest_kind": kind,
                    "manifest_name": name,
                    "raw_output": None,
                    "error": error_msg,
                }

            # Parse OPA JSON output
            try:
                opa_output = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {
                    "decision": "ERROR",
                    "message": f"Failed to parse OPA output: {proc.stdout[:200]}",
                    "opa_available": True,
                    "manifest_kind": kind,
                    "manifest_name": name,
                    "raw_output": None,
                    "error": "JSON parse error",
                }

            # Extract result value from OPA output
            # Format: {"result": [{"expressions": [{"value": <result>, ...}]}]}
            expressions = opa_output.get("result", [{}])[0].get("expressions", [])
            if not expressions or expressions[0].get("value") is None:
                return {
                    "decision": "ALLOW",
                    "message": "No deny rules matched -- resource would be allowed",
                    "opa_available": True,
                    "manifest_kind": kind,
                    "manifest_name": name,
                    "raw_output": opa_output,
                    "error": None,
                }

            result_value = expressions[0]["value"]
            if isinstance(result_value, str) and result_value:
                return {
                    "decision": "DENY",
                    "message": result_value,
                    "opa_available": True,
                    "manifest_kind": kind,
                    "manifest_name": name,
                    "raw_output": opa_output,
                    "error": None,
                }

            return {
                "decision": "ALLOW",
                "message": "Result was empty or non-string -- resource would be allowed",
                "opa_available": True,
                "manifest_kind": kind,
                "manifest_name": name,
                "raw_output": opa_output,
                "error": None,
            }
