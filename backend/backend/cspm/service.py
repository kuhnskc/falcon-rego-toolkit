from typing import Optional

from backend.common.crowdstrike_client import CrowdStrikeClient
from backend.common.cloud_detection import determine_cloud_provider, get_cloud_provider_param


class CspmService:
    """CrowdStrike CSPM IOM API operations."""

    def __init__(self, client: CrowdStrikeClient):
        self.client = client

    # ── List policies ───────────────────────────────────────────────

    def list_policies(self) -> list[dict]:
        resp = self.client.get(
            "/cloud-policies/queries/rules/v1",
            params={"filter": "rule_origin:'Custom'", "limit": 500},
        )
        if resp.status_code != 200:
            # Fallback without filter
            resp = self.client.get(
                "/cloud-policies/queries/rules/v1",
                params={"limit": 500},
            )

        rule_ids = resp.json().get("resources", [])
        if not rule_ids:
            return []

        all_rules: list[dict] = []
        for i in range(0, len(rule_ids), 50):
            batch = rule_ids[i : i + 50]
            detail = self.client.get(
                "/cloud-policies/entities/rules/v1",
                params={"ids": batch},
            )
            if detail.status_code == 200:
                all_rules.extend(detail.json().get("resources", []))

        return all_rules

    # ── Create policy ───────────────────────────────────────────────

    def create_policy(
        self,
        name: str,
        description: str,
        logic: str,
        resource_type: str,
        severity: int,
        alert_info: str,
        remediation_info: str = "",
    ) -> dict:
        cloud = determine_cloud_provider(resource_type)
        payload = {
            "name": name,
            "description": description,
            "logic": logic,
            "resource_type": resource_type,
            "severity": severity,
            "platform": cloud["platform"],
            "provider": cloud["provider"],
            "domain": "CSPM",
            "subdomain": "IOM",
            "alert_info": alert_info,
            "attack_types": "Misconfiguration",
        }
        if remediation_info:
            payload["remediation_info"] = remediation_info

        resp = self.client.post("/cloud-policies/entities/rules/v1", json=payload)
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Update policy ───────────────────────────────────────────────

    def update_policy(self, uuid: str, updates: dict) -> dict:
        payload = {"uuid": uuid}
        payload.update(updates)
        resp = self.client.patch("/cloud-policies/entities/rules/v1", json=payload)
        data = resp.json()
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": data}
        return data

    # ── Delete policy ───────────────────────────────────────────────

    def delete_policy(self, uuid: str) -> dict:
        resp = self.client.delete(
            "/cloud-policies/entities/rules/v1",
            params={"ids": [uuid]},
        )
        if resp.status_code != 200:
            return {"error": True, "status_code": resp.status_code, "detail": resp.json()}
        return {"deleted": True, "uuid": uuid}

    # ── Test / evaluate policy ──────────────────────────────────────

    def test_policy(self, logic: str, resource_type: str, num_assets: int = 3) -> dict:
        # Step 1: discover active assets
        discover_resp = self.client.get(
            "/cloud-security-assets/queries/resources/v1",
            params={"filter": f"resource_type:'{resource_type}'", "limit": 10},
        )
        asset_ids = []
        if discover_resp.status_code == 200:
            asset_ids = discover_resp.json().get("resources", [])[:num_assets]

        if not asset_ids:
            return {
                "total_assets": 0,
                "resource_type": resource_type,
                "test_results": [],
                "pass_count": 0,
                "fail_count": 0,
                "error_count": 0,
                "summary": f"No active {resource_type} assets found for testing.",
            }

        cloud_provider = get_cloud_provider_param(resource_type)
        test_results = []

        for asset_id in asset_ids:
            tenant_id = asset_id.split("|")[0]

            # Get enriched data
            enriched_resp = self.client.get(
                "/cloud-policies/entities/enriched-resources/v1",
                params={"ids": [asset_id]},
                extra_headers={"X-CS-CUSTID": tenant_id},
            )
            if enriched_resp.status_code != 200:
                test_results.append({"asset_id": asset_id, "result": "error", "error": f"Enriched data fetch failed: {enriched_resp.status_code}"})
                continue

            resources = enriched_resp.json().get("resources", [])
            if not resources:
                test_results.append({"asset_id": asset_id, "result": "error", "error": "No enriched data returned"})
                continue

            asset_data = resources[0]

            # Evaluate
            eval_resp = self.client.post(
                "/cloud-policies/entities/evaluation/v1",
                params={
                    "cloud_provider": cloud_provider,
                    "resource_type": resource_type,
                    "ids": asset_id,
                },
                json={"logic": logic},
                extra_headers={"X-CS-CUSTID": tenant_id},
            )
            if eval_resp.status_code == 200:
                eval_resources = eval_resp.json().get("resources", [])
                if eval_resources:
                    r = eval_resources[0]
                    test_results.append({
                        "asset_id": asset_id,
                        "result": r.get("result", "unknown"),
                        "details": r.get("details", {}),
                    })
                else:
                    test_results.append({"asset_id": asset_id, "result": "error", "error": "No evaluation results"})
            else:
                test_results.append({"asset_id": asset_id, "result": "error", "error": f"Evaluation failed: {eval_resp.status_code}"})

        pass_count = sum(1 for r in test_results if r.get("result") == "pass")
        fail_count = sum(1 for r in test_results if r.get("result") == "fail")
        error_count = sum(1 for r in test_results if r.get("result") == "error")

        return {
            "total_assets": len(test_results),
            "resource_type": resource_type,
            "test_results": test_results,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "error_count": error_count,
            "summary": f"Tested against {len(test_results)} assets: {pass_count} pass, {fail_count} fail, {error_count} errors",
        }

    # ── Sample asset data ───────────────────────────────────────────

    def get_sample_asset(self, resource_type: str) -> Optional[dict]:
        discover_resp = self.client.get(
            "/cloud-security-assets/queries/resources/v1",
            params={"filter": f"resource_type:'{resource_type}'", "limit": 5},
        )
        if discover_resp.status_code != 200:
            return None

        resource_ids = discover_resp.json().get("resources", [])
        if not resource_ids:
            return None

        for resource_id in resource_ids[:3]:
            tenant_id = resource_id.split("|")[0]
            enriched_resp = self.client.get(
                "/cloud-policies/entities/enriched-resources/v1",
                params={"ids": [resource_id]},
                extra_headers={"X-CS-CUSTID": tenant_id},
            )
            if enriched_resp.status_code == 200:
                resources = enriched_resp.json().get("resources", [])
                if resources:
                    return resources[0]

        return None

    # ── Discover resource types ─────────────────────────────────────

    def discover_resource_types(self) -> list[str]:
        resp = self.client.get(
            "/cloud-security-assets/queries/resources/v1",
            params={"limit": 500},
        )
        if resp.status_code != 200:
            return []

        resource_ids = resp.json().get("resources", [])
        types = set()
        for rid in resource_ids:
            parts = rid.split("|")
            if len(parts) >= 2:
                types.add(parts[1])

        return sorted(types)

    # ── Input schema ────────────────────────────────────────────────

    def get_input_schema(self, resource_type: str) -> Optional[dict]:
        cloud_provider = get_cloud_provider_param(resource_type)
        resp = self.client.get(
            "/cloud-policies/combined/rules/input-schema/v1",
            params={
                "domain": "CSPM",
                "subdomain": "IOM",
                "cloud_provider": cloud_provider,
                "resource_type": resource_type,
            },
        )
        if resp.status_code == 200:
            return resp.json()
        return None
