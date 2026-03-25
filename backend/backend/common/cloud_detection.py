def determine_cloud_provider(resource_type: str) -> dict:
    """Determine cloud provider and platform from resource type string."""
    if not resource_type:
        return {"platform": "AWS", "provider": "AWS"}

    if "googleapis.com" in resource_type.lower():
        return {"platform": "GCP", "provider": "GCP"}
    if resource_type.startswith("AWS::"):
        return {"platform": "AWS", "provider": "AWS"}
    if resource_type.startswith("Microsoft."):
        return {"platform": "Azure", "provider": "Azure"}
    if "kubernetes" in resource_type.lower():
        return {"platform": "Kubernetes", "provider": "Kubernetes"}

    return {"platform": "AWS", "provider": "AWS"}


def get_cloud_provider_param(resource_type: str) -> str:
    """Get the lowercase cloud_provider query param value for evaluation endpoints."""
    if resource_type.startswith("AWS::"):
        return "aws"
    if resource_type.startswith("Microsoft."):
        return "azure"
    if "googleapis.com" in resource_type.lower():
        return "gcp"
    return "aws"
