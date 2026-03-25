# Deny Latest Image Tag
#
# This KAC custom rule prevents containers from using the :latest tag or
# omitting a tag entirely (which implicitly resolves to :latest). Using :latest
# makes deployments non-reproducible and can introduce unexpected changes when
# images are rebuilt and pushed to the registry.
#
# Checks both regular containers and init containers. Detects two conditions:
# 1. Image explicitly tagged as :latest (e.g., "nginx:latest")
# 2. Image with no tag at all (e.g., "nginx") which defaults to :latest
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob
#
# Tested: EKS v1.31, KAC v7.35 - ENFORCED (Prevent mode)
# Deny message: "Container nginx uses latest tag"

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
	msg := sprintf("Container '%s' uses :latest tag - use a specific version tag instead", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not contains(container.image, ":")
	msg := sprintf("Container '%s' image '%s' has no tag - use a specific version tag", [container.name, container.image])
}

result := msg if {
	some container in pod_spec.initContainers
	endswith(container.image, ":latest")
	msg := sprintf("Init container '%s' uses :latest tag - use a specific version tag instead", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not contains(container.image, ":")
	msg := sprintf("Init container '%s' image '%s' has no tag - use a specific version tag", [container.name, container.image])
}
