# Enforce Container Resource Limits
#
# This KAC custom rule requires all containers to define CPU and memory limits.
# Without resource limits, a single container can consume all available node
# resources, causing resource starvation for other workloads and potentially
# impacting cluster stability.
#
# Checks both regular containers and init containers.
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob

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
	msg := sprintf("Container '%s' must define CPU limits in resources.limits.cpu", [container.name])
}

result := msg if {
	some container in pod_spec.containers
	not container.resources.limits.memory
	msg := sprintf("Container '%s' must define memory limits in resources.limits.memory", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not container.resources.limits.cpu
	msg := sprintf("Init container '%s' must define CPU limits in resources.limits.cpu", [container.name])
}

result := msg if {
	some container in pod_spec.initContainers
	not container.resources.limits.memory
	msg := sprintf("Init container '%s' must define memory limits in resources.limits.memory", [container.name])
}
