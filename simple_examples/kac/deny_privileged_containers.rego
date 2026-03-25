# Deny Privileged Containers
#
# This KAC custom rule prevents any container from running in privileged mode.
# Privileged containers have full access to the host's devices and kernel
# capabilities, making them a critical security risk. This rule checks both
# regular containers and init containers across all supported workload types.
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob
#
# Tested: EKS v1.31, KAC v7.35 - ENFORCED (Prevent mode)
# Deny message: "Container nginx must not run in privileged mode"

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
