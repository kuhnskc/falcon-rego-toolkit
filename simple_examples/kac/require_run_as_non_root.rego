# Require runAsNonRoot
#
# This KAC custom rule enforces that all containers explicitly set
# runAsNonRoot: true in their security context. Running containers as root
# (UID 0) increases the blast radius of container escapes and allows
# modification of sensitive files within the container filesystem.
#
# Uses a set comprehension to collect non-compliant container names, then
# checks if the pod-level setting is also missing. This avoids the Regal
# "non-loop-expression" lint error that occurs when mixing loop variables
# with non-loop conditions.
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob
#
# Tested: EKS v1.31, KAC v7.35 - ENFORCED (Prevent mode)
# Deny message: "Containers must set runAsNonRoot to true - nginx"

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
