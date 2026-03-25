# Block hostPath Volumes
#
# This KAC custom rule prevents pods from mounting hostPath volumes, which
# give containers direct access to the host filesystem. An attacker with
# hostPath access can read sensitive files (/etc/shadow, kubelet credentials),
# modify host binaries, or escape the container entirely.
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob
#
# Tested: EKS v1.31, KAC v7.35 - ENFORCED (Prevent mode)
# Deny message: "Volume host-etc uses hostPath - not allowed"

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
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf("Volume '%s' uses hostPath '%s' - not allowed", [volume.name, volume.hostPath.path])
}
