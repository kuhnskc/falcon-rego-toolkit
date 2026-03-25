# Deny Host Namespaces (hostNetwork, hostPID, hostIPC)
#
# This KAC custom rule prevents pods from sharing the host's network, PID,
# or IPC namespaces. Enabling any of these gives a container visibility into
# host processes and network traffic, which can be exploited for lateral
# movement, data exfiltration, or privilege escalation.
#
# NOTE: hostNetwork=true causes the K8s admission webhook to be bypassed
# entirely (the pod never reaches the webhook). hostPID and hostIPC are
# enforceable. hostNetwork can only be detected in Alert (warning) mode.
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob
#
# Tested: EKS v1.31, KAC v7.35 - ENFORCED (hostPID/hostIPC in Prevent mode)
# Deny message: "Pod must not use hostPID"

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

result := "Pod must not use hostNetwork" if {
	pod_spec.hostNetwork == true
}

result := "Pod must not use hostPID" if {
	pod_spec.hostPID == true
}

result := "Pod must not use hostIPC" if {
	pod_spec.hostIPC == true
}
