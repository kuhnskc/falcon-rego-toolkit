# Require Approved Image Registry
#
# This KAC custom rule ensures all container images come from the organization's
# approved container registry. Prevents use of untrusted public images that may
# contain vulnerabilities, malware, or supply chain compromises.
#
# To use: Change the approved_registry value below to your organization's
# registry prefix (e.g., your ECR, GCR, ACR, or private registry URL).
#
# Applies to: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet,
#             ReplicationController, Job, CronJob

package customrule

import rego.v1

approved_registry := "123456789012.dkr.ecr.us-east-1.amazonaws.com/"

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
	not startswith(container.image, approved_registry)
	msg := sprintf("Container '%s' uses unapproved image '%s' - only images from '%s' are allowed", [container.name, container.image, approved_registry])
}

result := msg if {
	some container in pod_spec.initContainers
	not startswith(container.image, approved_registry)
	msg := sprintf("Init container '%s' uses unapproved image '%s' - only images from '%s' are allowed", [container.name, container.image, approved_registry])
}
