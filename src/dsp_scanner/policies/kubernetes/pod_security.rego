package dsp_scanner.kubernetes

# Check for privileged pods
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg = {
        "title": "Privileged Pod Detected",
        "description": sprintf("Container '%v' is running in privileged mode", [container.name]),
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": "Remove privileged security context or justify its usage",
        "code_snippet": sprintf("securityContext:\n  privileged: true # in container '%v'", [container.name])
    }
}

# Check for hostPath volumes
deny[msg] {
    input.kind == "Pod"
    volume := input.spec.volumes[_]
    volume.hostPath
    msg = {
        "title": "Host Path Volume Mount Detected",
        "description": sprintf("Volume '%v' mounts from host filesystem", [volume.name]),
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": "Avoid using hostPath volumes as they can lead to container breakout",
        "code_snippet": sprintf("volumes:\n- name: %v\n  hostPath:\n    path: %v", [volume.name, volume.hostPath.path])
    }
}

# Check for containers running as root
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg = {
        "title": "Container Running as Root",
        "description": sprintf("Container '%v' may run as root user", [container.name]),
        "severity": "MEDIUM",
        "platform": "kubernetes",
        "recommendation": "Set runAsNonRoot: true in container's securityContext",
        "code_snippet": sprintf("containers:\n- name: %v\n  # Missing securityContext.runAsNonRoot", [container.name])
    }
}

# Check for containers without resource limits
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    not container.resources.limits
    msg = {
        "title": "Missing Resource Limits",
        "description": sprintf("Container '%v' does not have resource limits defined", [container.name]),
        "severity": "MEDIUM",
        "platform": "kubernetes",
        "recommendation": "Set resource limits to prevent resource exhaustion",
        "code_snippet": sprintf("containers:\n- name: %v\n  # Missing resources.limits", [container.name])
    }
}

# Check for containers with hostNetwork
deny[msg] {
    input.kind == "Pod"
    input.spec.hostNetwork == true
    msg = {
        "title": "Host Network Access Enabled",
        "description": "Pod has access to host network interfaces",
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": "Disable hostNetwork unless absolutely necessary",
        "code_snippet": "spec:\n  hostNetwork: true"
    }
}

# Check for containers with hostPID or hostIPC
deny[msg] {
    input.kind == "Pod"
    input.spec[field] == true
    field == "hostPID"
    msg = {
        "title": "Host PID Namespace Sharing",
        "description": "Pod shares host's process ID namespace",
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": "Disable hostPID to maintain proper isolation",
        "code_snippet": "spec:\n  hostPID: true"
    }
}

deny[msg] {
    input.kind == "Pod"
    input.spec[field] == true
    field == "hostIPC"
    msg = {
        "title": "Host IPC Namespace Sharing",
        "description": "Pod shares host's IPC namespace",
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": "Disable hostIPC to maintain proper isolation",
        "code_snippet": "spec:\n  hostIPC: true"
    }
}

# Check for unsafe capabilities
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    cap := container.securityContext.capabilities.add[_]
    unsafe_caps := ["ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW"]
    cap == unsafe_caps[_]
    msg = {
        "title": "Unsafe Capability Added",
        "description": sprintf("Container '%v' adds unsafe capability: %v", [container.name, cap]),
        "severity": "HIGH",
        "platform": "kubernetes",
        "recommendation": sprintf("Remove %v capability or justify its usage", [cap]),
        "code_snippet": sprintf("securityContext:\n  capabilities:\n    add: [%v]", [cap])
    }
}

# Check for automounted service account token
deny[msg] {
    input.kind == "Pod"
    input.spec.automountServiceAccountToken == true
    msg = {
        "title": "Automounted Service Account Token",
        "description": "Pod automatically mounts service account token",
        "severity": "MEDIUM",
        "platform": "kubernetes",
        "recommendation": "Disable automountServiceAccountToken unless required",
        "code_snippet": "spec:\n  automountServiceAccountToken: true"
    }
}

# Check for latest tag in container images
deny[msg] {
    input.kind == "Pod"
    container := input.spec.containers[_]
    endswith(container.image, ":latest")
    msg = {
        "title": "Latest Tag Used",
        "description": sprintf("Container '%v' uses the :latest tag", [container.name]),
        "severity": "MEDIUM",
        "platform": "kubernetes",
        "recommendation": "Use specific version tags for container images",
        "code_snippet": sprintf("containers:\n- name: %v\n  image: %v", [container.name, container.image])
    }
}

# Check for containers in default namespace
deny[msg] {
    input.kind == "Pod"
    input.metadata.namespace == "default"
    msg = {
        "title": "Pod in Default Namespace",
        "description": "Pod is deployed in the default namespace",
        "severity": "LOW",
        "platform": "kubernetes",
        "recommendation": "Use explicit namespaces to organize and secure resources",
        "code_snippet": "metadata:\n  namespace: default"
    }
}
