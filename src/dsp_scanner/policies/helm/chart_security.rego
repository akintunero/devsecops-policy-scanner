package dsp_scanner.helm

# Check for latest tag usage in container images
deny[msg] {
    template := input.templates[_]
    container := template.spec.containers[_]
    endswith(container.image, ":latest")
    msg = {
        "title": "Latest Tag Usage",
        "description": sprintf("Container '%v' uses the :latest tag", [container.name]),
        "severity": "MEDIUM",
        "platform": "helm",
        "recommendation": "Use specific version tags for container images",
        "code_snippet": sprintf("containers:\n- name: %v\n  image: %v", [container.name, container.image])
    }
}

# Check for missing resource limits
deny[msg] {
    template := input.templates[_]
    container := template.spec.containers[_]
    not container.resources.limits
    msg = {
        "title": "Missing Resource Limits",
        "description": sprintf("Container '%v' does not have resource limits defined", [container.name]),
        "severity": "MEDIUM",
        "platform": "helm",
        "recommendation": "Set resource limits to prevent resource exhaustion",
        "code_snippet": sprintf("containers:\n- name: %v\n  # Missing resources.limits", [container.name])
    }
}

# Check for sensitive data in values
deny[msg] {
    sensitive_keys := ["password", "secret", "key", "token", "credential"]
    value_key := input.values[key]
    contains(lower(key), sensitive_keys[_])
    msg = {
        "title": "Sensitive Data in Values",
        "description": sprintf("Values file contains sensitive data key: %v", [key]),
        "severity": "HIGH",
        "platform": "helm",
        "recommendation": "Use Kubernetes secrets for sensitive data storage",
        "code_snippet": sprintf("values.yaml:\n%v: <sensitive-value>", [key])
    }
}

# Check for potential template injection
deny[msg] {
    template := input.templates[_]
    contains(template, "{{")
    not contains(template, "{{ .Quote ")
    not contains(template, "{{ .quote ")
    msg = {
        "title": "Potential Template Injection",
        "description": "Template contains unquoted variables that could lead to injection",
        "severity": "HIGH",
        "platform": "helm",
        "recommendation": "Use the Quote or quote function for template variables",
        "code_snippet": "# Use:\n{{ .Values.someValue | quote }}\n# Instead of:\n{{ .Values.someValue }}"
    }
}

# Check for deprecated API versions
deny[msg] {
    api_version := input.metadata.apiVersion
    api_version == "v1"
    msg = {
        "title": "Deprecated Helm API Version",
        "description": "Chart uses deprecated API version v1",
        "severity": "MEDIUM",
        "platform": "helm",
        "recommendation": "Update to apiVersion: v2",
        "code_snippet": "apiVersion: v1  # Update to v2"
    }
}

# Check for missing maintainers
deny[msg] {
    not input.metadata.maintainers
    msg = {
        "title": "Missing Maintainers",
        "description": "Chart does not specify maintainers",
        "severity": "LOW",
        "platform": "helm",
        "recommendation": "Add maintainers section for better accountability",
        "code_snippet": "maintainers:\n- name: maintainer-name\n  email: maintainer@example.com"
    }
}

# Check for privileged containers
deny[msg] {
    template := input.templates[_]
    container := template.spec.containers[_]
    container.securityContext.privileged == true
    msg = {
        "title": "Privileged Container",
        "description": sprintf("Container '%v' is running in privileged mode", [container.name]),
        "severity": "HIGH",
        "platform": "helm",
        "recommendation": "Avoid running containers in privileged mode",
        "code_snippet": sprintf("containers:\n- name: %v\n  securityContext:\n    privileged: true", [container.name])
    }
}

# Check for host path volumes
deny[msg] {
    template := input.templates[_]
    volume := template.spec.volumes[_]
    volume.hostPath
    msg = {
        "title": "Host Path Volume Mount",
        "description": sprintf("Volume '%v' mounts from host filesystem", [volume.name]),
        "severity": "HIGH",
        "platform": "helm",
        "recommendation": "Avoid using hostPath volumes for better security isolation",
        "code_snippet": sprintf("volumes:\n- name: %v\n  hostPath:\n    path: %v", [volume.name, volume.hostPath.path])
    }
}

# Check for missing security context
deny[msg] {
    template := input.templates[_]
    template.kind == "Deployment"
    not template.spec.template.spec.securityContext
    msg = {
        "title": "Missing Pod Security Context",
        "description": "Deployment does not specify pod security context",
        "severity": "MEDIUM",
        "platform": "helm",
        "recommendation": "Add security context with appropriate settings",
        "code_snippet": "spec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true"
    }
}

# Check for unsafe capabilities
deny[msg] {
    template := input.templates[_]
    container := template.spec.containers[_]
    cap := container.securityContext.capabilities.add[_]
    unsafe_caps := ["ALL", "SYS_ADMIN", "NET_ADMIN"]
    cap == unsafe_caps[_]
    msg = {
        "title": "Unsafe Capability Added",
        "description": sprintf("Container '%v' adds unsafe capability: %v", [container.name, cap]),
        "severity": "HIGH",
        "platform": "helm",
        "recommendation": sprintf("Remove %v capability or justify its usage", [cap]),
        "code_snippet": sprintf("securityContext:\n  capabilities:\n    add: [%v]", [cap])
    }
}

# Check for default namespace usage
deny[msg] {
    template := input.templates[_]
    template.metadata.namespace == "default"
    msg = {
        "title": "Default Namespace Usage",
        "description": "Resource is deployed in default namespace",
        "severity": "LOW",
        "platform": "helm",
        "recommendation": "Use explicit namespaces to organize and secure resources",
        "code_snippet": "metadata:\n  namespace: default  # Specify a proper namespace"
    }
}

# Check for missing health checks
deny[msg] {
    template := input.templates[_]
    template.kind == "Deployment"
    container := template.spec.template.spec.containers[_]
    not container.livenessProbe
    not container.readinessProbe
    msg = {
        "title": "Missing Health Checks",
        "description": sprintf("Container '%v' is missing health checks", [container.name]),
        "severity": "MEDIUM",
        "platform": "helm",
        "recommendation": "Add liveness and readiness probes",
        "code_snippet": "containers:\n- name: app\n  livenessProbe:\n    httpGet:\n      path: /health\n      port: 8080"
    }
}
