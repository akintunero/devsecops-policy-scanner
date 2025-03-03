package dsp_scanner.docker

# Check for privileged containers
deny[msg] {
    input.type == "Dockerfile"
    contains(input.content, "privileged")
    msg = {
        "title": "Privileged Container Detected",
        "description": "Container is running in privileged mode which gives extended privileges to the container",
        "severity": "HIGH",
        "platform": "docker",
        "recommendation": "Avoid using privileged mode unless absolutely necessary"
    }
}

# Check for root user
deny[msg] {
    input.type == "Dockerfile"
    not contains(input.content, "USER")
    msg = {
        "title": "Container Running as Root",
        "description": "No USER instruction found. Container may run as root by default",
        "severity": "MEDIUM",
        "platform": "docker",
        "recommendation": "Add USER instruction to run container as non-root user"
    }
}
