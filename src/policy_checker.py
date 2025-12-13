import os

import yaml


class PolicyChecker:
    def __init__(self, policy_dir="policies/"):
        self.policy_dir = policy_dir
        self.policies = self.load_policies()

    def load_policies(self):
        policies = []
        for filename in os.listdir(self.policy_dir):
            if filename.endswith(".yaml"):
                with open(os.path.join(self.policy_dir, filename), "r") as file:
                    data = yaml.safe_load(file)
                    if isinstance(data, list):  # Ensure it's a list of policies
                        policies.extend(data)
        return policies

    def scan(self, repo_config):
        violations = []
        for policy in self.policies:  # Iterate over list of dictionaries
            if (
                policy["key"] in repo_config
                and repo_config[policy["key"]] != policy["value"]
            ):
                violations.append(f"Violation: {policy['description']}")
        return violations if violations else ["✅ All security policies passed!"]


if __name__ == "__main__":
    sample_config = {
        "enforce_2fa": False,
        "secret_in_code": True,
        "branch_protection": True,
    }
    checker = PolicyChecker()
    print("\n".join(checker.scan(sample_config)))
