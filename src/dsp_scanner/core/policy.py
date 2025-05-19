"""
Core policy module for managing and evaluating security policies using OPA.
"""

import json
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import asyncio
import opa_python

from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class Policy:
    """
    Represents a security policy that can be evaluated against infrastructure code.
    Supports both built-in and custom policies using Open Policy Agent (OPA).
    """

    def __init__(
        self,
        name: str,
        description: str,
        platform: str,
        rego_policy: str,
        severity: str = "medium",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize a new policy.

        Args:
            name: Unique name of the policy
            description: Detailed description of what the policy checks
            platform: Target platform (docker, kubernetes, terraform, helm)
            rego_policy: OPA Rego policy code
            severity: Policy violation severity level
            tags: List of tags for categorizing the policy
            metadata: Additional metadata for the policy
        """
        self.name = name
        self.description = description
        self.platform = platform
        self.rego_policy = rego_policy
        self.severity = severity
        self.tags = tags or []
        self.metadata = metadata or {}
        
        # Validate and compile the Rego policy
        self._validate_policy()

    def _validate_policy(self) -> None:
        """Validate the Rego policy syntax and compilation."""
        try:
            opa_python.compile_str(self.rego_policy)
        except Exception as e:
            raise ValueError(f"Invalid Rego policy: {str(e)}")

    async def evaluate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate the policy against the provided input data.

        Args:
            input_data: Data to evaluate the policy against

        Returns:
            Dictionary containing evaluation results
        """
        try:
            # Create OPA instance with the policy
            opa = opa_python.OPA()
            opa.add_policy(self.name, self.rego_policy)

            # Evaluate policy
            result = await asyncio.to_thread(
                opa.evaluate,
                self.name,
                input_data
            )

            return self._process_evaluation_result(result)

        except Exception as e:
            logger.error(f"Policy evaluation failed: {str(e)}")
            raise PolicyEvaluationError(f"Failed to evaluate policy {self.name}: {str(e)}")

    def _process_evaluation_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Process and format the policy evaluation result."""
        return {
            "policy_name": self.name,
            "platform": self.platform,
            "severity": self.severity,
            "violations": result.get("violations", []),
            "passed": not bool(result.get("violations", [])),
            "metadata": {
                "description": self.description,
                "tags": self.tags,
                **self.metadata
            }
        }

class PolicySet:
    """
    A collection of related policies that can be evaluated together.
    """

    def __init__(
        self,
        name: str,
        description: str,
        policies: Optional[List[Policy]] = None
    ):
        """
        Initialize a new policy set.

        Args:
            name: Name of the policy set
            description: Description of the policy set
            policies: List of policies in the set
        """
        self.name = name
        self.description = description
        self.policies = policies or []

    async def evaluate_all(
        self,
        input_data: Dict[str, Any],
        platform: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all policies in the set against the input data.

        Args:
            input_data: Data to evaluate policies against
            platform: Optional platform filter

        Returns:
            List of evaluation results
        """
        results = []
        for policy in self.policies:
            if platform and policy.platform != platform:
                continue
            try:
                result = await policy.evaluate(input_data)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to evaluate policy {policy.name}: {str(e)}")
                results.append({
                    "policy_name": policy.name,
                    "platform": policy.platform,
                    "error": str(e),
                    "passed": False
                })
        return results

class PolicyManager:
    """
    Manages policy loading, validation, and evaluation across the application.
    """

    def __init__(self):
        """Initialize the policy manager."""
        self.policy_sets: Dict[str, PolicySet] = {}
        self.custom_policies: Dict[str, Policy] = {}

    async def load_builtin_policies(self) -> None:
        """Load built-in policies from the policies directory."""
        policy_dir = Path(__file__).parent.parent / "policies"
        
        for platform_dir in policy_dir.iterdir():
            if not platform_dir.is_dir():
                continue

            for policy_file in platform_dir.glob("*.rego"):
                try:
                    policy_data = self._load_policy_metadata(policy_file)
                    policy = Policy(
                        name=policy_data["name"],
                        description=policy_data["description"],
                        platform=platform_dir.name,
                        rego_policy=policy_file.read_text(),
                        severity=policy_data.get("severity", "medium"),
                        tags=policy_data.get("tags", []),
                        metadata=policy_data.get("metadata", {})
                    )
                    
                    # Add to appropriate policy set
                    set_name = policy_data.get("set", "default")
                    if set_name not in self.policy_sets:
                        self.policy_sets[set_name] = PolicySet(
                            name=set_name,
                            description=f"Policy set for {set_name}"
                        )
                    self.policy_sets[set_name].policies.append(policy)
                    
                except Exception as e:
                    logger.error(f"Failed to load policy {policy_file}: {str(e)}")

    def _load_policy_metadata(self, policy_file: Path) -> Dict[str, Any]:
        """Load policy metadata from accompanying JSON file."""
        metadata_file = policy_file.with_suffix(".json")
        if not metadata_file.exists():
            raise ValueError(f"Missing metadata file for policy: {policy_file}")
        
        with metadata_file.open() as f:
            return json.load(f)

    def add_custom_policy(self, policy: Policy) -> None:
        """Add a custom policy."""
        self.custom_policies[policy.name] = policy

    def get_policy_set(self, name: str) -> Optional[PolicySet]:
        """Get a policy set by name."""
        return self.policy_sets.get(name)

    def get_custom_policy(self, name: str) -> Optional[Policy]:
        """Get a custom policy by name."""
        return self.custom_policies.get(name)

    async def evaluate_policies(
        self,
        input_data: Dict[str, Any],
        policy_sets: Optional[List[str]] = None,
        platform: Optional[str] = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Evaluate specified policy sets against input data.

        Args:
            input_data: Data to evaluate policies against
            policy_sets: List of policy set names to evaluate
            platform: Optional platform filter

        Returns:
            Dictionary mapping policy set names to their evaluation results
        """
        results = {}
        
        # If no specific sets specified, evaluate all
        sets_to_evaluate = (
            [self.policy_sets[name] for name in (policy_sets or [])]
            or list(self.policy_sets.values())
        )
        
        for policy_set in sets_to_evaluate:
            results[policy_set.name] = await policy_set.evaluate_all(
                input_data,
                platform
            )
            
        # Also evaluate any custom policies
        if self.custom_policies:
            custom_results = []
            for policy in self.custom_policies.values():
                if platform and policy.platform != platform:
                    continue
                try:
                    result = await policy.evaluate(input_data)
                    custom_results.append(result)
                except Exception as e:
                    logger.error(f"Failed to evaluate custom policy {policy.name}: {str(e)}")
                    custom_results.append({
                        "policy_name": policy.name,
                        "platform": policy.platform,
                        "error": str(e),
                        "passed": False
                    })
            results["custom"] = custom_results
            
        return results

class PolicyEvaluationError(Exception):
    """Raised when policy evaluation fails."""
    pass
