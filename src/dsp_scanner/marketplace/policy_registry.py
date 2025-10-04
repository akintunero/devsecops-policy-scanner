"""
Policy-as-Code Marketplace & Community Hub.
First-of-its-kind marketplace for sharing and versioning security policies.
"""
import json
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import semver

from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

@dataclass
class PolicyVersion:
    """Represents a versioned policy."""
    name: str
    version: str
    author: str
    description: str
    content: Dict[str, Any]
    dependencies: List[str]
    tags: List[str]
    downloads: int = 0
    rating: float = 0.0
    reviews: List[Dict[str, Any]] = None
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.reviews is None:
            self.reviews = []
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data

class PolicyRegistry:
    """
    Policy marketplace registry.
    Manages policy versioning, search, discovery, and community features.
    """
    
    def __init__(self, registry_path: str = "policy_registry"):
        self.registry_path = Path(registry_path)
        self.registry_path.mkdir(exist_ok=True)
        self.policies: Dict[str, Dict[str, PolicyVersion]] = {}  # {name: {version: PolicyVersion}}
        self.index: Dict[str, List[str]] = {}  # {tag: [policy_names]}
        self._load_registry()
    
    def _load_registry(self):
        """Load registry from disk."""
        registry_file = self.registry_path / "registry.json"
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    data = json.load(f)
                    for name, versions in data.items():
                        self.policies[name] = {}
                        for version, policy_data in versions.items():
                            policy = PolicyVersion(**policy_data)
                            policy.created_at = datetime.fromisoformat(policy_data['created_at'])
                            policy.updated_at = datetime.fromisoformat(policy_data['updated_at'])
                            self.policies[name][version] = policy
                
                # Rebuild index
                self._rebuild_index()
                logger.info(f"Loaded {len(self.policies)} policies from registry")
            except Exception as e:
                logger.error(f"Failed to load registry: {e}")
    
    def _save_registry(self):
        """Save registry to disk."""
        registry_file = self.registry_path / "registry.json"
        data = {}
        for name, versions in self.policies.items():
            data[name] = {
                version: policy.to_dict()
                for version, policy in versions.items()
            }
        
        with open(registry_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _rebuild_index(self):
        """Rebuild search index."""
        self.index = {}
        for name, versions in self.policies.items():
            # Get latest version for indexing
            latest = self.get_latest_version(name)
            if latest:
                for tag in latest.tags:
                    if tag not in self.index:
                        self.index[tag] = []
                    if name not in self.index[tag]:
                        self.index[tag].append(name)
    
    def register_policy(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        content: Dict[str, Any],
        dependencies: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> PolicyVersion:
        """Register a new policy version."""
        # Validate version format
        try:
            semver.parse_version_info(version)
        except ValueError:
            raise ValueError(f"Invalid version format: {version}. Use semantic versioning (e.g., 1.0.0)")
        
        # Check if version already exists
        if name in self.policies and version in self.policies[name]:
            raise ValueError(f"Policy {name} version {version} already exists")
        
        # Create policy version
        policy = PolicyVersion(
            name=name,
            version=version,
            author=author,
            description=description,
            content=content,
            dependencies=dependencies or [],
            tags=tags or []
        )
        
        # Store policy
        if name not in self.policies:
            self.policies[name] = {}
        self.policies[name][version] = policy
        
        # Update index
        for tag in policy.tags:
            if tag not in self.index:
                self.index[tag] = []
            if name not in self.index[tag]:
                self.index[tag].append(name)
        
        # Save registry
        self._save_registry()
        
        logger.info(f"Registered policy {name} version {version}")
        return policy
    
    def get_policy(self, name: str, version: Optional[str] = None) -> Optional[PolicyVersion]:
        """Get a specific policy version."""
        if name not in self.policies:
            return None
        
        if version is None:
            return self.get_latest_version(name)
        
        return self.policies[name].get(version)
    
    def get_latest_version(self, name: str) -> Optional[PolicyVersion]:
        """Get latest version of a policy."""
        if name not in self.policies:
            return None
        
        versions = list(self.policies[name].keys())
        if not versions:
            return None
        
        # Sort by semantic version
        try:
            sorted_versions = sorted(versions, key=lambda v: semver.VersionInfo.parse(v), reverse=True)
            return self.policies[name][sorted_versions[0]]
        except Exception:
            # Fallback to string comparison
            return self.policies[name][max(versions)]
    
    def search_policies(
        self,
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        author: Optional[str] = None,
        min_rating: float = 0.0
    ) -> List[PolicyVersion]:
        """Search policies."""
        results = []
        
        for name, versions in self.policies.items():
            latest = self.get_latest_version(name)
            if not latest:
                continue
            
            # Filter by rating
            if latest.rating < min_rating:
                continue
            
            # Filter by author
            if author and latest.author != author:
                continue
            
            # Filter by tags
            if tags and not any(tag in latest.tags for tag in tags):
                continue
            
            # Filter by query
            if query:
                query_lower = query.lower()
                if (query_lower not in latest.name.lower() and
                    query_lower not in latest.description.lower() and
                    not any(query_lower in tag.lower() for tag in latest.tags)):
                    continue
            
            results.append(latest)
        
        # Sort by rating and downloads
        results.sort(key=lambda p: (p.rating, p.downloads), reverse=True)
        return results
    
    def install_policy(self, name: str, version: Optional[str] = None) -> PolicyVersion:
        """Install a policy (increment download count)."""
        policy = self.get_policy(name, version)
        if not policy:
            raise ValueError(f"Policy {name} version {version or 'latest'} not found")
        
        policy.downloads += 1
        policy.updated_at = datetime.utcnow()
        self._save_registry()
        
        logger.info(f"Installed policy {name} version {policy.version}")
        return policy
    
    def rate_policy(self, name: str, version: str, rating: float, review: Optional[str] = None, reviewer: Optional[str] = None):
        """Rate and review a policy."""
        policy = self.get_policy(name, version)
        if not policy:
            raise ValueError(f"Policy {name} version {version} not found")
        
        if not 0.0 <= rating <= 5.0:
            raise ValueError("Rating must be between 0.0 and 5.0")
        
        # Add review
        if review:
            policy.reviews.append({
                'reviewer': reviewer or 'anonymous',
                'rating': rating,
                'review': review,
                'date': datetime.utcnow().isoformat()
            })
        
        # Update average rating
        if policy.reviews:
            policy.rating = sum(r['rating'] for r in policy.reviews) / len(policy.reviews)
        else:
            policy.rating = rating
        
        policy.updated_at = datetime.utcnow()
        self._save_registry()
        
        logger.info(f"Rated policy {name} version {version}: {rating}/5.0")
    
    def get_policy_dependencies(self, name: str, version: Optional[str] = None) -> List[PolicyVersion]:
        """Get all dependencies for a policy."""
        policy = self.get_policy(name, version)
        if not policy:
            return []
        
        dependencies = []
        for dep in policy.dependencies:
            # Parse dependency (format: "name@version" or "name")
            if '@' in dep:
                dep_name, dep_version = dep.split('@', 1)
            else:
                dep_name = dep
                dep_version = None
            
            dep_policy = self.get_policy(dep_name, dep_version)
            if dep_policy:
                dependencies.append(dep_policy)
                # Recursively get dependencies
                dependencies.extend(self.get_policy_dependencies(dep_name, dep_policy.version))
        
        return dependencies
    
    def list_policies(self) -> List[PolicyVersion]:
        """List all policies (latest versions)."""
        return [self.get_latest_version(name) for name in self.policies.keys()]

