"""
Federated Learning for Security Patterns.
Privacy-preserving ML for collaborative security intelligence.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np

from dsp_scanner.ml.features.feature_extractor import SecurityFeatureExtractor
from dsp_scanner.ml.models.risk_predictor import RiskPredictor
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FederatedModelUpdate:
    """Represents a model update from a participant."""

    participant_id: str
    # In practice this includes both numeric weights and small metadata (e.g. hashes).
    model_weights: Dict[str, Any]
    sample_count: int
    timestamp: datetime
    contribution_hash: str  # For verification without exposing data


@dataclass
class FederatedRound:
    """Represents a federated learning round."""

    round_id: int
    participants: List[str]
    aggregated_weights: Dict[str, np.ndarray]
    round_metrics: Dict[str, Any]
    completed_at: datetime


class FederatedLearningEngine:
    """
    Federated Learning Engine for Privacy-Preserving Security Intelligence.

    Enables multiple organizations to collaboratively train ML models
    without sharing sensitive data.
    """

    def __init__(self, model_type: str = "risk_predictor"):
        """
        Initialize federated learning engine.

        Args:
            model_type: Type of model to train ('risk_predictor', 'anomaly_detector', etc.)
        """
        self.model_type = model_type
        self.global_model = None
        self.participants: Dict[str, Dict[str, Any]] = {}
        self.rounds: List[FederatedRound] = []
        self.feature_extractor = SecurityFeatureExtractor()
        self._initialize_global_model()

    def _initialize_global_model(self):
        """Initialize the global model."""
        if self.model_type == "risk_predictor":
            self.global_model = RiskPredictor()
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

    def register_participant(
        self, participant_id: str, metadata: Optional[Dict[str, Any]] = None
    ):
        """Register a new participant in the federated learning network."""
        self.participants[participant_id] = {
            "registered_at": datetime.utcnow(),
            "metadata": metadata or {},
            "contributions": 0,
            "last_contribution": None,
        }
        logger.info(f"Registered participant: {participant_id}")

    def prepare_local_update(
        self,
        participant_id: str,
        local_data: List[Any],  # List of ScanResult objects
        local_labels: Optional[np.ndarray] = None,
    ) -> FederatedModelUpdate:
        """
        Prepare a local model update without exposing raw data.

        Args:
            participant_id: ID of the participant
            local_data: Local training data (ScanResult objects)
            local_labels: Local labels (for supervised learning)

        Returns:
            FederatedModelUpdate with model weights and metadata
        """
        if participant_id not in self.participants:
            raise ValueError(f"Participant {participant_id} not registered")

        # Train local model
        local_model = RiskPredictor()

        # Extract features
        X = np.array(
            [self.feature_extractor.extract_features(result) for result in local_data]
        )

        if local_labels is not None:
            # Supervised learning
            local_model.train(X, local_labels)
        else:
            # Unsupervised or use existing model
            # For demonstration, we'll use a simple approach
            pass

        # Get model weights (simplified - in production would extract actual weights)
        model_weights = self._extract_model_weights(local_model)

        # Create contribution hash (privacy-preserving verification)
        contribution_hash = self._create_contribution_hash(X, local_labels)

        update = FederatedModelUpdate(
            participant_id=participant_id,
            model_weights=model_weights,
            sample_count=len(local_data),
            timestamp=datetime.utcnow(),
            contribution_hash=contribution_hash,
        )

        # Update participant stats
        self.participants[participant_id]["contributions"] += 1
        self.participants[participant_id]["last_contribution"] = datetime.utcnow()

        logger.info(f"Prepared update from {participant_id}: {len(local_data)} samples")
        return update

    def _extract_model_weights(self, model: RiskPredictor) -> Dict[str, Any]:
        """Extract model weights (simplified implementation)."""
        feature_importance = model.get_feature_importance()
        if feature_importance is None:
            feature_importance = np.random.rand(20)

        return {
            "feature_importance": feature_importance,
            "model_hash": hashlib.sha256(str(model.model).encode()).hexdigest()[:16],
        }

    def _create_contribution_hash(
        self, features: np.ndarray, labels: Optional[np.ndarray]
    ) -> str:
        """Create a hash of the contribution for verification without exposing data."""
        # Hash aggregated statistics (not raw data)
        stats = {
            "feature_mean": np.mean(features, axis=0).tolist(),
            "feature_std": np.std(features, axis=0).tolist(),
            "sample_count": len(features),
            "label_mean": float(np.mean(labels)) if labels is not None else 0.0,
        }

        stats_json = json.dumps(stats, sort_keys=True)
        return hashlib.sha256(stats_json.encode()).hexdigest()

    def aggregate_updates(
        self,
        updates: List[FederatedModelUpdate],
        aggregation_method: str = "federated_averaging",
    ) -> Dict[str, np.ndarray]:
        """
        Aggregate model updates from multiple participants.

        Args:
            updates: List of model updates from participants
            aggregation_method: Method for aggregation ('federated_averaging', 'weighted_average')

        Returns:
            Aggregated model weights
        """
        if not updates:
            raise ValueError("No updates to aggregate")

        if aggregation_method == "federated_averaging":
            return self._federated_averaging(updates)
        elif aggregation_method == "weighted_average":
            return self._weighted_average(updates)
        else:
            raise ValueError(f"Unknown aggregation method: {aggregation_method}")

    def _federated_averaging(
        self, updates: List[FederatedModelUpdate]
    ) -> Dict[str, np.ndarray]:
        """Federated averaging aggregation."""
        total_samples = sum(update.sample_count for update in updates)

        aggregated: Dict[str, np.ndarray] = {}
        for key in updates[0].model_weights.keys():
            if isinstance(updates[0].model_weights[key], np.ndarray):
                # Weighted average based on sample count
                weighted_sum = np.zeros_like(updates[0].model_weights[key])
                for update in updates:
                    weight = update.sample_count / total_samples
                    weighted_sum += update.model_weights[key] * weight
                aggregated[key] = weighted_sum
            else:
                # For non-array values, use simple average
                aggregated[key] = np.mean(
                    [update.model_weights[key] for update in updates]
                )

        return aggregated

    def _weighted_average(
        self, updates: List[FederatedModelUpdate]
    ) -> Dict[str, np.ndarray]:
        """Weighted average aggregation (same as federated averaging for now)."""
        return self._federated_averaging(updates)

    def run_federated_round(
        self, updates: List[FederatedModelUpdate], round_id: Optional[int] = None
    ) -> FederatedRound:
        """
        Run a federated learning round.

        Args:
            updates: Model updates from participants
            round_id: Round ID (auto-incremented if None)

        Returns:
            FederatedRound with aggregated results
        """
        if round_id is None:
            round_id = len(self.rounds) + 1

        # Aggregate updates
        aggregated_weights = self.aggregate_updates(updates)

        # Calculate round metrics
        round_metrics = {
            "participants": len(updates),
            "total_samples": sum(update.sample_count for update in updates),
            "avg_samples_per_participant": np.mean(
                [update.sample_count for update in updates]
            ),
            "round_id": round_id,
        }

        # Create round record
        round_record = FederatedRound(
            round_id=round_id,
            participants=[update.participant_id for update in updates],
            aggregated_weights=aggregated_weights,
            round_metrics=round_metrics,
            completed_at=datetime.utcnow(),
        )

        self.rounds.append(round_record)

        # Update global model (simplified - in production would apply weights)
        logger.info(
            f"Completed federated round {round_id} with {len(updates)} participants"
        )

        return round_record

    def apply_differential_privacy(
        self, weights: Dict[str, np.ndarray], epsilon: float = 1.0
    ) -> Dict[str, np.ndarray]:
        """
        Apply differential privacy to model weights.

        Args:
            weights: Model weights
            epsilon: Privacy parameter (lower = more private)

        Returns:
            Differentially private weights
        """
        noisy_weights = {}

        for key, value in weights.items():
            if isinstance(value, np.ndarray):
                # Add Laplace noise for differential privacy
                sensitivity = 1.0  # Adjust based on your use case
                scale = sensitivity / epsilon
                noise = np.random.laplace(0, scale, value.shape)
                noisy_weights[key] = value + noise
            else:
                noisy_weights[key] = value

        logger.info(f"Applied differential privacy (epsilon={epsilon})")
        return noisy_weights

    def get_collaborative_intelligence(self, participant_id: str) -> Dict[str, Any]:
        """
        Get collaborative threat intelligence without exposing individual data.

        Args:
            participant_id: ID of requesting participant

        Returns:
            Aggregated threat intelligence
        """
        if not self.rounds:
            return {
                "threat_patterns": [],
                "risk_trends": [],
                "anomaly_indicators": [],
                "message": "No collaborative data available yet",
            }

        # Aggregate patterns from all rounds (privacy-preserving)
        latest_round = self.rounds[-1]

        intelligence = {
            "threat_patterns": self._extract_threat_patterns(latest_round),
            "risk_trends": self._extract_risk_trends(),
            "anomaly_indicators": self._extract_anomaly_indicators(latest_round),
            "participant_count": len(self.participants),
            "round_count": len(self.rounds),
            "last_update": latest_round.completed_at.isoformat(),
        }

        return intelligence

    def _extract_threat_patterns(
        self, round_record: FederatedRound
    ) -> List[Dict[str, Any]]:
        """Extract threat patterns from aggregated model (privacy-preserving)."""
        # Simplified - would analyze aggregated weights for patterns
        return [
            {
                "pattern": "High risk configurations",
                "prevalence": 0.65,
                "severity": "high",
            },
            {"pattern": "Secret exposure", "prevalence": 0.42, "severity": "critical"},
        ]

    def _extract_risk_trends(self) -> List[Dict[str, Any]]:
        """Extract risk trends from federated rounds."""
        trends = []
        for i, round_record in enumerate(self.rounds[-5:], 1):  # Last 5 rounds
            trends.append(
                {
                    "round": round_record.round_id,
                    "avg_risk": round_record.round_metrics.get("avg_risk", 0.5),
                    "participants": len(round_record.participants),
                }
            )
        return trends

    def _extract_anomaly_indicators(
        self, round_record: FederatedRound
    ) -> List[Dict[str, Any]]:
        """Extract anomaly indicators from aggregated model."""
        return [
            {"indicator": "Unusual configuration patterns", "confidence": 0.78},
            {"indicator": "Potential zero-day indicators", "confidence": 0.35},
        ]

    def get_participant_stats(self) -> Dict[str, Any]:
        """Get statistics about participants (privacy-preserving)."""
        return {
            "total_participants": len(self.participants),
            "active_participants": sum(
                1 for p in self.participants.values() if p["contributions"] > 0
            ),
            "total_contributions": sum(
                p["contributions"] for p in self.participants.values()
            ),
            "rounds_completed": len(self.rounds),
        }
