#!/usr/bin/env python3
"""
Training script for ML models.
Trains risk prediction, anomaly detection, and zero-day prediction models.
"""
import sys
import os
from pathlib import Path
import numpy as np

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dsp_scanner.ml.ai_engine import AIRiskPredictionEngine
from dsp_scanner.core.results import ScanResult, Finding, Severity

def generate_synthetic_training_data(n_samples: int = 1000):
    """
    Generate synthetic training data for demonstration.
    In production, use real historical scan data.
    
    Args:
        n_samples: Number of training samples to generate
        
    Returns:
        Tuple of (training_data, risk_labels, zero_day_labels)
    """
    training_data = []
    risk_labels = []
    zero_day_labels = []
    
    np.random.seed(42)  # For reproducibility
    
    for i in range(n_samples):
        # Create synthetic scan result
        result = ScanResult()
        
        # Random number of findings
        n_findings = np.random.randint(0, 25)
        
        # Generate risk score (will be used as label)
        base_risk = np.random.uniform(0, 100)
        
        # Determine if this is a zero-day (rare, ~5% of cases)
        is_zero_day = np.random.random() < 0.05
        
        for j in range(n_findings):
            # Severity distribution based on risk level
            if base_risk > 70:
                severity_weights = [0.3, 0.3, 0.2, 0.15, 0.05]  # More critical
            elif base_risk > 40:
                severity_weights = [0.1, 0.2, 0.3, 0.3, 0.1]
            else:
                severity_weights = [0.05, 0.1, 0.2, 0.3, 0.35]  # More low/info
            
            severity = np.random.choice(
                ['critical', 'high', 'medium', 'low', 'info'],
                p=severity_weights
            )
            
            finding = Finding(
                id=f"finding_{i}_{j}",
                title=f"Security Issue {j}",
                description=f"Description of {severity} security issue {j}",
                severity=Severity(severity),
                location=f"file_{j}.yaml",
                platform=np.random.choice(['kubernetes', 'docker', 'terraform', 'helm']),
                code_snippet=f"code snippet {j}" * np.random.randint(10, 100) if np.random.random() > 0.3 else None,
                cvss_score=np.random.uniform(0, 10) if np.random.random() > 0.5 else None
            )
            
            # Add tags based on finding type
            if 'secret' in finding.description.lower() or 'password' in finding.description.lower():
                finding.tags.append('secret')
            if 'vulnerability' in finding.description.lower() or 'cve' in finding.description.lower():
                finding.tags.append('vulnerability')
            if 'compliance' in finding.description.lower():
                finding.tags.append('compliance')
            
            result.findings.append(finding)
        
        # Adjust risk based on findings
        severity_weights = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 2,
            'info': 1
        }
        calculated_risk = sum(
            severity_weights.get(f.severity.value, 0)
            for f in result.findings
        )
        
        # Add some noise and cap at 100
        final_risk = min(calculated_risk + np.random.uniform(-5, 5), 100)
        final_risk = max(0, final_risk)
        
        training_data.append(result)
        risk_labels.append(final_risk)
        zero_day_labels.append(1 if is_zero_day else 0)
    
    return training_data, np.array(risk_labels), np.array(zero_day_labels)

def main():
    """Main training function."""
    print("🚀 Training ML models for security risk prediction...")
    print("=" * 60)
    
    # Generate or load training data
    print("\n📊 Generating training data...")
    training_data, risk_labels, zero_day_labels = generate_synthetic_training_data(n_samples=1000)
    print(f"✅ Generated {len(training_data)} training samples")
    print(f"   - Risk scores range: {risk_labels.min():.1f} to {risk_labels.max():.1f}")
    print(f"   - Zero-day samples: {zero_day_labels.sum()} ({zero_day_labels.sum()/len(zero_day_labels)*100:.1f}%)")
    
    # Initialize AI engine
    print("\n🤖 Initializing AI engine...")
    ai_engine = AIRiskPredictionEngine(
        enable_risk_prediction=True,
        enable_anomaly_detection=True,
        enable_zero_day_prediction=True
    )
    
    # Train models
    print("\n🎓 Training models...")
    print("-" * 60)
    
    try:
        ai_engine.train_models(
            training_data=training_data,
            risk_labels=risk_labels,
            zero_day_labels=zero_day_labels
        )
        
        print("\n✅ Training complete!")
        print(f"📁 Models saved to models/")
        print("\n📊 Model Summary:")
        print("   - Risk Predictor: Trained")
        print("   - Anomaly Detector: Trained")
        print("   - Zero-Day Predictor: Trained")
        
    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())

