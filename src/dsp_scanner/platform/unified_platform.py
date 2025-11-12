"""
Unified Platform integrating all advanced features:
1. Real-Time Continuous Security Monitoring
2. Policy-as-Code Marketplace
3. Advanced Compliance Automation
4. Federated Learning for Security Patterns
"""
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from dsp_scanner.monitoring.realtime_monitor import RealTimeMonitor, MonitoringEvent, EventType
from dsp_scanner.marketplace.policy_registry import PolicyRegistry, PolicyVersion
from dsp_scanner.compliance.automation import ComplianceAutomation, ComplianceFramework, ComplianceReport
from dsp_scanner.federated_learning.federated_engine import FederatedLearningEngine, FederatedModelUpdate
from dsp_scanner.core.results import ScanResult
from dsp_scanner.core.scanner import Scanner
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class UnifiedSecurityPlatform:
    """
    Unified platform integrating all advanced security features.
    
    Features:
    1. Real-Time Continuous Security Monitoring
    2. Policy-as-Code Marketplace & Community Hub
    3. Advanced Compliance Automation
    4. Federated Learning for Security Patterns
    
    This platform orchestrates all components to provide a comprehensive
    security scanning and compliance solution with real-time monitoring,
    policy management, and collaborative intelligence.
    """
    
    def __init__(
        self,
        enable_monitoring: bool = True,
        enable_marketplace: bool = True,
        enable_compliance: bool = True,
        enable_federated_learning: bool = True
    ):
        """
        Initialize unified platform.
        
        Args:
            enable_monitoring: Enable real-time monitoring features
            enable_marketplace: Enable policy marketplace features
            enable_compliance: Enable compliance automation features
            enable_federated_learning: Enable federated learning features
        """
        self.monitor = RealTimeMonitor() if enable_monitoring else None
        self.marketplace = PolicyRegistry() if enable_marketplace else None
        self.compliance = ComplianceAutomation() if enable_compliance else None
        self.federated_learning = FederatedLearningEngine() if enable_federated_learning else None
        self.scanner = Scanner(enable_ai=True)
        
        logger.info("Unified Security Platform initialized with all features enabled")
    
    async def scan_with_full_analysis(
        self,
        path: str,
        frameworks: Optional[List[ComplianceFramework]] = None,
        enable_federated_update: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive scan with all platform features.
        
        Args:
            path: Path to scan
            frameworks: Compliance frameworks to check
            enable_federated_update: Whether to contribute to federated learning
            
        Returns:
            Comprehensive scan results with all analyses
        """
        scan_id = f"scan_{datetime.utcnow().timestamp()}"
        
        # Notify monitoring
        if self.monitor:
            await self.monitor.notify_scan_started(scan_id, {
                'path': path,
                'frameworks': [f.value for f in (frameworks or [])]
            })
        
        # Perform scan
        scan_result = await self.scanner.scan_path(path)
        
        # Compliance assessment
        compliance_reports = {}
        if self.compliance and frameworks:
            compliance_reports = self.compliance.assess_compliance(scan_result, frameworks)
        
        # Notify monitoring of completion
        if self.monitor:
            await self.monitor.notify_scan_completed(scan_id, scan_result)
            
            # Notify about findings
            for finding in scan_result.findings:
                if finding.severity.value in ['critical', 'high']:
                    await self.monitor.notify_finding(scan_id, finding)
            
            # Notify about anomalies
            if scan_result.ai_analysis and scan_result.ai_analysis.pattern_findings:
                for anomaly in scan_result.ai_analysis.pattern_findings:
                    await self.monitor.notify_anomaly(scan_id, anomaly)
            
            # Notify about zero-days
            if scan_result.ai_analysis and scan_result.ai_analysis.zero_day_risks:
                for zero_day in scan_result.ai_analysis.zero_day_risks:
                    await self.monitor.notify_zero_day(scan_id, zero_day)
        
        # Contribute to federated learning (privacy-preserving)
        if self.federated_learning and enable_federated_update:
            try:
                # Prepare update (doesn't expose raw data)
                participant_id = "default_participant"  # In production, use actual participant ID
                update = self.federated_learning.prepare_local_update(
                    participant_id=participant_id,
                    local_data=[scan_result],  # Single scan result
                    local_labels=None  # Unsupervised or use risk score
                )
                logger.info(f"Prepared federated learning update from {participant_id}")
            except Exception as e:
                logger.warning(f"Failed to prepare federated update: {e}")
        
        return {
            'scan_id': scan_id,
            'scan_result': scan_result,
            'compliance_reports': {
                framework.value: report.__dict__ for framework, report in compliance_reports.items()
            },
            'monitoring': {
                'dashboard_data': self.monitor.get_dashboard_data() if self.monitor else None,
                'event_history': self.monitor.get_event_history(limit=50) if self.monitor else []
            },
            'marketplace': {
                'available_policies': len(self.marketplace.list_policies()) if self.marketplace else 0
            },
            'federated_learning': {
                'participant_stats': self.federated_learning.get_participant_stats() if self.federated_learning else None
            }
        }
    
    async def install_policy_from_marketplace(
        self,
        policy_name: str,
        version: Optional[str] = None
    ) -> PolicyVersion:
        """Install a policy from the marketplace."""
        if not self.marketplace:
            raise ValueError("Marketplace not enabled")
        
        policy = self.marketplace.install_policy(policy_name, version)
        logger.info(f"Installed policy {policy_name} version {policy.version}")
        return policy
    
    async def search_policies(
        self,
        query: Optional[str] = None,
        tags: Optional[List[str]] = None,
        author: Optional[str] = None
    ) -> List[PolicyVersion]:
        """Search policies in marketplace."""
        if not self.marketplace:
            raise ValueError("Marketplace not enabled")
        
        return self.marketplace.search_policies(query=query, tags=tags, author=author)
    
    async def assess_compliance(
        self,
        scan_result: ScanResult,
        frameworks: List[ComplianceFramework]
    ) -> Dict[ComplianceFramework, ComplianceReport]:
        """Assess compliance against multiple frameworks."""
        if not self.compliance:
            raise ValueError("Compliance automation not enabled")
        
        return self.compliance.assess_compliance(scan_result, frameworks)
    
    async def get_collaborative_intelligence(
        self,
        participant_id: str
    ) -> Dict[str, Any]:
        """Get collaborative threat intelligence from federated learning."""
        if not self.federated_learning:
            raise ValueError("Federated learning not enabled")
        
        return self.federated_learning.get_collaborative_intelligence(participant_id)
    
    async def run_federated_round(
        self,
        updates: List[FederatedModelUpdate]
    ):
        """Run a federated learning round."""
        if not self.federated_learning:
            raise ValueError("Federated learning not enabled")
        
        return self.federated_learning.run_federated_round(updates)
    
    def get_platform_status(self) -> Dict[str, Any]:
        """Get overall platform status."""
        return {
            'monitoring': {
                'enabled': self.monitor is not None,
                'connected_clients': len(self.monitor.connected_clients) if self.monitor else 0,
                'active_scans': len(self.monitor.active_scans) if self.monitor else 0,
                'metrics': self.monitor.metrics if self.monitor else {}
            },
            'marketplace': {
                'enabled': self.marketplace is not None,
                'total_policies': len(self.marketplace.list_policies()) if self.marketplace else 0
            },
            'compliance': {
                'enabled': self.compliance is not None,
                'frameworks_supported': len(self.compliance.frameworks) if self.compliance else 0
            },
            'federated_learning': {
                'enabled': self.federated_learning is not None,
                'participants': len(self.federated_learning.participants) if self.federated_learning else 0,
                'rounds_completed': len(self.federated_learning.rounds) if self.federated_learning else 0
            }
        }

