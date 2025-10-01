"""
Real-time continuous security monitoring platform.
Provides WebSocket-based live monitoring, event streaming, and real-time dashboards.
"""
import asyncio
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum

from dsp_scanner.core.results import ScanResult
from dsp_scanner.utils.logger import get_logger

logger = get_logger(__name__)

class EventType(Enum):
    """Types of monitoring events."""
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    FINDING_DETECTED = "finding_detected"
    RISK_UPDATED = "risk_updated"
    COMPLIANCE_CHANGED = "compliance_changed"
    ANOMALY_DETECTED = "anomaly_detected"
    ZERO_DAY_DETECTED = "zero_day_detected"
    ALERT_TRIGGERED = "alert_triggered"

@dataclass
class MonitoringEvent:
    """Represents a monitoring event."""
    event_type: EventType
    timestamp: datetime
    data: Dict[str, Any]
    scan_id: Optional[str] = None
    severity: Optional[str] = None

class RealTimeMonitor:
    """
    Real-time security monitoring platform.
    Manages WebSocket connections, event streaming, and live dashboards.
    """
    
    def __init__(self):
        self.connected_clients: Set[Any] = set()
        self.event_history: List[MonitoringEvent] = []
        self.max_history: int = 1000
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.metrics: Dict[str, Any] = {
            'total_scans': 0,
            'active_scans': 0,
            'findings_detected': 0,
            'alerts_triggered': 0,
            'risk_score_avg': 0.0
        }
    
    async def connect_client(self, websocket: Any):
        """Register a new WebSocket client."""
        self.connected_clients.add(websocket)
        logger.info(f"Client connected. Total clients: {len(self.connected_clients)}")
        
        # Send current state to new client
        await self._send_to_client(websocket, {
            'type': 'connection',
            'data': {
                'connected_at': datetime.utcnow().isoformat(),
                'active_scans': len(self.active_scans),
                'metrics': self.metrics
            }
        })
    
    async def disconnect_client(self, websocket: Any):
        """Unregister a WebSocket client."""
        self.connected_clients.discard(websocket)
        logger.info(f"Client disconnected. Total clients: {len(self.connected_clients)}")
    
    async def broadcast_event(self, event: MonitoringEvent):
        """Broadcast event to all connected clients."""
        self.event_history.append(event)
        
        # Maintain history size
        if len(self.event_history) > self.max_history:
            self.event_history = self.event_history[-self.max_history:]
        
        # Broadcast to all clients
        message = {
            'type': event.event_type.value,
            'timestamp': event.timestamp.isoformat(),
            'data': event.data,
            'scan_id': event.scan_id,
            'severity': event.severity
        }
        
        await self._broadcast(message)
    
    async def _broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        disconnected = set()
        
        for client in self.connected_clients:
            try:
                await self._send_to_client(client, message)
            except Exception as e:
                logger.warning(f"Failed to send to client: {e}")
                disconnected.add(client)
        
        # Remove disconnected clients
        for client in disconnected:
            self.connected_clients.discard(client)
    
    async def _send_to_client(self, websocket: Any, message: Dict[str, Any]):
        """Send message to a specific client."""
        if hasattr(websocket, 'send_json'):
            await websocket.send_json(message)
        elif hasattr(websocket, 'send'):
            await websocket.send(json.dumps(message))
        else:
            raise ValueError("WebSocket does not support sending messages")
    
    async def notify_scan_started(self, scan_id: str, scan_info: Dict[str, Any]):
        """Notify that a scan has started."""
        self.active_scans[scan_id] = {
            'started_at': datetime.utcnow(),
            'status': 'running',
            **scan_info
        }
        self.metrics['total_scans'] += 1
        self.metrics['active_scans'] = len(self.active_scans)
        
        event = MonitoringEvent(
            event_type=EventType.SCAN_STARTED,
            timestamp=datetime.utcnow(),
            data=scan_info,
            scan_id=scan_id
        )
        await self.broadcast_event(event)
    
    async def notify_scan_completed(self, scan_id: str, result: ScanResult):
        """Notify that a scan has completed."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['completed_at'] = datetime.utcnow()
            del self.active_scans[scan_id]
        
        self.metrics['active_scans'] = len(self.active_scans)
        self.metrics['findings_detected'] += len(result.findings)
        
        # Update average risk score
        if result.ai_analysis and result.ai_analysis.risk_predictions:
            risk_score = result.ai_analysis.risk_predictions[0].get('predicted_risk_score', 0)
            # Update rolling average
            current_avg = self.metrics['risk_score_avg']
            total_scans = self.metrics['total_scans']
            self.metrics['risk_score_avg'] = (current_avg * (total_scans - 1) + risk_score) / total_scans
        
        event = MonitoringEvent(
            event_type=EventType.SCAN_COMPLETED,
            timestamp=datetime.utcnow(),
            data={
                'total_findings': len(result.findings),
                'risk_score': result.ai_analysis.risk_predictions[0].get('predicted_risk_score', 0) if result.ai_analysis else 0,
                'summary': result.get_summary()
            },
            scan_id=scan_id
        )
        await self.broadcast_event(event)
    
    async def notify_finding(self, scan_id: str, finding: Any):
        """Notify about a new finding."""
        event = MonitoringEvent(
            event_type=EventType.FINDING_DETECTED,
            timestamp=datetime.utcnow(),
            data={
                'finding_id': finding.id,
                'title': finding.title,
                'severity': finding.severity.value,
                'location': finding.location,
                'platform': finding.platform
            },
            scan_id=scan_id,
            severity=finding.severity.value
        )
        await self.broadcast_event(event)
    
    async def notify_anomaly(self, scan_id: str, anomaly_data: Dict[str, Any]):
        """Notify about detected anomaly."""
        event = MonitoringEvent(
            event_type=EventType.ANOMALY_DETECTED,
            timestamp=datetime.utcnow(),
            data=anomaly_data,
            scan_id=scan_id,
            severity=anomaly_data.get('severity', 'medium')
        )
        await self.broadcast_event(event)
        self.metrics['alerts_triggered'] += 1
    
    async def notify_zero_day(self, scan_id: str, zero_day_data: Dict[str, Any]):
        """Notify about potential zero-day."""
        event = MonitoringEvent(
            event_type=EventType.ZERO_DAY_DETECTED,
            timestamp=datetime.utcnow(),
            data=zero_day_data,
            scan_id=scan_id,
            severity='critical'
        )
        await self.broadcast_event(event)
        self.metrics['alerts_triggered'] += 1
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data."""
        return {
            'metrics': self.metrics,
            'active_scans': len(self.active_scans),
            'connected_clients': len(self.connected_clients),
            'recent_events': [
                asdict(event) for event in self.event_history[-50:]
            ],
            'active_scan_details': list(self.active_scans.values())
        }
    
    def get_event_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get event history."""
        return [asdict(event) for event in self.event_history[-limit:]]

