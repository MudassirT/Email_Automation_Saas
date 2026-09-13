"""
WebSocket Connection & Telemetry Manager for AutoMail AI.
Provides real-time event streaming directly to browser clients:
- 'new_email': Live incoming emails ingested
- 'draft_ready': AI drafts generated for human-in-the-loop review
- 'draft_approved': Drafts dispatched via SMTP outbox
- 'threat_intercepted': PromptShield adversarial injections quarantined
- 'live_log': Real-time activity log stream
- 'stats_update': Instant metric counter synchronization
- 'sync_status': Mailbox sync lifecycle updates
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Set, Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("automail.websocket")

class LiveSocketManager:
    """Manages active browser WebSocket connections and broadcasts real-time events."""
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def connect(self, websocket: WebSocket):
        """Accept incoming client connection and register socket."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"[WebSocket] Client connected. Total active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Deregister client connection."""
        self.active_connections.discard(websocket)
        logger.info(f"[WebSocket] Client disconnected. Total active: {len(self.active_connections)}")

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Asynchronously send an event JSON payload to all active client connections."""
        if not self.active_connections:
            return

        payload = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        message = json.dumps(payload, default=str)
        stale_connections = set()

        for conn in list(self.active_connections):
            try:
                await conn.send_text(message)
            except Exception as exc:
                logger.debug(f"[WebSocket] Error sending to client: {exc}")
                stale_connections.add(conn)

        for conn in stale_connections:
            self.disconnect(conn)

    def broadcast_sync(self, event_type: str, data: Dict[str, Any]):
        """Synchronous wrapper so background threads and standard handlers can broadcast effortlessly."""
        if not self.active_connections:
            return

        try:
            # Try to get existing running loop
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = self._loop

            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(event_type, data), loop)
            else:
                # Fallback: create temporary task in new loop if needed
                asyncio.run(self.broadcast(event_type, data))
        except Exception as e:
            logger.debug(f"[WebSocket] broadcast_sync exception: {e}")

# Global singleton
ws_manager = LiveSocketManager()
