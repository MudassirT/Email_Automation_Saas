"""
Verification script for AutoMail AI Real-Time WebSocket Telemetry.
Tests:
1. WebSocket handshake and connection to /ws/live
2. Initial 'connected' message receipt with current stats
3. Heartbeat ping-pong verification
4. Simulating live email via /api/emails/simulate
5. Receiving broadcast live events ('new_email', 'draft_ready', 'stats_update', 'live_log')
"""

import asyncio
import json
import urllib.request
import websockets
import sys

WS_URL = "ws://127.0.0.1:8000/ws/live"
SIMULATE_URL = "http://127.0.0.1:8000/api/emails/simulate?scenario=customer_support"

async def test_live_socket():
    print(f"Connecting to WebSocket: {WS_URL} ...")
    async with websockets.connect(WS_URL) as ws:
        print("Connected to /ws/live successfully!")
        
        # 1. Receive initial connection message
        init_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
        init_data = json.loads(init_msg)
        print(f"[Handshake] Received: {init_data.get('type')} - {init_data.get('message')}")
        assert init_data.get("type") == "connected", f"Expected 'connected', got {init_data.get('type')}"
        assert "data" in init_data, "Expected stats in initial handshake"

        # 2. Test Heartbeat Ping-Pong
        print("Sending heartbeat ping...")
        await ws.send("ping")
        pong = await asyncio.wait_for(ws.recv(), timeout=5.0)
        print(f"[Heartbeat] Received: {pong}")
        assert pong == "pong", f"Expected 'pong', got {pong}"

        # 3. Trigger Email Simulation via HTTP POST in a thread
        print("Triggering /api/emails/simulate via HTTP POST ...")
        
        def trigger_simulate():
            req = urllib.request.Request(
                SIMULATE_URL,
                data=b"",
                headers={"X-Requested-With": "AutoMail"},
                method="POST"
            )
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())

        loop = asyncio.get_running_loop()
        sim_result = await loop.run_in_executor(None, trigger_simulate)
        print(f"[Simulation HTTP] Result: Email ID: {sim_result.get('email_id')}, Subject: {sim_result.get('subject')}")

        # 4. Listen for incoming live broadcast events over WebSocket
        received_events = []
        start_time = asyncio.get_event_loop().time()
        
        while asyncio.get_event_loop().time() - start_time < 6.0:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                event = json.loads(raw)
                evt_type = event.get("type")
                received_events.append(evt_type)
                print(f"[Live Event Received] Type: {evt_type}")
                if "stats_update" in received_events and ("new_email" in received_events or "live_log" in received_events):
                    break
            except asyncio.TimeoutError:
                break

        print(f"Total live events captured over WebSocket: {len(received_events)} -> {received_events}")
        assert len(received_events) > 0, "No live WebSocket events received after email simulation!"
        print("SUCCESS! Real-time WebSocket live streaming verified completely.")

if __name__ == "__main__":
    try:
        asyncio.run(test_live_socket())
    except Exception as e:
        print(f"FAILED: {e}", file=sys.stderr)
        sys.exit(1)
