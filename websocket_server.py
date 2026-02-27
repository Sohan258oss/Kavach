import asyncio
import websockets
import json
from collections import deque

connected_clients = set()
alert_queue = deque()
current_stats = {}

async def handler(websocket):
    print(f"[WS] Client connected: {websocket.remote_address}")
    connected_clients.add(websocket)

    # Send current stats immediately on connect
    if current_stats:
        try:
            await websocket.send(json.dumps({'type': 'stats', 'stats': current_stats}))
        except Exception:
            pass

    try:
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)
        print(f"[WS] Client disconnected: {websocket.remote_address}")

async def queue_alert(data: dict):
    """Called from main.py to broadcast any event to dashboard."""
    if data.get('type') == 'stats':
        global current_stats
        current_stats = data.get('stats', {})
    alert_queue.append(data)

async def process_queue():
    while True:
        while alert_queue and connected_clients:
            data = alert_queue.popleft()
            message = json.dumps(data)

            # Copy set to avoid mutation during iteration
            dead = set()
            for client in connected_clients.copy():
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    dead.add(client)
                except Exception as e:
                    print(f"[WS] Send error: {e}")
                    dead.add(client)

            # Clean up dead connections
            for client in dead:
                connected_clients.discard(client)

        await asyncio.sleep(0.05)

async def start_server():
    print("[WS] Starting WebSocket server on ws://localhost:8765")
    try:
        async with websockets.serve(
            handler, "0.0.0.0", 8765,
            reuse_address=True,
            ping_interval=20,     # keep-alive ping every 20s
            ping_timeout=10       # drop client if no pong in 10s
        ):
            print("[WS] Server running — open dashboard.html in browser")
            asyncio.create_task(process_queue())
            await asyncio.Future()
    except OSError as e:
        print(f"[WS] Port 8765 already in use. Kill the old process first:")
        print(f"      netstat -ano | findstr :8765")
        print(f"      taskkill /PID <pid> /F")
        raise
    except Exception as e:
        print(f"[WS] Server error: {e}")
        raise