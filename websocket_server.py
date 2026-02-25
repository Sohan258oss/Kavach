import asyncio
import websockets
import json
from collections import deque

connected_clients = set()
alert_queue = deque()
current_stats = {}

async def handler(websocket):
    print(f"[*] New client connected: {websocket.remote_address}")
    connected_clients.add(websocket)

    # Send current stats to new client
    if current_stats:
        try:
            await websocket.send(json.dumps({
                'type': 'stats',
                'stats': current_stats
            }))
        except Exception as e:
            print(f"[!] Error sending initial stats: {e}")

    try:
        await websocket.wait_closed()
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
    finally:
        connected_clients.discard(websocket)
        print(f"[*] Client disconnected: {websocket.remote_address}")

async def queue_alert(data: dict):
    if data.get('type') == 'stats':
        global current_stats
        current_stats = data.get('stats', {})
    alert_queue.append(data)

async def process_queue():
    while True:
        while alert_queue and connected_clients:
            data = alert_queue.popleft()
            message = json.dumps(data)
            # Send to all connected clients
            results = await asyncio.gather(
                *[c.send(message) for c in connected_clients],
                return_exceptions=True
            )
            for res in results:
                if isinstance(res, Exception):
                    print(f"[!] Broadcast error: {res}")
                else:
                    print(f"[*] Broadcast message: {data.get('type')} to {len(results)} clients")
        await asyncio.sleep(0.1)

async def start_server():
    print("[*] Starting WebSocket server on 0.0.0.0:8765")
    try:
        # Using reuse_address to help with quick restarts
        async with websockets.serve(handler, "0.0.0.0", 8765, reuse_address=True):
            print("[*] WebSocket server is running")
            asyncio.create_task(process_queue())
            await asyncio.Future()
    except Exception as e:
        print(f"[!!!] Could not start WebSocket server: {e}")
        raise