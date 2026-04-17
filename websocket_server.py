"""
websocket_server.py — Authenticated WebSocket server with JWT and WSS.

Every client must send a valid JWT as its first message.
Unauthenticated connections are rejected with close-code 4001.
If TLS certificates exist, the server runs over WSS automatically.
"""

import asyncio
import json
import ssl
import os
import time
from collections import deque
from typing import Dict, Set, Any, Optional

import websockets
from websockets.server import WebSocketServerProtocol

from config import (
    WS_HOST, WS_PORT, WS_PING_INTERVAL, WS_PING_TIMEOUT,
    JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_HOURS,
    SSL_CERT_FILE, SSL_KEY_FILE,
)
from logging_utils import get_logger

logger = get_logger('websocket')

connected_clients: Set[WebSocketServerProtocol] = set()
alert_queue: deque[Dict[str, Any]] = deque()
current_stats: Dict[str, Any] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# JWT helpers
# ═══════════════════════════════════════════════════════════════════════════════

def generate_token(subject: str = 'dashboard') -> str:
    """Create a signed JWT token for client authentication."""
    import jwt as pyjwt  # type: ignore[import-untyped]
    payload: Dict[str, Any] = {
        'sub': subject,
        'iat': int(time.time()),
        'exp': int(time.time()) + JWT_EXPIRY_HOURS * 3600,
        'iss': 'sentinel',
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Return decoded payload or None if token is invalid / expired."""
    try:
        import jwt as pyjwt  # type: ignore[import-untyped]
        return pyjwt.decode(
            token, JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            issuer='sentinel',
        )
    except Exception as exc:
        logger.warning("JWT verification failed: %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SSL / TLS
# ═══════════════════════════════════════════════════════════════════════════════

def _get_ssl_context() -> Optional[ssl.SSLContext]:
    """Build an SSLContext if cert + key files exist on disk."""
    if not (os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE)):
        logger.info(
            "TLS certs not found — running plain WS.  Generate with:\n"
            "  openssl req -x509 -newkey rsa:4096 -keyout %s "
            "-out %s -days 365 -nodes",
            SSL_KEY_FILE, SSL_CERT_FILE,
        )
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        logger.info("WSS (TLS) enabled — cert: %s", SSL_CERT_FILE)
        return ctx
    except Exception as exc:
        logger.error("Failed to load TLS certificates: %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication handshake
# ═══════════════════════════════════════════════════════════════════════════════

async def _authenticate(ws: WebSocketServerProtocol) -> bool:
    """
    Expect the client's first message to be:
        {"type": "auth", "token": "<jwt>"}
    within 10 seconds.
    """
    try:
        raw: str = await asyncio.wait_for(ws.recv(), timeout=10.0)
        msg: Dict[str, Any] = json.loads(raw)

        if msg.get('type') != 'auth' or 'token' not in msg:
            await ws.send(json.dumps({
                'type': 'auth_error',
                'message': 'Expected {"type":"auth","token":"<jwt>"}',
            }))
            return False

        payload = _verify_token(msg['token'])
        if payload is None:
            await ws.send(json.dumps({
                'type': 'auth_error',
                'message': 'Invalid or expired token',
            }))
            return False

        await ws.send(json.dumps({
            'type': 'auth_success',
            'message': f"Authenticated as {payload.get('sub', 'unknown')}",
        }))
        logger.info(
            "Client authenticated: %s (sub=%s)",
            ws.remote_address, payload.get('sub'),
        )
        return True

    except asyncio.TimeoutError:
        await ws.send(json.dumps({
            'type': 'auth_error',
            'message': 'Authentication timeout (10 s)',
        }))
        return False
    except Exception as exc:
        logger.warning("Auth error from %s: %s", ws.remote_address, exc)
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Connection handler
# ═══════════════════════════════════════════════════════════════════════════════

async def handler(websocket: WebSocketServerProtocol) -> None:
    """Handle a single WebSocket connection (JWT-first handshake)."""
    logger.info("Client connecting: %s", websocket.remote_address)

    if not await _authenticate(websocket):
        logger.warning("Rejected: %s", websocket.remote_address)
        await websocket.close(4001, 'Authentication failed')
        return

    connected_clients.add(websocket)

    if current_stats:
        try:
            await websocket.send(
                json.dumps({'type': 'stats', 'stats': current_stats})
            )
        except Exception:
            pass

    try:
        await websocket.wait_closed()
    finally:
        connected_clients.discard(websocket)
        logger.info("Client disconnected: %s", websocket.remote_address)


# ═══════════════════════════════════════════════════════════════════════════════
# Alert queue
# ═══════════════════════════════════════════════════════════════════════════════

async def queue_alert(data: Dict[str, Any]) -> None:
    """Called from main.py to broadcast any event to the dashboard."""
    global current_stats
    if data.get('type') == 'stats':
        current_stats = data.get('stats', {})
    alert_queue.append(data)


async def process_queue() -> None:
    """Drain the alert queue and fan-out to all authenticated clients."""
    while True:
        while alert_queue and connected_clients:
            data: Dict[str, Any] = alert_queue.popleft()
            message: str = json.dumps(data)

            dead: Set[WebSocketServerProtocol] = set()
            for client in connected_clients.copy():
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    dead.add(client)
                except Exception as exc:
                    logger.error("Send error: %s", exc)
                    dead.add(client)

            for client in dead:
                connected_clients.discard(client)

        await asyncio.sleep(0.05)


# ═══════════════════════════════════════════════════════════════════════════════
# Server start
# ═══════════════════════════════════════════════════════════════════════════════

async def start_server() -> None:
    """Start the WebSocket server with optional WSS and mandatory JWT auth."""
    ssl_ctx = _get_ssl_context()
    proto: str = 'wss' if ssl_ctx else 'ws'

    logger.info(
        "Starting WebSocket server on %s://%s:%d", proto, WS_HOST, WS_PORT,
    )

    # ── Print a dashboard token for convenience ──
    try:
        token: str = generate_token()
        logger.info("Dashboard JWT (valid %dh): %s", JWT_EXPIRY_HOURS, token)
    except ImportError:
        logger.warning(
            "PyJWT not installed — JWT auth disabled.  "
            "Install with: pip install PyJWT"
        )

    try:
        async with websockets.serve(
            handler,
            WS_HOST,
            WS_PORT,
            ssl=ssl_ctx,
            reuse_address=True,
            ping_interval=WS_PING_INTERVAL,
            ping_timeout=WS_PING_TIMEOUT,
        ):
            logger.info("Server running — open dashboard.html in browser")
            asyncio.create_task(process_queue())
            await asyncio.Future()  # run forever

    except OSError:
        logger.error(
            "Port %d already in use.  Kill the old process:\n"
            "  netstat -ano | findstr :%d\n"
            "  taskkill /PID <pid> /F",
            WS_PORT, WS_PORT,
        )
        raise
    except Exception as exc:
        logger.error("Server error: %s", exc)
        raise