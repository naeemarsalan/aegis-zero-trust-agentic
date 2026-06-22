"""asyncio bridge between the FastAPI WebSocket client and an oc-exec PTY (C4).

open_bridge(ws, pod_name, namespace, container) drives bidirectional byte pumping:
  - browser -> ws.receive_bytes() -> subprocess stdin
  - subprocess stdout/stderr -> ws.send_bytes() -> browser

The bridge runs as an asyncio task; it closes cleanly when either side disconnects.

Security:
  - The pod_name and namespace are resolved server-side from the Agent record;
    they are NEVER taken from the WebSocket URL or message payload.
  - The actor (Keycloak identity) must be the agent owner before open_bridge is called.
  - ext-proc remains in front of any MCP tool calls the human makes in the PTY.
  - No credentials pass through the bridge; the oc-exec session inherits the
    console pod's RBAC (approval-console SA — must have 'get pods/exec' in ns openshell).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

logger = logging.getLogger("approval_console.webshell.bridge")

_OC_BIN = shutil.which("oc") or "/usr/local/bin/oc"
_KUBECONFIG = os.environ.get("KUBECONFIG", "")


async def open_bridge(
    ws: "WebSocket",
    pod_name: str,
    namespace: str,
    container: str = "agent",
) -> None:
    """Bidirectionally bridge the WebSocket ws to an oc exec PTY on pod_name.

    Closes ws gracefully when the exec process exits or the client disconnects.

    NOTE: In the test stub this is called with a monkeypatched subprocess so no
    real cluster access is required in unit tests.
    """
    cmd = [_OC_BIN, "exec", "-it", pod_name, "-n", namespace, "-c", container, "--", "/bin/bash"]
    if _KUBECONFIG:
        cmd = [_OC_BIN, "--kubeconfig", _KUBECONFIG] + cmd[1:]

    logger.info(
        "webshell.bridge.open pod=%s ns=%s container=%s", pod_name, namespace, container
    )

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    async def _pump_output() -> None:
        assert proc.stdout is not None
        try:
            while True:
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    break
                await ws.send_bytes(chunk)
        except Exception as exc:  # noqa: BLE001
            logger.debug("webshell.bridge.output_pump_error: %s", exc)
        finally:
            try:
                await ws.close()
            except Exception:  # noqa: BLE001
                pass

    async def _pump_input() -> None:
        assert proc.stdin is not None
        try:
            while True:
                data = await ws.receive_bytes()
                proc.stdin.write(data)
                await proc.stdin.drain()
        except Exception as exc:  # noqa: BLE001
            logger.debug("webshell.bridge.input_pump_error: %s", exc)
        finally:
            proc.stdin.close()
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    output_task = asyncio.create_task(_pump_output())
    input_task = asyncio.create_task(_pump_input())

    done, pending = await asyncio.wait(
        [output_task, input_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()

    rc = await proc.wait()
    logger.info("webshell.bridge.closed pod=%s rc=%d", pod_name, rc)
