"""asyncio bridge between the FastAPI WebSocket client and an oc-exec PTY (C4).

open_bridge(ws, pod_name, namespace, container) drives bidirectional byte pumping
over a REAL local PTY:

  - A local PTY master/slave pair is allocated with pty.openpty().
  - `oc exec -it ... -- /bin/bash` is spawned with the SLAVE fd as its
    stdin/stdout/stderr.  Because the slave is a genuine TTY, `oc -t` sees a TTY
    on its own stdin and allocates a proper REMOTE PTY in the sandbox pod (no
    "Unable to use a TTY - input is not a terminal..." warning, real prompt,
    line editing, job control, vim/top/less all work).
  - Bytes are pumped bidirectionally:
      browser -> ws (binary) -> PTY master  (keystrokes)
      PTY master -> ws (binary) -> browser  (terminal output)
  - The browser may also send a TEXT (JSON) control frame to resize the TTY:
      {"type": "resize", "cols": <int>, "rows": <int>}
    which is applied to the PTY master via TIOCSWINSZ.  If the frontend never
    sends one, a sane default window size is set at open time.

The bridge runs as asyncio tasks; it closes cleanly when either side
disconnects (PTY closed, subprocess reaped, ws closed).

Security:
  - The pod_name and namespace are resolved server-side from the Agent record;
    they are NEVER taken from the WebSocket URL or message payload.
  - The actor (Keycloak identity) must be the agent owner before open_bridge is
    called.
  - ext-proc remains in front of any MCP tool calls the human makes in the PTY.
  - No credentials pass through the bridge; the oc-exec session inherits the
    console pod's RBAC (approval-console SA — must have 'get pods/exec' in ns
    openshell).
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import json
import logging
import os
import pty
import shutil
import struct
import termios
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

logger = logging.getLogger("approval_console.webshell.bridge")

_OC_BIN = shutil.which("oc") or "/usr/local/bin/oc"
_KUBECONFIG = os.environ.get("KUBECONFIG", "")

# Default terminal window size used until (or unless) the frontend sends a
# resize control frame.  120x40 is a comfortable popup-window default.
_DEFAULT_COLS = 120
_DEFAULT_ROWS = 40


def _robust_write(fd: int, data: bytes) -> int:
    """Write all of ``data`` to a non-blocking PTY master fd.

    The master fd is non-blocking (os.set_blocking(master_fd, False) is required
    for loop.add_reader on the OUTPUT side). A bare os.write on a non-blocking fd
    can short-write or raise BlockingIOError when the PTY buffer is momentarily
    full (large pastes). This loops until every byte is written, briefly yielding
    on EAGAIN so a big paste never silently drops input.
    """
    total = 0
    view = memoryview(data)
    while total < len(view):
        try:
            n = os.write(fd, view[total:])
            if n <= 0:
                break
            total += n
        except BlockingIOError:
            # PTY buffer full — yield the GIL briefly and retry.
            time.sleep(0.001)
            continue
    return total


def _set_winsize(fd: int, cols: int, rows: int) -> None:
    """Set the terminal window size on the PTY master fd via TIOCSWINSZ.

    struct winsize is {ws_row, ws_col, ws_xpixel, ws_ypixel} (all unsigned short).
    A SIGWINCH is delivered to the foreground process group as a side effect, so
    full-screen programs (vim/top/less) re-lay-out correctly.
    """
    try:
        rows = max(1, min(int(rows), 0xFFFF))
        cols = max(1, min(int(cols), 0xFFFF))
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except (OSError, ValueError) as exc:  # noqa: PERF203
        logger.debug("webshell.bridge.winsize_error: %s", exc)


async def open_bridge(
    ws: "WebSocket",
    pod_name: str,
    namespace: str,
    container: str = "agent",
) -> None:
    """Bidirectionally bridge the WebSocket ws to an oc exec PTY on pod_name.

    Uses a real local PTY so `oc exec -it` allocates a proper remote TTY.
    Closes ws gracefully when the exec process exits or the client disconnects.
    """
    cmd = [_OC_BIN, "exec", "-it", pod_name, "-n", namespace, "-c", container, "--", "/bin/bash"]
    if _KUBECONFIG:
        cmd = [_OC_BIN, "--kubeconfig", _KUBECONFIG] + cmd[1:]

    logger.info(
        "webshell.bridge.open pod=%s ns=%s container=%s", pod_name, namespace, container
    )

    # Allocate a real PTY.  The slave becomes the subprocess's controlling-style
    # TTY; we keep the master to pump bytes to/from the websocket.
    master_fd, slave_fd = pty.openpty()

    # Seed a sane default window size before exec so the remote PTY starts sized.
    _set_winsize(master_fd, _DEFAULT_COLS, _DEFAULT_ROWS)

    def _make_controlling_tty() -> None:
        # Run in the child after fork, before exec.  Start a new session so the
        # child has no inherited controlling tty, then make the PTY slave its
        # controlling terminal.  This is what lets `oc exec` receive SIGWINCH
        # when we later resize the master (TIOCSWINSZ) — without a controlling
        # tty, oc reads the size only once at startup and ignores later resizes.
        os.setsid()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        except OSError:
            pass

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=_make_controlling_tty,  # noqa: PLW1509 — intentional PTY setup
        )
    except Exception:
        os.close(master_fd)
        os.close(slave_fd)
        raise

    # The child now owns the slave fd; close our copy so we see EOF when it exits.
    os.close(slave_fd)

    loop = asyncio.get_running_loop()
    # Make the master non-blocking for loop.add_reader.
    os.set_blocking(master_fd, False)

    output_queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def _on_master_readable() -> None:
        try:
            data = os.read(master_fd, 65536)
        except BlockingIOError:
            return
        except OSError:
            # PTY closed (child exited) — signal EOF.
            data = b""
        if data:
            output_queue.put_nowait(data)
        else:
            output_queue.put_nowait(None)

    loop.add_reader(master_fd, _on_master_readable)

    async def _pump_output() -> None:
        """Drain the PTY master read-queue to the websocket as binary frames."""
        try:
            while True:
                chunk = await output_queue.get()
                if chunk is None:  # EOF from the PTY
                    break
                await ws.send_bytes(chunk)
        except Exception as exc:  # noqa: BLE001
            logger.debug("webshell.bridge.output_pump_error: %s", exc)

    async def _pump_input() -> None:
        """Pump websocket frames to the PTY master.

        Binary frames are raw terminal keystrokes.  Text frames are JSON control
        messages; only {"type":"resize","cols":..,"rows":..} is honored — ANY
        other text (including non-JSON) is treated as raw keystrokes, so a browser
        that sends keystrokes as text frames still works.

        Instrumented at INFO level (visible in `oc logs`) so a browser test
        produces evidence that the keystroke frame actually reached the bridge.
        """
        try:
            while True:
                msg = await ws.receive()
                msg_type = msg.get("type")
                if msg_type == "websocket.disconnect":
                    logger.info("webshell.in type=disconnect pod=%s", pod_name)
                    break
                data = msg.get("bytes")
                if data is not None:
                    logger.info("webshell.in type=bytes len=%d pod=%s", len(data), pod_name)
                    written = _robust_write(master_fd, data)
                    logger.info("webshell.write fd=master len=%d pod=%s", written, pod_name)
                    continue
                text = msg.get("text")
                if text is None:
                    logger.info("webshell.in type=empty pod=%s", pod_name)
                    continue
                # A text frame is EITHER a {"type":"resize",...} control message
                # OR raw keystrokes. Try to parse JSON; only a well-formed resize
                # dict is treated as control — everything else is keystrokes.
                ctrl = None
                try:
                    ctrl = json.loads(text)
                except (ValueError, TypeError):
                    ctrl = None
                if isinstance(ctrl, dict) and ctrl.get("type") == "resize":
                    logger.info(
                        "webshell.in type=resize cols=%s rows=%s pod=%s",
                        ctrl.get("cols"), ctrl.get("rows"), pod_name,
                    )
                    _set_winsize(
                        master_fd,
                        ctrl.get("cols", _DEFAULT_COLS),
                        ctrl.get("rows", _DEFAULT_ROWS),
                    )
                else:
                    # Not a resize control frame — treat the text as raw input.
                    raw = text.encode("utf-8", "replace")
                    logger.info("webshell.in type=text len=%d pod=%s", len(raw), pod_name)
                    written = _robust_write(master_fd, raw)
                    logger.info("webshell.write fd=master len=%d pod=%s", written, pod_name)
        except Exception as exc:  # noqa: BLE001
            logger.info("webshell.in type=error err=%s pod=%s", exc, pod_name)
        finally:
            logger.info("webshell.in_pump exit pod=%s", pod_name)

    output_task = asyncio.create_task(_pump_output())
    input_task = asyncio.create_task(_pump_input())

    try:
        _done, pending = await asyncio.wait(
            [output_task, input_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        with contextlib.suppress(Exception):
            await asyncio.gather(*pending, return_exceptions=True)
    finally:
        # Tear down: stop watching the master, kill+reap the child, close fds, ws.
        with contextlib.suppress(Exception):
            loop.remove_reader(master_fd)
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        with contextlib.suppress(Exception):
            rc = await proc.wait()
        with contextlib.suppress(OSError):
            os.close(master_fd)
        with contextlib.suppress(Exception):
            await ws.close()

    logger.info(
        "webshell.bridge.closed pod=%s rc=%s", pod_name, getattr(proc, "returncode", "?")
    )
