"""Wakes long-polls (pact_events, pact_wait) when the database changes, on every board instance.

Triggers on tasks and task_messages ``NOTIFY pact_events`` with the organization as payload when the
writing transaction commits. Each process keeps one connection that LISTENs and wakes the waiters of
that organization; a woken waiter re-reads the database, so a notification is only a hint. Waiters
re-read on a timer too, often while the listener is down, rarely while it is up, so a lost
notification costs seconds, never an event.
"""

import asyncio
import contextlib
import logging
from collections.abc import Iterator

from psycopg import AsyncConnection

CHANNEL = "pact_events"
RECHECK_LISTENING = 10.0
"""Seconds between re-reads while the listener is up: a safety net for a lost notification."""
RECHECK_POLLING = 2.0
"""Seconds between re-reads while it is down (not started yet, or reconnecting)."""
RECONNECT_SECONDS = 2.0

log = logging.getLogger(__name__)


class Subscription:
    """One waiter. Subscribe before reading the database, so a change that commits between the
    read and the wait still wakes it."""

    def __init__(self, hub: "EventHub", org: str | None) -> None:
        self.hub = hub
        self.org = org
        self.event = asyncio.Event()

    async def wait(self, seconds: float) -> None:
        """Until a change in the organization, the re-read interval, or ``seconds``, whichever is first."""
        self.event.clear()
        timeout = max(0.0, min(seconds, self.hub.recheck_seconds()))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self.event.wait(), timeout)


class EventHub:
    def __init__(self, conninfo: str) -> None:
        self.conninfo = conninfo
        self.listening = False
        self._subs: set[Subscription] = set()
        self._task: asyncio.Task[None] | None = None

    def recheck_seconds(self) -> float:
        return RECHECK_LISTENING if self.listening else RECHECK_POLLING

    @contextlib.contextmanager
    def subscribe(self, org: str | None = None) -> Iterator[Subscription]:
        """Wake on changes in ``org``; None wakes on every change."""
        self._start()
        sub = Subscription(self, org)
        self._subs.add(sub)
        try:
            yield sub
        finally:
            self._subs.discard(sub)

    def _start(self) -> None:
        loop = asyncio.get_running_loop()
        if self._task is None or self._task.done() or self._task.get_loop() is not loop:
            self.listening = False
            self._task = loop.create_task(self._listen(), name="pact-events-listener")

    def _wake(self, org: str | None) -> None:
        for sub in self._subs:
            if org is None or sub.org is None or sub.org == org:
                sub.event.set()

    async def _listen(self) -> None:
        while True:
            try:
                async with await AsyncConnection.connect(self.conninfo, autocommit=True) as conn:
                    await conn.execute(f"LISTEN {CHANNEL}")
                    self.listening = True
                    self._wake(None)  # whatever changed while nobody listened: everyone re-reads
                    async for note in conn.notifies():
                        self._wake(note.payload or None)
            except asyncio.CancelledError:
                raise
            except Exception as err:
                log.warning("pact_events listener lost its connection (%s); waiters poll until it is back", err)
            finally:
                self.listening = False
            await asyncio.sleep(RECONNECT_SECONDS)

    async def close(self) -> None:
        task, self._task = self._task, None
        self.listening = False
        if task is None or task.done():
            return
        if task.get_loop() is not asyncio.get_running_loop():
            return  # left behind by a loop that has ended; nothing to await here
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
