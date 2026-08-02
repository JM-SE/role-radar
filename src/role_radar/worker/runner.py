"""Polling, CAS claim y lifecycle del worker único previsto."""

import asyncio
import os
import socket
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from role_radar.config import Settings
from role_radar.repositories.runs import RunRepository
from role_radar.worker.pipeline import Pipeline


class WorkerRunner:
    def __init__(
        self,
        session_factory: Callable[[], Session],
        pipeline: Pipeline,
        *,
        settings: Settings,
        worker_id: str | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._pipeline = pipeline
        self._settings = settings
        self._worker_id = worker_id or settings.worker_id or f"{socket.gethostname()}-{os.getpid()}"

    def run_once(self) -> bool:
        """Convenience síncrona para tests/CLI fuera de un loop asyncio."""
        return asyncio.run(self.run_once_async())

    async def run_once_async(self) -> bool:
        with self._session_factory() as session:
            run = RunRepository(session).claim_next(
                worker_id=self._worker_id,
                lease_duration_seconds=self._settings.worker_lease_duration_seconds,
                now=datetime.now(UTC),
                max_recoveries=self._settings.worker_max_recoveries,
            )
            session.commit()
            if run is None:
                return False
            run_id = run.id
        try:
            heartbeat_stop = asyncio.Event()
            heartbeat_task = asyncio.create_task(
                self._heartbeat_forever(run_id, heartbeat_stop)
            )
            try:
                await self._pipeline.run(run_id)
            finally:
                heartbeat_stop.set()
                heartbeat_task.cancel()
                with suppress(asyncio.CancelledError):
                    await heartbeat_task
        except Exception:
            # A process crash must leave a recoverable lease. Do not mark failed.
            return True
        return True

    async def _heartbeat_forever(self, run_id: str, stop: asyncio.Event) -> None:
        interval = self._settings.worker_heartbeat_interval_seconds
        while not stop.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=interval)
            if stop.is_set():
                return
            with self._session_factory() as session:
                alive = RunRepository(session).heartbeat(
                    run_id,
                    worker_id=self._worker_id,
                    lease_duration_seconds=self._settings.worker_lease_duration_seconds,
                    now=datetime.now(UTC),
                )
                session.commit()
            if not alive:
                return

    async def run_forever(self, stop_event: asyncio.Event | None = None) -> None:
        stop = stop_event or asyncio.Event()
        while not stop.is_set():
            worked = await self.run_once_async()
            if not worked:
                with suppress(TimeoutError):
                    await asyncio.wait_for(
                        stop.wait(), timeout=self._settings.worker_poll_interval_seconds
                    )
