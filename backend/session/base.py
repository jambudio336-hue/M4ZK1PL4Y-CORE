from __future__ import annotations
import asyncio, abc, time
from dataclasses import dataclass, field


@dataclass
class ExecResult:
    out: str = ""
    rc: int = 0
    dur: float = 0.0


class ShellBackend(abc.ABC):
    kind = "abstract"
    streamable = False          # True = raw byte bridge (PTY)

    def __init__(self, ctx, session_id: str, target: str):
        self.ctx = ctx
        self.sid = session_id
        self.target = target
        self.cwd = "/"
        self.env: dict[str, str] = {}
        self.alive = True
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    @abc.abstractmethod
    async def establish(self) -> bool: ...

    @abc.abstractmethod
    async def exec(self, cmd: str, timeout: int = 30) -> ExecResult: ...

    async def push(self, data: bytes) -> None:
        if self.writer:
            self.writer.write(data); await self.writer.drain()

    async def close(self) -> None:
        self.alive = False
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def timed(self, coro) -> ExecResult:
        t0 = time.time()
        r = await coro
        r.dur = time.time() - t0
        return r
