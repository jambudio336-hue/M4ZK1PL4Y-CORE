from __future__ import annotations
import asyncio, uuid
from .base import ShellBackend
from .cmdinject import CmdInjectShell
from .webshell import WebShell
from .reverse import ReverseShell
from .bind import BindShell


class SessionManager:
    def __init__(self):
        self.sessions: dict[str, ShellBackend] = {}
        self.io_subs: dict[str, set[asyncio.Queue]] = {}

    def make(self, kind: str, ctx, target: str, **kw) -> ShellBackend:
        sid = uuid.uuid4().hex[:12]
        cls = {"cmd-injection": CmdInjectShell, "webshell": WebShell,
               "reverse": ReverseShell, "bind": BindShell}[kind]
        s = cls(ctx, sid, target, **kw)
        self.sessions[sid] = s
        return s

    def get(self, sid: str) -> ShellBackend | None:
        return self.sessions.get(sid)

    def all(self, job_id: str | None = None):
        return [s for s in self.sessions.values()
                if s.alive and (job_id is None or s.ctx.job_id == job_id)]

    async def pump(self, s: ShellBackend):
        """Bridge byte dari stream target ke semua subscriber WS."""
        if not s.reader:
            return
        while s.alive:
            try:
                data = await s.reader.read(65536)
            except Exception:
                break
            if not data:
                break
            for q in list(self.io_subs.get(s.sid, ())):
                q.put_nowait(data)
        s.alive = False
        for q in list(self.io_subs.get(s.sid, ())):
            q.put_nowait(b"\r\n\x1b[31m[session closed]\x1b[0m\r\n")

    def subscribe(self, sid: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(5000)
        self.io_subs.setdefault(sid, set()).add(q)
        return q

    def unsubscribe(self, sid: str, q):
        self.io_subs.get(sid, set()).discard(q)

    async def close(self, sid: str):
        s = self.sessions.pop(sid, None)
        if s:
            await s.close()


manager = SessionManager()
