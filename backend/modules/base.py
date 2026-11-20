from __future__ import annotations
import asyncio, dataclasses, hashlib, json, secrets, shutil, time, uuid
from dataclasses import dataclass, field
from typing import Any
import httpx


def marker() -> str:
    return "m4z" + secrets.token_hex(6)


def body_hash(t: str) -> str:
    return hashlib.sha256((t or "").encode(errors="ignore")).hexdigest()


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    sa, sb = set(a.split()), set(b.split())
    return len(sa & sb) / max(len(sa), len(sb)) if sa and sb else 0.0


@dataclass
class Finding:
    kind: str
    title: str
    target: str
    severity: str = "info"
    confidence: str = "tentative"
    evidence: str = ""
    repro: list[str] = field(default_factory=list)
    poc: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    verified: bool = False
    hits: int = 0
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclass
class Ctx:
    job_id: str
    target: str
    store: Any
    log: Any
    cfg: Any
    http: httpx.AsyncClient
    sem: asyncio.Semaphore
    cancelled: asyncio.Event | None = None
    state: dict = field(default_factory=dict)
    manager: Any = None

    def check(self):
        if self.cancelled and self.cancelled.is_set():
            raise asyncio.CancelledError

    def ev_dir(self):
        from ..settings import REPORTS
        p = REPORTS / self.job_id / "evidence"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save(self, name: str, content: str) -> str:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:100]
        p = self.ev_dir() / f"{int(time.time()*1000)}-{safe}"
        p.write_text(content or "", errors="ignore")
        return f"evidence/{p.name}"


class Module:
    name = "module"
    phase = 0

    def __init__(self, ctx: Ctx):
        self.ctx = ctx

    async def tool(self, argv: list[str], stdin: str | None = None, timeout: int | None = None):
        self.ctx.check()
        if shutil.which(argv[0]) is None:
            await self.ctx.log(f"[skip] {argv[0]} tidak terpasang", level="warn")
            return 127, "", ""
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(
                proc.communicate(stdin.encode() if stdin else None),
                timeout or self.ctx.cfg.get("app.tool_timeout", 900))
        except asyncio.TimeoutError:
            proc.kill(); out, err = await proc.communicate()
        return proc.returncode or 0, out.decode("utf8", "ignore"), err.decode("utf8", "ignore")

    async def emit(self, f: Finding) -> Finding:
        await self.ctx.store.add_finding(self.ctx.job_id, f)
        await self.ctx.bus.publish(self.ctx.job_id, {"type": "finding", "finding": f.as_dict()})
        await self.ctx.log(f"[{f.severity.upper()}] {f.kind}: {f.title} → {f.target}")
        return f

    async def run(self) -> list[Finding]:
        raise NotImplementedError
