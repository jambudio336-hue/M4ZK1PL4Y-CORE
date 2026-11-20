from __future__ import annotations
import asyncio, time, uuid
import httpx

from .modules.base import Ctx, Finding
from .modules import (subdomains, live, tls, dns, origin, ports, fingerprint,
                      waf, crawl, fuzz, sqli, idor, ssti, lfi, upload, rce, secrets)
from . import validate, poc, chain, report

PHASES = [
    ("1/11 subdomain", [subdomains.SubdomainEnum]),
    ("2/11 live", [live.LiveProbe]),
    ("3/11 tls·dns·origin", [tls.TLSHarvest, dns.DNSHarvest, origin.OriginHunt]),
    ("4/11 ports", [ports.PortScan]),
    ("5/11 fingerprint", [fingerprint.HeaderAudit, waf.WAFDetect]),
    ("6/11 crawl·fuzz", [crawl.Crawl, fuzz.PathFuzz]),
    ("7/11 detect", [sqli.SQLi, idor.IDOR, ssti.SSTI, lfi.LFIHunt,
                     upload.UploadHunt, rce.RCE, secrets.Secrets]),
]
MODMAP = {m.name: m(None) for _, ms in PHASES for m in ms}


class Runner:
    def __init__(self, store, bus):
        self.store, self.bus = store, bus
        self.cancels: dict[str, asyncio.Event] = {}

    async def start(self, target: str) -> str:
        jid = uuid.uuid4().hex[:16]
        await self.store.create_job(jid, target)
        ev = asyncio.Event()
        self.cancels[jid] = ev
        asyncio.create_task(self._run(jid, target, ev))
        return jid

    def cancel(self, jid):
        self.cancels.get(jid, asyncio.Event()).set()

    async def _run(self, jid, target, ev):
        from .settings import settings
        from .session.manager import manager

        async def log(msg, level="info"):
            await self.store.add_event(jid, level, msg)
            await self.bus.publish(jid, {"type": "log", "level": level, "msg": msg})

        await self.store.set_job(jid, status="running")
        all_f: list[Finding] = []
        t0 = time.time()

        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                     limits=httpx.Limits(max_connections=80),
                                     headers={"User-Agent": "M4zk1pL4y/2.0"}) as http:
            ctx = Ctx(job_id=jid, target=target, store=self.store, log=log,
                      cfg=settings, http=http,
                      sem=asyncio.Semaphore(settings.get("app.concurrency", 40)),
                      cancelled=ev, manager=manager)
            ctx.bus = self.bus

            async def emit(f: Finding):
                await self.store.add_finding(jid, f)
                await self.bus.publish(jid, {"type": "finding", "finding": f.as_dict()})
                return f
            ctx.emit = emit

            try:
                for i, (label, mods) in enumerate(PHASES):
                    if ev.is_set():
                        raise asyncio.CancelledError
                    await self.store.set_job(jid, phase=label, progress=i / 11)
                    await self.bus.publish(jid, {"type": "phase", "label": label, "progress": i / 11})
                    await log(f"══ {label} ══")
                    res = await asyncio.gather(*(m(ctx).run() for m in mods),
                                               return_exceptions=True)
                    for r in res:
                        if isinstance(r, list):
                            all_f += r
                        elif isinstance(r, Exception):
                            await log(f"[err] {r}", level="error")

                await self.store.set_job(jid, phase="8/11 validate", progress=0.74)
                await self.bus.publish(jid, {"type": "phase", "label": "8/11 validate", "progress": 0.74})
                await log("══ 8/11 VALIDASI 2× ══")
                all_f = await validate.run(ctx, all_f, MODMAP)
                for f in all_f:
                    if f.verified:
                        poc.build(f)
                        await self.store.add_finding(jid, f)

                await self.store.set_job(jid, phase="9/11 exploit", progress=0.82)
                await self.bus.publish(jid, {"type": "phase", "label": "9/11 exploit", "progress": 0.82})
                await log("══ 9/11 EXPLOIT ══")
                await chain.execute(ctx, all_f)

            except asyncio.CancelledError:
                await log("[!] dibatalkan", level="warn")

            await self.store.set_job(jid, phase="11/11 report", progress=0.96)
            rows = await self.store.get_findings(jid)
            payload = [{"id": r["id"], "kind": r["kind"], "title": r["title"],
                        "target": r["target"], "severity": r["severity"],
                        "confidence": r["confidence"], "evidence": r["evidence"],
                        "repro": __import__("json").loads(r["repro"] or "[]"),
                        "poc": r["poc"], "verified": bool(r["verified"])} for r in rows]
            z = await asyncio.to_thread(report.build, jid, target, payload)
            await self.store.set_job(jid, status="done", phase="selesai",
                                     progress=1.0, finished=time.time())
            await self.bus.publish(jid, {"type": "done", "report": z.name,
                                         "duration": round(time.time() - t0, 1)})
            await log(f"[✓] selesai: {z.name}", level="good")
