from __future__ import annotations
"""Pass-2: tiap temuan di-replay modulnya sendiri, 2 putaran, marker baru."""
import asyncio
from .modules.base import Finding

VERIFIERS = {}


def register(mod):
    VERIFIERS[mod.name] = mod


async def run(ctx, findings: list[Finding], mods: dict) -> list[Finding]:
    out = []
    for f in findings:
        mod = mods.get(f.kind)
        ok = 0
        if mod:
            for _ in range(2):
                try:
                    if await mod.verify(f):
                        ok += 1
                except Exception:
                    pass
                await asyncio.sleep(0.5)
        else:
            ok = 2 if f.kind in ("open-port", "waf", "origin-ip", "asset") else 0
        f.hits = ok
        f.verified = ok == 2
        f.confidence = "confirmed" if f.verified else "unverified"
        await ctx.store.add_finding(ctx.job_id, f)
        await ctx.log(("[✓] CONFIRMED " if f.verified else "[~] unverified ") + f.title,
                      level="good" if f.verified else "warn")
        out.append(f)
    return out
