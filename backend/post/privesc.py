from __future__ import annotations
from ..modules.base import Finding

CHECKS = [
    ("sudo-nopasswd", "sudo -n -l 2>&1 | grep -i 'NOPASSWD'", "critical"),
    ("suid", "find / -perm -4000 -type f 2>/dev/null | head -20", "high"),
    ("writable-passwd", "[ -w /etc/passwd ] && echo WRITABLE", "high"),
    ("docker-group", "id | grep -o docker", "high"),
    ("capabilities", "getcap -r / 2>/dev/null | head -20", "medium"),
    ("cron-writable", "ls -la /etc/cron.d /etc/cron.daily 2>/dev/null | grep -i 'rw'", "medium"),
]


async def check(ctx, sh) -> list[Finding]:
    findings = []
    for name, cmd, sev in CHECKS:
        r = await sh.exec(cmd, timeout=60)
        if not r.out.strip():
            continue
        findings.append(await ctx.emit(Finding(
            kind="privesc", title=f"Jalur privesc: {name}", target=ctx.target,
            severity=sev, confidence="confirmed",
            evidence=r.out[:1500],
            repro=[cmd],
            poc=f"# {name}\n{cmd}")))
    if not findings:
        await ctx.emit(Finding(kind="privesc", title="Tidak ada jalur privesc jelas",
                               target=ctx.target, severity="info", confidence="confirmed",
                               evidence="semua cek kosong"))
    return findings
