from __future__ import annotations
import asyncio, json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from ..session.manager import manager
from ..db import store
from ..settings import settings
from ..modules.base import Ctx
import httpx

router = APIRouter()


class ExecIn(BaseModel):
    sid: str
    cmd: str


@router.get("/session/{jid}")
async def list_sessions(jid: str):
    return [{"sid": s.sid, "kind": s.kind, "streamable": s.streamable}
            for s in manager.all(jid)]


@router.post("/session/exec")
async def exec_cmd(body: ExecIn):
    s = manager.get(body.sid)
    if not s:
        raise HTTPException(404, "sesi mati")
    r = await s.exec(body.cmd, timeout=60)
    return {"output": r.out, "rc": r.rc, "cwd": s.cwd}


@router.post("/session/{sid}/resize")
async def resize(sid: str, rows: int = 40, cols: int = 160):
    s = manager.get(sid)
    if s and s.streamable and s.writer:
        s.writer.write(f"stty rows {rows} cols {cols}\n".encode())
        await s.writer.drain()
    return {"ok": True}


@router.websocket("/session/{sid}/io")
async def io(ws: WebSocket, sid: str):
    s = manager.get(sid)
    if not s or not s.streamable:
        await ws.close(code=4004); return
    await ws.accept()
    q = manager.subscribe(sid)

    async def up():
        while True:
            try:
                data = await ws.receive_text()
            except WebSocketDisconnect:
                return
            try:
                msg = json.loads(data)
            except Exception:
                await s.push(data.encode()); continue
            if msg.get("t") == "resize":
                await s.push(f"stty rows {msg['rows']} cols {msg['cols']}\n".encode())
            elif msg.get("t") == "data":
                await s.push(msg["d"].encode())

    async def down():
        while True:
            chunk = await q.get()
            await ws.send_bytes(chunk if isinstance(chunk, bytes) else chunk.encode())

    try:
        await asyncio.gather(up(), down())
    finally:
        manager.unsubscribe(sid, q)
