import { useEffect, useRef, useState } from 'react'
import Terminal from './components/Terminal'

type F = { id: string; kind: string; title: string; target: string; severity: string
           confidence: string; evidence: string; repro: string[]; poc: string; verified: boolean }

const SEV: Record<string, string> = {
  critical: 'bg-red-600/20 text-red-400 border border-red-500/40',
  high: 'bg-amber-600/20 text-amber-400 border border-amber-500/40',
  medium: 'bg-yellow-500/15 text-yellow-300 border border-yellow-500/30',
  low: 'bg-sky-500/15 text-sky-300 border border-sky-500/30',
  info: 'bg-slate-600/15 text-slate-400 border border-slate-600/40',
}

export default function App() {
  const [target, setTarget] = useState('')
  const [job, setJob] = useState<string|null>(null)
  const [logs, setLogs] = useState<{level:string;msg:string}[]>([])
  const [finds, setFinds] = useState<F[]>([])
  const [prog, setProg] = useState(0)
  const [phase, setPhase] = useState('idle')
  const [report, setReport] = useState<string|null>(null)
  const [open, setOpen] = useState<string|null>(null)
  const [sids, setSids] = useState<{sid:string;kind:string;streamable:boolean}[]>([])
  const [active, setActive] = useState<string|null>(null)
  const term = useRef<HTMLDivElement>(null)

  useEffect(() => { term.current?.scrollTo({top: term.current.scrollHeight}) }, [logs])

  async function start() {
    if (!target.trim()) return
    setLogs([]); setFinds([]); setReport(null); setSids([]); setActive(null); setProg(0)
    const r = await fetch('/api/scan', { method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({target}) })
    if (!r.ok) { setLogs([{level:'error', msg: await r.text()}]); return }
    const { job_id } = await r.json()
    setJob(job_id); setPhase('running')
    const p = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${p}://${location.host}/api/ws/${job_id}`)
    ws.onmessage = e => {
      const m = JSON.parse(e.data)
      if (m.type === 'log') setLogs(x => [...x, m])
      if (m.type === 'phase') { setPhase(m.label); setProg(m.progress) }
      if (m.type === 'finding') setFinds(x => [m.finding, ...x])
      if (m.type === 'shell') {
        setSids(m.sessions)
        setActive(m.sessions.find((s:any) => s.streamable)?.sid ?? m.sessions[0]?.sid)
      }
      if (m.type === 'done') { setReport(m.report); setPhase('selesai'); setProg(1); ws.close() }
    }
  }

  return (
    <div className="relative min-h-screen">
      <video id="bgvid" src="/videobagroundtools.mp4" autoPlay muted loop playsInline />
      <div className="veil" /><div className="scanline" />
      <main className="relative z-10 mx-auto max-w-6xl space-y-4 px-4 py-8">
        <header className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="animate-flicker text-2xl font-bold tracking-tight text-emerald-400 sm:text-3xl">
              M4ZK1PL4Y<span className="text-slate-600">_</span>CORE
            </h1>
            <p className="mt-1 text-xs text-slate-500">
              enum → origin → validate → exploit → shell → dump → report
            </p>
          </div>
          <span className="rounded border border-line px-2 py-1 text-[10px] text-slate-600">v2.0.0</span>
        </header>

        <section className="panel flex flex-col gap-2 p-4 sm:flex-row">
          <input value={target} onChange={e => setTarget(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && start()}
                 placeholder="target.com | 203.0.113.10"
                 className="flex-1 rounded border border-line bg-ink/70 px-3 py-2 text-sm outline-none focus:border-emerald-500/60" />
          <button onClick={start} disabled={phase === 'running'} className="btn">
            {phase === 'running' ? 'RUNNING…' : 'START'}
          </button>
        </section>

        <section className="panel p-3">
          <div className="mb-1 flex justify-between text-[11px] text-slate-500">
            <span>{phase}</span><span>{Math.round(prog*100)}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded bg-line">
            <div className="h-full bg-emerald-400 transition-all" style={{width:`${prog*100}%`}} />
          </div>
        </section>

        {report && <a href={`/api/report/${job}`} className="btn block text-center">⬇ DOWNLOAD BUNDLE</a>}

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="panel p-3">
            <h2 className="mb-2 text-xs text-slate-500">STREAM</h2>
            <div ref={term} className="h-64 space-y-0.5 overflow-auto text-[11px]">
              {logs.map((l,i) => (
                <div key={i} className={l.level==='error'?'text-red-400':l.level==='warn'?'text-amber-400':l.level==='good'?'text-emerald-400':'text-slate-400'}>{l.msg}</div>
              ))}
            </div>
          </section>

          <section className="panel p-3">
            <h2 className="mb-2 text-xs text-slate-500">
              FINDINGS · {finds.filter(f=>f.verified).length} verified / {finds.length}
            </h2>
            <div className="h-64 space-y-2 overflow-auto">
              {finds.map(f => (
                <article key={f.id} className="rounded border border-line p-2 text-[11px]">
                  <div className="flex items-start gap-2">
                    <span className={`chip ${SEV[f.severity]||SEV.info}`}>{f.severity}</span>
                    <button className="flex-1 text-left hover:text-emerald-400"
                            onClick={() => setOpen(open===f.id?null:f.id)}>{f.title}</button>
                    <span className={f.verified?'text-emerald-400':'text-slate-600'}>{f.verified?'✓':'~'}</span>
                  </div>
                  <div className="mt-1 truncate text-slate-600">{f.target}</div>
                  {open === f.id && (
                    <div className="mt-2 space-y-2">
                      <pre className="whitespace-pre-wrap rounded bg-ink/60 p-2 text-slate-400">{f.evidence}</pre>
                      {!!f.repro?.length && <pre className="whitespace-pre-wrap rounded bg-ink/60 p-2 text-sky-300">{f.repro.join('\n')}</pre>}
                      {f.poc && <pre className="whitespace-pre-wrap rounded bg-ink/60 p-2 text-amber-300">{f.poc}</pre>}
                    </div>
                  )}
                </article>
              ))}
            </div>
          </section>
        </div>

        {!!sids.length && (
          <section className="panel space-y-2 p-3">
            <div className="flex items-center gap-2">
              <h2 className="text-xs text-emerald-400">SHELL</h2>
              {sids.map(s => (
                <button key={s.sid} onClick={() => setActive(s.sid)}
                        className={`chip border ${active===s.sid?'border-emerald-500 text-emerald-400':'border-line text-slate-500'}`}>
                  {s.kind}{s.streamable?' ·pty':''}
                </button>
              ))}
            </div>
            {active && sids.find(s=>s.sid===active)?.streamable
              ? <Terminal sid={active} />
              : active && <LineShell sid={active} />}
          </section>
        )}

        <footer className="pt-4 text-center text-[10px] text-slate-700">
          authorized use only · MIT
        </footer>
      </main>
    </div>
  )
}

function LineShell({ sid }: { sid: string }) {
  const [cmd, setCmd] = useState('id')
  const [out, setOut] = useState('')
  async function run() {
    const r = await fetch('/api/session/exec', { method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({sid, cmd}) })
    const j = await r.json()
    setOut(o => o + `\n$ ${cmd}\n${j.output}`)
  }
  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <input value={cmd} onChange={e=>setCmd(e.target.value)}
               onKeyDown={e=>e.key==='Enter'&&run()}
               className="flex-1 rounded border border-line bg-ink/70 px-3 py-2 text-sm outline-none" />
        <button onClick={run} className="btn text-sm">RUN</button>
      </div>
      <pre className="h-56 overflow-auto whitespace-pre-wrap rounded border border-line bg-ink/80 p-2 text-[11px] text-emerald-400">{out}</pre>
    </div>
  )
}
