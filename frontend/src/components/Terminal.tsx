import { useEffect, useRef } from 'react'
import { Terminal as XT } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

export default function Terminal({ sid }: { sid: string }) {
  const host = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!host.current) return
    const term = new XT({
      fontFamily: 'JetBrains Mono, monospace', fontSize: 13,
      theme: { background: '#05060a', foreground: '#c9d1d9', cursor: '#00ff9c',
               selectionBackground: '#00ff9c44' },
      cursorBlink: true, scrollback: 8000, convertEol: false,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(host.current)
    fit.fit()

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/api/session/${sid}/io`)
    ws.binaryType = 'arraybuffer'

    ws.onopen = () => {
      term.focus()
      ws.send(JSON.stringify({ t: 'resize', rows: term.rows, cols: term.cols }))
    }
    ws.onmessage = e => {
      const txt = typeof e.data === 'string'
        ? e.data : new TextDecoder().decode(new Uint8Array(e.data))
      term.write(txt)
    }
    ws.onclose = () => term.write('\r\n\x1b[31m[session closed]\x1b[0m\r\n')
    term.onData(d => ws.readyState === 1 && ws.send(JSON.stringify({ t: 'data', d })))

    const ro = new ResizeObserver(() => {
      fit.fit()
      if (ws.readyState === 1)
        ws.send(JSON.stringify({ t: 'resize', rows: term.rows, cols: term.cols }))
    })
    ro.observe(host.current)

    return () => { ro.disconnect(); ws.close(); term.dispose() }
  }, [sid])

  return <div ref={host} className="h-[420px] w-full rounded border border-line bg-ink p-1" />
}
