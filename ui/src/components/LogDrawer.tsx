import { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from 'lucide-react';
import { useLogStream } from '../hooks/useLogStream';

export function LogDrawer() {
  const lines = useLogStream();
  const [open, setOpen] = useState(true);
  const [filter, setFilter] = useState('');
  const shown = useMemo(
    () => (filter ? lines.filter((l) => l.toLowerCase().includes(filter.toLowerCase())) : lines),
    [lines, filter],
  );
  const boxRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const b = boxRef.current;
    if (b) b.scrollTop = b.scrollHeight;
  }, [shown.length]);

  return (
    <div className="border-t border-line bg-panel">
      <div className="flex items-center gap-2 px-5 py-2 text-[13px]">
        <Terminal size={14} className="text-accent" />
        <span className="font-semibold">live log</span>
        <span className="text-muted">({shown.length})</span>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter…"
          className="ml-2 bg-panel2 border border-line rounded px-2 py-0.5 text-xs text-fg outline-none focus:border-accent w-40"
        />
        <button onClick={() => setOpen((o) => !o)} className="ml-auto text-muted hover:text-fg text-xs">
          {open ? 'hide' : 'show'}
        </button>
      </div>
      {open && (
        <div ref={boxRef} className="max-h-52 overflow-auto px-5 pb-3 font-mono text-[11px] leading-relaxed text-muted">
          {shown.length === 0 && <div className="text-muted/60">waiting for log lines…</div>}
          {shown.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap break-all">
              {l}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
