// Tiny inline-SVG sparkline (no chart dep). Renders a dash when there isn't enough history yet.
export function Sparkline({ values, className }: { values: number[]; className?: string }) {
  if (!values || values.length < 2) return <span className="text-muted/40 text-[11px]">—</span>;
  const w = 84;
  const h = 18;
  const max = Math.max(1, ...values);
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(h - (v / max) * (h - 2) - 1).toFixed(1)}`).join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className={className} aria-hidden>
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
