import { useEffect, useState } from 'react';
import { fetchDoctor, type DoctorCheck } from '../lib/api';

const DOT: Record<string, string> = { ok: 'bg-ok', warn: 'bg-amber', bad: 'bg-danger' };
const TXT: Record<string, string> = { ok: 'text-ok', warn: 'text-amber', bad: 'text-danger' };

export function HealthPage() {
  const [checks, setChecks] = useState<DoctorCheck[] | null>(null);
  const [ran, setRan] = useState('');

  const load = () =>
    fetchDoctor()
      .then((d) => {
        setChecks(d.checks);
        setRan(d.ran);
      })
      .catch(() => setChecks([]));

  useEffect(() => {
    load();
  }, []);

  const bad = checks?.some((c) => c.status === 'bad');
  const warn = checks?.some((c) => c.status === 'warn');

  return (
    <div className="max-w-[900px] w-full mx-auto p-6 flex flex-col gap-4">
      <div
        className={`text-base font-bold px-4 py-3 rounded-xl bg-panel border ${
          bad ? 'border-danger text-danger' : warn ? 'border-amber text-amber' : 'border-ok text-ok'
        }`}
      >
        {checks == null ? 'running checks…' : bad ? 'problems found' : warn ? 'warnings' : 'all healthy'}
        <button onClick={load} className="ml-3 text-xs font-normal text-muted hover:text-fg">
          re-run
        </button>
      </div>

      <div className="flex flex-col gap-2">
        {(checks ?? []).map((c) => (
          <div key={c.name} className="grid grid-cols-[14px_160px_1fr] gap-3 items-center px-4 py-3 bg-panel border border-line rounded-lg">
            <span className={`w-2.5 h-2.5 rounded-full ${DOT[c.status]}`} />
            <span className="font-bold flex items-center gap-2">
              {c.name}
              <span className={`text-[11px] uppercase ${TXT[c.status]}`}>{c.status}</span>
            </span>
            <span className="text-muted truncate" title={c.detail}>
              {c.detail}
            </span>
          </div>
        ))}
      </div>

      {ran && <div className="text-xs text-muted">ran {new Date(ran).toLocaleTimeString()}</div>}
    </div>
  );
}
