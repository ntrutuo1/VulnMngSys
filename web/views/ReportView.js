function ReportPage({ scanId }) {
  const detail = usePoll(scanId);

  if (!scanId) return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', minHeight: 320, color: C.txt3, gap: 14,
    }}>
      <Ico.Doc s={36} />
      <span style={{ fontSize: 13 }}>Select a scan from History to view its full report</span>
    </div>
  );

  if (!detail) return (
    <div style={{ textAlign: 'center', padding: '80px 0', color: C.txt3 }}>Loading report…</div>
  );

  const { scan, findings, job } = detail;
  const summary = scan?.summary || {};
  const sevCounts = {};
  (findings || []).forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  const duration = scan?.completed_at
    ? Math.round((new Date(scan.completed_at) - new Date(scan.created_at)) / 1000)
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Scan header card ── */}
      <div style={{ display: 'flex', gap: 14 }}>
        {/* Meta */}
        <Panel style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono, marginBottom: 8 }}>
                {scan?.target || '—'}
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                <ScanTypeBadge type={scan?.type} />
                <StatusBadge status={scan?.status} />
                {summary.benchmark && (
                  <span style={{ background: 'rgba(79,131,255,.08)', border: `1px solid rgba(79,131,255,.15)`, borderRadius: 4, padding: '1.5px 7px', fontSize: 10, fontWeight: 600, color: C.txt2, fontFamily: C.txtMono }}>
                    {summary.benchmark}
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
                {[
                  ['Scan ID', (scan?.id || '').slice(0, 8) + '…'],
                  ['Started', dayjs(scan?.created_at).format('YYYY-MM-DD HH:mm:ss')],
                  ['Duration', duration != null ? `${duration}s` : '—'],
                  ['Findings', (findings || []).length],
                ].map(([lbl, val]) => (
                  <div key={lbl}>
                    <div style={{ fontSize: 9.5, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 2 }}>{lbl}</div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: C.txt2, fontFamily: C.txtMono }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>
            <ScoreArc score={scan?.score || 0} maxScore={100} type={scan?.type} summary={summary} />
          </div>
        </Panel>

        {/* Severity breakdown */}
        <Panel title="Severity Breakdown" style={{ width: 210 }} bodyPad="12px 14px">
          {['critical', 'high', 'medium', 'low'].map(sev => {
            const cnt = sevCounts[sev] || 0;
            const max = Math.max(...Object.values(sevCounts), 1);
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <div style={{ width: 56 }}><SevTag severity={sev} /></div>
                <div style={{ flex: 1, height: 4, borderRadius: 2, background: '#182034' }}>
                  <div style={{
                    height: '100%', borderRadius: 2, background: (SEV[sev] || {}).color,
                    width: `${(cnt / max) * 100}%`, transition: 'width .5s ease',
                  }} />
                </div>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono, minWidth: 18, textAlign: 'right' }}>{cnt}</span>
              </div>
            );
          })}
        </Panel>
      </div>

      {/* ── CIS stats row ── */}
      {scan?.type === 'cis' && typeof summary.rules === 'number' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
          {[
            ['Rules Checked', summary.rules,   C.accent],
            ['Passed',        summary.passed,  C.green],
            ['Failed',        summary.failed,  C.red],
            ['Skipped',       summary.skipped, C.medium],
          ].map(([lbl, val, color]) => (
            <div key={lbl} style={{
              background: C.bgSurface, border: `1px solid ${C.border}`, borderRadius: 9,
              padding: '12px 14px', position: 'relative', overflow: 'hidden',
            }}>
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color, borderRadius: '9px 9px 0 0' }} />
              <div style={{ fontSize: 10, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 5 }}>{lbl}</div>
              <div style={{ fontSize: 26, fontWeight: 700, color, fontVariantNumeric: 'tabular-nums' }}>{val ?? '—'}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Services & Modules stats row ── */}
      {scan?.type === 'services' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          {/* Detected Services */}
          <Panel title="Detected Services" icon={<Ico.Radar />}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {summary.detectedServices && summary.detectedServices.length > 0 ? (
                summary.detectedServices.map(svc => (
                  <span key={svc} style={{ background: '#182034', border: `1px solid ${C.border}`, color: C.txt1, borderRadius: 5, padding: '3px 8px', fontSize: 11, fontWeight: 600, fontFamily: C.txtMono }}>
                    {svc}
                  </span>
                ))
              ) : (
                <span style={{ color: C.txt3, fontSize: 11 }}>No services detected.</span>
              )}
            </div>
          </Panel>
          {/* Metasploit Modules Used */}
          <Panel title="Metasploit Modules Executed" icon={<Ico.CheckList />}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {summary.modulesUsed && summary.modulesUsed.length > 0 ? (
                summary.modulesUsed.map(mod => (
                  <span key={mod} style={{ background: '#182034', border: `1px solid ${C.border}`, color: C.txt1, borderRadius: 5, padding: '3px 8px', fontSize: 11, fontWeight: 600, fontFamily: C.txtMono, display: 'inline-block', width: 'fit-content' }}>
                    {mod}
                  </span>
                ))
              ) : (
                <span style={{ color: C.txt3, fontSize: 11 }}>No Metasploit modules were executed.</span>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* ── Findings ── */}
      <Panel title={`Findings (${(findings || []).length})`} icon={<Ico.Warning />}>
        {job?.status === 'RUNNING' && <ScanProgressWidget job={job} style={{ marginBottom: 14 }} />}
        <FindingsList findings={findings} />
      </Panel>
    </div>
  );
}
