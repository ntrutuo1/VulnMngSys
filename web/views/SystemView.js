function SystemPage() {
  const [info,    setInfo]    = useState(null);
  const [loading, setLoading] = useState(false);

  const collect = async () => {
    setLoading(true);
    try {
      setInfo(await api('/api/system/info'));
    } catch (e) {
      message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const rows = info ? [
    ['Hostname',      info.CsName],
    ['OS Name',       info.OsName],
    ['OS Version',    info.OsVersion],
    ['Product Name',  info.WindowsProductName],
    ['Architecture',  info.OsArchitecture],
  ] : [];

  return (
    <Panel title="System Information" icon={<Ico.Monitor />}
      extra={<Button size="small" type="primary" loading={loading} onClick={collect}>Collect Info</Button>}
    >
      {!info ? (
        <div style={{ textAlign: 'center', padding: '56px 0', color: C.txt3 }}>
          <div style={{ fontSize: 36, opacity: .3, marginBottom: 14 }}>🖥️</div>
          <div style={{ fontSize: 13, marginBottom: 18 }}>
            Click <strong style={{ color: C.txt2 }}>Collect Info</strong> to gather system data via PowerShell
          </div>
          <Button type="primary" loading={loading} onClick={collect} size="large">Collect Info</Button>
        </div>
      ) : (
        <div style={{ borderRadius: 8, overflow: 'hidden', border: `1px solid ${C.border}` }}>
          {rows.map(([lbl, val], i) => (
            <div key={lbl} style={{ display: 'flex', background: i % 2 === 0 ? C.bgCard : C.bgSurface }}>
              <div style={{
                width: 170, padding: '11px 14px', fontSize: 11, fontWeight: 600,
                color: C.txt3, textTransform: 'uppercase', letterSpacing: '.6px', flexShrink: 0,
              }}>{lbl}</div>
              <div style={{
                flex: 1, padding: '11px 14px', fontSize: 13, color: C.txt1,
                fontFamily: C.txtMono, borderLeft: `1px solid ${C.border}`,
              }}>{val || '—'}</div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
