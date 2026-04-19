import { useMemo, useState } from 'react';
import { moduleCatalog, simulateScan } from './catalog';

const osOptions = ['all', 'linux', 'windows', 'macos'];
const serviceOptions = ['all', 'ssh', 'apache-http', 'apache-tomcat'];
const stepLabels = ['Target', 'Module', 'Review', 'Result'];

function gradeTone(grade) {
  if (grade === 'A') return 'tone-a';
  if (grade === 'B') return 'tone-b';
  if (grade === 'C') return 'tone-c';
  return 'tone-d';
}

export default function App() {
  const [osFamily, setOsFamily] = useState('windows');
  const [service, setService] = useState('ssh');
  const [selectedId, setSelectedId] = useState('');
  const [osVersion, setOsVersion] = useState('windows-11');
  const [serviceVersion, setServiceVersion] = useState('9.7');
  const [scanMode, setScanMode] = useState('balanced');
  const [step, setStep] = useState(1);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);

  const filteredModules = useMemo(() => {
    return moduleCatalog.filter((item) => {
      const osOk = osFamily === 'all' || item.osFamily === osFamily;
      const serviceOk = service === 'all' || item.service === service;
      return osOk && serviceOk;
    });
  }, [osFamily, service]);

  const currentModule = useMemo(() => {
    if (selectedId) {
      const found = filteredModules.find((item) => item.id === selectedId);
      if (found) return found;
    }
    return filteredModules[0] || null;
  }, [filteredModules, selectedId]);

  function onRun() {
    if (!currentModule) return;
    setRunning(true);
    setResult(null);
    setStep(4);

    window.setTimeout(() => {
      setResult(simulateScan(currentModule));
      setRunning(false);
    }, 900);
  }

  function nextStep() {
    setStep((prev) => Math.min(prev + 1, 4));
  }

  function prevStep() {
    setStep((prev) => Math.max(prev - 1, 1));
  }

  function jump(stepNumber) {
    setStep(stepNumber);
  }

  function resetFlow() {
    setResult(null);
    setRunning(false);
    setStep(1);
  }

  return (
    <div className="page-shell">
      <div className="aura aura-left" />
      <div className="aura aura-right" />
      <div className="mesh" />

      <header className="hero wizard-card reveal-up">
        <div>
          <p className="eyebrow">VulnMngSys React Console</p>
          <h1>Hardening Scan Journey</h1>
          <p className="subtitle">
            Wizard nhiều bước, mỗi view tập trung một nhiệm vụ: chọn target, chọn module, xác nhận cấu hình và xem kết quả.
          </p>
        </div>
        <div className="hero-badge">Step {step}/4</div>
      </header>

      <main className="wizard-layout">
        <aside className="wizard-card step-rail reveal-up delay-1">
          <p className="rail-title">Flow</p>
          {stepLabels.map((label, idx) => {
            const stepIndex = idx + 1;
            const active = step === stepIndex;
            const done = step > stepIndex;
            return (
              <button
                key={label}
                className={`rail-step ${active ? 'active' : ''} ${done ? 'done' : ''}`}
                onClick={() => jump(stepIndex)}
              >
                <span>{stepIndex}</span>
                <p>{label}</p>
              </button>
            );
          })}
        </aside>

        <section className="wizard-card view-panel reveal-up delay-2">
          {step === 1 && (
            <div className="step-view">
              <h2>Step 1: Select Target Profile</h2>
              <p className="step-lead">Chọn nền tảng và dịch vụ cần đánh giá.</p>
              <div className="field-grid">
                <label>
                  OS Family
                  <select value={osFamily} onChange={(e) => setOsFamily(e.target.value)}>
                    {osOptions.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Service
                  <select value={service} onChange={(e) => setService(e.target.value)}>
                    {serviceOptions.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </label>
                <label>
                  OS Version
                  <input
                    value={osVersion}
                    onChange={(e) => setOsVersion(e.target.value)}
                    placeholder="ubuntu-22.04 / windows-11"
                  />
                </label>
                <label>
                  Service Version
                  <input
                    value={serviceVersion}
                    onChange={(e) => setServiceVersion(e.target.value)}
                    placeholder="2.4.58 / 9.7"
                  />
                </label>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="step-view">
              <h2>Step 2: Choose Module</h2>
              <p className="step-lead">Chọn module hardening cụ thể theo OS/service đã lọc.</p>
              <label>
                Module
                <select
                  value={currentModule?.id || ''}
                  onChange={(e) => setSelectedId(e.target.value)}
                >
                  {filteredModules.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </select>
              </label>

              <div className="mode-grid">
                {['strict', 'balanced', 'quick'].map((mode) => (
                  <button
                    key={mode}
                    className={`mode-card ${scanMode === mode ? 'active' : ''}`}
                    onClick={() => setScanMode(mode)}
                  >
                    <h3>{mode.toUpperCase()}</h3>
                    <p>
                      {mode === 'strict' && 'Ưu tiên cảnh báo mạnh, pass rate thấp hơn.'}
                      {mode === 'balanced' && 'Mặc định cân bằng giữa độ nhạy và tính thực tiễn.'}
                      {mode === 'quick' && 'Ưu tiên tốc độ và chỉ báo các vấn đề chính.'}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="step-view">
              <h2>Step 3: Review and Confirm</h2>
              <p className="step-lead">Kiểm tra lại cấu hình trước khi chạy scan.</p>

              <div className="review-grid">
                <article>
                  <span>Target OS</span>
                  <strong>{osFamily}</strong>
                </article>
                <article>
                  <span>OS Version</span>
                  <strong>{osVersion || 'N/A'}</strong>
                </article>
                <article>
                  <span>Service</span>
                  <strong>{service}</strong>
                </article>
                <article>
                  <span>Service Version</span>
                  <strong>{serviceVersion || 'N/A'}</strong>
                </article>
                <article className="wide">
                  <span>Selected Module</span>
                  <strong>{currentModule ? currentModule.name : 'No module selected'}</strong>
                </article>
                <article className="wide">
                  <span>Scan Mode</span>
                  <strong>{scanMode}</strong>
                </article>
              </div>
            </div>
          )}

          {step === 4 && (
            <div className="step-view">
              <h2>Step 4: Scan Result</h2>
              <p className="step-lead">Kết quả hardening và tình trạng rule sau khi chạy scan.</p>

              {!result && !running && (
                <div className="empty-state">
                  <p>Chưa có kết quả scan.</p>
                  <p>Quay lại step trước để chạy scan.</p>
                </div>
              )}

              {running && (
                <div className="loader-wrap">
                  <div className="loader" />
                  <p>Đang phân tích cấu hình và tính điểm...</p>
                </div>
              )}

              {result && (
                <>
                  <div className="score-row">
                    <article className="metric">
                      <span>Hardening Index</span>
                      <strong>{result.hardeningIndex}</strong>
                    </article>
                    <article className={`metric ${gradeTone(result.grade)}`}>
                      <span>Grade</span>
                      <strong>{result.grade}</strong>
                    </article>
                    <article className="metric">
                      <span>Pass Ratio</span>
                      <strong>{result.passedChecks}/{result.totalChecks}</strong>
                    </article>
                  </div>

                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Code</th>
                          <th>Rule</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.rows.map((row) => (
                          <tr key={row.code}>
                            <td>{row.code}</td>
                            <td>{row.title}</td>
                            <td>{row.severity}</td>
                            <td>
                              <span className={row.passed ? 'pill pass' : 'pill fail'}>
                                {row.passed ? 'PASS' : 'FAIL'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          <footer className="wizard-actions">
            <button className="btn-ghost" onClick={resetFlow}>Reset</button>
            <div className="spacer" />
            <button className="btn-ghost" onClick={prevStep} disabled={step === 1}>Back</button>
            {step < 3 && <button className="btn-primary" onClick={nextStep}>Next</button>}
            {step === 3 && (
              <button className="btn-primary" onClick={onRun} disabled={!currentModule || running}>
                {running ? 'Scanning...' : 'Run Scan'}
              </button>
            )}
          </footer>
        </section>
      </main>
    </div>
  );
}
