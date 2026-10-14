
import { useCallback, useEffect, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:5000";

function App() {
  const [page, setPage] = useState("Overview");
  const [mode, setMode] = useState("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [stats, setStats] = useState({
    total: 0, high_risk: 0, url_scans: 0, message_scans: 0
  });
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadDashboard = useCallback(async () => {
    try {
      const [statsResponse, historyResponse] = await Promise.all([
        fetch(`${API}/api/stats`),
        fetch(`${API}/api/history`)
      ]);

      if (!statsResponse.ok || !historyResponse.ok) {
        throw new Error("Could not load dashboard data.");
      }

      setStats(await statsResponse.json());
      setHistory(await historyResponse.json());
    } catch {
      setError("Unable to load dashboard data. Check that Flask is running.");
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  function openScanner(type) {
    setMode(type);
    setPage(type === "url" ? "URL Scanner" : "Message Scanner");
    setResult(null);
    setError("");
  }

  async function handleScan(event) {
    event.preventDefault();
    const value = mode === "url" ? url.trim() : message.trim();

    if (!value) {
      setError("Enter something to scan first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API}/api/scan-${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          mode === "url" ? { url: value } : { message: value }
        )
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "The scan failed.");
      }

      setResult(data);
      await loadDashboard();
    } catch (err) {
      setError(err.message || "Could not connect to Flask.");
    } finally {
      setLoading(false);
    }
  }

  const navItems = [
    { name: "Overview", icon: "▦" },
    { name: "URL Scanner", icon: "↗" },
    { name: "Message Scanner", icon: "☷" },
    { name: "Recent Activity", icon: "◷" }
  ];

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">CR</span>
          <span>Cyber<span>Rakshak</span></span>
        </div>

        <p className="nav-label">WORKSPACE</p>
        <nav>
          {navItems.map((item) => (
            <button
              key={item.name}
              className={`nav-item ${page === item.name ? "selected" : ""}`}
              onClick={() => {
                setPage(item.name);
                setResult(null);
                setError("");
              }}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.name}
              {page === item.name && <span className="nav-active" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <span className="online-dot" />
          Local detection engine
          <small>CyberRakshak · Prototype</small>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="breadcrumb">CYBERRAKSHAK / WORKSPACE</p>
            <h1>{page}</h1>
          </div>
          <div className="system-status">
            <span className="online-dot" />
            Detection console
          </div>
        </header>

        {page === "Overview" && (
          <>
            <section className="welcome">
              <div>
                <p className="eyebrow">SECURITY OVERVIEW</p>
                <h2>Monitor your digital safety.</h2>
                <p>Scan URLs and messages for common warning signs.</p>
              </div>
              <button className="primary" onClick={() => openScanner("url")}>
                + New scan
              </button>
            </section>

            <section className="stats-grid">
              <StatCard title="Total scans" value={stats.total} icon="⌕" />
              <StatCard title="High-risk results" value={stats.high_risk} icon="⚠" />
              <StatCard title="URL scans" value={stats.url_scans} icon="↗" />
              <StatCard title="Message scans" value={stats.message_scans} icon="☷" />
            </section>

            <section className="panel quick-panel">
              <div className="section-heading">
                <div>
                  <h2>Quick scan</h2>
                  <p>Choose what you want to inspect.</p>
                </div>
              </div>
              <div className="quick-grid">
                <button className="quick-card" onClick={() => openScanner("url")}>
                  <span className="quick-icon">↗</span>
                  <strong>URL threat scanner</strong>
                  <span>Check suspicious web addresses</span>
                  <b>Open scanner →</b>
                </button>
                <button className="quick-card" onClick={() => openScanner("message")}>
                  <span className="quick-icon">☷</span>
                  <strong>Message scanner</strong>
                  <span>Inspect possible scam messages</span>
                  <b>Open scanner →</b>
                </button>
              </div>
            </section>

            <HistoryPanel history={history.slice(0, 5)} onViewAll={() => setPage("Recent Activity")} />
          </>
        )}

        {(page === "URL Scanner" || page === "Message Scanner") && (
          <section className="panel scanner-panel">
            <p className="eyebrow">THREAT ANALYSIS</p>
            <h2>{mode === "url" ? "Analyze a website URL" : "Analyze a message"}</h2>
            <p className="muted">
              {mode === "url"
                ? "Look for suspicious URL patterns without opening the website."
                : "Inspect the text for common scam and phishing indicators."}
            </p>

            <div className="scanner-tabs">
              <button className={mode === "url" ? "tab-active" : ""} onClick={() => openScanner("url")}>↗ URL scanner</button>
              <button className={mode === "message" ? "tab-active" : ""} onClick={() => openScanner("message")}>☷ Message scanner</button>
            </div>

            <form onSubmit={handleScan}>
              {mode === "url" ? (
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  aria-label="URL to scan"
                />
              ) : (
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Paste a suspicious SMS, email, or message..."
                  rows={5}
                  aria-label="Message to scan"
                />
              )}
              <button className="primary scan-submit" disabled={loading}>
                {loading ? "Analyzing..." : "⌕  Scan for threats"}
              </button>
            </form>

            {error && <p className="error">{error}</p>}
            {result && <ResultPanel result={result} />}
          </section>
        )}

        {page === "Recent Activity" && (
          <HistoryPanel history={history} onRefresh={loadDashboard} />
        )}

        {error && page === "Overview" && <p className="error">{error}</p>}

        <footer>
          <span>CyberRakshak · Security analysis prototype</span>
          <span>Results are indicators, not proof of malicious activity.</span>
        </footer>
      </main>
    </div>
  );
}

function StatCard({ title, value, icon }) {
  return (
    <article className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <strong>{value.toLocaleString()}</strong>
      <span className="stat-caption">Recorded in local history</span>
    </article>
  );
}

function HistoryPanel({ history, onViewAll, onRefresh }) {
  return (
    <section className="panel history-panel">
      <div className="section-heading">
        <div>
          <h2>Recent activity</h2>
          <p>Latest scans saved by the detection API.</p>
        </div>
        {onViewAll && <button className="text-button" onClick={onViewAll}>View all →</button>}
        {onRefresh && <button className="text-button" onClick={onRefresh}>Refresh ↻</button>}
      </div>

      {history.length === 0 ? (
        <div className="empty-state">
          <span>◷</span>
          <strong>No scans recorded yet</strong>
          <p>Your completed scans will appear here.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>TYPE / INPUT</th>
                <th>RISK</th>
                <th>SCORE</th>
                <th>TIME</th>
              </tr>
            </thead>
            <tbody>
              {history.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <span className="scan-type">{scan.type === "url" ? "↗ URL" : "☷ MESSAGE"}</span>
                    <span className="scan-input" title={scan.input}>{scan.input}</span>
                  </td>
                  <td><span className={`risk risk-${scan.risk.toLowerCase()}`}>{scan.risk}</span></td>
                  <td>{scan.score}/100</td>
                  <td>{new Date(scan.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ResultPanel({ result }) {
  return (
    <div className="result-panel">
      <div className="result-title">
        <h3>Scan report</h3>
        <span className={`risk risk-${result.risk.toLowerCase()}`}>{result.risk} risk</span>
      </div>
      <div className="result-score">
        <strong>{result.score}<small> / 100</small></strong>
        <div className="score-track">
          <div className="score-fill" style={{ width: `${Math.min(100, Math.max(0, result.score))}%` }} />
        </div>
      </div>
      <h4>Detected indicators</h4>
      <ul className="reason-list">
        {result.reasons.map((reason, index) => <li key={index}>{reason}</li>)}
      </ul>
      <p className="disclaimer">This rule-based result is not a guarantee that an item is safe or malicious.</p>
    </div>
  );
}

export default App;
