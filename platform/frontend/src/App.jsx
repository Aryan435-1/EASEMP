import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';
import './App.css';
import AttackSurfaceGraph from './AttackSurfaceGraph';

/**
 * EEIP — Enterprise Attack Surface & Exposure Management Platform
 * Main React Dashboard Component (Premium SaaS Security Theme)
 */
function App() {
  // =========================================================================
  // 1. STATE MANAGEMENT (UNTOUCHED)
  // =========================================================================
  const [summary, setSummary] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // =========================================================================
  // 2. DATA FETCHING (UNTOUCHED)
  // =========================================================================
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        setError(null);

        const [summaryRes, assetsRes, findingsRes] = await Promise.all([
          fetch('http://127.0.0.1:8000/api/summary'),
          fetch('http://127.0.0.1:8000/api/assets'),
          fetch('http://127.0.0.1:8000/api/findings')
        ]);

        if (!summaryRes.ok || !assetsRes.ok || !findingsRes.ok) {
          throw new Error('One or more backend API calls failed');
        }

        const summaryData = await summaryRes.json();
        const assetsData = await assetsRes.json();
        const findingsData = await findingsRes.json();

        setSummary(summaryData);
        setAssets(assetsData);
        setFindings(findingsData);
      } catch (err) {
        console.error('Error fetching backend data:', err);
        setError('Could not connect to backend');
      } finally {
        setLoading(false);
      }
    };

    fetchDashboardData();
  }, []);

  const handleDownloadReport = () => {
    window.open('http://127.0.0.1:8000/api/report', '_blank');
  };

  // =========================================================================
  // 3. CONDITIONAL RENDER: ERROR & SKELETON LOADING STATES
  // =========================================================================
  if (error) {
    return (
      <div className="app-shell">
        <div className="main-content">
          <div className="error-message premium-card">{error}</div>
        </div>
      </div>
    );
  }

  if (loading || !summary) {
    return (
      <div className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-header">
            <div className="avatar-placeholder">EP</div>
            <div className="sidebar-logo">
              <svg className="logo-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2.5">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span className="logo-text">EEIP</span>
            </div>
          </div>
        </aside>
        <main className="main-content">
          <div className="skeleton-container premium-card">
            <div className="skeleton-bar skeleton-title"></div>
            <div className="skeleton-cards-grid">
              <div className="skeleton-bar skeleton-card"></div>
              <div className="skeleton-bar skeleton-card"></div>
              <div className="skeleton-bar skeleton-card"></div>
              <div className="skeleton-bar skeleton-card"></div>
            </div>
            <div className="skeleton-bar skeleton-table"></div>
          </div>
        </main>
      </div>
    );
  }

  const isGraphDataReady = Boolean(assets && assets.length > 0 && findings);

  // Prepare Recharts PieChart Data
  const pieData = [
    { name: 'Critical', value: summary.critical_count ?? 0, color: '#ef4444' },
    { name: 'High', value: summary.high_count ?? 0, color: '#f97316' },
    { name: 'Medium', value: summary.medium_count ?? 0, color: '#eab308' },
    { name: 'Low', value: summary.low_count ?? 0, color: '#22c55e' }
  ];

  // =========================================================================
  // 4. MAIN DASHBOARD UI RENDER (SPACIOUS & PREMIUM SAAS THEME)
  // =========================================================================
  return (
    <div className="app-shell">
      {/* Fixed Left Sidebar (~240px) */}
      <aside className="sidebar">
        <div className="sidebar-top">
          {/* User Avatar Placeholder & Platform Logo */}
          <div className="sidebar-header">
            <div className="avatar-placeholder" title="Enterprise User Profile">
              EP
            </div>
            <div className="sidebar-logo">
              <svg className="logo-icon" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span className="logo-text">EEIP</span>
            </div>
          </div>

          <nav className="sidebar-nav">
            <a href="#overview" className="nav-item active">
              <span className="nav-icon-wrapper">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="3" width="7" height="7" rx="1"/>
                  <rect x="14" y="3" width="7" height="7" rx="1"/>
                  <rect x="14" y="14" width="7" height="7" rx="1"/>
                  <rect x="3" y="14" width="7" height="7" rx="1"/>
                </svg>
              </span>
              <span>Overview</span>
            </a>
            <a href="#assets" className="nav-item">
              <span className="nav-icon-wrapper">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                  <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                  <line x1="6" y1="6" x2="6.01" y2="6"/>
                  <line x1="6" y1="18" x2="6.01" y2="18"/>
                </svg>
              </span>
              <span>Assets</span>
            </a>
            <a href="#topology" className="nav-item">
              <span className="nav-icon-wrapper">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="18" cy="5" r="3"/>
                  <circle cx="6" cy="12" r="3"/>
                  <circle cx="18" cy="19" r="3"/>
                  <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                  <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                </svg>
              </span>
              <span>Topology</span>
            </a>
            <a href="#findings" className="nav-item">
              <span className="nav-icon-wrapper">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </span>
              <span>Findings</span>
            </a>
          </nav>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-footer-text">EEIP v1.0 — Minor Project</div>
        </div>
      </aside>

      {/* Main Content Scroll Area */}
      <main className="main-content">
        {/* Top Bar Row (Dashboard title, View selector & Download Pill Button) */}
        <div className="top-bar-row">
          <div className="top-bar-left">
            <h1 className="dashboard-title">Dashboard</h1>
            <div className="view-breadcrumb">
              <span>Current View / EEIP Default</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="6 9 12 15 18 9"></polyline>
              </svg>
            </div>
            <span className="status-badge">
              <span className="pulse-dot"></span>
              LIVE
            </span>
          </div>

          <div className="top-bar-right">
            <button className="btn-download-pill" onClick={handleDownloadReport}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              <span>Download Report</span>
            </button>
          </div>
        </div>

        {/* 4 Summary Cards in a Row (Rounded 2xl, Soft Tinted Icon Badges & Colored Shadows) */}
        <section id="overview" className="summary-cards-section">
          {/* Critical Card */}
          <div className="card card-critical premium-card">
            <div className="card-top-row">
              <div className="icon-badge icon-badge-critical">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </div>
              <span className="card-title">Critical</span>
            </div>
            <span className="card-value" style={{ color: '#ef4444' }}>
              {summary.critical_count ?? 0}
            </span>
          </div>

          {/* High Card */}
          <div className="card card-high premium-card">
            <div className="card-top-row">
              <div className="icon-badge icon-badge-high">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </div>
              <span className="card-title">High</span>
            </div>
            <span className="card-value" style={{ color: '#f97316' }}>
              {summary.high_count ?? 0}
            </span>
          </div>

          {/* Medium Card */}
          <div className="card card-medium premium-card">
            <div className="card-top-row">
              <div className="icon-badge icon-badge-medium">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#eab308" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="16" x2="12" y2="12"/>
                  <line x1="12" y1="8" x2="12.01" y2="8"/>
                </svg>
              </div>
              <span className="card-title">Medium</span>
            </div>
            <span className="card-value" style={{ color: '#eab308' }}>
              {summary.medium_count ?? 0}
            </span>
          </div>

          {/* Low Card */}
          <div className="card card-low premium-card">
            <div className="card-top-row">
              <div className="icon-badge icon-badge-low">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                  <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
              </div>
              <span className="card-title">Low</span>
            </div>
            <span className="card-value" style={{ color: '#22c55e' }}>
              {summary.low_count ?? 0}
            </span>
          </div>
        </section>

        {/* Recharts Donut Chart Section: "Findings by Severity" */}
        <section className="dashboard-section">
          <div className="donut-chart-card premium-card">
            <div className="donut-card-header">
              <h2>Findings by Severity</h2>
              <span className="section-description">Distribution of vulnerabilities across risk levels</span>
            </div>

            <div className="donut-content-layout">
              {/* Donut Chart with Centered Overlay */}
              <div className="donut-chart-wrapper">
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={90}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="#1e293b" strokeWidth={2} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="donut-center-label">
                  <span className="donut-total-count">{summary.total_findings ?? 0}</span>
                  <span className="donut-total-text">Total</span>
                </div>
              </div>

              {/* Donut Chart Severity Breakdown Legend */}
              <div className="donut-legend-grid">
                {pieData.map((item) => (
                  <div key={item.name} className="donut-legend-item">
                    <span className="donut-legend-dot" style={{ backgroundColor: item.color }}></span>
                    <span className="donut-legend-name">{item.name}</span>
                    <span className="donut-legend-count" style={{ color: item.color }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Asset Inventory Section */}
        <section id="assets" className="dashboard-section">
          <div className="section-header-block">
            <div className="section-title-row">
              <svg className="section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                <line x1="6" y1="6" x2="6.01" y2="6"/>
                <line x1="6" y1="18" x2="6.01" y2="18"/>
              </svg>
              <div>
                <span className="section-label">OVERVIEW</span>
                <h2>Asset Inventory</h2>
              </div>
            </div>
            <p className="section-description">
              All discovered assets within the authorized scan scope
            </p>
          </div>

          <div className="table-responsive premium-card">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>Exposure</th>
                  <th>Criticality</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {assets && assets.length > 0 ? (
                  assets.map((asset) => (
                    <tr key={asset.id || asset.hostname}>
                      <td className="font-mono">{asset.hostname}</td>
                      <td className="font-mono">{asset.ip}</td>
                      <td>
                        <span className={`badge badge-exposure badge-${String(asset.exposure || '').toLowerCase()}`}>
                          {asset.exposure}
                        </span>
                      </td>
                      <td>{asset.criticality}</td>
                      <td className="font-mono">{asset.finding_count}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" className="no-data">No assets found</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Attack Surface Graph Section */}
        <section id="topology" className="dashboard-section">
          <div className="section-header-block">
            <div className="section-title-row">
              <svg className="section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                <circle cx="18" cy="5" r="3"/>
                <circle cx="6" cy="12" r="3"/>
                <circle cx="18" cy="19" r="3"/>
                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
              </svg>
              <div>
                <span className="section-label">TOPOLOGY</span>
                <h2>Attack Surface Graph</h2>
              </div>
            </div>
            <p className="section-description">
              Interactive visual map of attack paths and entry-point exposure topology
            </p>
          </div>

          {isGraphDataReady ? (
            <AttackSurfaceGraph assets={assets} findings={findings} />
          ) : (
            <div className="no-data premium-card">Graph data loading...</div>
          )}
        </section>

        {/* Findings Section */}
        <section id="findings" className="dashboard-section">
          <div className="section-header-block">
            <div className="section-title-row">
              <svg className="section-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <div>
                <span className="section-label">VULNERABILITIES</span>
                <h2>Findings</h2>
              </div>
            </div>
            <p className="section-description">
              Identified vulnerabilities, misconfigurations, and risk prioritization scores
            </p>
          </div>

          <div className="table-responsive premium-card">
            <table className="dashboard-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Port</th>
                  <th>Product/Version</th>
                  <th>CVE</th>
                  <th>Risk Score</th>
                  <th>Priority</th>
                </tr>
              </thead>
              <tbody>
                {findings && findings.length > 0 ? (
                  findings.map((finding) => {
                    const isCritical = String(finding.priority || '').toLowerCase() === 'critical';
                    return (
                      <tr key={finding.id} className={isCritical ? 'row-critical' : ''}>
                        <td className="font-mono">{finding.asset}</td>
                        <td className="font-mono">{finding.port}</td>
                        <td>{`${finding.product || ''} ${finding.version || ''}`.trim()}</td>
                        <td className="font-mono">{finding.cve_id}</td>
                        <td className="font-mono">{finding.risk_score}</td>
                        <td>
                          <span className={`badge badge-priority badge-${String(finding.priority || '').toLowerCase()}`}>
                            {finding.priority}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan="6" className="no-data">No findings available</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {/* Dashboard Footer */}
        <footer className="dashboard-footer">
          <p>Generated by EEIP — Enterprise Attack Surface & Exposure Management Platform</p>
        </footer>
      </main>
    </div>
  );
}

export default App;
