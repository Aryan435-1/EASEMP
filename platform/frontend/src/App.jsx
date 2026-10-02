import React, { useState, useEffect } from 'react';
import './App.css';
import AttackSurfaceGraph from './AttackSurfaceGraph';

/**
 * EEIP — Enterprise Attack Surface & Exposure Management Platform
 * Main React Dashboard Component
 */
function App() {
  // =========================================================================
  // 1. STATE MANAGEMENT
  // =========================================================================
  // Store summary metrics: total_assets, total_findings, critical_count, high_count, medium_count, low_count
  const [summary, setSummary] = useState(null);

  // Store asset inventory list: [{id, hostname, ip, exposure, criticality, finding_count}, ...]
  const [assets, setAssets] = useState([]);

  // Store security findings list: [{id, asset_id, asset, port, product, version, cve_id, cvss_score, severity, known_exploited, risk_score, priority, confidence}, ...]
  const [findings, setFindings] = useState([]);

  // Indicator for loading status
  const [loading, setLoading] = useState(true);

  // Indicator for error state
  const [error, setError] = useState(null);

  // =========================================================================
  // 2. DATA FETCHING (API ENDPOINTS)
  // =========================================================================
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch all 3 endpoints concurrently using standard fetch API
        const [summaryRes, assetsRes, findingsRes] = await Promise.all([
          fetch('http://127.0.0.1:8000/api/summary'),
          fetch('http://127.0.0.1:8000/api/assets'),
          fetch('http://127.0.0.1:8000/api/findings')
        ]);

        // Check if any response returned a non-2xx status code
        if (!summaryRes.ok || !assetsRes.ok || !findingsRes.ok) {
          throw new Error('One or more backend API calls failed');
        }

        // Parse JSON responses
        const summaryData = await summaryRes.json();
        const assetsData = await assetsRes.json();
        const findingsData = await findingsRes.json();

        // Update state with fetched data
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

  // Helper function to map severity / priority level to specific color code
  const getSeverityColor = (level) => {
    const s = String(level || '').toLowerCase();
    switch (s) {
      case 'critical':
        return '#ef4444'; // Red
      case 'high':
        return '#f97316'; // Orange
      case 'medium':
        return '#eab308'; // Yellow
      case 'low':
        return '#22c55e'; // Green
      default:
        return '#9ca3af'; // Gray default
    }
  };

  // =========================================================================
  // 3. CONDITIONAL RENDER: ERROR & LOADING STATES
  // =========================================================================
  if (error) {
    return (
      <div className="app-container">
        <div className="error-message">{error}</div>
      </div>
    );
  }

  if (loading || !summary) {
    return (
      <div className="app-container">
        <div className="loading-message">Loading...</div>
      </div>
    );
  }

  // Check if both assets and findings are fully loaded for graph rendering
  const isGraphDataReady = Boolean(assets && assets.length > 0 && findings);

  // =========================================================================
  // 4. MAIN DASHBOARD UI RENDER
  // =========================================================================
  return (
    <div className="app-container">
      {/* Header Section */}
      <header className="dashboard-header">
        <h1>EEIP — Enterprise Attack Surface & Exposure Management Platform</h1>
      </header>

      {/* Summary Cards Section (4 cards in a row for Critical, High, Medium, Low) */}
      <section className="summary-cards-section">
        <div className="card card-critical" style={{ borderColor: getSeverityColor('critical') }}>
          <span className="card-title">Critical</span>
          <span className="card-value" style={{ color: getSeverityColor('critical') }}>
            {summary.critical_count ?? 0}
          </span>
        </div>
        <div className="card card-high" style={{ borderColor: getSeverityColor('high') }}>
          <span className="card-title">High</span>
          <span className="card-value" style={{ color: getSeverityColor('high') }}>
            {summary.high_count ?? 0}
          </span>
        </div>
        <div className="card card-medium" style={{ borderColor: getSeverityColor('medium') }}>
          <span className="card-title">Medium</span>
          <span className="card-value" style={{ color: getSeverityColor('medium') }}>
            {summary.medium_count ?? 0}
          </span>
        </div>
        <div className="card card-low" style={{ borderColor: getSeverityColor('low') }}>
          <span className="card-title">Low</span>
          <span className="card-value" style={{ color: getSeverityColor('low') }}>
            {summary.low_count ?? 0}
          </span>
        </div>
      </section>

      {/* Asset Inventory Section */}
      <section className="dashboard-section">
        <h2>Asset Inventory</h2>
        <div className="table-responsive">
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
                    <td>{asset.hostname}</td>
                    <td>{asset.ip}</td>
                    <td>{asset.exposure}</td>
                    <td>{asset.criticality}</td>
                    <td>{asset.finding_count}</td>
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
      <section className="dashboard-section">
        <h2>Attack Surface Graph</h2>
        {isGraphDataReady ? (
          <AttackSurfaceGraph assets={assets} findings={findings} />
        ) : (
          <div className="no-data">Graph data loading...</div>
        )}
      </section>

      {/* Findings Section */}
      <section className="dashboard-section">
        <h2>Findings</h2>
        <div className="table-responsive">
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
                findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>{finding.asset}</td>
                    <td>{finding.port}</td>
                    <td>{`${finding.product || ''} ${finding.version || ''}`.trim()}</td>
                    <td>{finding.cve_id}</td>
                    <td>{finding.risk_score}</td>
                    <td
                      style={{
                        color: getSeverityColor(finding.priority),
                        fontWeight: 'bold'
                      }}
                    >
                      {finding.priority}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="no-data">No findings available</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default App;
