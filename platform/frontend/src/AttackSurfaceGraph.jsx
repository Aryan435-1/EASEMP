import React from 'react';

/**
 * AttackSurfaceGraph Component
 *
 * Renders a visual network layout of target assets using SVG:
 * - Top Node: Internet (Fixed entry point)
 * - Row 1: External Assets (directly reachable from Internet)
 * - Row 2: Internal Assets (connected via modeled pivot-point topology)
 *
 * PIPELINED TOPOLOGY & PIVOT-POINT ASSUMPTION:
 * Internal assets are connected to the external asset with the HIGHEST criticality value.
 * In a real enterprise network, attackers pivot through the most critical, exposed edge systems
 * to reach internal segments. This node positioning models that attack vector simplification.
 * If no external assets exist, internal assets connect directly to the Internet node.
 */
function AttackSurfaceGraph({ assets = [], findings = [] }) {
  // Return empty container if no assets provided
  if (!assets || assets.length === 0) {
    return null;
  }

  // 1. Helper function to compute MAX risk_score for a given asset
  const getMaxRiskScore = (hostname) => {
    const assetFindings = findings.filter((f) => f.asset === hostname);
    if (assetFindings.length === 0) return 0;
    return Math.max(...assetFindings.map((f) => Number(f.risk_score) || 0));
  };

  // 2. Helper function to map risk score to severity color matching dashboard
  const getRiskColor = (score) => {
    if (score >= 76) return '#ef4444'; // Red / Critical (>=76)
    if (score >= 51) return '#f97316'; // Orange / High (51-75)
    if (score >= 26) return '#eab308'; // Yellow / Medium (26-50)
    return '#22c55e'; // Green / Low (<=25)
  };

  // 3. Classify assets into External vs Internal exposure
  const externalList = assets.filter(
    (a) => String(a.exposure || '').toLowerCase() === 'external'
  );
  const internalList = assets.filter(
    (a) => String(a.exposure || '').toLowerCase() !== 'external'
  );

  // 4. Determine Pivot External Asset (highest criticality score)
  let pivotAssetRaw = null;
  if (externalList.length > 0) {
    pivotAssetRaw = externalList.reduce((highest, current) => {
      const currentCrit = Number(current.criticality) || 0;
      const highestCrit = Number(highest.criticality) || 0;
      return currentCrit > highestCrit ? current : highest;
    }, externalList[0]);
  }

  // SVG Canvas configuration
  const width = 800;
  const height = 450;
  const nodeRadius = 28;

  // Internet node position (Top Center)
  const internetNode = {
    id: 'internet-node',
    label: 'Internet',
    x: width / 2,
    y: 65,
    color: '#38bdf8' // Distinct neutral blue color for non-scored Internet node
  };

  // Compute X positions for External Assets (Row 1, Y = 210)
  const externalY = 210;
  const externalNodes = externalList.map((asset, index) => {
    const x = ((index + 1) * width) / (externalList.length + 1);
    const maxRisk = getMaxRiskScore(asset.hostname);
    return {
      ...asset,
      x,
      y: externalY,
      maxRisk,
      color: getRiskColor(maxRisk)
    };
  });

  // Identify positioned Pivot Asset node
  const pivotNode = pivotAssetRaw
    ? externalNodes.find((node) => node.hostname === pivotAssetRaw.hostname)
    : null;

  // Compute X positions for Internal Assets (Row 2, Y = 360)
  const internalY = 360;
  const internalNodes = internalList.map((asset, index) => {
    const x = ((index + 1) * width) / (internalList.length + 1);
    const maxRisk = getMaxRiskScore(asset.hostname);
    return {
      ...asset,
      x,
      y: internalY,
      maxRisk,
      color: getRiskColor(maxRisk)
    };
  });

  return (
    <div className="attack-surface-graph-container">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="attack-surface-svg"
        style={{ width: '100%', height: 'auto', display: 'block' }}
      >
        {/* =========================================================================
            LAYER 1: CONNECTING LINES (Rendered first so they sit BEHIND nodes)
           ========================================================================= */}
        <g className="graph-edges">
          {/* Lines connecting Internet -> External Assets */}
          {externalNodes.map((node) => (
            <line
              key={`edge-internet-${node.id || node.hostname}`}
              x1={internetNode.x}
              y1={internetNode.y}
              x2={node.x}
              y2={node.y}
              stroke="#64748b"
              strokeWidth="2.5"
              strokeDasharray="4 4"
            />
          ))}

          {/* Lines connecting Internal Assets -> Pivot External Asset (or Internet if no external assets exist) */}
          {internalNodes.map((node) => {
            const target = pivotNode || internetNode;
            return (
              <line
                key={`edge-pivot-${node.id || node.hostname}`}
                x1={target.x}
                y1={target.y}
                x2={node.x}
                y2={node.y}
                stroke="#475569"
                strokeWidth="2.5"
              />
            );
          })}
        </g>

        {/* =========================================================================
            LAYER 2: INTERNET NODE (Fixed Top Center)
           ========================================================================= */}
        <g className="graph-node internet-node">
          <circle
            cx={internetNode.x}
            cy={internetNode.y}
            r={nodeRadius}
            fill="#1e293b"
            stroke={internetNode.color}
            strokeWidth="3.5"
          />
          {/* Cloud icon or label inside Internet node */}
          <text
            x={internetNode.x}
            y={internetNode.y + 4}
            fill="#38bdf8"
            fontSize="12"
            fontWeight="bold"
            textAnchor="middle"
          >
            WAN
          </text>
          {/* Label below Internet node */}
          <text
            x={internetNode.x}
            y={internetNode.y + nodeRadius + 16}
            fill="#94a3b8"
            fontSize="13"
            fontWeight="600"
            textAnchor="middle"
          >
            Internet
          </text>
        </g>

        {/* =========================================================================
            LAYER 3: EXTERNAL ASSET NODES
           ========================================================================= */}
        {externalNodes.map((node) => (
          <g key={`node-ext-${node.id || node.hostname}`} className="graph-node external-node">
            <circle
              cx={node.x}
              cy={node.y}
              r={nodeRadius}
              fill="#1e293b"
              stroke={node.color}
              strokeWidth="3.5"
            />
            {/* Risk score badge inside circle */}
            <text
              x={node.x}
              y={node.y + 5}
              fill="#f8fafc"
              fontSize="13"
              fontWeight="bold"
              textAnchor="middle"
            >
              {node.maxRisk}
            </text>
            {/* Hostname label below circle */}
            <text
              x={node.x}
              y={node.y + nodeRadius + 16}
              fill="#e2e8f0"
              fontSize="12"
              fontWeight="500"
              textAnchor="middle"
            >
              {node.hostname}
            </text>
            {/* Exposure tag */}
            <text
              x={node.x}
              y={node.y + nodeRadius + 30}
              fill="#64748b"
              fontSize="10"
              textAnchor="middle"
            >
              [External]
            </text>
          </g>
        ))}

        {/* =========================================================================
            LAYER 4: INTERNAL ASSET NODES
           ========================================================================= */}
        {internalNodes.map((node) => (
          <g key={`node-int-${node.id || node.hostname}`} className="graph-node internal-node">
            <circle
              cx={node.x}
              cy={node.y}
              r={nodeRadius}
              fill="#1e293b"
              stroke={node.color}
              strokeWidth="3.5"
            />
            {/* Risk score badge inside circle */}
            <text
              x={node.x}
              y={node.y + 5}
              fill="#f8fafc"
              fontSize="13"
              fontWeight="bold"
              textAnchor="middle"
            >
              {node.maxRisk}
            </text>
            {/* Hostname label below circle */}
            <text
              x={node.x}
              y={node.y + nodeRadius + 16}
              fill="#e2e8f0"
              fontSize="12"
              fontWeight="500"
              textAnchor="middle"
            >
              {node.hostname}
            </text>
            {/* Exposure tag */}
            <text
              x={node.x}
              y={node.y + nodeRadius + 30}
              fill="#64748b"
              fontSize="10"
              textAnchor="middle"
            >
              [Internal]
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export default AttackSurfaceGraph;
