# pedetect/html_report.py
"""
Full Interactive HTML Report Generator.
Produces a standalone HTML file with:
- D3.js entropy visualizations
- Spectral mapping (entropy as colored ribbon)
- Contextual anomaly highlighting
- Weighted scoring breakdown
- Evidence chain display
"""
import json


def generate_full_html_report(result: dict) -> str:
    """Generate a production-grade standalone HTML report with D3.js."""
    data_json = json.dumps(result, indent=2)
    verdict_colors = {
        'CLEAN': '#27ae60',
        'SUSPICIOUS': '#f39c12',
        'PACKED': '#e74c3c',
        'ERROR': '#95a5a6'
    }
    verdict_color = verdict_colors.get(result['verdict'], '#333')
    section_entropy = result.get('section_entropy', [])
    heuristics = result.get('heuristics', {})
    evidence_chain = result.get('evidence_chain', [])
    overlay = result.get('overlay', {})

    # Build section entropy JSON for D3.js
    section_data_json = json.dumps(section_entropy)

    # Build heuristic scoring data for D3.js
    scoring_data = []
    for name, info in heuristics.items():
        scoring_data.append({
            'name': name.replace('_', ' ').title(),
            'score': info['score'],
            'weight': info.get('weight', 0.5),
            'contribution': round(info['score'] * info.get('weight', 0.5), 4),
            'evidence': info.get('evidence', [])
        })
    scoring_json = json.dumps(scoring_data)

    # Contextual anomaly flags
    anomaly_sections = []
    for sec in section_entropy:
        is_anomaly = False
        reason = ""
        if sec['entropy'] > 7.0 and not sec['name'].startswith('[OVERLAY'):
            if sec['name'] in ['.text', '.code', 'CODE']:
                is_anomaly = True
                reason = "High entropy in executable section — likely encrypted payload"
            elif sec['name'] in ['.rsrc', '.rdata']:
                is_anomaly = True
                reason = "High entropy in resource/data section — possible hidden payload"
            else:
                is_anomaly = True
                reason = "High entropy detected — potential obfuscation"
        elif sec['entropy'] > 7.5:
            is_anomaly = True
            reason = "Extreme entropy — strong packing indicator"
        anomaly_sections.append({
            'name': sec['name'],
            'entropy': sec['entropy'],
            'anomaly': is_anomaly,
            'reason': reason
        })
    anomaly_json = json.dumps(anomaly_sections)

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PE Forensic Report — {result['file']['path']}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
    background: #0a0a1a;
    color: #e0e0e0;
    padding: 24px;
    line-height: 1.6;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 0;
    border-bottom: 2px solid #1a1a3e;
    margin-bottom: 24px;
  }}
  .header h1 {{ font-size: 1.4em; color: #e94560; font-weight: 700; }}
  .header .version {{ color: #666; font-size: 0.8em; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
  .grid-full {{ grid-column: 1 / -1; }}
  .card {{
    background: #12122a;
    border: 1px solid #1a1a3e;
    border-radius: 8px;
    padding: 20px;
  }}
  .card h2 {{
    font-size: 0.9em;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #7b7baa;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1a1a3e;
  }}
  .verdict-display {{
    text-align: center;
    padding: 24px;
  }}
  .verdict-text {{
    font-size: 2.4em;
    font-weight: 900;
    color: {verdict_color};
    letter-spacing: 2px;
  }}
  .confidence-text {{
    font-size: 1.2em;
    color: #888;
    margin-top: 8px;
  }}
  .file-info table {{ width: 100%; }}
  .file-info td {{ padding: 6px 0; vertical-align: top; }}
  .file-info td:first-child {{ color: #7b7baa; width: 80px; font-size: 0.85em; text-transform: uppercase; }}
  .file-info td:last-child {{ color: #ccc; word-break: break-all; font-size: 0.85em; }}
  .spectral-map {{
    width: 100%;
    height: 60px;
    border-radius: 4px;
    overflow: hidden;
    margin: 12px 0;
  }}
  #entropy-chart {{ width: 100%; height: 280px; }}
  #scoring-chart {{ width: 100%; height: 280px; }}
  .evidence-list {{ list-style: none; padding: 0; max-height: 400px; overflow-y: auto; }}
  .evidence-list li {{
    padding: 8px 12px;
    border-bottom: 1px solid #1a1a3e;
    font-size: 0.85em;
    transition: background 0.2s;
  }}
  .evidence-list li:hover {{ background: #1a1a3e; }}
  .evidence-list li::before {{ content: "▸ "; color: #e94560; }}
  .anomaly-badge {{
    display: inline-block;
    background: rgba(233, 69, 96, 0.15);
    border: 1px solid #e94560;
    color: #e94560;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75em;
    margin-left: 8px;
  }}
  .anomaly-row {{ background: rgba(233, 69, 96, 0.05) !important; }}
  .tooltip {{
    position: absolute;
    background: #1a1a3e;
    border: 1px solid #e94560;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 0.8em;
    pointer-events: none;
    z-index: 1000;
  }}
  .section-table {{ width: 100%; border-collapse: collapse; }}
  .section-table th {{
    text-align: left;
    padding: 8px;
    color: #7b7baa;
    font-size: 0.8em;
    text-transform: uppercase;
    border-bottom: 1px solid #1a1a3e;
  }}
  .section-table td {{ padding: 8px; font-size: 0.85em; border-bottom: 1px solid #0f0f2a; }}
  .bar-cell {{ width: 200px; }}
  .entropy-bar {{
    height: 18px;
    border-radius: 3px;
    transition: width 0.3s;
  }}
  .raw-json {{ display: none; }}
  .raw-json.active {{ display: block; }}
  .toggle-btn {{
    background: #1a1a3e;
    border: 1px solid #333;
    color: #aaa;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.8em;
    margin-top: 12px;
  }}
  .toggle-btn:hover {{ background: #2a2a4e; color: #fff; }}
  pre {{ background: #080818; padding: 16px; border-radius: 6px; overflow-x: auto; font-size: 0.75em; max-height: 400px; overflow-y: auto; }}
  .overlay-info {{ color: #f39c12; font-size: 0.9em; margin-top: 8px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>PE Obfuscation Detector</h1>
    <span class="version">v{result['metadata']['version']} | {result['metadata']['timestamp']}</span>
  </div>

  <div class="grid">
    <!-- Verdict -->
    <div class="card verdict-display">
      <h2>Verdict</h2>
      <div class="verdict-text">{result['verdict']}</div>
      <div class="confidence-text">{result['confidence']:.1%} confidence</div>
    </div>

    <!-- File Info -->
    <div class="card file-info">
      <h2>File Information</h2>
      <table>
        <tr><td>Path</td><td>{result['file']['path']}</td></tr>
        <tr><td>MD5</td><td>{result['file']['md5']}</td></tr>
        <tr><td>SHA256</td><td>{result['file']['sha256']}</td></tr>
        <tr><td>Size</td><td>{result['file']['size']:,} bytes</td></tr>
      </table>
      {"<p class='overlay-info'>Overlay: " + str(overlay.get('size', 0)) + " bytes (entropy: " + str(overlay.get('entropy', 0)) + ")</p>" if overlay.get('size', 0) > 0 else ""}
    </div>

    <!-- Spectral Map -->
    <div class="card grid-full">
      <h2>Spectral Entropy Map</h2>
      <p style="color:#666;font-size:0.8em;margin-bottom:8px;">Each block represents a PE section. Color intensity maps to entropy value. Click a block for details.</p>
      <div id="spectral-map" class="spectral-map"></div>
      <div id="spectral-tooltip" style="color:#888;font-size:0.85em;margin-top:8px;min-height:20px;"></div>
    </div>

    <!-- Entropy Bar Chart -->
    <div class="card">
      <h2>Section Entropy Analysis</h2>
      <div id="entropy-chart"></div>
    </div>

    <!-- Scoring Breakdown -->
    <div class="card">
      <h2>Weighted Scoring</h2>
      <div id="scoring-chart"></div>
    </div>

    <!-- Section Table with Anomaly Highlighting -->
    <div class="card grid-full">
      <h2>Section Detail & Anomaly Detection</h2>
      <table class="section-table" id="section-table">
        <thead>
          <tr><th>Section</th><th>Entropy</th><th>Visual</th><th>Status</th></tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

    <!-- Evidence Chain -->
    <div class="card grid-full">
      <h2>Evidence Chain ({len(evidence_chain)} findings)</h2>
      <ul class="evidence-list">
        {''.join(f'<li>{e}</li>' for e in evidence_chain)}
      </ul>
    </div>

    <!-- Raw JSON -->
    <div class="card grid-full">
      <h2>Raw Analysis Data</h2>
      <button class="toggle-btn" onclick="document.getElementById('raw-json').classList.toggle('active')">Toggle Raw JSON</button>
      <div id="raw-json" class="raw-json">
        <pre><code>{data_json}</code></pre>
      </div>
    </div>
  </div>
</div>

<script>
// Data
const sectionData = {section_data_json};
const scoringData = {scoring_json};
const anomalyData = {anomaly_json};

// Color scale for entropy (blue=low, yellow=mid, red=high)
const entropyColor = d3.scaleLinear()
  .domain([0, 3, 5, 7, 8])
  .range(['#1a5276', '#2980b9', '#f39c12', '#e74c3c', '#8e44ad']);

// === SPECTRAL MAP ===
(function() {{
  const container = document.getElementById('spectral-map');
  const width = container.clientWidth;
  const height = 60;
  const svg = d3.select('#spectral-map')
    .append('svg')
    .attr('width', width)
    .attr('height', height);

  const totalEntropy = sectionData.reduce((sum, d) => sum + d.entropy, 0);
  let x = 0;

  sectionData.forEach((d, i) => {{
    const blockWidth = Math.max((d.entropy / totalEntropy) * width, 20);
    const isAnomaly = anomalyData[i] && anomalyData[i].anomaly;

    const rect = svg.append('rect')
      .attr('x', x)
      .attr('y', 0)
      .attr('width', blockWidth - 1)
      .attr('height', height)
      .attr('fill', entropyColor(d.entropy))
      .attr('rx', 2)
      .style('cursor', 'pointer')
      .style('stroke', isAnomaly ? '#e94560' : 'none')
      .style('stroke-width', isAnomaly ? '2px' : '0');

    rect.on('click', function() {{
      const tooltip = document.getElementById('spectral-tooltip');
      let msg = `<strong>${{d.name}}</strong> — Entropy: ${{d.entropy.toFixed(2)}}`;
      if (isAnomaly) {{
        msg += ` <span style="color:#e94560;">⚠ ${{anomalyData[i].reason}}</span>`;
      }}
      tooltip.innerHTML = msg;
    }});

    x += blockWidth;
  }});
}})();

// === ENTROPY BAR CHART ===
(function() {{
  const margin = {{top: 20, right: 20, bottom: 40, left: 100}};
  const container = document.getElementById('entropy-chart');
  const width = container.clientWidth - margin.left - margin.right;
  const height = 260 - margin.top - margin.bottom;

  const svg = d3.select('#entropy-chart')
    .append('svg')
    .attr('width', width + margin.left + margin.right)
    .attr('height', height + margin.top + margin.bottom)
    .append('g')
    .attr('transform', `translate(${{margin.left}},${{margin.top}})`);

  const x = d3.scaleLinear().domain([0, 8]).range([0, width]);
  const y = d3.scaleBand().domain(sectionData.map(d => d.name)).range([0, height]).padding(0.3);

  svg.append('g')
    .attr('transform', `translate(0,${{height}})`)
    .call(d3.axisBottom(x).ticks(8))
    .selectAll('text').style('fill', '#888');

  svg.append('g')
    .call(d3.axisLeft(y))
    .selectAll('text').style('fill', '#ccc').style('font-size', '11px');

  svg.selectAll('.bar')
    .data(sectionData)
    .join('rect')
    .attr('x', 0)
    .attr('y', d => y(d.name))
    .attr('width', d => x(d.entropy))
    .attr('height', y.bandwidth())
    .attr('fill', d => entropyColor(d.entropy))
    .attr('rx', 3);

  // Threshold line at 7.0
  svg.append('line')
    .attr('x1', x(7)).attr('x2', x(7))
    .attr('y1', 0).attr('y2', height)
    .attr('stroke', '#e94560').attr('stroke-dasharray', '4,4').attr('opacity', 0.7);

  svg.append('text')
    .attr('x', x(7) + 4).attr('y', 12)
    .text('Threshold (7.0)')
    .style('fill', '#e94560').style('font-size', '10px');

  svg.selectAll('.domain, .tick line').style('stroke', '#333');
}})();

// === SCORING CHART ===
(function() {{
  const margin = {{top: 20, right: 20, bottom: 40, left: 140}};
  const container = document.getElementById('scoring-chart');
  const width = container.clientWidth - margin.left - margin.right;
  const height = 260 - margin.top - margin.bottom;

  const svg = d3.select('#scoring-chart')
    .append('svg')
    .attr('width', width + margin.left + margin.right)
    .attr('height', height + margin.top + margin.bottom)
    .append('g')
    .attr('transform', `translate(${{margin.left}},${{margin.top}})`);

  const maxContrib = d3.max(scoringData, d => d.contribution) || 1;
  const x = d3.scaleLinear().domain([0, Math.max(maxContrib, 1)]).range([0, width]);
  const y = d3.scaleBand().domain(scoringData.map(d => d.name)).range([0, height]).padding(0.3);

  svg.append('g')
    .attr('transform', `translate(0,${{height}})`)
    .call(d3.axisBottom(x).ticks(5))
    .selectAll('text').style('fill', '#888');

  svg.append('g')
    .call(d3.axisLeft(y))
    .selectAll('text').style('fill', '#ccc').style('font-size', '11px');

  const contribColor = d3.scaleLinear()
    .domain([0, 0.3, 0.7])
    .range(['#27ae60', '#f39c12', '#e74c3c']);

  svg.selectAll('.bar')
    .data(scoringData)
    .join('rect')
    .attr('x', 0)
    .attr('y', d => y(d.name))
    .attr('width', d => x(d.contribution))
    .attr('height', y.bandwidth())
    .attr('fill', d => contribColor(d.contribution))
    .attr('rx', 3);

  svg.selectAll('.label')
    .data(scoringData)
    .join('text')
    .attr('x', d => x(d.contribution) + 6)
    .attr('y', d => y(d.name) + y.bandwidth() / 2 + 4)
    .text(d => d.contribution.toFixed(3))
    .style('fill', '#aaa').style('font-size', '10px');

  svg.selectAll('.domain, .tick line').style('stroke', '#333');
}})();

// === SECTION TABLE WITH ANOMALY HIGHLIGHTING ===
(function() {{
  const tbody = document.querySelector('#section-table tbody');
  anomalyData.forEach(sec => {{
    const tr = document.createElement('tr');
    if (sec.anomaly) tr.classList.add('anomaly-row');

    const barWidth = (sec.entropy / 8) * 200;
    const color = entropyColor(sec.entropy);

    tr.innerHTML = `
      <td>${{sec.name}}</td>
      <td>${{sec.entropy.toFixed(2)}}</td>
      <td class="bar-cell"><div class="entropy-bar" style="width:${{barWidth}}px;background:${{color}};"></div></td>
      <td>${{sec.anomaly ? '<span class="anomaly-badge">⚠ ' + sec.reason + '</span>' : '<span style="color:#27ae60;">Normal</span>'}}</td>
    `;
    tbody.appendChild(tr);
  }});
}})();
</script>
</body>
</html>'''
    return html
