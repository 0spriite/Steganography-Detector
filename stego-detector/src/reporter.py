"""
Report Generator — menghasilkan laporan forensik dari hasil analisis.
Mendukung output JSON, teks, dan HTML.
"""

import json
import os
from datetime import datetime
from typing import List
from src.detector import AnalysisResult


def generate_text_report(results: List[AnalysisResult], output_path: str = None) -> str:
    """Buat laporan teks human-readable."""
    lines = []
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    lines.append("=" * 65)
    lines.append("       STEGANOGRAPHY DETECTION REPORT — DIGITAL FORENSICS")
    lines.append("=" * 65)
    lines.append(f"  Tanggal Analisis : {ts}")
    lines.append(f"  Total File       : {len(results)}")
    suspicious_count = sum(1 for r in results if r.overall_suspicious)
    lines.append(f"  File Mencurigakan: {suspicious_count}")
    lines.append("=" * 65)

    for i, r in enumerate(results, 1):
        status = "⚠ MENCURIGAKAN" if r.overall_suspicious else "✓ BERSIH"
        lines.append(f"\n[{i}] {r.filename}  [{status}]")
        lines.append(f"    Ukuran      : {r.filesize:,} bytes")
        lines.append(f"    Dimensi     : {r.image_size[0]}x{r.image_size[1]} px  Mode: {r.image_mode}")
        lines.append(f"    Confidence  : {r.confidence}")
        lines.append("")
        lines.append("    Hasil Analisis:")
        lines.append(f"    {'Test':<25} {'Status':<16} {'Score/p-value'}")
        lines.append(f"    {'-'*55}")

        lsb_s = "MENCURIGAKAN" if r.lsb_suspicious else "Normal"
        chi_s = "MENCURIGAKAN" if r.chi_square_suspicious else "Normal"
        his_s = "MENCURIGAKAN" if r.histogram_suspicious else "Normal"
        rs_s  = "MENCURIGAKAN" if r.rs_suspicious else "Normal"

        lines.append(f"    {'LSB Randomness':<25} {lsb_s:<16} {r.lsb_score:.4f}")
        lines.append(f"    {'Chi-Square Test':<25} {chi_s:<16} p={r.chi_square_pvalue:.6f}")
        lines.append(f"    {'Histogram Anomaly':<25} {his_s:<16} {r.histogram_score:.4f}")
        lines.append(f"    {'RS Analysis':<25} {rs_s:<16} {r.rs_score:.4f}")

        if r.embedded_message:
            lines.append(f"\n    *** PESAN DITEMUKAN: \"{r.embedded_message}\"")

        lines.append("")

    lines.append("=" * 65)
    lines.append("  END OF REPORT")
    lines.append("=" * 65)

    report = "\n".join(lines)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)

    return report


def generate_json_report(results: List[AnalysisResult], output_path: str = None) -> str:
    """Buat laporan JSON terstruktur."""
    data = {
        "report_meta": {
            "tool": "Steganography Detector v1.0",
            "timestamp": datetime.now().isoformat(),
            "total_files": len(results),
            "suspicious_files": sum(1 for r in results if r.overall_suspicious)
        },
        "results": [r.to_dict() for r in results]
    }
    output = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output)

    return output


def generate_html_report(results: List[AnalysisResult], output_path: str = None) -> str:
    """Buat laporan HTML interaktif."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    suspicious_count = sum(1 for r in results if r.overall_suspicious)
    clean_count = len(results) - suspicious_count

    rows = ""
    for r in results:
        badge_class = "badge-danger" if r.overall_suspicious else "badge-success"
        badge_text  = "Mencurigakan" if r.overall_suspicious else "Bersih"

        def cell(flag):
            return '<td class="suspicious">Ya</td>' if flag else '<td class="clean">Tidak</td>'

        msg_row = ""
        if r.embedded_message:
            msg_row = f'<tr><td colspan="8" class="msg-found">📩 Pesan Ditemukan: <strong>{r.embedded_message}</strong></td></tr>'

        rows += f"""
        <tr>
          <td>{r.filename}</td>
          <td>{r.filesize:,}</td>
          <td>{r.image_size[0]}x{r.image_size[1]}</td>
          {cell(r.lsb_suspicious)}
          {cell(r.chi_square_suspicious)}
          {cell(r.histogram_suspicious)}
          {cell(r.rs_suspicious)}
          <td><span class="{badge_class}">{badge_text} ({r.confidence})</span></td>
        </tr>{msg_row}"""

    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Steganography Detection Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; padding: 2rem; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; color: #fff; }}
  .subtitle {{ color: #94a3b8; font-size: 0.875rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat-card {{ background: #1e2330; border: 1px solid #2d3748; border-radius: 10px;
                padding: 1rem 1.5rem; min-width: 140px; }}
  .stat-card .num {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .lbl {{ font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem; }}
  .red {{ color: #fc8181; }}
  .green {{ color: #68d391; }}
  .white {{ color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e2330;
           border-radius: 10px; overflow: hidden; font-size: 0.85rem; }}
  th {{ background: #2d3748; padding: 0.75rem 1rem; text-align: left;
        font-weight: 600; color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #2d3748; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #252d3d; }}
  td.suspicious {{ color: #fc8181; font-weight: 600; }}
  td.clean {{ color: #68d391; }}
  .badge-danger {{ background: rgba(252,129,129,0.15); color: #fc8181; border: 1px solid rgba(252,129,129,0.3);
                   padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }}
  .badge-success {{ background: rgba(104,211,145,0.15); color: #68d391; border: 1px solid rgba(104,211,145,0.3);
                    padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }}
  .msg-found {{ background: rgba(246,173,85,0.1); color: #f6ad55; border-left: 3px solid #f6ad55;
                font-size: 0.825rem; padding: 0.6rem 1rem; }}
  .footer {{ margin-top: 2rem; color: #4a5568; font-size: 0.75rem; }}
</style>
</head>
<body>
<h1>Steganography Detection Report</h1>
<p class="subtitle">Digital Forensics Tool &nbsp;·&nbsp; Dianalisis: {ts}</p>

<div class="stats">
  <div class="stat-card"><div class="num white">{len(results)}</div><div class="lbl">Total File</div></div>
  <div class="stat-card"><div class="num red">{suspicious_count}</div><div class="lbl">Mencurigakan</div></div>
  <div class="stat-card"><div class="num green">{clean_count}</div><div class="lbl">Bersih</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>File</th><th>Ukuran</th><th>Dimensi</th>
      <th>LSB</th><th>Chi²</th><th>Histogram</th><th>RS</th>
      <th>Verdict</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>

<p class="footer">Generated by Steganography Detector v1.0 — For educational &amp; forensic use only.</p>
</body>
</html>"""

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    return html
