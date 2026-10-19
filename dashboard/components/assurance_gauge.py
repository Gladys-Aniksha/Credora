"""Self-contained assurance gauge markup, independent of page theme rules."""
from __future__ import annotations

from html import escape
from math import isfinite


def assurance_gauge_html(score: object, status_text: str) -> str:
    try:
        value = float(score) if not isinstance(score, bool) else float("nan")
    except (TypeError, ValueError, OverflowError):
        value = float("nan")
    measured = isfinite(value)
    value = min(100.0, max(0.0, value)) if measured else None
    readout = f"{value:.1f}" if measured else "--"
    label = f"Trust score {readout} out of 100" if measured else "Trust score not evaluated"
    if value is None:
        tier = "Not evaluated"
    else:
        tier = ("Tier 4: Enterprise Trusted" if value >= 85 else
                "Tier 3: Review Required" if value >= 70 else
                "Tier 2: High Risk" if value >= 50 else "Tier 1: Critical")
    arc = "M40 120 A80 80 0 0 1 200 120"
    bands = [("critical", "#a23438", 50, 0), ("warning", "#bb5e61", 20, 50),
             ("review", "#d99c97", 15, 70), ("trusted", "#2f8158", 15, 85)]
    paths = f'<path class="gauge-track" d="{arc}" fill="none" stroke="#f4e5dc" stroke-width="14" />'
    for name, color, length, offset in bands:
        paths += (f'<path class="gauge-{name}" d="{arc}" fill="none" stroke="{color}" '
                  f'stroke-width="14" pathLength="100" stroke-dasharray="{length} {100 - length}" '
                  f'stroke-dashoffset="{-offset}" />')
    needle = ""
    if value is not None:
        needle = f"""<g transform="rotate({-90 + value * 1.8:.1f} 120 120)">
          <line class="gauge-needle" x1="120" y1="120" x2="120" y2="48"
                fill="none" stroke="#a23438" stroke-width="3" stroke-linecap="round" />
          <circle class="gauge-hub" cx="120" cy="120" r="6" fill="#a23438" />
        </g>"""
    return f"""<div class="assurance-gauge" style="text-align:center;min-width:0;">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 180" role="img"
           aria-label="{label}" style="display:block;width:100%;max-width:320px;height:auto;margin:0 auto;">
        <title>{label}</title>
        {paths}{needle}
        <text x="40" y="140" text-anchor="middle" fill="#514847" font-size="11">0</text>
        <text x="200" y="140" text-anchor="middle" fill="#514847" font-size="11">100</text>
        <text class="assurance-readout" x="120" y="170" text-anchor="middle"
              fill="#201a1a" font-family="Arial, sans-serif" font-size="24" font-weight="700">
          {readout}<tspan font-size="12" font-weight="400"> / 100</tspan>
        </text>
      </svg>
      <div class="assurance-tier">{tier}</div>
      <div class="assurance-status">{escape(str(status_text))}</div>
    </div>"""
