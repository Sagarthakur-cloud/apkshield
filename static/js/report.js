document.addEventListener("DOMContentLoaded", () => {
  const r = window.REPORT_FROM_DB;
  if (!r) {
    document.querySelector("main").innerHTML = `<div class="text-center py-20 text-[#52525b]">No report available. <a href="/" class="text-[#22c55e] hover:underline">Scan an APK</a>.</div>`;
    return;
  }

  const circle = document.getElementById("conicCircle");
  const riskScoreEl = document.getElementById("riskScore");

  const totalDeg = (r.risk_score / 100) * 360;
  const start = performance.now();
  const duration = 1400;

  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    const deg = totalDeg * eased;
    circle.style.background = `conic-gradient(#ef4444 0deg, #ef4444 ${deg}deg, #17171a ${deg}deg, #17171a 360deg)`;
    riskScoreEl.textContent = Math.round(r.risk_score * eased);
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);

  document.getElementById("reportId").textContent = `#${String(r.id).slice(0, 13)}`;
  document.getElementById("reportFilename").textContent = r.filename;
  document.getElementById("reportPackage").textContent = r.package;
  document.getElementById("reportSummary").textContent = r.recommendation;
  document.getElementById("aiSummary").textContent = r.ai_summary;
  document.getElementById("malFamily").textContent = r.malware_family || "None detected";
  document.getElementById("malCategory").textContent = r.malware_category || "—";
  document.getElementById("aiConfidenceVal").textContent = `${r.ai_confidence}%`;
  document.getElementById("familyMatchVal").textContent = `${r.family_match}%`;
  document.getElementById("familyMatchDesc").textContent = `${r.family_match}% similarity to ${r.malware_family || "unknown"}`;

  setTimeout(() => {
    document.getElementById("aiConfidenceBar").style.width = r.ai_confidence + "%";
    document.getElementById("familyMatchBar").style.width = r.family_match + "%";
  }, 200);

  const cls = (r.classification || "").toLowerCase();
  const badge = document.getElementById("classBadge");
  const cfg = {
    malicious:  { color:"text-[#ef4444]", bg:"bg-[#ef4444]/15", border:"border-[#ef4444]/40", icon:"fa-skull-crossbones" },
    suspicious: { color:"text-[#f59e0b]", bg:"bg-[#f59e0b]/15", border:"border-[#f59e0b]/40", icon:"fa-triangle-exclamation" },
    safe:       { color:"text-[#22c55e]", bg:"bg-[#22c55e]/15", border:"border-[#22c55e]/40", icon:"fa-circle-check" },
  }[cls];
  badge.className = `inline-flex items-center gap-2 px-3 py-1.5 rounded-full font-bold text-[12px] border ${cfg.bg} ${cfg.color} ${cfg.border}`;
  badge.innerHTML = `<i class="fa-solid ${cfg.icon}"></i> ${r.classification}`;

  // Risk indicators
  const riskIndicators = document.getElementById("riskIndicators");
  const risks = (r.detected_risks || []).filter(x => x.severity !== "Safe").slice(0, 4);
  riskIndicators.innerHTML = risks.map(x => {
    const high = x.severity === "High";
    return `<span class="inline-flex items-center gap-2 text-[11px] font-mono font-semibold ${high ? "text-[#ef4444] bg-[#ef4444]/10 border-[#ef4444]/30" : "text-[#f59e0b] bg-[#f59e0b]/10 border-[#f59e0b]/30"} border rounded-full px-3 py-1.5">
      <i class="fa-solid ${high ? "fa-triangle-exclamation" : "fa-circle-exclamation"} text-[9px]"></i>
      ${escapeHtml(x.name)}
    </span>`;
  }).join("") || `<p class="text-[12px] text-[#52525b] italic">No high-risk permissions detected.</p>`;
});