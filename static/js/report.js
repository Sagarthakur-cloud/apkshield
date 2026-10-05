document.addEventListener("DOMContentLoaded", () => {
  const r = window.REPORT_FROM_DB;
  if (!r) {
    document.querySelector("main").innerHTML = `<div class="text-center py-20 text-[#52525b]">No report available. <a href="/" class="text-[#22c55e] hover:underline">Scan an APK</a>.</div>`;
    return;
  }

  // ═══════════════════════════════════════════════
  // RISK CIRCLE ANIMATION
  // ═══════════════════════════════════════════════
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

  // ═══════════════════════════════════════════════
  // STATIC FIELDS
  // ═══════════════════════════════════════════════
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

  // ═══════════════════════════════════════════════
  // CLASSIFICATION BADGE
  // ═══════════════════════════════════════════════
  const cls = (r.classification || "").toLowerCase();
  const badge = document.getElementById("classBadge");
  const cfg = {
    malicious:  { color:"text-[#ef4444]", bg:"bg-[#ef4444]/15", border:"border-[#ef4444]/40", icon:"fa-skull-crossbones" },
    suspicious: { color:"text-[#f59e0b]", bg:"bg-[#f59e0b]/15", border:"border-[#f59e0b]/40", icon:"fa-triangle-exclamation" },
    safe:       { color:"text-[#22c55e]", bg:"bg-[#22c55e]/15", border:"border-[#22c55e]/40", icon:"fa-circle-check" },
  }[cls] || { color:"text-[#a1a1aa]", bg:"bg-gray-800", border:"border-gray-700", icon:"fa-question" };

  badge.className = `inline-flex items-center gap-2 px-3 py-1.5 rounded-full font-bold text-[12px] border ${cfg.bg} ${cfg.color} ${cfg.border}`;
  badge.innerHTML = `<i class="fa-solid ${cfg.icon}"></i> ${r.classification}`;

  // ═══════════════════════════════════════════════
  // KEY RISK INDICATORS
  // ═══════════════════════════════════════════════
  const riskIndicators = document.getElementById("riskIndicators");
  const risks = (r.detected_risks || []).filter(x => x.severity !== "Safe").slice(0, 6);
  riskIndicators.innerHTML = risks.map(x => {
    const high = x.severity === "High" || x.severity === "Critical";
    return `<span class="inline-flex items-center gap-2 text-[11px] font-mono font-semibold ${high ? "text-[#ef4444] bg-[#ef4444]/10 border-[#ef4444]/30" : "text-[#f59e0b] bg-[#f59e0b]/10 border-[#f59e0b]/30"} border rounded-full px-3 py-1.5">
      <i class="fa-solid ${high ? "fa-triangle-exclamation" : "fa-circle-exclamation"} text-[9px]"></i>
      ${escapeHtml(x.name)}
    </span>`;
  }).join("") || `<p class="text-[12px] text-[#52525b] italic">No high-risk permissions detected.</p>`;

  // ═══════════════════════════════════════════════
  // CAPABILITIES RENDER
  // ═══════════════════════════════════════════════
  renderCapabilities(r.capabilities || []);
});


/* ═══════════════════════════════════════════════
   CAPABILITIES RENDERER
   ═══════════════════════════════════════════════ */
function renderCapabilities(capabilities) {
  const capCount = document.getElementById("capCount");
  const capEmpty = document.getElementById("capEmpty");
  const capList = document.getElementById("capList");

  if (!capCount || !capEmpty || !capList) return;

  capCount.textContent = `${capabilities.length} item${capabilities.length !== 1 ? "s" : ""}`;

  if (!capabilities.length) {
    capEmpty.classList.remove("hidden");
    capList.classList.add("hidden");
    return;
  }

  capEmpty.classList.add("hidden");
  capList.classList.remove("hidden");

  const styles = {
    Critical: { bg: "bg-[#ef4444]/15", border: "border-[#ef4444]/40", text: "text-[#ef4444]", label: "CRITICAL" },
    High:     { bg: "bg-[#ef4444]/10", border: "border-[#ef4444]/30", text: "text-[#ef4444]", label: "HIGH" },
    Medium:   { bg: "bg-[#f59e0b]/10", border: "border-[#f59e0b]/30", text: "text-[#f59e0b]", label: "MEDIUM" },
    Low:      { bg: "bg-[#22c55e]/10", border: "border-[#22c55e]/30", text: "text-[#22c55e]", label: "LOW" },
  };

  capList.innerHTML = capabilities.map((cap, i) => {
    const s = styles[cap.severity] || styles.Medium;

    const triggerTags = [];
    (cap.triggers?.permissions || []).forEach(p => {
      triggerTags.push(`<span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-black/40 border border-[#27272a] text-[#a1a1aa]">${escapeHtml(p)}</span>`);
    });
    (cap.triggers?.apis || []).forEach(a => {
      triggerTags.push(`<span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-black/40 border border-[#27272a] text-[#a1a1aa]">${escapeHtml(a)}</span>`);
    });

    return `
      <div class="bg-black/40 border border-[#1f1f23] hover:border-[#2a2a2f] rounded-lg p-4 transition fade-in-soft" style="animation-delay:${i * 40}ms">
        <div class="flex items-start gap-3">
          <div class="w-10 h-10 rounded-lg ${s.bg} border ${s.border} flex items-center justify-center shrink-0">
            <i class="fa-solid ${cap.icon} ${s.text}"></i>
          </div>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2 mb-1.5 flex-wrap">
              <p class="text-[13px] font-semibold text-white">${escapeHtml(cap.title)}</p>
              <span class="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${s.bg} ${s.border} ${s.text} border">
                ${s.label}
              </span>
            </div>
            <p class="text-[11px] text-[#a1a1aa] leading-relaxed mb-2.5">${escapeHtml(cap.description)}</p>
            ${triggerTags.length ? `
              <div class="flex flex-wrap gap-1 items-center">
                <span class="text-[9px] text-[#52525b] uppercase tracking-wider mr-1">Detected via:</span>
                ${triggerTags.join("")}
              </div>
            ` : ""}
          </div>
        </div>
      </div>
    `;
  }).join("");
}


/* ═══════════════════════════════════════════════
   HELPERS
   ═══════════════════════════════════════════════ */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}