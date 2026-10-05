document.addEventListener("DOMContentLoaded", () => {
  const historyBody = document.getElementById("historyBody");
  if (!historyBody) return;

  let MOCK_HISTORY = window.SCANS_FROM_DB || [];
  let searchQuery = "";
  let classificationFilter = "";
  let currentPage = 1;
  const PAGE_SIZE = 5;
  let selectedIds = new Set();

  const pageInfo = document.getElementById("pageInfo");
  const pageNumber = document.getElementById("pageNumber");
  const prevBtn = document.getElementById("prevBtn");
  const nextBtn = document.getElementById("nextBtn");

  function getFiltered() {
    let list = [...MOCK_HISTORY];
    if (classificationFilter) list = list.filter(s => s.classification === classificationFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      list = list.filter(s =>
        s.filename.toLowerCase().includes(q) ||
        s.package.toLowerCase().includes(q) ||
        (s.sha256 || "").toLowerCase().includes(q));
    }
    return list;
  }

  function riskBarStyle(score) {
    let color = "#22c55e";
    if (score >= 70) color = "#ef4444";
    else if (score >= 40) color = "#f59e0b";
    return { color, width: score + "%" };
  }

  function updateStats() {
    document.getElementById("statTotal").textContent = MOCK_HISTORY.length;
    document.getElementById("statMalicious").textContent = MOCK_HISTORY.filter(s => s.classification === "Malicious").length;
    document.getElementById("statSuspicious").textContent = MOCK_HISTORY.filter(s => s.classification === "Suspicious").length;
    document.getElementById("statSafe").textContent = MOCK_HISTORY.filter(s => s.classification === "Safe").length;
  }

  function render() {
    const filtered = getFiltered();
    updateStats();

    const total = filtered.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    if (currentPage > totalPages) currentPage = totalPages;
    const start = (currentPage - 1) * PAGE_SIZE;
    const end = Math.min(start + PAGE_SIZE, total);
    const pageSlice = filtered.slice(start, end);

    if (!total) {
      historyBody.innerHTML = `<tr><td colspan="7" class="px-4 py-16 text-center text-[#52525b]">
        <i class="fa-solid fa-magnifying-glass-minus text-3xl mb-2 block opacity-40"></i>
        <p class="text-sm">No scans found</p>
      </td></tr>`;
      pageInfo.textContent = "Showing 0 of 0 scans";
      pageNumber.textContent = "Page 1";
      prevBtn.disabled = true;
      nextBtn.disabled = true;
      return;
    }

    historyBody.innerHTML = pageSlice.map(s => {
      const cls = (s.classification || "").toLowerCase();
      const cfg = {
        malicious:  { color:"text-[#ef4444]", bg:"bg-[#ef4444]/15", border:"border-[#ef4444]/40", icon:"fa-skull-crossbones" },
        suspicious: { color:"text-[#f59e0b]", bg:"bg-[#f59e0b]/15", border:"border-[#f59e0b]/40", icon:"fa-triangle-exclamation" },
        safe:       { color:"text-[#22c55e]", bg:"bg-[#22c55e]/15", border:"border-[#22c55e]/40", icon:"fa-circle-check" },
      }[cls] || { color:"text-[#a1a1aa]", bg:"bg-gray-800", border:"border-gray-700", icon:"fa-question" };

      const rb = riskBarStyle(s.risk_score);
      const isChecked = selectedIds.has(s.id);

      let familyCell = `<span class="text-[11px] text-[#52525b] italic">Not detected</span>`;
      if (s.malware_family) {
        familyCell = `<span class="text-[12px] text-[#ef4444] font-mono">${escapeHtml(s.malware_family)}</span>
                      <p class="text-[10px] text-[#52525b]">${escapeHtml(s.malware_category || "")}</p>`;
      }

      return `
        <tr class="hover:bg-[#1a1a1a] transition">
          <td class="pl-4 pr-2 py-3"><input type="checkbox" class="cbx row-check" data-id="${s.id}" ${isChecked ? "checked" : ""} /></td>
          <td class="px-4 py-3"><span class="font-mono text-[11px] text-[#71717a]">${s.id.slice(0, 13)}</span></td>
          <td class="px-4 py-3">
            <div class="flex items-center gap-2.5">
              <div class="w-8 h-8 rounded-lg bg-[#22c55e]/10 border border-[#22c55e]/20 flex items-center justify-center shrink-0">
                <i class="fa-brands fa-android text-[#22c55e] text-xs"></i>
              </div>
              <div class="min-w-0">
                <p class="text-[13px] text-white truncate">${escapeHtml(s.filename)}</p>
                <p class="text-[10px] text-[#52525b] font-mono truncate">${escapeHtml(s.package)}</p>
              </div>
            </div>
          </td>
          <td class="px-4 py-3">${familyCell}</td>
          <td class="px-4 py-3">
            <div class="risk-bar w-36">
              <div class="risk-bar-fill" style="width: ${rb.width}; background: ${rb.color}22;"></div>
              <div class="absolute inset-0 flex items-center">
                <span class="risk-bar-text" style="color:${rb.color}">${s.risk_score}</span>
                <span class="text-[10px] text-[#52525b] ml-1">/ 100</span>
                <span class="ml-auto mr-2 inline-flex items-center gap-1 text-[9px] font-bold uppercase ${cfg.color}">
                  <i class="fa-solid ${cfg.icon} text-[7px]"></i>${s.classification}
                </span>
              </div>
            </div>
          </td>
          <td class="px-4 py-3"><span class="text-[11px] text-[#71717a] font-mono">${s.scan_date}</span></td>
          <td class="px-4 py-3">
            <a href="/report/${s.id}/" class="w-8 h-8 rounded-md bg-black/40 border border-[#1f1f23] hover:border-[#22c55e]/40 hover:text-[#22c55e] transition flex items-center justify-center text-[#71717a]">
              <i class="fa-solid fa-arrow-right text-[11px]"></i>
            </a>
          </td>
        </tr>`;
    }).join("");

    pageInfo.textContent = `Showing ${start + 1}–${end} of ${total} scans`;
    pageNumber.textContent = `Page ${currentPage} of ${totalPages}`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;

    document.querySelectorAll(".row-check").forEach(cb => {
      cb.addEventListener("change", e => {
        const id = e.target.dataset.id;
        if (e.target.checked) selectedIds.add(id);
        else selectedIds.delete(id);
      });
    });
  }

  document.getElementById("searchInput").addEventListener("input", e => {
    searchQuery = e.target.value.trim();
    currentPage = 1;
    render();
  });
  document.getElementById("filterClass").addEventListener("change", e => {
    classificationFilter = e.target.value;
    currentPage = 1;
    render();
  });
  prevBtn.addEventListener("click", () => { if (currentPage > 1) { currentPage--; render(); } });
  nextBtn.addEventListener("click", () => {
    const totalPages = Math.ceil(getFiltered().length / PAGE_SIZE);
    if (currentPage < totalPages) { currentPage++; render(); }
  });

  document.getElementById("exportCsvBtn").addEventListener("click", () => {
    const list = getFiltered();
    if (!list.length) return alert("Nothing to export");
    const headers = ["Scan ID", "Filename", "Package", "SHA-256", "Scan Date", "Risk Score", "Classification", "Malware Family"];
    const rows = list.map(s => [s.id, s.filename, s.package, s.sha256, s.scan_date, s.risk_score, s.classification, s.malware_family || "—"]);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `apkshield-history-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById("clearHistoryBtn").addEventListener("click", () => {
    if (confirm("Are you sure you want to clear all scan history?")) {
      MOCK_HISTORY = [];
      render();
    }
  });

  render();
});