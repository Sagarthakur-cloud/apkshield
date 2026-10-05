document.addEventListener("DOMContentLoaded", () => {
  const dropZone = document.getElementById("dropZone");
  if (!dropZone) return;

  const dropDefault   = document.getElementById("dropDefault");
  const filePreview   = document.getElementById("filePreview");
  const fileInput     = document.getElementById("fileInput");
  const fileName      = document.getElementById("fileName");
  const fileSize      = document.getElementById("fileSize");
  const removeFile    = document.getElementById("removeFile");
  const selectedLine  = document.getElementById("selectedLine");
  const selectedName  = document.getElementById("selectedName");
  const clearSelected = document.getElementById("clearSelected");
  const scanBtn       = document.getElementById("scanBtn");

  const gaugeCircle = document.getElementById("gaugeCircle");
  const dashedRing  = document.getElementById("dashedRing");
  const gaugeEmpty  = document.getElementById("gaugeEmpty");
  const gaugeFilled = document.getElementById("gaugeFilled");
  const riskScoreEl = document.getElementById("riskScore");
  const classBadge  = document.getElementById("classBadge");

  const permTableWrap = document.getElementById("permTableWrap");
  const permTableBody = document.getElementById("permTableBody");
  const permCount     = document.getElementById("permCount");
  const permEmpty     = document.getElementById("permEmpty");
  const permSkeleton  = document.getElementById("permSkeleton");

  const metaPackage   = document.getElementById("metaPackage");
  const metaSize      = document.getElementById("metaSize");
  const metaSha       = document.getElementById("metaSha");
  const metaFamily    = document.getElementById("metaFamily");
  const certBadgeWrap = document.getElementById("certBadgeWrap");
  const lastScanned   = document.getElementById("lastScanned");

  const breakdown = document.getElementById("breakdown");
  const bdSigVal  = document.getElementById("bdSigVal");
  const bdSigBar  = document.getElementById("bdSigBar");
  const bdHeuVal  = document.getElementById("bdHeuVal");
  const bdHeuBar  = document.getElementById("bdHeuBar");
  const bdBehVal  = document.getElementById("bdBehVal");
  const bdBehBar  = document.getElementById("bdBehBar");

  const fileActions    = document.getElementById("fileActions");
  const copyPackageBtn = document.getElementById("copyPackageBtn");
  const copyShaBtn     = document.getElementById("copyShaBtn");
  const quarantineBtn  = document.getElementById("quarantineBtn");
  const viewReportBtn  = document.getElementById("viewReportBtn");

  const loadDemoRiskBtn = document.getElementById("loadDemoRiskBtn");
  const loadDemoPermBtn = document.getElementById("loadDemoPermBtn");

  let selectedFile = null;

  /* File selection */
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-active"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-active"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("drag-active");
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  fileInput.addEventListener("change", e => { if (e.target.files.length) handleFile(e.target.files[0]); });
  removeFile.addEventListener("click", e => { e.stopPropagation(); resetFile(); });
  clearSelected.addEventListener("click", e => { e.stopPropagation(); resetFile(); });

  function handleFile(file) {
    if (!file.name.toLowerCase().endsWith(".apk")) return showToast("Only .apk files are allowed", "error");
    if (file.size > 100 * 1024 * 1024) return showToast("File too large (max 100 MB)", "error");
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    dropDefault.classList.add("hidden");
    filePreview.classList.remove("hidden");
    selectedName.textContent = `${file.name} (${formatBytes(file.size)})`;
    selectedLine.classList.remove("hidden");
    enableScanBtn();
  }

  function resetFile() {
    selectedFile = null;
    fileInput.value = "";
    dropDefault.classList.remove("hidden");
    filePreview.classList.add("hidden");
    selectedLine.classList.add("hidden");
    disableScanBtn();
  }

  function enableScanBtn() {
    scanBtn.disabled = false;
    scanBtn.className = `mt-4 w-full bg-[#22c55e] text-black font-semibold py-3.5 rounded-lg transition flex items-center justify-center gap-2 text-sm hover:bg-[#16a34a] active:scale-[0.99]`;
  }
  function disableScanBtn() {
    scanBtn.disabled = true;
    scanBtn.className = `mt-4 w-full bg-[#1f1f23] text-[#52525b] cursor-not-allowed font-semibold py-3.5 rounded-lg transition flex items-center justify-center gap-2 text-sm`;
  }

  /* Demo loaders */
  [loadDemoRiskBtn, loadDemoPermBtn].forEach(btn => {
    if (btn) btn.addEventListener("click", () => runPipelineDemo());
  });

  /* Scan button */
  scanBtn.addEventListener("click", async () => {
    if (!selectedFile) return;
    scanBtn.disabled = true;
    scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-xs"></i> <span>Scanning...</span>`;

    // Show skeleton
    permEmpty.classList.add("hidden");
    permTableWrap.classList.add("hidden");
    permSkeleton.classList.remove("hidden");
    permCount.textContent = "…";
    fileActions.classList.add("hidden");
    lastScanned.textContent = "Analyzing…";

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const res = await fetch("/api/scan/", {
        method: "POST",
        headers: { "X-CSRFToken": getCsrfToken() },
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Scan failed");
      }

      const report = await res.json();
      permSkeleton.classList.add("hidden");
      renderReport(report);
      showToast("Scan complete", "success");
    } catch (err) {
      permSkeleton.classList.add("hidden");
      permEmpty.classList.remove("hidden");
      showToast(err.message, "error");
    }

    scanBtn.disabled = false;
    scanBtn.innerHTML = `<i class="fa-solid fa-radar text-xs"></i> <span>Start Scan</span>`;
  });

  function runPipelineDemo() {
    // Demo: skip upload, just show mock
    permEmpty.classList.add("hidden");
    permTableWrap.classList.add("hidden");
    permSkeleton.classList.remove("hidden");
    permCount.textContent = "…";

    setTimeout(() => {
      permSkeleton.classList.add("hidden");
      const demo = {
        filename: "FakeBank.apk",
        package: "com.whatsapp.malware.test",
        size: "12.42 MB",
        sha256: "4f2a8d1e7b3c9f6a2d5e8b1c4f7a3d6e9b2c5f8a1d4e7b3c6f9a2d5e8b1c4f7a9c8e",
        certificate: "Self-signed",
        risk_score: 78,
        classification: "Malicious",
        malware_family: "Trojan.Generic",
        malware_category: "Trojan.Banker",
        ai_confidence: 98,
        family_match: 87,
        breakdown: { signature: 94, heuristic: 72, behavior: 85 },
        ai_summary: "This APK is a repackaged banking trojan with 87% code similarity to Cerberus v2.3.",
        recommendation: "Do NOT install. This APK is a variant of the Cerberus banking trojan.",
        detected_risks: [
          { name: "SEND_SMS", severity: "High", details: "Allows sending SMS without user confirmation." },
          { name: "READ_CONTACTS", severity: "High", details: "Full access to contact list." },
          { name: "ACCESS_FINE_LOCATION", severity: "Medium", details: "Precise GPS location." },
          { name: "READ_CALL_LOG", severity: "Medium", details: "Reads call history." },
          { name: "INTERNET", severity: "Safe", details: "Standard network access." },
        ],
      };
      renderReport(demo);
      showToast("Demo loaded", "success");
    }, 1200);
  }

  function renderReport(r) {
    animateScore(r.risk_score);

    const cls = r.classification.toLowerCase();
    const cfg = {
      safe:       { color: "text-[#22c55e]", bg: "bg-[#22c55e]/10", border: "border-[#22c55e]/30", icon: "fa-circle-check" },
      suspicious: { color: "text-[#f59e0b]", bg: "bg-[#f59e0b]/10", border: "border-[#f59e0b]/30", icon: "fa-triangle-exclamation" },
      malicious:  { color: "text-[#ef4444]", bg: "bg-[#ef4444]/10", border: "border-[#ef4444]/30", icon: "fa-skull-crossbones" },
    }[cls];
    classBadge.className = `text-[10px] uppercase tracking-wider px-2.5 py-1 rounded-full font-semibold border ${cfg.color} ${cfg.bg} ${cfg.border}`;
    classBadge.innerHTML = `<i class="fa-solid ${cfg.icon} mr-1"></i>${r.classification}`;

    breakdown.classList.remove("hidden");
    setTimeout(() => {
      bdSigBar.style.width = r.breakdown.signature + "%";
      bdHeuBar.style.width = r.breakdown.heuristic + "%";
      bdBehBar.style.width = r.breakdown.behavior + "%";
      bdSigVal.textContent = r.breakdown.signature + "%";
      bdHeuVal.textContent = r.breakdown.heuristic + "%";
      bdBehVal.textContent = r.breakdown.behavior + "%";
    }, 100);

    renderPermissions(r.detected_risks || []);

    metaPackage.textContent = r.package;
    metaPackage.className = "text-[12px] font-mono text-[#d4d4d8] truncate flex-1";
    metaPackage.dataset.full = r.package;

    metaSize.textContent = r.size;
    metaSize.className = "text-[12px] font-mono text-[#d4d4d8]";

    if (r.certificate === "Verified") {
      certBadgeWrap.innerHTML = `<span class="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-[#22c55e]/10 text-[#22c55e] border border-[#22c55e]/30"><i class="fa-solid fa-check text-[8px]"></i>Verified</span>`;
    } else {
      certBadgeWrap.innerHTML = `<span class="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-[#ef4444]/10 text-[#ef4444] border border-[#ef4444]/30"><i class="fa-solid fa-triangle-exclamation text-[8px]"></i>Self-signed</span>`;
    }

    const short = r.sha256.slice(0, 8) + "…" + r.sha256.slice(-8);
    metaSha.innerHTML = `<span title="Click to copy">${short}</span>`;
    metaSha.dataset.full = r.sha256;
    metaSha.className = "text-[11px] font-mono text-[#a1a1aa]";

    metaFamily.textContent = r.malware_family;
    metaFamily.className = "text-[12px] font-mono text-[#ef4444]";

    lastScanned.textContent = "Scanned just now";
    lastScanned.className = "text-[10px] font-mono text-[#22c55e]";

    fileActions.classList.remove("hidden");
  }

  function animateScore(score) {
    gaugeEmpty.classList.add("hidden");
    gaugeFilled.classList.remove("hidden");
    gaugeFilled.classList.add("flex");
    gaugeCircle.classList.remove("opacity-0");
    if (dashedRing) dashedRing.style.display = "none";

    const circumference = 534;
    const offset = circumference - (score / 100) * circumference;
    let color = "#22c55e";
    if (score >= 70) color = "#ef4444";
    else if (score >= 40) color = "#f59e0b";

    gaugeCircle.style.stroke = color;
    gaugeCircle.style.strokeDashoffset = offset;

    let current = 0;
    const step = Math.max(1, score / 40);
    const interval = setInterval(() => {
      current += step;
      if (current >= score) { current = score; clearInterval(interval); }
      riskScoreEl.textContent = Math.round(current);
    }, 25);
  }

  function renderPermissions(risks) {
    permCount.textContent = `${risks.length} item${risks.length !== 1 ? "s" : ""}`;
    if (!risks.length) {
      permTableWrap.classList.add("hidden");
      permEmpty.classList.remove("hidden");
      return;
    }
    permEmpty.classList.add("hidden");
    permTableWrap.classList.remove("hidden");

    const pillStyles = {
      High:     { bg: "bg-[#ef4444]/15", border: "border-[#ef4444]/40", text: "text-[#ef4444]", icon: "fa-triangle-exclamation", label: "HIGH RISK" },
      Medium:   { bg: "bg-[#f59e0b]/15", border: "border-[#f59e0b]/40", text: "text-[#f59e0b]", icon: "fa-circle-exclamation", label: "MEDIUM" },
      Safe:     { bg: "bg-[#22c55e]/15", border: "border-[#22c55e]/40", text: "text-[#22c55e]", icon: "fa-check", label: "SAFE" },
    };

    permTableBody.innerHTML = risks.map(r => {
      const s = pillStyles[r.severity] || pillStyles.Safe;
      return `
        <tr class="hover:bg-[#1a1a1a] transition">
          <td class="px-4 py-2.5">
            <div class="flex items-center gap-2">
              <i class="fa-solid fa-key text-[#52525b] text-[10px]"></i>
              <span class="font-mono text-[12px] text-[#d4d4d8]">${escapeHtml(r.name)}</span>
            </div>
          </td>
          <td class="px-4 py-2.5">
            <span class="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${s.bg} ${s.border} ${s.text}">
              <i class="fa-solid ${s.icon} text-[8px]"></i>${s.label}
            </span>
          </td>
          <td class="px-4 py-2.5 text-right">
            <span class="text-[11px] text-[#a1a1aa]">${escapeHtml(r.details || "")}</span>
          </td>
        </tr>`;
    }).join("");
  }

  copyPackageBtn.addEventListener("click", e => {
    e.stopPropagation();
    copyToClipboard(metaPackage.dataset.full || metaPackage.textContent, "Package name");
  });
  copyShaBtn.addEventListener("click", e => {
    e.stopPropagation();
    copyToClipboard(metaSha.dataset.full || metaSha.textContent, "SHA-256");
  });
  quarantineBtn.addEventListener("click", () => showToast("APK moved to quarantine", "success"));
  viewReportBtn.addEventListener("click", () => { window.location.href = "/report/"; });
});

/* ═══════════════════════════════════════════════
   PLAY STORE URL SCANNING
   ═══════════════════════════════════════════════ */
(function() {
    const tabFile = document.getElementById("tabFile");
    const tabPlaystore = document.getElementById("tabPlaystore");
    const dropZone = document.getElementById("dropZone");
    const playstorePanel = document.getElementById("playstorePanel");
    const selectedLine = document.getElementById("selectedLine");
    const scanBtn = document.getElementById("scanBtn");

    if (!tabFile || !tabPlaystore) return;

    // Tab switching
    tabFile.addEventListener("click", () => {
        // Activate file tab
        tabFile.classList.add("border-[#22c55e]", "bg-[#22c55e]/15", "text-[#22c55e]");
        tabFile.classList.remove("border-[#1f1f23]", "text-[#a1a1aa]");

        // Deactivate play store tab
        tabPlaystore.classList.remove("border-[#22c55e]", "bg-[#22c55e]/15", "text-[#22c55e]");
        tabPlaystore.classList.add("border-[#1f1f23]", "text-[#a1a1aa]");

        // Show file UI
        dropZone.classList.remove("hidden");
        selectedLine.classList.add("hidden");
        playstorePanel.classList.add("hidden");
        scanBtn.classList.remove("hidden");
    });

    tabPlaystore.addEventListener("click", () => {
        // Activate play store tab
        tabPlaystore.classList.add("border-[#22c55e]", "bg-[#22c55e]/15", "text-[#22c55e]");
        tabPlaystore.classList.remove("border-[#1f1f23]", "text-[#a1a1aa]");

        // Deactivate file tab
        tabFile.classList.remove("border-[#22c55e]", "bg-[#22c55e]/15", "text-[#22c55e]");
        tabFile.classList.add("border-[#1f1f23]", "text-[#a1a1aa]");

        // Show play store UI
        dropZone.classList.add("hidden");
        selectedLine.classList.add("hidden");
        scanBtn.classList.add("hidden");
        playstorePanel.classList.remove("hidden");
    });

    // Play Store scan button
    const scanPlaystoreBtn = document.getElementById("scanPlaystoreBtn");
    const playstoreUrlInput = document.getElementById("playstoreUrl");

    if (scanPlaystoreBtn) {
        scanPlaystoreBtn.addEventListener("click", async () => {
            const url = playstoreUrlInput.value.trim();
            if (!url) return showToast("Paste a Play Store URL first", "error");

            if (!url.includes("play.google.com") && !url.includes("play.app.goo.gl")) {
                return showToast("Not a valid Play Store URL", "error");
            }

            scanPlaystoreBtn.disabled = true;
            scanPlaystoreBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-xs"></i><span>Downloading & Analyzing...</span>`;

            // Show skeleton on permissions card
            const permEmpty = document.getElementById("permEmpty");
            const permTableWrap = document.getElementById("permTableWrap");
            const permSkeleton = document.getElementById("permSkeleton");
            const permCount = document.getElementById("permCount");
            const lastScanned = document.getElementById("lastScanned");

            if (permEmpty) permEmpty.classList.add("hidden");
            if (permTableWrap) permTableWrap.classList.add("hidden");
            if (permSkeleton) permSkeleton.classList.remove("hidden");
            if (permCount) permCount.textContent = "…";
            if (lastScanned) lastScanned.textContent = "Downloading…";

            try {
                const res = await fetch("/api/scan-playstore/", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": getCsrfToken(),
                    },
                    body: JSON.stringify({ url: url }),
                });

                const data = await res.json();

                if (!res.ok) {
                    throw new Error(data.error || "Scan failed");
                }

                if (permSkeleton) permSkeleton.classList.add("hidden");
                sessionStorage.setItem("apkshield_current_scan_id", data.id);
                sessionStorage.setItem("apkshield_current_report", JSON.stringify(data));
                renderReport(data);
                showToast("Play Store scan complete", "success");

            } catch (err) {
                if (permSkeleton) permSkeleton.classList.add("hidden");
                if (permEmpty) permEmpty.classList.remove("hidden");
                if (lastScanned) lastScanned.textContent = "Last scanned: Never";
                showToast(err.message, "error");
            }

            scanPlaystoreBtn.disabled = false;
            scanPlaystoreBtn.innerHTML = `<i class="fa-solid fa-satellite-dish text-xs"></i><span>Scan from Play Store</span>`;
        });
    }
})();