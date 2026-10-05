/* Sidebar toggle + shared utilities (no nav rendering — Django handles that) */

document.addEventListener("DOMContentLoaded", () => {
  const sidebar = document.getElementById("sidebar");
  const toggle = document.getElementById("sidebarToggle");
  const overlay = document.getElementById("sidebarOverlay");

  if (toggle && sidebar && overlay) {
    toggle.onclick = () => {
      sidebar.classList.toggle("-translate-x-full");
      overlay.classList.toggle("hidden");
    };
    overlay.onclick = () => {
      sidebar.classList.add("-translate-x-full");
      overlay.classList.add("hidden");
    };
  }
});

/* ── Shared utilities ── */
function showToast(msg, type = "info") {
  const t = document.getElementById("toast");
  if (!t) return;
  const colors = {
    info: "bg-[#22c55e] text-black",
    success: "bg-[#22c55e] text-black",
    error: "bg-[#ef4444] text-white",
  };
  t.className = `fixed bottom-6 right-6 px-5 py-3 rounded-lg shadow-lg text-sm font-semibold z-[60] transition-opacity duration-300 ${colors[type]}`;
  t.textContent = msg;
  t.style.opacity = "1";
  setTimeout(() => (t.style.opacity = "0"), 3000);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}

function copyToClipboard(text, label) {
  if (!text || text === "—" || text.startsWith("Not scanned")) {
    return showToast("Nothing to copy", "error");
  }
  navigator.clipboard.writeText(text)
    .then(() => showToast(`${label} copied`, "success"))
    .catch(() => showToast("Copy failed", "error"));
}

function getCsrfToken() {
  const m = document.cookie.match(/csrftoken=([^;]+)/);
  return m ? m[1] : "";
}