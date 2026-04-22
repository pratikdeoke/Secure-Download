/**
 * SecureDownload AI — Popup Script
 * Handles UI interactions and displays scan results from background.js
 */

const STATUS_CONFIG = {
  SAFE:      { cls: "safe",     icon: "✅", label: "SAFE",      scoreClass: "safe"    },
  SUSPICIOUS:{ cls: "warn",     icon: "⚠️", label: "SUSPICIOUS", scoreClass: "warn"    },
  MALICIOUS: { cls: "danger",   icon: "🚨", label: "MALICIOUS", scoreClass: "danger"  },
  UNKNOWN:   { cls: "scanning", icon: "❓", label: "UNKNOWN",   scoreClass: "scanning"},
  SCANNING:  { cls: "scanning", icon: "⏳", label: "SCANNING…", scoreClass: "scanning"},
};

// ─── On Load: fetch recent scans from background ──────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadRecentScans();

  document.getElementById("scanBtn").addEventListener("click", handleManualScan);
  document.getElementById("urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleManualScan();
  });

  document.getElementById("openDocs").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:8000/docs" });
  });
});


function loadRecentScans() {
  chrome.runtime.sendMessage({ type: "GET_LATEST_SCANS" }, (response) => {
    if (chrome.runtime.lastError || !response) return;
    const scans = response.scans || [];
    renderScanList(scans.reverse()); // newest first
  });
}


// ─── Render scan list ─────────────────────────────────────────────────────────

function renderScanList(scans) {
  const list = document.getElementById("scanList");

  if (!scans.length) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <div class="empty-text">No downloads detected yet.<br/>Start downloading a file to see results.</div>
      </div>`;
    return;
  }

  list.innerHTML = scans.map(scan => {
    const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.UNKNOWN;
    const name = scan.filename
      ? scan.filename.split("/").pop().split("\\").pop()
      : new URL(scan.url || "about:blank").pathname.split("/").pop() || "unknown";
    const shortUrl = (scan.url || "").replace(/^https?:\/\//, "").slice(0, 50);
    const score = scan.risk_score != null ? `${scan.risk_score}` : "--";

    return `
      <div class="scan-item" onclick="openReport('${escHtml(scan.url || "")}')">
        <div class="item-badge ${cfg.cls}">${cfg.icon}</div>
        <div class="item-info">
          <div class="item-name" title="${escHtml(name)}">${escHtml(name)}</div>
          <div class="item-url">${escHtml(shortUrl)}</div>
        </div>
        <div class="item-score ${cfg.scoreClass}">${score}</div>
      </div>`;
  }).join("");
}


// ─── Manual scan ─────────────────────────────────────────────────────────────

async function handleManualScan() {
  const input = document.getElementById("urlInput");
  const btn   = document.getElementById("scanBtn");
  const url   = input.value.trim();

  if (!url) { input.focus(); return; }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    showBanner({ status: "UNKNOWN", risk_score: null, message: "Please enter a full URL starting with http:// or https://" });
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  showBanner({ status: "SCANNING", risk_score: null, message: "Contacting backend…" });

  chrome.runtime.sendMessage({ type: "SCAN_URL", url }, (response) => {
    btn.disabled = false;
    btn.textContent = "Scan";

    if (chrome.runtime.lastError || !response) {
      showBanner({ status: "UNKNOWN", risk_score: null, message: "Extension error — is the backend running?" });
      return;
    }

    if (!response.success) {
      showBanner({ status: "UNKNOWN", risk_score: null, message: response.error || "Scan failed" });
      return;
    }

    showBanner(response.result);
    loadRecentScans(); // refresh list
  });
}


// ─── Banner ───────────────────────────────────────────────────────────────────

function showBanner(result) {
  const banner  = document.getElementById("resultBanner");
  const cfg     = STATUS_CONFIG[result.status] || STATUS_CONFIG.UNKNOWN;

  banner.className = `result-banner show ${cfg.cls}`;
  document.getElementById("bannerIcon").textContent  = cfg.icon;
  document.getElementById("bannerTitle").textContent = cfg.label;
  document.getElementById("bannerScore").textContent =
    result.risk_score != null ? `Risk: ${result.risk_score}/100` : "";
  document.getElementById("bannerMsg").textContent   = result.message || "";
}


// ─── Helpers ──────────────────────────────────────────────────────────────────

function openReport(url) {
  if (!url) return;
  const vtUrl = `https://www.virustotal.com/gui/url/${btoa(url).replace(/=/g, "")}`;
  chrome.tabs.create({ url: vtUrl });
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
