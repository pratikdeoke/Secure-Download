/**
 * SecureDownload AI — Content Script (content.js)
 *
 * Injected into every page. Intercepts clicks on download links
 * and shows an inline warning overlay BEFORE the browser starts
 * the download, giving the user a chance to cancel.
 *
 * This runs in the page context so it can intercept anchor clicks
 * before Chrome's download manager picks them up.
 */

(function () {
  "use strict";

  // File extensions we care about (skip images, fonts, etc.)
  const RISKY_EXTENSIONS = new Set([
    ".exe", ".msi", ".bat", ".cmd", ".scr", ".vbs", ".ps1",
    ".jar", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso",
    ".dll", ".so", ".sh", ".app",
  ]);

  function getRiskExtension(url) {
    try {
      const path = new URL(url).pathname.toLowerCase();
      return RISKY_EXTENSIONS.has(
        path.substring(path.lastIndexOf("."))
      );
    } catch {
      return false;
    }
  }

  // ── Intercept anchor-click downloads ──────────────────────────────────────

  document.addEventListener("click", async (e) => {
    const anchor = e.target.closest("a[href]");
    if (!anchor) return;

    const href = anchor.href;
    const hasDownloadAttr = anchor.hasAttribute("download");

    if (!href || (!hasDownloadAttr && !getRiskExtension(href))) return;

    e.preventDefault();
    e.stopPropagation();

    const overlay = showScanningOverlay(href);

    // Ask background.js to scan the URL
    chrome.runtime.sendMessage(
      { type: "SCAN_URL", url: href, filename: anchor.download || "" },
      (response) => {
        removeOverlay(overlay);

        if (!response || !response.success) {
          // If scan failed, allow download with a warning toast
          showToast("⚠️ Scan failed — downloading anyway", "warn");
          window.location.href = href;
          return;
        }

        const result = response.result;

        if (result.status === "MALICIOUS") {
          showBlockOverlay(href, result);
        } else if (result.status === "SUSPICIOUS") {
          showWarningOverlay(href, result);
        } else {
          // SAFE — show brief toast and proceed
          showToast(`✅ Safe (${result.risk_score}/100) — downloading`, "safe");
          window.location.href = href;
        }
      }
    );
  }, true);

  // ── Overlays ───────────────────────────────────────────────────────────────

  function showScanningOverlay(url) {
    return createOverlay(`
      <div style="text-align:center">
        <div style="font-size:32px;margin-bottom:12px">🔍</div>
        <div style="font-size:16px;font-weight:600;margin-bottom:6px">Scanning file…</div>
        <div style="font-size:12px;color:#8b949e">${truncate(url, 60)}</div>
      </div>
    `, "#161b22");
  }

  function showBlockOverlay(url, result) {
    const overlay = createOverlay(`
      <div style="text-align:center;max-width:420px">
        <div style="font-size:48px;margin-bottom:12px">🚨</div>
        <div style="font-size:20px;font-weight:700;color:#ef4444;margin-bottom:8px">MALICIOUS FILE DETECTED</div>
        <div style="font-size:13px;color:#8b949e;margin-bottom:16px;line-height:1.5">${result.message}</div>
        <div style="display:flex;gap:10px;justify-content:center">
          <button id="sda-cancel" style="${btnStyle("#ef4444")}">🚫 Cancel Download</button>
          <button id="sda-proceed" style="${btnStyle("#30363d")}">Download Anyway</button>
        </div>
        <div style="margin-top:12px;font-size:11px;color:#6e7681">Risk Score: ${result.risk_score}/100 · ${result.positives}/${result.total_engines} engines flagged</div>
      </div>
    `, "#0d0d0d");

    overlay.querySelector("#sda-cancel").onclick  = () => removeOverlay(overlay);
    overlay.querySelector("#sda-proceed").onclick = () => { removeOverlay(overlay); window.location.href = url; };
    return overlay;
  }

  function showWarningOverlay(url, result) {
    const overlay = createOverlay(`
      <div style="text-align:center;max-width:420px">
        <div style="font-size:48px;margin-bottom:12px">⚠️</div>
        <div style="font-size:20px;font-weight:700;color:#f59e0b;margin-bottom:8px">Suspicious File</div>
        <div style="font-size:13px;color:#8b949e;margin-bottom:16px;line-height:1.5">${result.message}</div>
        <div style="display:flex;gap:10px;justify-content:center">
          <button id="sda-cancel" style="${btnStyle("#f59e0b","#000")}">Cancel</button>
          <button id="sda-proceed" style="${btnStyle("#30363d")}">Download Anyway</button>
        </div>
        <div style="margin-top:12px;font-size:11px;color:#6e7681">Risk Score: ${result.risk_score}/100</div>
      </div>
    `, "#0d1117");

    overlay.querySelector("#sda-cancel").onclick  = () => removeOverlay(overlay);
    overlay.querySelector("#sda-proceed").onclick = () => { removeOverlay(overlay); window.location.href = url; };
    return overlay;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function createOverlay(html, bg = "#0d1117") {
    const el = document.createElement("div");
    el.setAttribute("id", "sda-overlay");
    el.style.cssText = `
      position:fixed;inset:0;z-index:2147483647;
      background:${bg}ee;
      display:flex;align-items:center;justify-content:center;
      color:#e6edf3;font-family:'Inter',system-ui,sans-serif;
      backdrop-filter:blur(4px);
    `;
    el.innerHTML = html;
    document.body.appendChild(el);
    return el;
  }

  function removeOverlay(el) {
    el && el.remove();
  }

  function showToast(msg, type = "safe") {
    const colors = { safe: "#22c55e", warn: "#f59e0b", danger: "#ef4444" };
    const toast = document.createElement("div");
    toast.style.cssText = `
      position:fixed;bottom:20px;right:20px;z-index:2147483647;
      background:#161b22;border:1px solid ${colors[type]};
      color:#e6edf3;padding:10px 16px;border-radius:8px;
      font-family:'Inter',system-ui,sans-serif;font-size:13px;
      box-shadow:0 4px 20px #00000080;
      animation:fadeIn .2s ease;
    `;
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3500);
  }

  function btnStyle(bg, color = "#fff") {
    return `
      padding:9px 20px;background:${bg};color:${color};
      border:none;border-radius:6px;font-size:13px;font-weight:600;
      cursor:pointer;transition:opacity .15s;
    `;
  }

  function truncate(str, n) {
    return str.length > n ? str.slice(0, n) + "…" : str;
  }

})();
