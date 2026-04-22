/**
 * SecureDownload AI — Background Service Worker
 *
 * Listens for Chrome download events, sends the download URL + filename
 * to the SecureDownload AI backend for analysis, and shows the user
 * a warning popup if the file is suspicious or malicious.
 */

const BACKEND_URL = "http://localhost:8000/api/v1";

// Stores scan results keyed by downloadId for the popup to read
const scanResults = {};

// ─── Download Listener ────────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const { id, url, filename, fileSize } = downloadItem;

  console.log(`[SecureDownload] Intercepted download: ${url}`);

  // Skip extensions' own resource fetches
  if (!url || url.startsWith("chrome-extension://") || url.startsWith("blob:")) return;

  // Store placeholder while we scan
  scanResults[id] = { status: "SCANNING", url, filename };

  try {
    const result = await scanUrl(url, filename);
    scanResults[id] = result;

    // Persist for popup.html to read later
    await chrome.storage.local.set({ [`scan_${id}`]: result });

    // Show a system notification for dangerous files
    if (result.status === "MALICIOUS" || result.status === "SUSPICIOUS") {
      showNotification(id, result);
    }

    // Update the extension badge
    updateBadge(result.status);

  } catch (err) {
    console.error("[SecureDownload] Scan failed:", err);
    scanResults[id] = { status: "UNKNOWN", error: err.message, url, filename };
  }
});


// ─── URL Scanner ─────────────────────────────────────────────────────────────

async function scanUrl(url, filename) {
  const response = await fetch(`${BACKEND_URL}/scan-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, filename }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.detail || "Backend error");
  }

  return response.json();
}


// ─── Notifications ────────────────────────────────────────────────────────────

function showNotification(downloadId, result) {
  const isMalicious = result.status === "MALICIOUS";

  chrome.notifications.create(`scan_${downloadId}`, {
    type: "basic",
    iconUrl: isMalicious ? "icons/icon_danger.png" : "icons/icon_warn.png",
    title: isMalicious ? "⚠️ MALICIOUS FILE DETECTED" : "⚠️ Suspicious File",
    message: `${result.message || "Potential threat detected"}\nRisk Score: ${result.risk_score}/100`,
    priority: 2,
  });
}


// ─── Badge ───────────────────────────────────────────────────────────────────

function updateBadge(status) {
  const config = {
    SAFE:       { text: "✓",  color: "#22c55e" },
    SUSPICIOUS: { text: "!",  color: "#f59e0b" },
    MALICIOUS:  { text: "✗",  color: "#ef4444" },
    UNKNOWN:    { text: "?",  color: "#6b7280" },
  };
  const { text, color } = config[status] || config.UNKNOWN;
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}


// ─── Message bridge for popup.html ───────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_LATEST_SCANS") {
    // Return all scan results (last 20 downloads)
    const recent = Object.entries(scanResults)
      .slice(-20)
      .map(([id, result]) => ({ downloadId: id, ...result }));
    sendResponse({ scans: recent });
    return true;
  }

  if (message.type === "SCAN_URL") {
    scanUrl(message.url, message.filename || "unknown")
      .then((result) => sendResponse({ success: true, result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // async response
  }
});
