export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

export function csrfToken() {
  const prefix = "__Host-MCAce-CSRF=";
  for (const part of document.cookie.split(";")) {
    const value = part.trim();
    if (value.startsWith(prefix)) return value.slice(prefix.length);
  }
  return "";
}

export async function api(path, options = {}) {
  const request = { credentials: "same-origin", headers: { Accept: "application/json" }, ...options };
  request.headers = { Accept: "application/json", ...(options.headers || {}) };
  if (request.body && !request.headers["Content-Type"]) request.headers["Content-Type"] = "application/json";
  if (request.method && request.method !== "GET") request.headers["X-MCAce-CSRF"] = csrfToken();
  const response = await fetch(path, request);
  const contentType = response.headers.get("Content-Type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const error = payload && payload.error ? payload.error : {};
    throw new ApiError(response.status, error.code || "REQUEST_FAILED", error.message || "Request failed");
  }
  return payload;
}

export function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
export function formatTime(value) { return value ? new Date(value).toLocaleString() : "—"; }
export function label(value) { return String(value || "unknown").replaceAll("_", " ").toLowerCase(); }
export function statusClass(value) { return "status " + String(value || "").toLowerCase().replaceAll("_", "-"); }

export function showBanner(message) {
  const banner = document.querySelector("#banner");
  if (!banner) return;
  banner.textContent = message;
  banner.classList.remove("hidden");
}

export async function signOut() {
  try { await api("/web/api/logout", { method: "POST" }); } finally { window.location.assign("/login"); }
}
