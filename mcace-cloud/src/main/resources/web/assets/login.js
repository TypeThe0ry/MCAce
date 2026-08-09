const status = document.querySelector("#login-status");

function fail(message) {
  status.classList.add("error");
  status.replaceChildren();
  const text = document.createElement("span");
  text.textContent = message;
  status.append(text);
}

async function redirectExistingSession() {
  const response = await fetch("/web/api/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) return false;
  const session = await response.json();
  window.location.replace(session.principal_type === "OPERATOR" ? "/dashboard" : "/appeal");
  return true;
}

async function run() {
  const parameters = new URLSearchParams(window.location.hash.slice(1));
  const code = parameters.get("code");
  if (!code) {
    if (!(await redirectExistingSession())) fail("This page needs a fresh one-time link from your server or identity provider.");
    return;
  }
  history.replaceState(null, "", "/login");
  if (!/^[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/.test(code)) {
    fail("The one-time link is malformed or incomplete.");
    return;
  }
  const response = await fetch("/web/api/session/exchange", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ code })
  });
  if (!response.ok) {
    fail("This one-time link is invalid, expired, or already used. Request a new link.");
    return;
  }
  const established = await response.json();
  window.location.replace(established.redirect_path);
}

run().catch(() => fail("The secure handoff could not be completed. Try a new link."));
