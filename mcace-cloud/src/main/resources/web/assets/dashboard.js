import { api, clear, element, formatTime, label, showBanner, signOut, statusClass } from "/assets/common.js";

const state = { reviews: [], selected: null, canReview: false };
const nextStates = {
  OPEN: ["UNDER_REVIEW", "CLOSED_NO_ACTION"],
  UNDER_REVIEW: ["ACTION_RECOMMENDED", "CLOSED_NO_ACTION"],
  ACTION_RECOMMENDED: ["CLOSED_ACTIONED", "CLOSED_NO_ACTION"],
  CLOSED_ACTIONED: [], CLOSED_NO_ACTION: []
};

async function loadSession() {
  const session = await api("/web/api/session");
  if (session.principal_type !== "OPERATOR") { window.location.replace("/appeal"); return false; }
  state.canReview = session.roles.includes("OPERATOR_REVIEWER");
  document.querySelector("#operator-name").textContent = session.subject_id + " · " + session.roles.map(label).join(", ");
  return true;
}

function reviewCard(review) {
  const button = element("button", "review-card" + (state.selected && state.selected.id === review.id ? " selected" : ""));
  button.type = "button";
  const top = element("div", "card-top");
  top.append(element("span", "card-title", review.title), element("span", statusClass(review.status), label(review.status)));
  button.append(top, element("div", "card-meta", review.player_uuid + " · updated " + formatTime(review.occurred_at)));
  button.addEventListener("click", () => selectReview(review));
  return button;
}

function renderReviews() {
  const list = document.querySelector("#review-list"); clear(list);
  if (!state.reviews.length) list.append(element("p", "muted", "No review cases are visible."));
  state.reviews.forEach(review => list.append(reviewCard(review)));
  document.querySelector("#metric-total").textContent = state.reviews.length;
  document.querySelector("#metric-open").textContent = state.reviews.filter(review => ["OPEN", "UNDER_REVIEW"].includes(review.status)).length;
  document.querySelector("#metric-action").textContent = state.reviews.filter(review => review.status === "ACTION_RECOMMENDED").length;
}

function selectReview(review) {
  state.selected = review; renderReviews();
  document.querySelector("#empty-detail").classList.add("hidden");
  document.querySelector("#review-detail").classList.remove("hidden");
  document.querySelector("#detail-heading").textContent = review.title;
  document.querySelector("#detail-status").textContent = label(review.status) + " · version " + review.version;
  document.querySelector("#detail-player").textContent = review.player_uuid;
  document.querySelector("#detail-reason").textContent = review.reason;
  document.querySelector("#detail-recommendation").textContent = review.recommendation || "No recommendation recorded";
  const select = document.querySelector("#target-status"); clear(select);
  const targets = nextStates[review.status] || [];
  targets.forEach(value => { const option = element("option", "", label(value)); option.value = value; select.append(option); });
  const form = document.querySelector("#transition-form");
  form.classList.toggle("hidden", !state.canReview || !targets.length);
}

async function loadReviews() {
  const payload = await api("/web/api/operator/reviews?limit=100");
  state.reviews = payload.reviews;
  if (state.selected) state.selected = state.reviews.find(value => value.id === state.selected.id) || null;
  renderReviews(); if (state.selected) selectReview(state.selected);
}

async function transition(event) {
  event.preventDefault(); if (!state.selected) return;
  const target = document.querySelector("#target-status").value;
  const recommendation = document.querySelector("#transition-recommendation").value.trim();
  if (target === "ACTION_RECOMMENDED" && !recommendation) { showBanner("An action recommendation needs explanatory text."); return; }
  await api(`/web/api/operator/reviews/${state.selected.id}/transitions`, {
    method: "POST", body: JSON.stringify({ expected_version: state.selected.version, target_status: target,
      reason: document.querySelector("#transition-reason").value.trim(), recommendation })
  });
  document.querySelector("#transition-form").reset(); await loadReviews();
}

function renderTimeline(payload) {
  const root = document.querySelector("#timeline"); clear(root);
  if (!payload.events.length) { root.append(element("p", "muted", "No timeline events found.")); return; }
  payload.events.forEach(event => {
    const item = element("article", "timeline-item");
    item.append(element("time", "", formatTime(event.occurred_at)));
    const body = element("div");
    body.append(element("strong", "", label(event.kind)));
    const summary = Object.entries(event).filter(([key]) => !["kind", "occurred_at", "id"].includes(key))
      .map(([key, value]) => `${label(key)}: ${value ?? "—"}`).join(" · ");
    body.append(element("p", "", summary)); item.append(body); root.append(item);
  });
}

async function loadPlayer(event) {
  event.preventDefault();
  const uuid = document.querySelector("#player-uuid").value.trim();
  renderTimeline(await api(`/web/api/operator/players/${encodeURIComponent(uuid)}/timeline?limit=100`));
}

document.querySelector("#logout").addEventListener("click", signOut);
document.querySelector("#refresh-reviews").addEventListener("click", () => loadReviews().catch(error => showBanner(error.message)));
document.querySelector("#transition-form").addEventListener("submit", event => transition(event).catch(error => showBanner(error.message)));
document.querySelector("#player-form").addEventListener("submit", event => loadPlayer(event).catch(error => showBanner(error.message)));

(async () => { if (await loadSession()) await loadReviews(); })().catch(error => {
  if (error.status === 401) window.location.replace("/login"); else showBanner(error.message);
});
