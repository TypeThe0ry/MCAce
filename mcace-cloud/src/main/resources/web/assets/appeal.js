import { api, clear, element, formatTime, label, showBanner, signOut, statusClass } from "/assets/common.js";

let timeline = null;

async function loadSession() {
  const session = await api("/web/api/session");
  if (session.principal_type !== "PLAYER") { window.location.replace("/dashboard"); return false; }
  document.querySelector("#player-name").textContent = session.subject_id;
  return true;
}

function renderCases(payload) {
  timeline = payload;
  const root = document.querySelector("#case-list"); clear(root);
  const appealsByCase = new Map(payload.current_appeals.map(value => [value.case_id, value]));
  if (!payload.current_reviews.length) root.append(element("p", "muted", "No review cases are associated with this account."));
  payload.current_reviews.forEach(review => {
    const card = element("article", "review-card");
    const top = element("div", "card-top"); top.append(element("span", "card-title", review.title), element("span", statusClass(review.status), label(review.status)));
    card.append(top, element("p", "card-meta", review.reason));
    const appeal = appealsByCase.get(review.id);
    if (appeal) card.append(element("p", "card-meta", `Appeal: ${label(appeal.status)} · updated ${formatTime(appeal.occurred_at)}`));
    card.append(element("p", "card-meta", `Case ${review.id} · version ${review.version}`)); root.append(card);
  });
  const selector = document.querySelector("#case-id"); clear(selector);
  const eligible = payload.current_reviews.filter(review => ["ACTION_RECOMMENDED", "CLOSED_ACTIONED"].includes(review.status) && !appealsByCase.has(review.id));
  eligible.forEach(review => { const option = element("option", "", review.title + " · " + label(review.status)); option.value = review.id; selector.append(option); });
  document.querySelector("#submit-appeal").disabled = eligible.length === 0;
  if (!eligible.length) { const option = element("option", "", "No case is currently eligible"); option.value = ""; selector.append(option); }
}

function notificationCard(notification) {
  const card = element("article", "notification-card" + (notification.read ? "" : " unread"));
  const top = element("div", "card-top"); top.append(element("span", "card-title", notification.title), element("time", "card-meta", formatTime(notification.created_at)));
  card.append(top, element("p", "card-meta", notification.message));
  if (!notification.read) {
    const button = element("button", "button secondary", "Mark read"); button.type = "button";
    button.addEventListener("click", async () => { await api(`/web/api/player/notifications/${notification.notification_id}/read`, { method: "POST" }); await loadNotifications(); });
    card.append(button);
  }
  return card;
}

async function loadNotifications() {
  const payload = await api("/web/api/player/notifications?limit=100");
  const root = document.querySelector("#notifications"); clear(root);
  payload.notifications.forEach(value => root.append(notificationCard(value)));
  if (!payload.notifications.length) root.append(element("p", "muted", "Your inbox is clear."));
  document.querySelector("#unread-count").textContent = payload.notifications.filter(value => !value.read).length;
}

async function loadAll() {
  const [history] = await Promise.all([api("/web/api/player/timeline?limit=100"), loadNotifications()]); renderCases(history);
}

async function submitAppeal(event) {
  event.preventDefault();
  const caseId = document.querySelector("#case-id").value;
  if (!caseId) return;
  await api("/web/api/player/appeals", { method: "POST", body: JSON.stringify({ appeal_id: crypto.randomUUID(), case_id: caseId, statement: document.querySelector("#statement").value.trim() }) });
  document.querySelector("#appeal-form").reset(); await loadAll();
}

document.querySelector("#logout").addEventListener("click", signOut);
document.querySelector("#refresh").addEventListener("click", () => loadAll().catch(error => showBanner(error.message)));
document.querySelector("#appeal-form").addEventListener("submit", event => submitAppeal(event).catch(error => showBanner(error.message)));

(async () => { if (await loadSession()) await loadAll(); })().catch(error => {
  if (error.status === 401) window.location.replace("/login"); else showBanner(error.message);
});
