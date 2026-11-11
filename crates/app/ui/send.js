"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const model = { connection: "logged_out", friends: [], names: [], busy: false };

function showError(message) {
  $("error").textContent = message ?? "";
  $("error").hidden = !message;
}

function renderHeader() {
  const { names } = model;
  $("title").textContent = names.length === 1 ? `Send ${names[0]}` : `Send ${names.length} items`;
  $("title").title = names.join("\n");
  $("detail").textContent = names.length > 1 ? names.slice(0, 3).join(", ") + (names.length > 3 ? "…" : "") : "";
}

function hintFor(accepted) {
  if (model.connection === "logged_out") return "Sign in to Transfer to send files.";
  if (model.connection === "connecting") return "Connecting…";
  if (!accepted.length) return "You have no friends yet. Add some in Transfer.";
  return null;
}

function friendRow(friend) {
  const usable = friend.online && !friend.key_changed && model.connection === "online";
  const note = friend.key_changed ? "their key has changed" : friend.online ? null : "offline";
  const row = document.createElement("button");
  row.className = "friend";
  row.disabled = !usable || model.busy;
  const dot = document.createElement("span");
  dot.className = `dot${friend.online ? " on" : ""}`;
  const name = document.createElement("span");
  name.className = "friend-name";
  name.textContent = friend.username;
  row.append(dot, name);
  if (note) {
    const label = document.createElement("span");
    label.className = "muted small";
    label.textContent = note;
    row.append(label);
  }
  row.addEventListener("click", () => send(friend.username));
  return row;
}

function renderFriends() {
  const accepted = model.friends
    .filter((f) => f.status === "accepted")
    .sort((a, b) => b.online - a.online || a.username.localeCompare(b.username));
  const hint = hintFor(accepted);
  $("hint").textContent = hint ?? "";
  $("hint").hidden = !hint;
  $("open-app").hidden = !hint || model.connection === "connecting";
  $("friends").replaceChildren(...(model.connection === "online" ? accepted.map(friendRow) : []));
}

async function send(to) {
  model.busy = true;
  showError(null);
  renderFriends();
  try {
    await invoke("send_pending", { to });
  } catch (e) {
    showError(String(e));
  }
  model.busy = false;
  renderFriends();
}

async function refreshPending() {
  model.names = await invoke("pending_send");
  showError(null);
  renderHeader();
}

$("cancel").addEventListener("click", () => invoke("cancel_send"));
$("open-app").addEventListener("click", () => invoke("show_main"));

async function init() {
  await listen("pending-send", refreshPending);
  await listen("engine", ({ payload }) => {
    if (payload.type === "connection") model.connection = payload.state;
    else if (payload.type === "friends") model.friends = payload.friends;
    else return;
    renderFriends();
  });
  const snapshot = await invoke("snapshot");
  model.connection = snapshot.connection;
  model.friends = snapshot.friends;
  renderFriends();
  await refreshPending();
}

init();
