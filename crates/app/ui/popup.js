"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

// Offers waiting for an answer, oldest first. Names come from peers, so they
// only ever reach the DOM through textContent.
const pending = new Map();
let busy = false;

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n;
  let unit = -1;
  do {
    value /= 1024;
    unit += 1;
  } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

function current() {
  return pending.values().next().value;
}

function render() {
  const offer = current();
  if (!offer) return;
  const count = offer.file_count;
  $("title").textContent = `${offer.peer} wants to send you a file`;
  $("name").textContent = count > 1 ? `${offer.first_file} and ${count - 1} more` : offer.first_file;
  $("name").title = offer.first_file;
  $("meta").textContent = formatBytes(offer.total_bytes);
  $("open").hidden = pending.size < 2;
  $("open").textContent = `See ${pending.size} requests`;
  $("accept").disabled = busy;
  $("decline").disabled = busy;
}

function track(transfer) {
  if (transfer.state === "incoming") pending.set(transfer.id, transfer);
  else pending.delete(transfer.id);
}

async function answer(command) {
  const offer = current();
  if (!offer) return;
  busy = true;
  render();
  // Accepting moves the user to the main window to follow the progress.
  if (command === "accept") invoke("show_main");
  try {
    await invoke(command, { id: offer.id });
  } catch (e) {
    // The engine marks the transfer as failed, which removes it from here.
    console.error(e);
  }
  busy = false;
  render();
}

$("accept").addEventListener("click", () => answer("accept"));
$("decline").addEventListener("click", () => answer("decline"));
$("later").addEventListener("click", () => invoke("hide_popup"));
$("open").addEventListener("click", () => {
  invoke("show_main");
  invoke("hide_popup");
});

async function init() {
  await listen("engine", (event) => {
    if (event.payload.type === "transfer") {
      track(event.payload.transfer);
      render();
    }
  });
  const snapshot = await invoke("snapshot");
  snapshot.transfers.forEach(track);
  render();
}

init();
