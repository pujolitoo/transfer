"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const model = {
  connection: "logged_out",
  username: null,
  friends: [],
  transfers: new Map(),
  settings: null,
  myFingerprint: "",
  selected: null,
  registering: false,
  speed: new Map(), // id -> { bytes, at, rate }
  cards: new Map(), // id -> { node, meta, bar, key }
};

// Everything from peers (names, file paths) reaches the DOM as text, never HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  }
  node.append(...children.filter((c) => c !== null));
  return node;
}

function showError(id, message) {
  const node = $(id);
  node.textContent = message ?? "";
  node.hidden = !message;
}

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

function formatEta(seconds) {
  if (seconds < 60) return `${Math.ceil(seconds)} s`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

/** Runs a command, routing a failure to an error slot. */
async function run(errorSlot, command, args) {
  showError(errorSlot, null);
  try {
    return await invoke(command, args);
  } catch (e) {
    showError(errorSlot, String(e));
    return undefined;
  }
}

/* Sign-in */

function setAuthMode(registering) {
  model.registering = registering;
  $("tab-login").setAttribute("aria-selected", String(!registering));
  $("tab-register").setAttribute("aria-selected", String(registering));
  $("auth-pass2-row").hidden = !registering;
  $("auth-pass2").required = registering;
  $("auth-submit").textContent = registering ? "Crear cuenta" : "Entrar";
  $("auth-pass").autocomplete = registering ? "new-password" : "current-password";
  showError("auth-error", null);
}

$("tab-login").addEventListener("click", () => setAuthMode(false));
$("tab-register").addEventListener("click", () => setAuthMode(true));

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (model.registering && $("auth-pass").value !== $("auth-pass2").value) {
    showError("auth-error", "Las contraseñas no coinciden");
    return;
  }
  const submit = $("auth-submit");
  submit.disabled = true;
  await run("auth-error", model.registering ? "register" : "login", {
    server: $("auth-server").value,
    fingerprint: $("auth-fingerprint").value,
    username: $("auth-user").value,
    password: $("auth-pass").value,
  });
  submit.disabled = false;
  if ($("auth-error").hidden) {
    $("auth-pass").value = "";
    $("auth-pass2").value = "";
  }
});

/* Friends */

function renderFriends() {
  const friends = model.friends;
  const accepted = friends
    .filter((f) => f.status === "accepted")
    .sort((a, b) => b.online - a.online || a.username.localeCompare(b.username));
  const incoming = friends.filter((f) => f.status === "incoming");
  const outgoing = friends.filter((f) => f.status === "outgoing");

  if (!accepted.some((f) => f.username === model.selected)) {
    model.selected = accepted[0]?.username ?? null;
  }

  const nodes = [];
  if (incoming.length) {
    nodes.push(el("div", { class: "friend-group" }, "SOLICITUDES"));
    for (const f of incoming) {
      nodes.push(
        el("div", { class: "request" },
          el("span", {}, f.username),
          el("div", { class: "row" },
            el("button", {
              class: "primary",
              onclick: () => run("friend-error", "respond_friend", { username: f.username, accept: true }),
            }, "Aceptar"),
            el("button", {
              onclick: () => run("friend-error", "respond_friend", { username: f.username, accept: false }),
            }, "Rechazar"),
          ),
        ),
      );
    }
  }
  nodes.push(el("div", { class: "friend-group" }, "AMIGOS"));
  if (!accepted.length) {
    nodes.push(el("p", { class: "muted small", style: "padding:4px 8px" },
      "Añade a alguien por su nombre de usuario."));
  }
  for (const f of accepted) {
    nodes.push(
      el("button", {
        class: "friend",
        "aria-current": String(f.username === model.selected),
        onclick: () => {
          model.selected = f.username;
          renderFriends();
        },
      },
        el("span", { class: `dot${f.online ? " on" : ""}`, title: f.online ? "Conectado" : "Desconectado" }),
        el("span", { class: "friend-name" }, f.username),
        f.key_changed ? el("span", { class: "badge" }, "clave") : null,
      ),
    );
  }
  if (outgoing.length) {
    nodes.push(el("div", { class: "friend-group" }, "PENDIENTES"));
    for (const f of outgoing) {
      nodes.push(el("div", { class: "friend muted" },
        el("span", { class: "friend-name" }, f.username),
        el("button", {
          class: "link",
          onclick: () => run("friend-error", "remove_friend", { username: f.username }),
        }, "Cancelar"),
      ));
    }
  }
  $("friends").replaceChildren(...nodes);
  renderPeer();
}

function renderPeer() {
  const friend = model.friends.find((f) => f.username === model.selected);
  const header = $("peer-header");
  const zone = $("dropzone");
  if (!friend) {
    header.replaceChildren(el("div", { class: "peer-title" },
      el("h2", {}, "Sin amigo seleccionado"),
      el("p", { class: "muted" }, "Cuando alguien acepte tu solicitud podrás enviarle ficheros.")));
    zone.hidden = true;
    return;
  }
  const title = el("div", { class: "peer-title" },
    el("h2", {}, friend.username),
    el("code", { title: "Huella de su clave" }, friend.fingerprint ?? ""));
  const remove = el("button", {
    class: "link",
    onclick: async () => {
      const message = `¿Eliminar a ${friend.username} de tus amigos?`;
      if (await invoke("ask_confirmation", { message, confirm: "Eliminar" })) {
        run("send-error", "remove_friend", { username: friend.username });
      }
    },
  }, "Eliminar amigo");
  header.replaceChildren(title, remove);

  if (friend.key_changed) {
    zone.hidden = true;
    header.replaceChildren(el("div", { class: "key-warning" },
      el("p", {}, `La clave de ${friend.username} ha cambiado. Puede ser un dispositivo nuevo o una suplantación. `
        + `Comprueba con esa persona que su huella es ${friend.fingerprint} antes de confiar en ella.`),
      el("button", { onclick: () => run("send-error", "trust_key", { username: friend.username }) }, "Confiar"),
    ));
    return;
  }
  zone.hidden = false;
  $("drop-title").textContent = friend.online
    ? `Arrastra aquí lo que quieras enviar a ${friend.username}`
    : `${friend.username} no está conectado; podrás enviarle ficheros cuando vuelva`;
  $("pick-files").disabled = !friend.online;
  $("pick-folder").disabled = !friend.online;
}

function canSendToSelected() {
  const friend = model.friends.find((f) => f.username === model.selected);
  return friend && friend.online && !friend.key_changed && model.connection === "online";
}

$("add-friend").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("add-friend-input");
  const username = input.value.trim();
  if (!username) return;
  await run("friend-error", "add_friend", { username });
  if ($("friend-error").hidden) input.value = "";
});

$("pick-files").addEventListener("click", () =>
  run("send-error", "pick_and_send", { to: model.selected, folder: false }));
$("pick-folder").addEventListener("click", () =>
  run("send-error", "pick_and_send", { to: model.selected, folder: true }));

/* Transfers */

const STATE_LABEL = {
  incoming: "Quiere enviarte esto",
  waiting_peer: "Esperando a que lo acepte",
  connecting: "Abriendo túnel…",
  running: "",
  done: "Completado",
  failed: "Error",
  declined: "Rechazado",
  cancelled: "Cancelado",
};
const FINISHED = new Set(["done", "failed", "declined", "cancelled"]);

function trackSpeed(t) {
  const now = performance.now();
  const prev = model.speed.get(t.id);
  if (!prev) {
    model.speed.set(t.id, { bytes: t.done_bytes, at: now, rate: 0 });
    return;
  }
  const elapsed = (now - prev.at) / 1000;
  if (elapsed >= 0.4) {
    const instant = (t.done_bytes - prev.bytes) / elapsed;
    prev.rate = prev.rate ? prev.rate * 0.7 + instant * 0.3 : instant;
    prev.bytes = t.done_bytes;
    prev.at = now;
  }
}

function transferMeta(t) {
  const direction = t.sending ? `Para ${t.peer}` : `De ${t.peer}`;
  const size = formatBytes(t.total_bytes);
  if (t.state === "running") {
    const rate = model.speed.get(t.id)?.rate ?? 0;
    const parts = [direction, `${formatBytes(t.done_bytes)} de ${size}`];
    if (rate > 0) {
      parts.push(`${formatBytes(rate)}/s`, `quedan ${formatEta((t.total_bytes - t.done_bytes) / rate)}`);
    }
    return parts.join(" · ");
  }
  const label = t.message ?? STATE_LABEL[t.state];
  return [direction, size, label].filter(Boolean).join(" · ");
}

function openButton(t) {
  const open = () => run("send-error", "open_received", { id: t.id });
  return el("button", { class: "primary", onclick: open }, "Abrir archivo");
}

function transferActions(t) {
  if (t.state === "incoming") {
    return [
      el("button", { class: "primary", onclick: () => run("send-error", "accept", { id: t.id }) }, "Aceptar"),
      el("button", { onclick: () => run("send-error", "decline", { id: t.id }) }, "Rechazar"),
    ];
  }
  if (t.state === "done" && t.saved_location) {
    const reveal = el("button", {
      onclick: () => run("send-error", "reveal_received", { id: t.id }),
    }, "Abrir ubicación");
    return t.file_count === 1 ? [openButton(t), reveal] : [reveal];
  }
  if (FINISHED.has(t.state)) return [];
  return [el("button", { onclick: () => run("send-error", "cancel", { id: t.id }) }, "Cancelar")];
}

function buildCard(t) {
  const name = t.file_count > 1 ? `${t.first_file} y ${t.file_count - 1} más` : t.first_file;
  const stateClass = t.state === "incoming" ? " incoming" : t.state === "failed" ? " failed" : "";
  const meta = el("div", { class: "transfer-meta" });
  const bar = t.state === "running" ? el("div") : null;
  const node = el("article", { class: `transfer${stateClass}` },
    el("div", { class: "transfer-name", title: t.first_file }, name),
    meta,
    el("div", { class: "transfer-actions" }, ...transferActions(t)),
    bar ? el("div", { class: "progress" }, bar) : null,
  );
  return { node, meta, bar };
}

/**
 * Progress arrives many times a second. Cards are only rebuilt when their state
 * changes, because replacing a button between press and release loses the click.
 */
function renderTransfers() {
  const order = { incoming: 0, running: 1, connecting: 1, waiting_peer: 2 };
  const list = [...model.transfers.values()].sort(
    (a, b) => (order[a.state] ?? 3) - (order[b.state] ?? 3),
  );
  $("clear-finished").hidden = !list.some((t) => FINISHED.has(t.state));
  for (const id of model.cards.keys()) {
    if (!model.transfers.has(id)) model.cards.delete(id);
  }
  const container = $("transfers");
  if (!list.length) {
    container.replaceChildren(el("p", { class: "empty" }, "Todavía no hay transferencias."));
    return;
  }
  const nodes = list.map((t) => {
    const key = `${t.state}|${t.saved_location ?? ""}`;
    let card = model.cards.get(t.id);
    if (card?.key !== key) {
      card = { ...buildCard(t), key };
      model.cards.set(t.id, card);
    }
    card.meta.textContent = transferMeta(t);
    if (card.bar) {
      const percent = t.total_bytes ? (t.done_bytes / t.total_bytes) * 100 : 100;
      card.bar.style.width = `${percent}%`;
    }
    return card.node;
  });
  const current = [...container.children];
  if (current.length !== nodes.length || current.some((node, i) => node !== nodes[i])) {
    container.replaceChildren(...nodes);
  }
}

$("clear-finished").addEventListener("click", () => invoke("clear_finished"));

/* Drag and drop onto the window */

listen("tauri://drag-enter", () => {
  if (model.connection !== "online" || !model.selected) return;
  $("drop-overlay-text").textContent = canSendToSelected()
    ? `Enviar a ${model.selected}`
    : `No se puede enviar a ${model.selected} ahora`;
  $("drop-overlay").hidden = false;
});
listen("tauri://drag-leave", () => {
  $("drop-overlay").hidden = true;
});
listen("tauri://drag-drop", (event) => {
  $("drop-overlay").hidden = true;
  if (canSendToSelected() && event.payload.paths?.length) {
    run("send-error", "send_paths", { to: model.selected, paths: event.payload.paths });
  }
});

/* Settings */

$("open-settings").addEventListener("click", async () => {
  $("my-fingerprint").textContent = model.myFingerprint;
  $("download-dir").textContent = model.settings?.download_dir ?? "";
  $("password-message").hidden = true;
  $("autostart").checked = await invoke("get_autostart").catch(() => false);
  $("settings").showModal();
});

$("change-download-dir").addEventListener("click", async () => {
  const dir = await invoke("pick_download_dir");
  if (dir) {
    model.settings.download_dir = dir;
    $("download-dir").textContent = dir;
  }
});
$("open-download-dir").addEventListener("click", () => invoke("open_downloads"));
$("autostart").addEventListener("change", (event) =>
  invoke("set_autostart", { enabled: event.target.checked }));

$("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = $("password-message");
  message.hidden = false;
  try {
    await invoke("change_password", { current: $("pass-current").value, next: $("pass-next").value });
    message.className = "small";
    message.textContent = "Contraseña cambiada.";
    event.target.reset();
  } catch (e) {
    message.className = "small error";
    message.textContent = String(e);
  }
});

/* Updates */

function renderUpdate(status) {
  $("version-text").textContent = `Transfer ${status.current}`;
  $("update-banner").hidden = !status.ready;
  $("update-text").textContent = status.ready ? `La versión ${status.ready} está lista para instalarse.` : "";
}

$("update-install").addEventListener("click", () => invoke("install_update"));
$("check-updates").addEventListener("click", async (event) => {
  const button = event.target;
  button.disabled = true;
  button.textContent = "Buscando…";
  try {
    const status = await invoke("check_updates");
    renderUpdate(status);
    $("version-text").textContent += status.ready ? "" : " · Es la última versión";
  } catch (e) {
    $("version-text").textContent = String(e);
  }
  button.disabled = false;
  button.textContent = "Buscar actualizaciones";
});

$("logout").addEventListener("click", async () => {
  $("settings").close();
  await invoke("logout");
});

/* Engine state */

function renderConnection() {
  const signedIn = model.username !== null;
  $("auth").hidden = signedIn;
  $("app").hidden = !signedIn;
  if (!signedIn) return;
  $("me-name").textContent = model.username;
  const online = model.connection === "online";
  $("conn-dot").className = `dot ${online ? "on" : "wait"}`;
  $("conn-label").textContent = online ? "Conectado" : "Reconectando…";
}

function handleEvent(event) {
  switch (event.type) {
    case "connection":
      model.connection = event.state;
      model.username = event.username;
      if (event.state === "logged_out") {
        model.transfers.clear();
        model.cards.clear();
        if (event.reason) showError("auth-error", event.reason);
      }
      renderConnection();
      renderTransfers();
      break;
    case "friends":
      model.friends = event.friends;
      renderFriends();
      break;
    case "transfer":
      trackSpeed(event.transfer);
      model.transfers.set(event.transfer.id, event.transfer);
      renderTransfers();
      break;
    case "transfer_removed":
      model.transfers.delete(event.id);
      model.speed.delete(event.id);
      renderTransfers();
      break;
  }
}

async function init() {
  // Subscribe first so nothing is lost between the snapshot and the listener.
  await listen("engine", (event) => handleEvent(event.payload));
  await listen("update", (event) => renderUpdate(event.payload));
  renderUpdate(await invoke("update_status"));
  const snapshot = await invoke("snapshot");
  model.connection = snapshot.connection;
  model.username = snapshot.username;
  model.friends = snapshot.friends;
  model.settings = snapshot.settings;
  model.myFingerprint = snapshot.my_fingerprint;
  for (const t of snapshot.transfers) model.transfers.set(t.id, t);
  $("auth-server").value = snapshot.settings.server;
  $("auth-fingerprint").value = snapshot.settings.fingerprint;
  $("server-box").open = snapshot.settings.server.startsWith("127.0.0.1");
  setAuthMode(false);
  renderConnection();
  renderFriends();
  renderTransfers();
}

init();
