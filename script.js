"use strict";

/*
  VaultLock Password Manager

  Security:
  - AES-256-GCM
  - PBKDF2-SHA-256
  - Random salt
  - Random IV
  - Web Crypto API
  - Encrypted localStorage
  - Encrypted export
  - Automatic locking
*/


/* =========================================================
   CONFIG
========================================================= */

const STORAGE_KEY = "vaultlock_encrypted_v1";
const THEME_KEY = "vaultlock_theme";

const PBKDF2_ITERATIONS = 250000;

const AUTO_LOCK_MS =
  5 * 60 * 1000; // 5 minutes


/* =========================================================
   STATE
========================================================= */

let vault = [];

let masterPassword = null;

let editingId = null;

let autoLockTimer = null;

const visiblePasswords = new Set();


/* =========================================================
   DOM HELPERS
========================================================= */

const $ = id =>
  document.getElementById(id);


/* =========================================================
   TEXT ENCODING
========================================================= */

const encoder =
  new TextEncoder();

const decoder =
  new TextDecoder();


/* =========================================================
   BASE64
========================================================= */

function bufferToBase64(buffer) {

  const bytes =
    new Uint8Array(buffer);

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}


function base64ToBuffer(base64) {

  const binary =
    atob(base64);

  const bytes =
    new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}


/* =========================================================
   DERIVE AES KEY
========================================================= */

async function deriveKey(
  password,
  salt,
  iterations = PBKDF2_ITERATIONS
) {

  const passwordKey =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );


  return crypto.subtle.deriveKey(

    {
      name: "PBKDF2",

      salt,

      iterations,

      hash: "SHA-256"
    },

    passwordKey,

    {
      name: "AES-GCM",

      length: 256
    },

    false,

    [
      "encrypt",
      "decrypt"
    ]
  );
}


/* =========================================================
   ENCRYPT
========================================================= */

async function encryptVault(
  data,
  password
) {

  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );


  const key =
    await deriveKey(
      password,
      salt
    );


  const plaintext =
    encoder.encode(
      JSON.stringify(data)
    );


  const encrypted =
    await crypto.subtle.encrypt(

      {
        name: "AES-GCM",
        iv
      },

      key,

      plaintext
    );


  return {

    version: 1,

    algorithm:
      "AES-256-GCM",

    kdf:
      "PBKDF2-SHA256",

    iterations:
      PBKDF2_ITERATIONS,

    salt:
      bufferToBase64(salt),

    iv:
      bufferToBase64(iv),

    data:
      bufferToBase64(encrypted)
  };
}


/* =========================================================
   DECRYPT
========================================================= */

async function decryptVault(
  encryptedVault,
  password
) {

  try {

    if (
      !encryptedVault ||
      !encryptedVault.salt ||
      !encryptedVault.iv ||
      !encryptedVault.data
    ) {
      return null;
    }


    const salt =
      new Uint8Array(
        base64ToBuffer(
          encryptedVault.salt
        )
      );


    const iv =
      new Uint8Array(
        base64ToBuffer(
          encryptedVault.iv
        )
      );


    const encrypted =
      base64ToBuffer(
        encryptedVault.data
      );


    const iterations =
      Number(
        encryptedVault.iterations
      ) ||
      PBKDF2_ITERATIONS;


    const key =
      await deriveKey(
        password,
        salt,
        iterations
      );


    const decrypted =
      await crypto.subtle.decrypt(

        {
          name: "AES-GCM",
          iv
        },

        key,

        encrypted
      );


    return JSON.parse(
      decoder.decode(decrypted)
    );

  } catch {

    return null;
  }
}


/* =========================================================
   PERSIST ENCRYPTED VAULT
========================================================= */

async function persistVault() {

  if (!masterPassword) {
    return;
  }


  const encrypted =
    await encryptVault(
      vault,
      masterPassword
    );


  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify(encrypted)
  );
}


/* =========================================================
   INITIALIZATION
========================================================= */

function initialize() {

  loadTheme();


  const existing =
    localStorage.getItem(
      STORAGE_KEY
    );


  if (existing) {

    $("lockText").textContent =
      "Enter your master password to unlock your vault.";

    $("confirmBox")
      .classList
      .add("hidden");

    $("unlockBtn").textContent =
      "Unlock Vault";

    $("unlockBtn").onclick =
      unlockVault;

  } else {

    $("lockText").textContent =
      "Create your master password to secure your vault.";

    $("confirmBox")
      .classList
      .remove("hidden");

    $("unlockBtn").textContent =
      "Create Vault";

    $("unlockBtn").onclick =
      createVault;
  }
}

initialize();


/* =========================================================
   CREATE VAULT
========================================================= */

async function createVault() {

  const password =
    $("masterPassword").value;

  const confirmation =
    $("confirmPassword").value;


  if (password.length < 10) {

    showToast(
      "Master password must contain at least 10 characters."
    );

    return;
  }


  if (password !== confirmation) {

    showToast(
      "Master passwords do not match."
    );

    return;
  }


  vault = [];

  masterPassword =
    password;


  await persistVault();


  openApp();


  showToast(
    "Vault created."
  );
}


/* =========================================================
   UNLOCK VAULT
========================================================= */

async function unlockVault() {

  const password =
    $("masterPassword").value;


  const saved =
    localStorage.getItem(
      STORAGE_KEY
    );


  if (!saved) {

    initialize();

    return;
  }


  let encryptedVault;


  try {

    encryptedVault =
      JSON.parse(saved);

  } catch {

    showToast(
      "Invalid vault data."
    );

    return;
  }


  const decrypted =
    await decryptVault(
      encryptedVault,
      password
    );


  if (!Array.isArray(decrypted)) {

    showToast(
      "Incorrect master password."
    );

    return;
  }


  vault =
    decrypted;

  masterPassword =
    password;


  openApp();


  showToast(
    "Vault unlocked."
  );
}


/* =========================================================
   OPEN APP
========================================================= */

function openApp() {

  $("lockScreen")
    .classList
    .add("hidden");


  $("app")
    .classList
    .remove("hidden");


  renderEntries();

  resetAutoLock();
}


/* =========================================================
   LOCK VAULT
========================================================= */

function lockVault() {

  masterPassword = null;

  vault = [];

  editingId = null;

  visiblePasswords.clear();


  clearTimeout(
    autoLockTimer
  );


  $("app")
    .classList
    .add("hidden");


  $("lockScreen")
    .classList
    .remove("hidden");


  $("masterPassword").value = "";

  $("confirmPassword").value = "";


  $("confirmBox")
    .classList
    .add("hidden");


  $("lockText").textContent =
    "Enter your master password to unlock your vault.";


  $("unlockBtn").textContent =
    "Unlock Vault";


  $("unlockBtn").onclick =
    unlockVault;
}


/* =========================================================
   ADD ENTRY
========================================================= */

function openAddModal() {

  editingId = null;


  $("modalTitle").textContent =
    "Add Password";


  $("site").value = "";

  $("url").value = "";

  $("username").value = "";

  $("password").value = "";

  $("generatedPassword").value = "";

  $("category").value =
    "Personal";


  $("password").type =
    "password";


  $("modal")
    .classList
    .remove("hidden");
}


/* =========================================================
   EDIT ENTRY
========================================================= */

function editEntry(id) {

  const entry =
    vault.find(
      item => item.id === id
    );


  if (!entry) {
    return;
  }


  editingId =
    id;


  $("modalTitle").textContent =
    "Edit Password";


  $("site").value =
    entry.site;

  $("url").value =
    entry.url;

  $("username").value =
    entry.username;

  $("password").value =
    entry.password;

  $("category").value =
    entry.category;


  $("password").type =
    "password";


  $("modal")
    .classList
    .remove("hidden");
}


/* =========================================================
   SAVE ENTRY
========================================================= */

async function saveEntry() {

  const site =
    $("site").value.trim();

  const url =
    $("url").value.trim();

  const username =
    $("username").value.trim();

  const password =
    $("password").value;

  const category =
    $("category").value;


  if (
    !site ||
    !username ||
    !password
  ) {

    showToast(
      "Website, username and password are required."
    );

    return;
  }


  if (editingId) {

    const entry =
      vault.find(
        item =>
          item.id === editingId
      );


    if (entry) {

      entry.site =
        site;

      entry.url =
        url;

      entry.username =
        username;

      entry.password =
        password;

      entry.category =
        category;

      entry.updatedAt =
        Date.now();
    }

  } else {

    vault.push({

      id:
        crypto.randomUUID(),

      site,

      url,

      username,

      password,

      category,

      createdAt:
        Date.now(),

      updatedAt:
        Date.now()
    });
  }


  await persistVault();


  closeModal();

  renderEntries();


  showToast(
    editingId
      ? "Password updated."
      : "Password saved."
  );
}


/* =========================================================
   DELETE ENTRY
========================================================= */

async function deleteEntry(id) {

  const entry =
    vault.find(
      item => item.id === id
    );


  if (!entry) {
    return;
  }


  if (
    !confirm(
      `Delete "${entry.site}"?`
    )
  ) {
    return;
  }


  vault =
    vault.filter(
      item => item.id !== id
    );


  await persistVault();


  renderEntries();


  showToast(
    "Password deleted."
  );
}


/* =========================================================
   RENDER ENTRIES
========================================================= */

function renderEntries() {

  const container =
    $("entries");


  const search =
    $("search")
      .value
      .trim()
      .toLowerCase();


  const category =
    $("categoryFilter").value;


  const filtered =
    vault.filter(entry => {

      const searchable =
        [
          entry.site,
          entry.url,
          entry.username,
          entry.category
        ]
        .join(" ")
        .toLowerCase();


      const searchMatch =
        searchable.includes(search);


      const categoryMatch =
        !category ||
        entry.category === category;


      return (
        searchMatch &&
        categoryMatch
      );
    });


  if (!filtered.length) {

    container.innerHTML = `
      <div class="empty">

        <div class="empty-icon">
          🔐
        </div>

        <h3>No passwords found</h3>

        <p>
          Add your first password or change your search.
        </p>

      </div>
    `;

    return;
  }


  container.innerHTML =
    filtered
      .map(createEntryHTML)
      .join("");
}


/* =========================================================
   ENTRY HTML
========================================================= */

function createEntryHTML(entry) {

  const id =
    escapeHTML(entry.id);


  return `

    <article class="entry">

      <div class="entry-top">

        <div>

          <div class="site-name">
            ${escapeHTML(entry.site)}
          </div>

          ${
            entry.url
              ? `
                <div class="site-url">
                  ${escapeHTML(entry.url)}
                </div>
              `
              : ""
          }

        </div>

        <span class="category-badge">
          ${escapeHTML(entry.category)}
        </span>

      </div>


      <!-- USERNAME -->

      <div class="entry-field">

        <div class="field-label">
          Username
        </div>

        <div class="secret-row">

          <div class="secret">
            ${escapeHTML(entry.username)}
          </div>

          <button
            class="icon-btn"
            title="Copy username"
            onclick="copyEntry('${id}', 'username')"
          >
            📋
          </button>

        </div>

      </div>


      <!-- PASSWORD -->

      <div class="entry-field">

        <div class="field-label">
          Password
        </div>

        <div class="secret-row">

          <div
            class="secret"
            id="password-${id}"
          >
            ••••••••••••
          </div>

          <button
            class="icon-btn"
            title="Show/hide password"
            onclick="toggleEntryPassword('${id}')"
          >
            👁
          </button>

          <button
            class="icon-btn"
            title="Copy password"
            onclick="copyEntry('${id}', 'password')"
          >
            📋
          </button>

        </div>

      </div>


      <!-- ACTIONS -->

      <div class="entry-actions">

        <button
          class="btn primary small"
          onclick="editEntry('${id}')"
        >
          ✏️ Edit
        </button>

        <button
          class="btn danger small"
          onclick="deleteEntry('${id}')"
        >
          🗑 Delete
        </button>

      </div>

    </article>
  `;
}


/* =========================================================
   SHOW / HIDE PASSWORD
========================================================= */

function toggleEntryPassword(id) {

  const entry =
    vault.find(
      item => item.id === id
    );


  const element =
    $("password-" + id);


  if (!entry || !element) {
    return;
  }


  if (
    visiblePasswords.has(id)
  ) {

    visiblePasswords.delete(id);

    element.textContent =
      "••••••••••••";

  } else {

    visiblePasswords.add(id);

    element.textContent =
      entry.password;
  }
}


/* =========================================================
   MODAL PASSWORD VISIBILITY
========================================================= */

$("showModalPassword")
  .addEventListener(
    "click",
    () => {

      const input =
        $("password");

      input.type =
        input.type === "password"
          ? "text"
          : "password";
    }
  );


/* =========================================================
   PASSWORD GENERATOR
========================================================= */

function generatePassword() {

  let characters = "";


  if (
    $("uppercase").checked
  ) {
    characters +=
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  }


  if (
    $("lowercase").checked
  ) {
    characters +=
      "abcdefghijklmnopqrstuvwxyz";
  }


  if (
    $("numbers").checked
  ) {
    characters +=
      "0123456789";
  }


  if (
    $("symbols").checked
  ) {
    characters +=
      "!@#$%^&*()-_=+[]{};:,.<>?";
  }


  if (!characters.length) {

    showToast(
      "Select at least one character set."
    );

    return;
  }


  const length = 24;


  const random =
    crypto.getRandomValues(
      new Uint32Array(length)
    );


  let password = "";


  for (
    let i = 0;
    i < length;
    i++
  ) {

    password +=
      characters[
        random[i] %
        characters.length
      ];
  }


  $("generatedPassword").value =
    password;

  $("password").value =
    password;
}


/* =========================================================
   COPY USERNAME / PASSWORD
========================================================= */

async function copyEntry(
  id,
  type
) {

  const entry =
    vault.find(
      item => item.id === id
    );


  if (!entry) {
    return;
  }


  const value =
    type === "username"
      ? entry.username
      : entry.password;


  try {

    await navigator.clipboard.writeText(
      value
    );


    showToast(
      type === "username"
        ? "Username copied."
        : "Password copied."
    );

  } catch {

    showToast(
      "Could not access clipboard."
    );
  }
}


/* =========================================================
   EXPORT ENCRYPTED VAULT
========================================================= */

function exportVault() {

  const encrypted =
    localStorage.getItem(
      STORAGE_KEY
    );


  if (!encrypted) {

    showToast(
      "No vault to export."
    );

    return;
  }


  const blob =
    new Blob(
      [encrypted],
      {
        type:
          "application/json"
      }
    );


  const url =
    URL.createObjectURL(blob);


  const link =
    document.createElement("a");


  link.href =
    url;

  link.download =
    "vaultlock-encrypted.json";


  document.body.appendChild(link);

  link.click();

  link.remove();


  URL.revokeObjectURL(url);


  showToast(
    "Encrypted vault exported."
  );
}


/* =========================================================
   IMPORT ENCRYPTED VAULT
========================================================= */

function importVault(file) {

  const reader =
    new FileReader();


  reader.onload = () => {

    try {

      const imported =
        JSON.parse(
          reader.result
        );


      if (
        !imported.salt ||
        !imported.iv ||
        !imported.data
      ) {

        throw new Error(
          "Invalid encrypted vault"
        );
      }


      if (
        !confirm(
          "Import this vault? Your current browser vault will be replaced."
        )
      ) {
        return;
      }


      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(imported)
      );


      lockVault();


      showToast(
        "Vault imported. Unlock it with its original master password."
      );

    } catch {

      showToast(
        "Invalid encrypted vault file."
      );
    }
  };


  reader.readAsText(file);
}


/* =========================================================
   DARK MODE
========================================================= */

function toggleTheme() {

  const current =
    document.documentElement
      .getAttribute(
        "data-theme"
      );


  const next =
    current === "dark"
      ? "light"
      : "dark";


  document.documentElement
    .setAttribute(
      "data-theme",
      next
    );


  localStorage.setItem(
    THEME_KEY,
    next
  );
}


function loadTheme() {

  const saved =
    localStorage.getItem(
      THEME_KEY
    );


  if (saved) {

    document.documentElement
      .setAttribute(
        "data-theme",
        saved
      );

    return;
  }


  if (
    window.matchMedia &&
    window.matchMedia(
      "(prefers-color-scheme: dark)"
    ).matches
  ) {

    document.documentElement
      .setAttribute(
        "data-theme",
        "dark"
      );
  }
}


/* =========================================================
   AUTO LOCK
========================================================= */

function resetAutoLock() {

  clearTimeout(
    autoLockTimer
  );


  if (!masterPassword) {
    return;
  }


  autoLockTimer =
    setTimeout(
      () => {

        if (
          !$("app")
            .classList
            .contains("hidden")
        ) {

          lockVault();

          showToast(
            "Vault automatically locked."
          );
        }

      },
      AUTO_LOCK_MS
    );
}


[
  "mousemove",
  "mousedown",
  "keydown",
  "touchstart",
  "scroll"
].forEach(event => {

  document.addEventListener(
    event,
    () => {

      if (masterPassword) {
        resetAutoLock();
      }

    },
    {
      passive: true
    }
  );

});


/* =========================================================
   HTML ESCAPING
========================================================= */

function escapeHTML(value) {

  return String(value ?? "")
    .replaceAll(
      "&",
      "&amp;"
    )
    .replaceAll(
      "<",
      "&lt;"
    )
    .replaceAll(
      ">",
      "&gt;"
    )
    .replaceAll(
      '"',
      "&quot;"
    )
    .replaceAll(
      "'",
      "&#039;"
    );
}


/* =========================================================
   TOAST
========================================================= */

let toastTimer;


function showToast(message) {

  const toast =
    $("toast");


  toast.textContent =
    message;


  toast.classList.add(
    "show"
  );


  clearTimeout(
    toastTimer
  );


  toastTimer =
    setTimeout(
      () => {

        toast.classList.remove(
          "show"
        );

      },
      2500
    );
}


/* =========================================================
   EVENT LISTENERS
========================================================= */

$("addBtn")
  .addEventListener(
    "click",
    openAddModal
  );


$("closeModal")
  .addEventListener(
    "click",
    () => {

      $("modal")
        .classList
        .add("hidden");

      editingId = null;
    }
  );


$("saveBtn")
  .addEventListener(
    "click",
    saveEntry
  );


$("generateBtn")
  .addEventListener(
    "click",
    generatePassword
  );


$("search")
  .addEventListener(
    "input",
    renderEntries
  );


$("categoryFilter")
  .addEventListener(
    "change",
    renderEntries
  );


$("themeBtn")
  .addEventListener(
    "click",
    toggleTheme
  );


$("lockBtn")
  .addEventListener(
    "click",
    lockVault
  );


$("exportBtn")
  .addEventListener(
    "click",
    exportVault
  );


$("importBtn")
  .addEventListener(
    "click",
    () => {

      $("importFile").click();

    }
  );


$("importFile")
  .addEventListener(
    "change",
    event => {

      const file =
        event.target.files[0];

      if (file) {
        importVault(file);
      }

      event.target.value = "";

    }
  );


/* Close modal when clicking backdrop */

$("modal")
  .addEventListener(
    "click",
    event => {

      if (
        event.target ===
        $("modal")
      ) {

        $("modal")
          .classList
          .add("hidden");

        editingId = null;
      }
    }
  );


/* Escape key */

document.addEventListener(
  "keydown",
  event => {

    if (
      event.key === "Escape" &&
      !$("modal")
        .classList
        .contains("hidden")
    ) {

      $("modal")
        .classList
        .add("hidden");

      editingId = null;
    }
  }
);
