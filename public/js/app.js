// app.js — binthere client controller. Routes between "create" and "view" based
// on the URL path (/p/<id>#<key>), drives encryption/decryption, and renders
// decrypted content via DOM construction only. The fragment key never leaves the
// browser and is never placed in a network request.

import { encryptPaste, decryptPaste, decryptContent, deriveContentKey, PasswordRequired } from './crypto.js';
import { createPaste, fetchPaste, fetchPasteMeta, consumePaste, deletePaste, fetchStatus, ApiError } from './api.js';
import { validateHead, validatePaste, buildAAD, EXPIRE_SECONDS } from './format.js';
import { renderMarkdown } from './markdown.js';
import { looksLikeCode, highlightInto } from './highlight.js';
import { $, showView, toast, copyText, flashCopied, pill } from './ui.js';
import { btUrl } from './base.js';
import { uploadFile, downloadFile, saveAs, MAX_FILE } from './files-ui.js';

// Module-level state referenced by helpers that may run during the top-level
// route dispatch below. Declared here (not near the timer helpers further down)
// because `let` in the temporal dead zone would throw if `status()` fired first
// and called `stopExpiryTimer()` before this line was reached — turning every
// view into a stuck "loading…" screen.
let expiryTimer = null;

// ── boot ─────────────────────────────────────────────────────────────────────
const route = location.pathname.match(new RegExp('^' + ((window.__btBase || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) + '/p/([^/]+)/?$'));
const mroute = location.pathname.match(new RegExp('^' + ((window.__btBase || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) + '/m/([^/]+)/?$'));
if (route) {
  let id = null;
  // Malformed percent-encoding must not throw during module evaluation (it
  // would leave every view hidden — a blank page). Show a proper error instead.
  try { id = decodeURIComponent(route[1]); } catch { /* fall through */ }
  if (id !== null) initView(id);
  else status('链接格式不完整——请检查是否已完整复制。', true);
} else if (mroute) {
  let id = null;
  try { id = decodeURIComponent(mroute[1]); } catch { /* fall through */ }
  if (id !== null) initManageView(id);
  else status('链接格式不完整——请检查是否已完整复制。', true);
} else {
  initCreate();
}

// ── CREATE ─────────────────────────────────────────────────────────────────
function initCreate() {
  showView('create');
  // Format is uniform now — every note is stored as plaintext and any obvious
  // source code is syntax-highlighted at view time (see renderContent).
  const fmt = 'plaintext';
  // The lock toggle only records intent ("this note needs a password"); the
  // password itself is typed in the modal shown when Create link is pressed.
  let pwRequired = false;

  const lock = $('#lock');
  if (lock) {
    lock.addEventListener('click', () => {
      pwRequired = lock.classList.toggle('active');
      lock.setAttribute('aria-pressed', String(pwRequired));
    });
  }

  const createBtn = $('#create');
  const sendTxt = createBtn.querySelector('.send-txt');
  const msg = $('#create-msg');

  // ── file attachment state ────────────────────────────────────────────────
  let file = null; // selected File object, null = text mode
  // Burn toggle — attachments only. Default ON (阅后即焚: destroyed right after
  // the receiver's complete download, with an optional keep window); OFF keeps
  // the file until expiry and logs accesses for the sender instead. Text notes
  // are always one-time-view; the toggle is hidden in text mode.
  let fileBurn = true;
  const burnBtn = $('#burn-toggle');
  const paintBurn = () => {
    burnBtn.classList.toggle('active', fileBurn);
    burnBtn.setAttribute('aria-pressed', String(fileBurn));
    burnBtn.querySelector('.lock-txt').textContent = fileBurn ? '阅后即焚' : '到期销毁';
  };
  if (burnBtn) {
    paintBurn();
    burnBtn.addEventListener('click', () => { fileBurn = !fileBurn; paintBurn(); });
  }
  const fileInput = $('#file-input');
  const fileRow = $('#file-row');
  const fileChip = $('#file-chip');
  const fileClear = $('#file-clear');
  const fmtLabel = (n) => n > 1024 * 1024 ? (n / 1048576).toFixed(1) + ' MiB' : Math.ceil(n / 1024) + ' KiB';
  const paintFile = () => {
    if (file) {
      fileChip.textContent = `📎 ${file.name}（${fmtLabel(file.size)}）`;
      fileRow.hidden = false;
      fileClear.hidden = false;
      if (burnBtn) burnBtn.hidden = false; // burn toggle only makes sense for files
    } else {
      fileRow.hidden = true;
      fileChip.textContent = '';
      fileClear.hidden = true;
      fileInput.value = '';
      if (burnBtn) burnBtn.hidden = true;
    }
  };
  $('#attach-btn').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const f = fileInput.files && fileInput.files[0];
    if (!f) return;
    if (f.size > MAX_FILE) { showMsg(msg, `文件过大（上限 ${Math.floor(MAX_FILE / 1048576)} MiB）。`); return; }
    file = f;
    paintFile();
    msg.hidden = true;
  });
  fileClear.addEventListener('click', () => { file = null; paintFile(); });

  const requestCreate = () => {
    if (createBtn.disabled) return;
    if (file) { submitFile(); return; }
    if (!$('#editor').value.trim()) { showMsg(msg, '先写点内容。'); $('#editor').focus(); return; }
    msg.hidden = true;
    if (pwRequired) openPasswordModal((password) => submitPaste(password));
    else submitPaste('');
  };
  createBtn.addEventListener('click', requestCreate);
  // Editor convention: Ctrl/Cmd+Enter submits without leaving the textarea.
  $('#editor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); requestCreate(); }
  });

  // ── file upload path ─────────────────────────────────────────────────────
  // Files skip the arrow choreography: the button relabels to per-chunk
  // progress, which is the honest signal during a multi-second transfer.
  async function submitFile() {
    createBtn.disabled = true;
    const label = sendTxt ? sendTxt.textContent : '';
    const setLabel = (t) => { if (sendTxt) sendTxt.textContent = t; };
    setLabel('加密中……');
    try {
      const { id, fragment, deletetoken } = await uploadFile(file, {
        expire: $('#expire-select').value,
        burn: fileBurn,
        onProgress: (done, total) => setLabel(`上传中 ${done}/${total}…`),
      });
      const url = `${location.origin}${btUrl('/p/')}${id}#${fragment}`;
      file = null;
      paintFile();
      $('#editor').value = '';
      await leaveCreateView();
      showSuccess({ id, deletetoken, url, isFile: true, isFileBurn: fileBurn });
    } catch (e) {
      showMsg(msg, friendlyError(e));
      createBtn.disabled = false;
      setLabel(label);
    }
  }

  // Every note is one-time view (bar:true) and auto-deletes within 24h — a
  // deliberate product choice, not a missing picker. The wire format (and the
  // CLI/API) supports the full expiry range; the web client does not expose it.
  async function submitPaste(password) {
    createBtn.disabled = true;
    const label = sendTxt ? sendTxt.textContent : '';
    // Press → the arrow leaves the button (`.sending`), then the composer follows
    // it out and the success view takes over, so the arrow leads the navigation.
    // Skipped under reduced motion: the CSS travel is off there, so the 32px jump
    // would just make the arrow vanish.
    const animate = !reducedMotion();
    let relabel = null;
    if (animate) {
      createBtn.classList.add('sending');
      // The label waits for the arrow to clear — swapping it mid-flight resizes
      // the button and jogs the icon the eye is following.
      relabel = setTimeout(() => { if (sendTxt) sendTxt.textContent = '加密中……'; }, ARROW_LEAD_MS);
    } else if (sendTxt) {
      sendTxt.textContent = '加密中……';
    }
    const arrowGone = animate ? wait(ARROW_LEAD_MS) : null;
    try {
      const { body, fragment } = await encryptPaste({
        text: $('#editor').value,
        password,
        fmt,
        bar: true,
        expire: $('#expire-select').value,
      });
      const { id, deletetoken } = await createPaste(body);
      const url = `${location.origin}${btUrl('/p/')}${id}#${fragment}`;
      clearTimeout(relabel);
      if (arrowGone) await arrowGone; // never hand over ahead of the arrow
      await leaveCreateView();
      // Only after the server confirmed the create, and after the composer has
      // left the screen so the editor is never seen blanking. The plaintext has
      // served its purpose; don't leave it in the (now hidden) textarea. On any
      // failure it is deliberately kept — the user must not lose their note.
      $('#editor').value = '';
      showSuccess({ id, deletetoken, url, isBurn: true });
    } catch (e) {
      clearTimeout(relabel);
      createBtn.classList.remove('sending'); // the arrow glides back in
      showMsg(msg, friendlyError(e));
      createBtn.disabled = false;
      if (sendTxt) sendTxt.textContent = label;
    }
  }
}

// Slide the composer out behind the departing arrow. The class is dropped before
// the caller swaps views, both within the same frame, so the faded sheet is never
// seen snapping back.
async function leaveCreateView() {
  const view = $('#view-create');
  if (!view || reducedMotion()) return;
  view.classList.add('view-leaving');
  await wait(VIEW_EXIT_MS);
  view.classList.remove('view-leaving');
}

// ── password modal ───────────────────────────────────────────────────────────
// The single popup: "Paste password" with Cancel / Create. Calls onSubmit(pw)
// once with a non-empty password; closes on backdrop click, Escape, or cancel.
// While open, Tab is trapped inside the dialog; on close, focus returns to the
// element that opened it (a11y — the modal is aria-modal="true").
function openPasswordModal(onSubmit) {
  const scrim = $('#pw-modal');
  if (!scrim) { onSubmit(''); return; }

  const input = $('#modal-password');
  const confirmInput = $('#modal-password-confirm');
  const create = $('#pw-create');
  const cancel = $('#pw-cancel');
  const mmsg = $('#pw-modal-msg');
  const opener = document.activeElement;
  // One group: the confirm field holds the same secret, so both eyes toggle together.
  wirePeek(
    ['#modal-password', '#modal-peek'],
    ['#modal-password-confirm', '#modal-peek-confirm'],
  );

  const close = () => {
    scrim.hidden = true;
    input.value = ''; // don't leave the password in the hidden DOM
    confirmInput.value = '';
    create.onclick = cancel.onclick = scrim.onclick = input.onkeydown = confirmInput.onkeydown = null;
    document.removeEventListener('keydown', onKey);
    if (opener && typeof opener.focus === 'function') opener.focus();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') { close(); return; }
    if (e.key !== 'Tab') return;
    // Focus trap: cycle within the dialog's enabled, visible controls.
    const focusables = [...scrim.querySelectorAll('input, button')]
      .filter((el) => !el.disabled && el.offsetParent !== null);
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && (document.activeElement === first || !scrim.contains(document.activeElement))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !scrim.contains(document.activeElement))) {
      e.preventDefault();
      first.focus();
    }
  };
  const submit = () => {
    if (!input.value) { showMsg(mmsg, '请输入密码，或取消。'); input.focus(); return; }
    // Practical cap, enforced VISIBLY — never via maxlength, whose silent
    // truncation could seal the note with a password the reader doesn't have.
    if (input.value.length > 128) {
      showMsg(mmsg, '密码过长——最多 128 个字符。');
      input.focus();
      return;
    }
    // A mistyped password permanently locks a one-time note (there is no safe
    // way to test it afterwards — opening the link consumes the note).
    if (input.value !== confirmInput.value) {
      showMsg(mmsg, '两次输入不一致——请在两个字段中输入相同的密码。');
      confirmInput.focus();
      return;
    }
    const pw = input.value;
    close();
    onSubmit(pw);
  };

  create.onclick = submit;
  cancel.onclick = close;
  scrim.onclick = (e) => { if (e.target === scrim) close(); };
  input.onkeydown = confirmInput.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
  document.addEventListener('keydown', onKey);

  mmsg.hidden = true;
  input.value = '';
  confirmInput.value = '';
  scrim.hidden = false;
  // Focus the dialog (not the input) so the modal is reachable and the focus
  // trap works, without painting a focus ring on the field before the user
  // has clicked or tabbed into it.
  $('#pw-modal-dialog').focus();
}

// Poll the sender status endpoint while the creator is on the success screen.
// The server holds the event log (metadata only: time + type), so this survives
// tab closes and works for both file and burn pastes. 15s cadence — this is a
// reassurance signal, not a live feed. 404 → gone (expired/deleted) → final
// state, stop. The same info is available any time via /m/<id>#<deletetoken>.
let dlTimer = null;
function watchDownloads(id, token, kind = 'file') {
  if (dlTimer !== null) { clearInterval(dlTimer); dlTimer = null; }
  const el = $('#dl-status');
  const paint = (s) => {
    el.hidden = false;
    if (s.state === 'consumed') {
      el.textContent = `✅ 已被接收方下载并销毁${s.consumedAt ? '（' + fmtTime(s.consumedAt) + '）' : ''}`;
    } else if (s.state === 'kept') {
      el.textContent = `⏳ 接收方选择保留至 ${fmtTime(s.keepUntil)}`;
    } else if (s.state === 'expired' || s.state === 'abandoned') {
      el.textContent = s.state === 'expired' ? '📭 已到期销毁（无人下载）' : '📭 下载未完成，已回收';
    } else {
      const opens = s.events.filter((e) => e.e === 'download').length;
      el.textContent = opens > 0 ? `📥 已有 ${opens} 次下载${s.state === 'armed' ? '，等待打开' : ''}` : '📥 还没有人下载';
    }
  };
  const tick = async () => {
    try {
      paint(await fetchStatus(kind, id, token));
    } catch (e) {
      if (dlTimer !== null) { clearInterval(dlTimer); dlTimer = null; }
      el.hidden = false;
      el.textContent = e instanceof ApiError && e.status === 403
        ? '📥 状态不可用（令牌不匹配）'
        : '📥 链接已失效（到期或已删除）';
    }
  };
  tick();
  dlTimer = setInterval(tick, 15000);
}

// unix seconds → local "MM-DD HH:mm" for status lines.
function fmtTime(unixSeconds) {
  if (!Number.isInteger(unixSeconds) || unixSeconds <= 0) return '';
  const d = new Date(unixSeconds * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function showSuccess({ id, deletetoken, url, isBurn, isFile, isFileBurn }) {
  showView('success');
  $('#paste-url').textContent = url;
  if (isFile) {
    $('#success-note').textContent = isFileBurn
      ? '附件默认阅后即焚：接收方完整下载后立即销毁（可由接收方选择保留一段时间）。'
      : '附件保留到到期自动销毁，期间每次下载都会记录在管理页。';
  } else if (isBurn) {
    $('#success-note').textContent =
      '任何持有此链接的人都只能阅读一次。';
  }
  renderQr(url);
  // Persistent sender view: /m/<id>#<deletetoken> — token IS the credential,
  // same trust model as the delete button. Survives tab/browser closes, unlike
  // the old in-memory download counter.
  const murl = `${location.origin}${btUrl('/m/')}${id}#${deletetoken}`;
  const mrow = $('#manage-row');
  if (mrow) mrow.hidden = !(isFile || isBurn);
  const mEl = $('#manage-url');
  if (mEl) mEl.textContent = murl;
  const mCopy = $('#copy-manage');
  if (mCopy) mCopy.onclick = async () => {
    flashCopied(mCopy, (await copyText(murl)) ? '已复制' : '复制失败');
  };
  const mOpen = $('#open-manage');
  if (mOpen) mOpen.onclick = () => { location.href = murl; };
  if (isFile || isBurn) watchDownloads(id, deletetoken, isFile ? 'file' : 'paste');
  else $('#dl-status').hidden = true;

  $('#copy-url').onclick = async () => {
    flashCopied($('#copy-url'), (await copyText(url)) ? '已复制' : '复制失败');
  };
  // Both irreversible actions are two-step: opening a one-time link consumes it,
  // and delete is permanent. A stray click must not kill a note about to be shared.
  armConfirm($('#open-link'), '打开将消耗唯一一次阅读——确定？', () => { location.href = url; });
  $('#another').onclick = () => { location.href = btUrl('/'); };

  const delBtn = $('#delete-btn');
  const sMsg = $('#success-msg');
  const delLabel = delBtn.textContent;
  armConfirm(delBtn, '永久删除？', async () => {
    delBtn.disabled = true;
    delBtn.textContent = '删除中……';
    try {
      await deletePaste(id, deletetoken);
      showMsg(sMsg, '该内容已删除。');
      toast('已删除');
      delBtn.textContent = '已删除';
      // The link is dead now — don't leave live-looking actions pointing at it.
      $('#open-link').disabled = true;
      $('#copy-url').disabled = true;
    } catch (e) {
      showMsg(sMsg, friendlyError(e));
      delBtn.disabled = false;
      delBtn.textContent = delLabel;
    }
  });
}

// Two-step confirmation for irreversible actions. The first activation "arms"
// the button — its label changes in place to name the destructive effect (the
// change is announced by screen readers since focus stays on the control); a
// second activation within the window confirms. Disarms on timeout or blur so
// an abandoned half-click can't linger as a landmine.
function armConfirm(btn, armedLabel, onConfirm) {
  const label = btn.textContent;
  let timer = null;
  const disarm = () => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
    btn.textContent = label;
    btn.classList.remove('armed');
  };
  btn.onclick = () => {
    if (timer !== null) { disarm(); onConfirm(); return; }
    btn.textContent = armedLabel;
    btn.classList.add('armed');
    timer = setTimeout(disarm, 5000);
  };
  btn.onblur = disarm;
}

function renderQr(url) {
  const img = $('#qr');
  try {
    if (typeof window.qrcode !== 'function') throw new Error('qr unavailable');
    const qr = window.qrcode(0, 'M');
    qr.addData(url);
    qr.make();
    img.src = qr.createDataURL(6, 12);
  } catch {
    img.closest('.qr')?.remove();
  }
}

// ── VIEW ─────────────────────────────────────────────────────────────────────
function initView(id) {
  // Only show the "new paste" shortcut when viewing someone's note, not on the
  // landing page (where the whole screen already is the composer).
  const newlink = $('#newlink');
  if (newlink) newlink.hidden = false;

  const fragment = location.hash.slice(1);
  if (!fragment) { status('链接缺少解密密钥。', true); return; }
  if (id[0] === 'b') initBurnView(id, fragment);
  else initNormalView(id, fragment);
}

// Normal (KV) paste: reads are idempotent, so fetch and decrypt directly.
async function initNormalView(id, fragment) {
  status('解密中……');
  let paste;
  try { paste = await fetchPaste(id); } catch (e) { return handleReadError(e); }
  // File pastes carry an encrypted manifest (name/size/chunks/ivs) instead of
  // text. Detect by decrypting as a manifest first; fall back to text view.
  try {
    const info = await tryFilePaste(paste, id, fragment);
    if (info) return;
  } catch { /* not a file — fall through to text path */ }
  try {
    renderPaste(paste, await decryptPaste({ paste, fragment }));
  } catch (e) {
    if (e instanceof PasswordRequired) return promptPasswordNormal(paste, fragment);
    status('无法解密该内容。链接可能已损坏或被改动。', true);
  }
}

// Returns true if the paste was rendered as a file download. Throws when it
// isn't a valid file paste (caller falls back to the text path).
async function tryFilePaste(paste, id, fragment) {
  const cek = await deriveContentKey({ adata: paste.adata, wk: paste.wk, fragment });
  let man;
  try {
    const content = await decryptContent({ adata: paste.adata, ct: paste.ct, cek });
    man = JSON.parse(content.text);
  } catch { throw new Error('not a file paste'); }
  if (!man || typeof man.size !== 'number' || typeof man.chunks !== 'number'
      || !Array.isArray(man.ivs) || man.ivs.length !== man.chunks) {
    throw new Error('not a file paste');
  }
  const burn = !!paste.adata.bar; // burn-on-download mode
  showView('paste');
  const pills = $('#paste-pills');
  pills.textContent = '';
  pills.appendChild(pill(`文件 ${man.name} · ${man.size > 1048576 ? (man.size / 1048576).toFixed(1) + ' MiB' : Math.ceil(man.size / 1024) + ' KiB'}`));
  if (burn) pills.appendChild(pill('阅后即焚 · 下载后销毁', 'bad'));
  const container = $('#paste-content');
  container.textContent = '';
  const pre = document.createElement('pre');
  pre.className = 'code';
  pre.textContent = burn
    ? `📎 ${man.name}\n大小：${man.size} 字节 · ${man.chunks} 个加密分块\n\n点击下方「下载并销毁」下载解密到本地——完成后服务器立即销毁此文件。`
    : `📎 ${man.name}\n大小：${man.size} 字节 · ${man.chunks} 个加密分块\n\n点击下方「保存文件」下载并解密到本地。`;
  container.appendChild(pre);
  const rawBtn = $('#toggle-raw');
  rawBtn.hidden = true;
  const saveBtn = $('#save-file');
  saveBtn.hidden = false;
  saveBtn.disabled = false;
  saveBtn.textContent = burn ? '下载并销毁' : '保存文件';
  // Burn mode: a small keep picker beside the button — "destroy now" is the
  // default; the receiver may ask for a bounded window (capped server-side by
  // the paste's own expiry). Hidden in retention mode.
  const keepSel = $('#keep-select');
  const keepRow = $('#keep-row');
  if (keepRow) keepRow.hidden = !burn;
  saveBtn.onclick = async () => {
    saveBtn.disabled = true;
    saveBtn.textContent = '下载解密中……';
    const keepSeconds = burn && keepSel ? Number(keepSel.value || 0) : 0;
    try {
      const { name, size, bytes, consumed } = await downloadFile(id, fragment, { keepSeconds });
      saveAs({ name, bytes });
      if (burn && consumed) {
        saveBtn.textContent = consumed.state === 'kept'
          ? `已保存；文件保留至 ${fmtTime(consumed.keepUntil)}`
          : `已保存 ${name}（${size} 字节）；原文件已销毁`;
        saveBtn.disabled = true; // nothing left to download
      } else if (burn) {
        saveBtn.textContent = `已保存 ${name}（${size} 字节）`;
      } else {
        saveBtn.textContent = `已保存 ${name}（${size} 字节）`;
        saveBtn.disabled = false; // retention mode: repeat downloads allowed
      }
    } catch (e) {
      toast(e && e.message ? e.message : '下载失败');
      saveBtn.disabled = false;
      saveBtn.textContent = burn ? '下载并销毁' : '保存文件';
    }
  };
  return true;
}

// Burn paste: peek the head (adata + wrapped key, NO ciphertext) without
// consuming, so a password can be verified before the single destructive read.
// The paste is only consumed once we actually reveal it.
async function initBurnView(id, fragment) {
  status('校验中……');
  let head;
  try { head = await fetchPasteMeta(id); } catch (e) { return handleReadError(e); }
  try {
    // Fail-closed validation of the peeked head BEFORE any key derivation, so a
    // hostile/buggy server can't demand an absurd PBKDF2 workload (adata.iter is
    // clamped) or feed malformed fields into the crypto path.
    head = validateHead(head);
  } catch {
    return status('无法读取该内容——服务器响应格式异常。', true);
  }

  if (head.adata.kdf === 'pbkdf2-hkdf') {
    // Password-protected: prompt + verify against the wrapped key BEFORE consuming.
    promptPasswordBurn(id, fragment, head);
  } else {
    // No password: an explicit "reveal" click is the consent to burn it.
    status('该内容仅可查看一次。', false, { reveal: true });
    const revealBtn = $('#reveal-burn');
    revealBtn.disabled = false;
    // When the countdown hits zero the note is gone server-side — leaving an
    // enabled Reveal pointing at a doomed 410 would be a lie. Transition to the
    // expired state immediately (status() also stops and hides the timer).
    startExpiryTimer(head.meta, () => {
      revealBtn.disabled = true;
      status('该内容已过期，无法再打开。', true);
    });
    revealBtn.onclick = async () => {
      revealBtn.disabled = true;
      $('#status-actions').hidden = true;
      // Verify the fragment key against the peeked wrapped key BEFORE the
      // destructive read: a truncated/corrupted link must not burn the note.
      let cek;
      try {
        cek = await deriveContentKey({ adata: head.adata, wk: head.wk, fragment });
      } catch {
        return status('无法解密该内容——链接可能不完整或已损坏。内容未开启且仍然保留。', true);
      }
      consumeBurn(id, head, cek);
    };
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Perform the single destructive read and render. The fragment key (and any
// password) has already been verified against the peeked head, and `cek` is the
// unwrapped content key from that verification — reused here so the password is
// never stretched (PBKDF2) twice and the consumed read cannot "fail late".
async function consumeBurn(id, head, cek) {
  status('解密中……');
  let paste;
  try { paste = await consumePaste(id); } catch (e) { return handleReadError(e); }
  try {
    paste = validatePaste(paste);
    // Defense in depth: the consumed record must match the authenticated head we
    // verified the key against. (GCM would reject a swap anyway — the AAD and wk
    // are bound — but failing here is clearer and cheaper.)
    if (paste.wk !== head.wk || !bytesEqual(buildAAD(paste.adata), buildAAD(head.adata))) {
      throw new Error('head mismatch');
    }
    const result = await decryptContent({ adata: paste.adata, ct: paste.ct, cek });
    // The note is consumed; drop the key from the address bar so a reload or a
    // shared screenshot of the URL doesn't carry a now-useless (but real) secret.
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    renderPaste(paste, result);
  } catch {
    status('无法解密该内容。链接可能已损坏或被改动。', true);
  }
}

function promptPasswordNormal(paste, fragment) {
  wirePasswordScreen(false, async (password) => {
    renderPaste(paste, await decryptPaste({ paste, fragment, password }));
  });
}

function promptPasswordBurn(id, fragment, head) {
  wirePasswordScreen(true, async (password) => {
    // Verify the password against the peeked wrapped key WITHOUT consuming.
    // Throws PasswordRequired / DecryptError, leaving the paste intact.
    const cek = await deriveContentKey({ adata: head.adata, wk: head.wk, fragment, password });
    // Verified → the one destructive read, reusing the already-unwrapped CEK
    // (no second 310k-iteration PBKDF2 run).
    await consumeBurn(id, head, cek);
  });
}

// Shared password screen. `verify(password)` throws on a bad/empty password
// (paste untouched) and otherwise transitions the view itself.
function wirePasswordScreen(isBurn, verify) {
  showView('password');
  wirePeek(['#decrypt-password', '#peek2']);
  const sub = $('#password-subtitle');
  if (sub) {
    sub.textContent = isBurn
      ? '这条一次性内容受密码保护。只有输入正确密码才会打开并销毁。'
      : '这条内容除链接中的密钥外，还设有密码保护。';
  }
  const input = $('#decrypt-password');
  const btn = $('#decrypt-btn');
  const msg = $('#password-msg');
  input.value = '';
  input.focus();

  // Guard the handler itself, not just the button: the Enter keydown path
  // bypasses `disabled`, and on a burn paste a second concurrent verify would
  // issue a second destructive read — the losing 410 could then overwrite the
  // decrypted view. Stays latched on success (verify() replaced the view).
  let inFlight = false;
  const submit = async () => {
    if (inFlight) return;
    inFlight = true;
    msg.hidden = true;
    btn.disabled = true;
    // Password key derivation (PBKDF2) takes real time — say so, like the
    // create button 的「加密中……」。
    const label = btn.textContent;
    btn.textContent = '解密中……';
    try {
      await verify(input.value);
      input.value = ''; // verified — don't leave the password in the hidden DOM
    } catch (e) {
      // A GCM auth failure cannot distinguish a wrong password from a
      // corrupted/tampered link, so the message covers both honestly.
      showMsg(msg, e instanceof PasswordRequired
        ? '请输入密码。'
        : '密码错误——请重试。如果确认无误，则链接可能已损坏或被改动。');
      inFlight = false;
      btn.disabled = false;
      btn.textContent = label;
      input.focus();
    }
  };
  btn.onclick = submit;
  input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
}

function handleReadError(e) {
  // A fetch that never reached the server (offline, DNS, blocked) is NOT the
  // same as "gone" — telling a burn-note reader their note was consumed when
  // they are merely offline would be needlessly alarming.
  if (!(e instanceof ApiError)) {
    status('无法连接服务器——请检查网络后重试。', true);
  } else if (e.status === 410) {
    status('该内容已过期或已被阅读。', true);
  } else {
    status('该内容已过期、已被阅读，或从未存在。', true);
  }
}

// ── MANAGE (/m/<id>#<deletetoken>) ───────────────────────────────────────────
// Sender-only view. The fragment carries the DELETE TOKEN — the same secret
// that powers the delete button — so this link authorizes status reads and
// deletion, never decryption. Rendered with DOM construction only.
const EVENT_LABELS = {
  read: '被阅读',
  download: '开始下载',
  complete: '下载完成',
};
function initManageView(id) {
  const fragment = location.hash.slice(1);
  if (!fragment) { status('管理链接缺少凭据——请使用创建时保存的管理链接。', true); return; }
  const kind = id[0] === 'f' ? 'file' : 'paste';

  const paint = (s) => {
    showView('manage');
    const pills = $('#manage-pills');
    pills.textContent = '';
    const statePill = {
      armed: ['待接收 · 仅可查看一次', 'warn'],
      live: ['存活中', 'ok'],
      consumed: ['已被接收', 'bad'],
      kept: ['接收方保留中', 'warn'],
      expired: ['已到期销毁', 'bad'],
      abandoned: ['下载未完成 · 已回收', 'bad'],
    }[s.state] || [s.state, ''];
    pills.appendChild(pill(statePill[0], statePill[1]));
    if (s.keepUntil) pills.appendChild(pill(`保留至 ${fmtTime(s.keepUntil)}`, 'warn'));
    if (s.exp > 0) pills.appendChild(pill(`${s.consumedAt || s.state === 'expired' ? '原' : ''}到期 ${fmtTime(s.exp)}`));

    const meta = $('#manage-meta');
    meta.textContent = '';
    if (s.meta && Number.isInteger(s.meta.created)) {
      meta.textContent = `创建于 ${fmtTime(s.meta.created)}`;
    }

    // Event log, newest first. Metadata only (time + type) by design.
    const log = $('#manage-log');
    log.textContent = '';
    const events = [...s.events].reverse();
    if (!events.length) {
      const li = document.createElement('li');
      li.textContent = '还没有任何访问记录。';
      log.appendChild(li);
    }
    for (const ev of events) {
      const li = document.createElement('li');
      li.textContent = `${fmtTime(ev.t)} · ${EVENT_LABELS[ev.e] || ev.e}`;
      log.appendChild(li);
    }

    // Content link is only shown while content still exists.
    const crow = $('#manage-content-row');
    if (crow) {
      crow.hidden = !['armed', 'live', 'kept'].includes(s.state);
      const curl = `${location.origin}${btUrl('/p/')}${id}`;
      const cEl = $('#manage-content-url');
      if (cEl) cEl.textContent = curl;
      const cCopy = $('#copy-content-url');
      if (cCopy) cCopy.onclick = async () => {
        flashCopied(cCopy, (await copyText(curl)) ? '已复制' : '复制失败');
      };
    }
    const delBtn = $('#manage-delete');
    if (delBtn) {
      delBtn.disabled = !['armed', 'live', 'kept'].includes(s.state);
      delBtn.textContent = ['armed', 'live', 'kept'].includes(s.state) ? '立即删除' : '已销毁';
    }
  };

  const refresh = async () => {
    try { paint(await fetchStatus(kind, id, fragment)); return true; }
    catch (e) {
      if (e instanceof ApiError && e.status === 403) {
        status('凭据不匹配——这条管理链接不属于此内容。', true);
      } else if (e instanceof ApiError && e.status === 404) {
        status('记录已过期清理（销毁记录保留 7 天）。', true);
      } else {
        status('无法连接服务器——请检查网络后重试。', true);
      }
      return false;
    }
  };
  refresh();
  clearInterval(dlTimer);
  dlTimer = setInterval(async () => {
    // Stop polling once the content is gone for good.
    if (!(await refresh()) && dlTimer !== null) { clearInterval(dlTimer); dlTimer = null; }
  }, 15000);

  const delBtn = $('#manage-delete');
  if (delBtn) {
    armConfirm(delBtn, '永久删除？', async () => {
      delBtn.disabled = true;
      delBtn.textContent = '删除中……';
      try {
        await deletePaste(id, fragment);
        toast('已删除');
        clearInterval(dlTimer); dlTimer = null;
        await refresh();
      } catch {
        delBtn.disabled = false;
        delBtn.textContent = '立即删除';
        toast('删除失败，请重试');
      }
    });
  }
}

function renderPaste(paste, result) {
  showView('paste');

  // Notes are uniform text now; source code is auto-detected and highlighted.
  // `isCode` also covers older pastes explicitly saved with fmt:'code'.
  const isMarkdown = result.fmt === 'markdown';
  const isCode = result.fmt === 'code' || (result.fmt === 'plaintext' && looksLikeCode(result.text));

  // Pills: (code|markdown) · (one-time view). Plain text gets no kind pill —
  // it's the default and adds nothing. No expiry pill either: an opened note is
  // already consumed, so "expires in 24h" would be misleading.
  const pills = $('#paste-pills');
  pills.textContent = '';
  if (isMarkdown) pills.appendChild(pill('markdown'));
  else if (isCode) pills.appendChild(pill('code'));
  if (result.bar) pills.appendChild(pill('一次性查看 · 已删除', 'bad'));

  // Content (DOM construction only).
  const container = $('#paste-content');
  let showRaw = false;
  const draw = () => renderContent(container, result, isCode, showRaw);
  draw();

  const rawBtn = $('#toggle-raw');
  rawBtn.hidden = !isMarkdown;
  rawBtn.textContent = '原文';
  rawBtn.onclick = () => { showRaw = !showRaw; rawBtn.textContent = showRaw ? '渲染' : '原文'; draw(); };

  $('#copy-content').onclick = async () => {
    toast((await copyText(result.text)) ? '已复制到剪贴板' : '复制失败');
  };
}

function renderContent(container, result, isCode, showRaw) {
  container.textContent = '';
  if (result.fmt === 'markdown' && !showRaw) {
    const div = document.createElement('div');
    div.className = 'md';
    renderMarkdown(div, result.text);
    container.appendChild(div);
    return;
  }
  const pre = document.createElement('pre');
  pre.className = 'code';
  if (isCode) {
    // Highlight via createElement + textContent only (never innerHTML).
    const code = document.createElement('code');
    highlightInto(code, result.text);
    pre.appendChild(code);
  } else {
    pre.textContent = result.text;
  }
  container.appendChild(pre);
}

// ── shared helpers ───────────────────────────────────────────────────────────
// Timings for the create→success hand-off; both are bound to styles.css
// (`.send .send-ico` and `.view-leaving`) and must change with it. ARROW_LEAD_MS
// is not the arrow's full 300ms transition but the point it clears the button's
// edge: an ease-out over 32px covers the visible ~29px in under half that, so the
// view leaves here and overlaps the invisible tail instead of waiting it out.
const ARROW_LEAD_MS = 150;
const VIEW_EXIT_MS = 170;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The stylesheet turns every animation and transition off under
// `prefers-reduced-motion: reduce`, so don't sit through durations nothing spends.
const reducedMotion = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

// Wire one or more [inputSel, btnSel] pairs to a shared reveal state, so a group
// of fields holding the *same* secret (the modal's password + confirm) unmasks
// as one — clicking either eye updates both fields and both icons. No secret is
// exposed that the user hasn't already asked to see: the pair is two entries of
// one password, on one screen, revealed only by explicit click.
function wirePeek(...pairs) {
  const fields = pairs
    .map(([inputSel, btnSel]) => ({ input: $(inputSel), btn: $(btnSel) }))
    .filter(({ input, btn }) => input && btn);
  if (!fields.length) return;

  // The eye / struck-eye icons are static markup in index.html; `revealed`
  // picks which one is visible (see .peek in styles.css) — never touch the
  // button's children, that would wipe them.
  const paint = (show) => {
    for (const { input, btn } of fields) {
      input.type = show ? 'text' : 'password';
      btn.classList.toggle('revealed', show);
      btn.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
      btn.setAttribute('aria-pressed', String(show));
    }
  };

  // Re-wiring means a fresh entry (modal reopened, password screen shown):
  // always start masked, even if the field was left revealed last time.
  paint(false);
  for (const { btn } of fields) {
    // Read the state off the group, not this button, so both eyes agree even if
    // one was somehow left out of sync.
    btn.onclick = () => paint(fields[0].input.type === 'password');
  }
}

// `reveal` shows the burn "reveal once" action block; callers opt in explicitly
// rather than the function sniffing the message text (which broke on rewording).
function status(message, isError = false, { reveal = false } = {}) {
  showView('status');
  // Any status transition supersedes a running countdown; the reveal branch
  // restarts it explicitly. Prevents a stale timer ticking under a later screen.
  stopExpiryTimer();
  const el = $('#status-msg');
  el.textContent = message;
  el.classList.toggle('error', isError);
  // Error states get a warning glyph + a "Create new paste" action, like the
  // reference expired screen. The burn "reveal once" prompt keeps its own action.
  const ico = $('#status-ico');
  if (ico) ico.hidden = !isError;
  const actions = $('#status-actions');
  if (actions) actions.hidden = !reveal;
  const newActions = $('#status-new');
  if (newActions) newActions.hidden = !isError;
}

// ── self-destruct countdown ──────────────────────────────────────────────────
// Shown on the burn "reveal once" screen: how long until the note auto-expires.
// Purely informational — the authoritative expiry is the DO alarm server-side;
// this is derived from the non-secret meta (created + expire) in the peeked head.
// `expiryTimer` itself is declared near the top of the module (see the boot
// section) so it is initialized before `status()` can reference it.

function stopExpiryTimer() {
  if (expiryTimer !== null) { clearInterval(expiryTimer); expiryTimer = null; }
  const box = $('#status-timer');
  if (box) { box.hidden = true; box.classList.remove('ending'); }
}

// `meta.created` (unix seconds) is set by the server on create and echoed in the
// peek response; `expire` maps to a fixed TTL. A note with no expiry (never) or
// missing created gets no timer rather than a bogus one. `onExpire` fires once
// when the countdown reaches zero (possibly synchronously, if already past).
function startExpiryTimer(meta, onExpire) {
  const box = $('#status-timer');
  const clock = $('#status-timer-clock');
  if (!box || !clock || !meta) return;
  const ttl = EXPIRE_SECONDS[meta.expire] ?? 0;
  if (ttl <= 0 || !Number.isInteger(meta.created)) return;

  const expireAt = (meta.created + ttl) * 1000;
  let expired = false;
  const render = () => {
    const left = Math.max(0, expireAt - Date.now());
    clock.textContent = formatDuration(left);
    // Pulse under ten minutes — a quiet "hurry" cue without shouting.
    box.classList.toggle('ending', left > 0 && left <= 600000);
    if (left <= 0) {
      expired = true;
      if (expiryTimer !== null) { clearInterval(expiryTimer); expiryTimer = null; }
      box.classList.remove('ending');
      if (onExpire) onExpire();
    }
  };
  box.hidden = false;
  render();
  if (!expired) expiryTimer = setInterval(render, 1000);
}

// ms → H:MM:SS (or MM:SS under an hour). Clamps at 0 (shows "expired").
function formatDuration(ms) {
  const total = Math.floor(ms / 1000);
  if (total <= 0) return '已过期';
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

function showMsg(el, message) {
  el.textContent = message;
  el.hidden = false;
}

function friendlyError(e) {
  if (e instanceof ApiError) {
    if (e.status === 429) return '来自你所在网络的请求过于频繁——请稍候再试。';
    if (e.status === 413) return '内容过大。';
    return '服务器错误，请重试。';
  }
  if (e && /too large/.test(e.message || '')) return '内容过大（上限 1 MiB）。';
  return '出错了，请重试。';
}
