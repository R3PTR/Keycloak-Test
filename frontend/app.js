// Notes demo SPA. Authentication goes through user-service:
//   POST /users/login    -> access token in the body, refresh token as HttpOnly cookie
//   POST /users/refresh  -> new access token (cookie-based, needs X-Requested-With)
//   POST /users/logout   -> ends the Keycloak session, clears the cookie
// The access token lives only in memory, so a page reload restores the session via /users/refresh.

const $ = (sel, root = document) => root.querySelector(sel);
const CSRF = { 'X-Requested-With': 'fetch' };

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
const session = {
    token: null,
    claims: null,
    expiresAt: 0,       // epoch ms
    refreshTimer: null,
    refreshing: null,   // in-flight refresh promise (single flight)
};

class ApiError extends Error {
    constructor(status, body) {
        super(body?.message || `HTTP ${status}`);
        this.status = status;
        this.body = body || {};
    }
}

function decodeJwt(token) {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(atob(b64).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''));
    return JSON.parse(json);
}

function setTokens({ accessToken, expiresIn }) {
    session.token = accessToken;
    session.claims = decodeJwt(accessToken);
    session.expiresAt = Date.now() + expiresIn * 1000;
    clearTimeout(session.refreshTimer);
    // Refresh 30 s before expiry.
    session.refreshTimer = setTimeout(() => refresh().catch(() => {}), Math.max((expiresIn - 30) * 1000, 5000));
    renderToken();
}

function clearSession() {
    clearTimeout(session.refreshTimer);
    Object.assign(session, { token: null, claims: null, expiresAt: 0, refreshTimer: null });
}

async function readJson(res) {
    const text = await res.text();
    try { return text ? JSON.parse(text) : null; } catch { return { message: text }; }
}

async function login(username, password) {
    const res = await fetch('/users/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
    });
    const body = await readJson(res);
    log('POST', '/users/login', res.status, 'credentials');
    if (!res.ok) throw new ApiError(res.status, body);
    setTokens(body);
}

/** Returns true if a new access token was obtained. Single-flight. */
function refresh() {
    if (!session.refreshing) {
        session.refreshing = (async () => {
            const res = await fetch('/users/refresh', { method: 'POST', headers: CSRF });
            log('POST', '/users/refresh', res.status, 'cookie');
            if (!res.ok) { clearSession(); return false; }
            setTokens(await res.json());
            return true;
        })().finally(() => { session.refreshing = null; });
    }
    return session.refreshing;
}

async function logout() {
    await fetch('/users/logout', { method: 'POST', headers: CSRF }).catch(() => {});
    clearSession();
    showAnon('You are signed out.');
}

// ---------------------------------------------------------------------------
// API helper: bearer token, transparent refresh, one retry on 401.
// ---------------------------------------------------------------------------
async function api(path, { method = 'GET', body, auth = 'yes', retry = true } = {}) {
    const headers = {};
    if (auth !== 'no') {
        if (!session.token || session.expiresAt - Date.now() < 15000) {
            if (!(await refresh())) return sessionLost();
        }
        headers.Authorization = `Bearer ${auth === 'bad' ? tamper(session.token) : session.token}`;
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const data = res.status === 204 ? null : await readJson(res);
    log(method, path, res.status, auth);

    if (res.status === 401 && auth === 'yes' && retry) {
        if (await refresh()) return api(path, { method, body, auth, retry: false });
        return sessionLost();
    }
    if (!res.ok) throw new ApiError(res.status, data);
    return data;
}

function sessionLost() {
    clearSession();
    showAnon('Your session has ended. Please sign in again.');
    throw new ApiError(401, { message: 'Session ended' });
}

function tamper(token) {
    const i = token.length - 5;
    return token.slice(0, i) + (token[i] === 'A' ? 'B' : 'A') + token.slice(i + 1);
}

const isAdmin = () => session.claims?.realm_access?.roles?.includes('admin');

// ---------------------------------------------------------------------------
// DOM helpers (textContent only: everything shown may be user input)
// ---------------------------------------------------------------------------
function el(tag, props = {}, ...children) {
    const node = Object.assign(document.createElement(tag), props);
    node.append(...children);
    return node;
}

function setStatus(text, kind = '') {
    const s = $('#status');
    s.hidden = !text;
    s.textContent = text || '';
    s.className = `banner ${kind}`;
}

function formError(form, error) {
    const p = $('.form-error', form);
    form.querySelectorAll('.field-error').forEach((n) => n.remove());
    form.querySelectorAll('[aria-invalid]').forEach((n) => n.removeAttribute('aria-invalid'));
    if (!error) { p.hidden = true; return; }
    p.hidden = false;
    p.textContent = error instanceof ApiError ? error.message : String(error.message || error);
    const fields = error.body?.fields || {};
    for (const [name, msg] of Object.entries(fields)) {
        const input = form.elements[name];
        if (!input) continue;
        input.setAttribute('aria-invalid', 'true');
        input.after(el('span', { className: 'field-error', textContent: msg }));
    }
}

function formOk(form, text) {
    const p = $('.form-ok', form);
    if (!p) return;
    p.hidden = !text;
    p.textContent = text || '';
    if (text) setTimeout(() => { p.hidden = true; }, 2500);
}

function formData(form) {
    return Object.fromEntries(new FormData(form).entries());
}

async function busy(form, fn) {
    const btn = $('button[type=submit]', form);
    btn.disabled = true;
    try { return await fn(); } finally { btn.disabled = false; }
}

function log(method, path, status, auth) {
    const kind = status < 300 ? 'ok' : status < 500 ? 'warn' : 'err';
    const label = { yes: 'token', no: 'no token', bad: 'tampered token' }[auth] || auth;
    $('#log').prepend(el('li', { className: kind },
        el('span', { className: 'status', textContent: status }), ` ${method} ${path} `,
        el('span', { className: 'muted', textContent: `(${label}, ${new Date().toLocaleTimeString()})` })));
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------
function showAnon(message) {
    $('#view-app').hidden = true;
    $('#view-anon').hidden = false;
    for (const id of ['#user-chip', '#btn-logout', '#btn-logout-all']) $(id).hidden = true;
    setStatus(message || '', message ? 'info' : '');
    $('#login-form').elements.username.focus();
}

async function showApp() {
    $('#view-anon').hidden = true;
    $('#view-app').hidden = false;
    for (const id of ['#user-chip', '#btn-logout', '#btn-logout-all']) $(id).hidden = false;
    $('#user-chip').textContent = session.claims.preferred_username;
    setStatus('');
    $('#user-search').hidden = !isAdmin();
    $('#admin-users-hint').textContent = isAdmin()
        ? 'Protected by auth_request /_auth/admin. Changes end the user\'s sessions, so they take effect immediately.'
        : 'Admins only. Your token has no "admin" role, so nginx returns 403 here (try the playground button).';

    try {
        const [me, profile] = await Promise.all([api('/api/me'), api('/users/me'), loadNotes()]);
        renderMe(me);
        renderProfile(profile);
        if (isAdmin()) await loadUsers();
    } catch (e) {
        if (e instanceof ApiError && e.status !== 401) setStatus(`Loading failed: ${e.message}`, 'err');
    }
}

function renderMe(me) {
    $('#me').replaceChildren(...Object.entries(me).flatMap(([k, v]) => [
        el('dt', { textContent: k }), el('dd', { textContent: Array.isArray(v) ? v.join(', ') : v })]));
}

function renderProfile(p) {
    const f = $('#profile-form');
    $('#profile-username').textContent = p.username;
    $('#profile-roles').textContent = p.roles.join(', ');
    f.elements.email.value = p.email;
    f.elements.firstName.value = p.firstName;
    f.elements.lastName.value = p.lastName;
}

function renderToken() {
    const c = session.claims;
    if (!c) return;
    $('#token-claims').textContent = JSON.stringify({
        iss: c.iss, sub: c.sub, aud: c.aud, azp: c.azp, typ: c.typ,
        preferred_username: c.preferred_username, email: c.email, name: c.name,
        realm_access: c.realm_access, scope: c.scope,
        iat: new Date(c.iat * 1000).toISOString(), exp: new Date(c.exp * 1000).toISOString(),
    }, null, 2);
}

function tickExpiry() {
    if (!session.token) return;
    const s = Math.round((session.expiresAt - Date.now()) / 1000);
    $('#token-exp').textContent = s > 0 ? `${Math.floor(s / 60)}m ${s % 60}s` : 'expired';
}

// --- notes ---
async function loadNotes() {
    const notes = await api('/api/notes');
    $('#notes').replaceChildren(...notes.map((n) => el('li', {},
        el('span', { className: 'grow', textContent: n.text }),
        el('time', { className: 'muted small', textContent: new Date(n.createdAt).toLocaleString() }),
        el('button', { className: 'small-btn danger', textContent: 'Delete',
            onclick: async () => { await api(`/api/notes/${encodeURIComponent(n.id)}`, { method: 'DELETE' }); loadNotes(); } }))));
    $('#notes-empty').hidden = notes.length > 0;
}

async function loadAllNotes() {
    const out = $('#admin-result');
    try {
        const data = await api('/api/admin/notes');
        out.replaceChildren(
            el('p', { className: 'small', textContent: `${data.totalNotes} notes · ${
                Object.entries(data.notesPerUser).map(([u, c]) => `${u}=${c}`).join(', ') || '–'}` }),
            el('table', {}, el('thead', {}, el('tr', {}, el('th', { textContent: 'User' }), el('th', { textContent: 'Note' }))),
                el('tbody', {}, ...data.notes.map((n) => el('tr', {},
                    el('td', { textContent: n.ownerName }), el('td', { textContent: n.text }))))));
    } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        out.replaceChildren(el('p', { className: 'error', textContent: e.status === 403
            ? '403 Forbidden: nginx denied the request because your token lacks the "admin" role.'
            : `Error ${e.status}: ${e.message}` }));
    }
}

// --- user administration ---
let lastQuery = '';

async function loadUsers(q = lastQuery) {
    lastQuery = q;
    const err = $('#admin-users-error');
    err.hidden = true;
    try {
        const page = await api(`/users/admin/users?size=50&q=${encodeURIComponent(q)}`);
        const selfSub = session.claims.sub;
        const rows = page.content.map((u) => {
            const self = selfSub.endsWith(`:${u.id}`);
            const adminBox = el('input', { type: 'checkbox', checked: u.roles.includes('admin'), disabled: self,
                title: self ? 'You cannot remove your own admin role' : 'Toggle admin role' });
            adminBox.onchange = () => updateUser(u, { roles: adminBox.checked ? ['user', 'admin'] : ['user'] });
            const enabledBox = el('input', { type: 'checkbox', checked: u.enabled, disabled: self,
                title: self ? 'You cannot disable yourself' : 'Enable / disable account' });
            enabledBox.onchange = () => updateUser(u, { enabled: enabledBox.checked });
            return el('tr', { className: u.enabled ? '' : 'disabled' },
                el('td', {}, el('strong', { textContent: u.username }), el('br'),
                    el('span', { className: 'muted small', textContent: `${u.firstName} ${u.lastName}` })),
                el('td', { textContent: u.email }),
                el('td', {}, adminBox),
                el('td', {}, enabledBox),
                el('td', { className: 'actions' },
                    el('button', { className: 'small-btn', textContent: 'Sign out', title: 'End all sessions of this user',
                        onclick: () => adminAction(() => api(`/users/admin/users/${u.id}/logout`, { method: 'POST' }),
                            `Signed out ${u.username} everywhere`) }),
                    el('button', { className: 'small-btn danger', textContent: 'Delete', disabled: self,
                        onclick: () => confirm(`Delete ${u.username}? This cannot be undone.`) &&
                            adminAction(() => api(`/users/admin/users/${u.id}`, { method: 'DELETE' }), `Deleted ${u.username}`) })));
        });
        $('#users-table tbody').replaceChildren(...rows);
        $('#users-table').hidden = false;
        $('#users-total').textContent = `${page.total} user(s)`;
    } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        err.hidden = false;
        err.textContent = e.status === 403 ? '403 Forbidden: admin role required.' : e.message;
    }
}

async function updateUser(u, patch) {
    await adminAction(() => api(`/users/admin/users/${u.id}`, { method: 'PATCH', body: patch }), `Updated ${u.username}`);
}

async function adminAction(fn, okMessage) {
    try {
        await fn();
        setStatus(okMessage, 'ok');
    } catch (e) {
        if (!(e instanceof ApiError)) throw e;
        setStatus(e.message, 'err');
    }
    await loadUsers();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function wire() {
    document.querySelectorAll('.tab').forEach((tab) => {
        tab.onclick = () => {
            document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
            document.querySelectorAll('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
            setStatus('');
        };
    });

    $('#login-form').onsubmit = (ev) => {
        ev.preventDefault();
        const form = ev.target;
        busy(form, async () => {
            formError(form, null);
            const { username, password } = formData(form);
            try {
                await login(username.trim(), password);
                form.reset();
                await showApp();
            } catch (e) {
                formError(form, e.status === 429 ? new Error('Too many attempts. Please wait a minute.') : e);
            }
        });
    };

    $('#register-form').onsubmit = (ev) => {
        ev.preventDefault();
        const form = ev.target;
        busy(form, async () => {
            formError(form, null);
            const data = formData(form);
            if (data.password !== data.password2) {
                return formError(form, new ApiError(400, { message: 'Passwords do not match', fields: { password2: 'Must match' } }));
            }
            delete data.password2;
            try {
                const res = await fetch('/users/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
                const body = await readJson(res);
                log('POST', '/users/register', res.status, 'no token');
                if (!res.ok) throw new ApiError(res.status, body);
                await login(data.username, data.password);
                form.reset();
                await showApp();
                setStatus(`Welcome, ${body.firstName}! Your account was created.`, 'ok');
            } catch (e) {
                formError(form, e);
            }
        });
    };

    $('#profile-form').onsubmit = (ev) => {
        ev.preventDefault();
        const form = ev.target;
        busy(form, async () => {
            formError(form, null);
            try {
                renderProfile(await api('/users/me', { method: 'PUT', body: formData(form) }));
                formOk(form, 'Saved. New tokens will carry the updated claims.');
                await refresh(); // pick up new email/name in the token right away
            } catch (e) {
                formError(form, e);
            }
        });
    };

    $('#password-form').onsubmit = (ev) => {
        ev.preventDefault();
        const form = ev.target;
        busy(form, async () => {
            formError(form, null);
            try {
                await api('/users/me/password', { method: 'PUT', body: formData(form) });
                form.reset();
                clearSession();
                showAnon('Password changed. All sessions were signed out. Please sign in with your new password.');
            } catch (e) {
                formError(form, e);
            }
        });
    };

    $('#note-form').onsubmit = async (ev) => {
        ev.preventDefault();
        const input = $('#note-text');
        const text = input.value.trim();
        if (!text) return;
        await api('/api/notes', { method: 'POST', body: { text } });
        input.value = '';
        await loadNotes();
    };

    $('#user-search').onsubmit = (ev) => {
        ev.preventDefault();
        loadUsers(ev.target.elements.q.value.trim());
    };

    $('#btn-admin').onclick = loadAllNotes;
    $('#btn-logout').onclick = logout;
    $('#btn-logout-all').onclick = async () => {
        try { await api('/users/me/logout-all', { method: 'POST' }); } catch { /* session is gone either way */ }
        clearSession();
        showAnon('Signed out on all devices.');
    };
    $('#btn-refresh').onclick = async () => { await refresh(); tickExpiry(); };

    document.querySelectorAll('[data-probe]').forEach((b) => {
        b.onclick = () => api(b.dataset.probe, { auth: b.dataset.auth, retry: false }).catch((e) => {
            if (!(e instanceof ApiError)) throw e; // status is already in the log
        });
    });
}

async function main() {
    wire();
    setInterval(tickExpiry, 1000);
    // Restore the session from the HttpOnly refresh cookie, if there is one.
    if (await refresh().catch(() => false)) {
        await showApp();
    } else {
        showAnon();
    }
}

main();
