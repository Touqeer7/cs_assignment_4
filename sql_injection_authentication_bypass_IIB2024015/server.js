import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openDatabase, authenticate, getProfile, getNotices } from './database.js';

// Values from SQLite are escaped before insertion into HTML.
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
const page = name => readFileSync(new URL(`./public/${name}`, import.meta.url), 'utf8');

export function createApp(db = openDatabase()) {
  const sessions = new Map();
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    const send = (status, body, type = 'text/html; charset=utf-8') => {
      res.writeHead(status, { 'Content-Type': type }); res.end(body);
    };
    const redirect = location => { res.writeHead(303, { Location: location }); res.end(); };
    const token = req.headers.cookie?.match(/(?:^|;\s*)portal_session=([a-f0-9]{48})(?:;|$)/)?.[1];
    let session = sessions.get(token);
    if (session && session.expires <= Date.now()) { sessions.delete(token); session = null; }
    const signOut = () => {
      sessions.delete(token);
      res.setHeader('Set-Cookie', 'portal_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    };
    // The deliberately vulnerable lab listens on loopback only.
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host || ''))
      return send(403, 'Use localhost or 127.0.0.1.', 'text/plain');
    if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`)
      return send(403, 'Cross-origin request rejected.', 'text/plain');
    const path = req.url.split('?')[0];
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      if (session && getProfile(db, session.userId)) return redirect('/home');
      return send(200, page('index.html'));
    }
    if (req.method === 'GET' && ['/style.css', '/login.js'].includes(path)) {
      return send(200, page(path.slice(1)), path.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8');
    }
    if (req.method === 'POST' && path === '/logout') { signOut(); return redirect('/'); }
    if (req.method === 'POST' && path === '/login') {
      signOut(); // Every attempt invalidates an old session.
      if (!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded'))
        return send(415, 'Expected a form submission.', 'text/plain');
      let body = '';
      try {
        for await (const chunk of req) {
          body += chunk;
          if (Buffer.byteLength(body) > 4096) return send(413, 'Request too large.', 'text/plain');
        }
        const form = new URLSearchParams(body);
        const username = form.get('username'), password = form.get('password'), mode = form.get('mode');
        if (!['vulnerable', 'secure'].includes(mode)) return redirect('/?error=credentials');
        const failed = () => redirect(`/?error=credentials&mode=${mode}`);
        if (!username || !password || username.length > 200 || password.length > 200) return failed();
        let user;
        try { user = authenticate(db, mode, username, password); }
        catch { return failed(); } // Do not expose database errors or SQL.
        if (!user) return failed();
        for (const [id, old] of sessions) if (old.expires <= Date.now()) sessions.delete(id);
        const id = randomBytes(24).toString('hex');
        sessions.set(id, { userId: user.id, expires: Date.now() + 15 * 60 * 1000 });
        res.setHeader('Set-Cookie', `portal_session=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=900`);
        return redirect('/home');
      } catch { return send(400, 'Invalid request.', 'text/plain'); }
    }
    if (req.method === 'GET' && path === '/home') {
      const user = session && getProfile(db, session.userId);
      if (!user) { signOut(); return redirect('/'); }
      const notices = getNotices(db);
      const values = {
        name: user.name, firstName: user.name.split(' ')[0], username: user.username,
        email: user.email, department: user.department,
        role: user.role === 'admin' ? 'Administrator' : user.role === 'student' ? 'Student' : user.role,
        initial: user.name.charAt(0).toUpperCase(), count: notices.length
      };
      // Replace profile tokens first, then insert separately escaped notice HTML.
      let html = page('home.html').replace(/\{\{(\w+)\}\}/g, (match, key) => key === 'notices' ? match : escapeHTML(values[key] ?? ''));
      const noticeHTML = notices.map(n => `<article class="notice"><div class="notice-meta"><span class="category">${escapeHTML(n.category)}</span><time datetime="${escapeHTML(n.published_on)}">${escapeHTML(new Date(n.published_on + 'T00:00:00Z').toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }))}</time></div><h3>${escapeHTML(n.title)}</h3><p>${escapeHTML(n.body)}</p></article>`).join('') || '<p class="empty">No announcements at the moment.</p>';
      html = html.replace('{{notices}}', () => noticeHTML);
      return send(200, html);
    }
    send(404, 'Page not found.', 'text/plain');
  });
  server.on('close', () => db.close());
  return server;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createApp().listen(Number(process.env.PORT || 3000), '127.0.0.1', () => {
    console.log('Campus Portal running at http://localhost:' + (process.env.PORT || 3000));
  });
}
