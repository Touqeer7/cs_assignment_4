import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createApp } from '../server.js';
import { openDatabase } from '../database.js';
let server, db, base;
before(async () => {
  db = openDatabase(':memory:'); server = createApp(db);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => new Promise(resolve => server.close(resolve)));
async function login(mode, username, password, cookie) {
  const r = await fetch(base + '/login', { method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams({ mode, username, password }) });
  return { r, cookie: r.headers.get('set-cookie')?.split(';')[0] };
}
const home = cookie => fetch(base + '/home', {redirect:'manual',headers:cookie ? {cookie} : {}});
test('home cannot be accessed without login', async () => {
  const r=await home();assert.equal(r.status,303);assert.equal(r.headers.get('location'),'/');
});
for(const mode of ['vulnerable','secure']) {
  test(`${mode}: valid credentials redirect to home with database profile and notices`, async () => {
    const {r,cookie}=await login(mode,'admin','Admin@123');
    assert.equal(r.status,303);assert.equal(r.headers.get('location'),'/home');
    const response=await home(cookie);assert.equal(response.status,200);
    const html=await response.text();
    for(const text of ['Welcome, Touqeer.','touqeer@example.com','Information Technology','Administrator','Cyber Security lab submission','Logout']) assert.ok(html.includes(text),text);
    assert.ok(!html.includes('Admin@123'));assert.ok(!html.includes('{{'));
  });
  test(`${mode}: wrong password stays on login`, async () => {
    const {r,cookie}=await login(mode,'admin','wrong');
    assert.match(r.headers.get('location'),/^\/\?error=credentials/);
    assert.equal((await home(cookie)).headers.get('location'),'/');
  });
}
test('exact SQL injection bypass produces an authenticated admin home page', async () => {
  const {r,cookie}=await login('vulnerable',"admin' -- ",'anything');
  assert.equal(r.headers.get('location'),'/home');
  assert.match(r.headers.get('set-cookie'),/HttpOnly/);assert.match(r.headers.get('set-cookie'),/SameSite=Strict/);
  const html=await (await home(cookie)).text();assert.ok(html.includes('Administrator'));assert.ok(html.includes('Welcome, Touqeer.'));
});
test('same payload fails after parameterisation and invalidates old session', async () => {
  const first=await login('vulnerable',"admin' -- ",'anything');
  const fixed=await login('secure',"admin' -- ",'anything',first.cookie);
  assert.equal(fixed.r.headers.get('location'),'/?error=credentials&mode=secure');
  assert.equal((await home(first.cookie)).headers.get('location'),'/');
});
test('student gets their own database profile', async () => {
  const {cookie}=await login('secure','student','Student@123');
  const html=await (await home(cookie)).text();
  assert.ok(html.includes('Welcome, Ayaan.'));assert.ok(html.includes('ayaan@example.com'));assert.ok(html.includes('Student'));
  assert.ok(!html.includes('touqeer@example.com'));
});
test('logout redirects to login and revokes home access', async () => {
  const {cookie}=await login('secure','admin','Admin@123');
  const r=await fetch(base+'/logout',{method:'POST',headers:{cookie},redirect:'manual'});
  assert.equal(r.headers.get('location'),'/');assert.match(r.headers.get('set-cookie'),/Max-Age=0/);
  assert.equal((await home(cookie)).headers.get('location'),'/');
});
test('profiles and notices are fetched fresh from SQLite and escaped', async () => {
  const {cookie}=await login('secure','student','Student@123');
  try {
    db.prepare('UPDATE users SET name = ? WHERE username = ?').run('<script>alert(1)</script>','student');
    db.prepare('INSERT INTO notices VALUES (?, ?, ?, ?, ?)').run(99,'Database notice','<img src=x onerror=alert(1)>','Test','2026-10-28');
    const html=await (await home(cookie)).text();
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(html.includes('Database notice'));assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
    assert.ok(!html.includes('<img src=x'));
  } finally { db.prepare('UPDATE users SET name = ? WHERE username = ?').run('Ayaan Ahmad','student');db.prepare('DELETE FROM notices WHERE id = ?').run(99); }
});
test('logged-in visitor to login page is redirected home',async()=>{
 const {cookie}=await login('secure','admin','Admin@123');
 const r=await fetch(base+'/',{headers:{cookie},redirect:'manual'});assert.equal(r.headers.get('location'),'/home');
});
test('syntax errors stay generic, alternate injection is blocked by fixed query', async()=>{
 const broken=await login('vulnerable',"'",'anything');assert.match(broken.r.headers.get('location'),/error=credentials/);
 assert.equal(await broken.r.text(),'');
 assert.equal((await login('vulnerable',"' OR 1=1 -- ",'anything')).r.headers.get('location'),'/home');
 assert.match((await login('secure',"' OR 1=1 -- ",'anything')).r.headers.get('location'),/error=credentials/);
});
test('unknown modes, oversized forms and cross-origin posts are rejected',async()=>{
 assert.match((await login('unknown','admin','Admin@123')).r.headers.get('location'),/error=credentials/);
 const huge=await fetch(base+'/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'x='.padEnd(5000,'x')});assert.equal(huge.status,413);
 const cross=await fetch(base+'/logout',{method:'POST',headers:{origin:'https://example.com'},redirect:'manual'});assert.equal(cross.status,403);
 assert.equal((await fetch(base+'/database.js')).status,404);
 assert.equal((await fetch(base+'/public/home.html')).status,404);
});

test('all five additional users can sign in and receive their own profiles in both modes', async () => {
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 7);
  for (const [username, password, name] of [
    ['ahmad', 'Ahmad@123', 'Ahmad Khan'],
    ['sara', 'Sara@123', 'Sara Ali'],
    ['hamza', 'Hamza@123', 'Hamza Mir'],
    ['zoya', 'Zoya@123', 'Zoya Shah'],
    ['bilal', 'Bilal@123', 'Bilal Ahmad']
  ]) {
    for (const mode of ['vulnerable', 'secure']) {
      const { r, cookie } = await login(mode, username, password);
      assert.equal(r.headers.get('location'), '/home');
      const response = await home(cookie);
      assert.equal(response.status, 200);
      const html = await response.text();
      assert.ok(html.includes(name));
      assert.ok(html.includes(`${username}@example.com`));
      assert.ok(html.includes('Student'));
      assert.ok(!html.includes('touqeer@example.com'));
    }
  }
});
