import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function openDatabase(path) {
  if (!path) {
    mkdirSync(new URL('./data/', import.meta.url), { recursive: true });
    path = fileURLToPath(new URL('./data/portal.sqlite', import.meta.url));
  }
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      department TEXT NOT NULL,
      role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notices (
      id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      category TEXT NOT NULL,
      published_on TEXT NOT NULL
    );
  `);
  // Fictional records for the assignment; no real personal data.
  const user = db.prepare('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?)');
  user.run(1, 'admin', 'Admin@123', 'Touqeer', 'touqeer@example.com', 'Information Technology', 'admin');
  user.run(2, 'student', 'Student@123', 'Ayaan Ahmad', 'ayaan@example.com', 'Information Technology', 'student');
  user.run(3, 'ahmad', 'Ahmad@123', 'Ahmad Khan', 'ahmad@example.com', 'Information Technology', 'student');
  user.run(4, 'sara', 'Sara@123', 'Sara Ali', 'sara@example.com', 'Information Technology', 'student');
  user.run(5, 'hamza', 'Hamza@123', 'Hamza Mir', 'hamza@example.com', 'Information Technology', 'student');
  user.run(6, 'zoya', 'Zoya@123', 'Zoya Shah', 'zoya@example.com', 'Information Technology', 'student');
  user.run(7, 'bilal', 'Bilal@123', 'Bilal Ahmad', 'bilal@example.com', 'Information Technology', 'student');
  const notice = db.prepare('INSERT OR IGNORE INTO notices VALUES (?, ?, ?, ?, ?)');
  notice.run(1, 'Cyber Security lab submission', 'Keep your source code, demonstration video and assignment documents ready for the lab evaluation.', 'Academics', '2026-10-27');
  notice.run(2, 'Library study hours', 'The reading room is available for individual study. Please carry your institute identity card.', 'Library', '2026-10-26');
  notice.run(3, 'Project discussion meeting', 'Students can discuss their project progress and questions with their respective lab groups.', 'Department', '2026-10-25');
  return db;
}

export function authenticate(db, mode, username, password) {
  if (mode === 'vulnerable') {
    // FLAW: input is concatenated into SQL syntax.
    const sql = "SELECT id FROM users WHERE username = '" + username +
      "' AND password = '" + password + "'";
    return db.prepare(sql).get();
  }
  // FIX: a fixed query, with input bound separately as literal values.
  const sql = 'SELECT id FROM users WHERE username = ? AND password = ?';
  return db.prepare(sql).get(username, password);
}

export function getProfile(db, id) {
  return db.prepare('SELECT id, name, username, email, department, role FROM users WHERE id = ?').get(id);
}

export function getNotices(db) {
  return db.prepare('SELECT title, body, category, published_on FROM notices ORDER BY published_on DESC, id DESC').all();
}
