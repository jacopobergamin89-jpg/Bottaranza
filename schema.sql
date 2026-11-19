CREATE TABLE IF NOT EXISTS users(
  email TEXT PRIMARY KEY,
  nick TEXT NOT NULL,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  age TEXT,
  terms_version TEXT,
  terms_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_email ON sessions(email);
CREATE TABLE IF NOT EXISTS saves(
  email TEXT PRIMARY KEY,
  at INTEGER NOT NULL,
  data TEXT NOT NULL
);
