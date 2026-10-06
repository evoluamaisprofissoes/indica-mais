-- Indica+ | Migração segura
-- Execute no D1 indica-mais-db. Não apaga dados existentes.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS student_sessions (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL UNIQUE,
  student_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_student_sessions_token ON student_sessions(token);
CREATE INDEX IF NOT EXISTS idx_student_sessions_student ON student_sessions(student_id);
