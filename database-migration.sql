PRAGMA foreign_keys = ON;

-- Migração segura para o Indica+ já em produção.
-- Pode ser executada sem apagar dados existentes.

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL UNIQUE,
  admin_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS student_sessions (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL UNIQUE,
  student_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_student_sessions_token ON student_sessions(token);

INSERT OR IGNORE INTO admins (
  id,name,email,password_hash,role,active,created_at,updated_at
) VALUES (
  'admin-principal','Administrador','evoluamaisprofissoes@gmail.com',NULL,'admin',1,datetime('now'),datetime('now')
);
