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
CREATE INDEX IF NOT EXISTS idx_tickets_code ON tickets(code);
CREATE INDEX IF NOT EXISTS idx_tickets_student_campaign ON tickets(student_id,campaign_id);
CREATE INDEX IF NOT EXISTS idx_referrals_campaign ON referrals(campaign_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_campaign_status ON enrollments(campaign_id,enrollment_status);
CREATE INDEX IF NOT EXISTS idx_draws_campaign ON draws(campaign_id);
CREATE INDEX IF NOT EXISTS idx_prizes_campaign_active ON prizes(campaign_id,active,stock);

INSERT OR IGNORE INTO admins (
  id,name,email,password_hash,role,active,created_at,updated_at
) VALUES (
  'admin-principal',
  'Administrador',
  'evoluamaisprofissoes@gmail.com',
  NULL,
  'admin',
  1,
  datetime('now'),
  datetime('now')
);

INSERT OR IGNORE INTO campaigns (
  id,name,badge,title,subtitle,logo_text,primary_color,secondary_color,status,created_at,updated_at
) VALUES (
  'campanha-principal',
  'Indica+ 2026',
  'CAMPANHA ATIVA',
  'Indique. Concorra. Ganhe.',
  'Indique novos alunos e participe dos sorteios da campanha.',
  'Indica+',
  '#6d28d9',
  '#8b5cf6',
  'active',
  datetime('now'),
  datetime('now')
);
