PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  badge TEXT DEFAULT 'CAMPANHA ATIVA',
  title TEXT NOT NULL,
  subtitle TEXT,
  logo_text TEXT DEFAULT 'Indica+',
  primary_color TEXT DEFAULT '#6d28d9',
  secondary_color TEXT DEFAULT '#8b5cf6',
  banner_url TEXT,
  logo_url TEXT,
  background_url TEXT,
  starts_at TEXT,
  ends_at TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','active','paused','finished','archived')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','manager')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  whatsapp TEXT NOT NULL UNIQUE,
  phone TEXT,
  email TEXT,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS referrals (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  lead_name TEXT NOT NULL,
  lead_whatsapp TEXT NOT NULL,
  lead_phone TEXT,
  lead_email TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','cancelled')),
  created_at TEXT NOT NULL,
  eligible_at TEXT NOT NULL,
  confirmed_at TEXT,
  confirmed_by TEXT,
  cancelled_at TEXT,
  cancellation_reason TEXT,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE RESTRICT,
  FOREIGN KEY (confirmed_by) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  referral_id TEXT NOT NULL UNIQUE,
  campaign_id TEXT NOT NULL,
  lead_name TEXT NOT NULL,
  enrollment_status TEXT NOT NULL DEFAULT 'paid_waiting' CHECK (enrollment_status IN ('paid_waiting','eligible','confirmed','cancelled','refunded')),
  paid_at TEXT NOT NULL,
  eligible_at TEXT NOT NULL,
  confirmed_at TEXT,
  confirmed_by TEXT,
  cancelled_at TEXT,
  cancellation_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (referral_id) REFERENCES referrals(id) ON DELETE RESTRICT,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT,
  FOREIGN KEY (confirmed_by) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS prizes (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  icon TEXT DEFAULT '🎁',
  image_url TEXT,
  stock INTEGER NOT NULL DEFAULT 1 CHECK (stock >= 0),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  display_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  student_id TEXT NOT NULL,
  referral_id TEXT NOT NULL UNIQUE,
  code TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','used','revoked')),
  created_at TEXT NOT NULL,
  used_at TEXT,
  revoked_at TEXT,
  revoked_reason TEXT,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE RESTRICT,
  FOREIGN KEY (referral_id) REFERENCES referrals(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS draws (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  prize_id TEXT NOT NULL,
  ticket_id TEXT NOT NULL UNIQUE,
  student_id TEXT NOT NULL,
  drawn_at TEXT NOT NULL,
  FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE RESTRICT,
  FOREIGN KEY (prize_id) REFERENCES prizes(id) ON DELETE RESTRICT,
  FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE RESTRICT,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE RESTRICT
);


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

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  admin_id TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
CREATE INDEX IF NOT EXISTS idx_referrals_campaign ON referrals(campaign_id);
CREATE INDEX IF NOT EXISTS idx_referrals_student ON referrals(student_id);
CREATE INDEX IF NOT EXISTS idx_referrals_status ON referrals(status);
CREATE INDEX IF NOT EXISTS idx_referrals_eligible_at ON referrals(eligible_at);
CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(enrollment_status);
CREATE INDEX IF NOT EXISTS idx_enrollments_eligible_at ON enrollments(eligible_at);
CREATE INDEX IF NOT EXISTS idx_tickets_student ON tickets(student_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_campaign ON tickets(campaign_id);
CREATE INDEX IF NOT EXISTS idx_draws_campaign ON draws(campaign_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_student_sessions_token ON student_sessions(token);

INSERT OR IGNORE INTO campaigns (
  id, name, badge, title, subtitle, logo_text,
  primary_color, secondary_color, status, created_at, updated_at
) VALUES (
  'campanha-inicial',
  'Primeira Campanha',
  'CAMPANHA ATIVA',
  'Indique. Ganhe. Evolua.',
  'Indique novos alunos, acumule tickets e participe de sorteios incríveis.',
  'Indica+',
  '#6d28d9',
  '#8b5cf6',
  'active',
  datetime('now'),
  datetime('now')
);
