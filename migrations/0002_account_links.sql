-- 0002_account_links.sql
-- ClassIn Teachers 계정 연동

CREATE TABLE IF NOT EXISTS account_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  teachers_email TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_account_links_user_id ON account_links(user_id);
