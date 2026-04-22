-- Questions table
CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_name TEXT NOT NULL DEFAULT '익명',
  author_grade TEXT DEFAULT '',
  title TEXT NOT NULL,
  content TEXT DEFAULT '',
  image_data TEXT,
  subject TEXT DEFAULT '기타',
  difficulty TEXT DEFAULT '중',
  comment_count INTEGER DEFAULT 0,
  status TEXT DEFAULT '채택 대기 중',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Answers table
CREATE TABLE IF NOT EXISTS answers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  question_id INTEGER NOT NULL,
  user_id INTEGER,
  author_name TEXT NOT NULL DEFAULT '익명',
  author_grade TEXT DEFAULT '',
  content TEXT DEFAULT '',
  image_data TEXT,
  drawing_data TEXT,
  is_accepted INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_questions_subject ON questions(subject);
CREATE INDEX IF NOT EXISTS idx_questions_difficulty ON questions(difficulty);
CREATE INDEX IF NOT EXISTS idx_questions_created_at ON questions(created_at);
CREATE INDEX IF NOT EXISTS idx_answers_question_id ON answers(question_id);
