import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { AwsClient } from 'aws4fetch'

type Bindings = {
  DB: D1Database
  R2: R2Bucket
  GEMINI_API_KEY: string
  ANTHROPIC_API_KEY: string
  OPENAI_API_KEY: string
  R2_ACCESS_KEY_ID: string
  R2_SECRET_ACCESS_KEY: string
  R2_ACCOUNT_ID: string
  ADMIN_SECRET: string
  EXTERNAL_AUTH_SECRET: string
  QC_API_KEY: string
  AI_PROXY_URL: string
  AI_PROXY_SECRET: string
  AI_TUTOR_URL: string         // ai_tutor /v1/platform/* base URL (https://www.jungyoul.com/chat-tutor-api.php)
  AI_TUTOR_SECRET: string      // X-Proxy-Secret value for /v1/platform/*
  TEACHERS_API_URL: string     // ClassIn Teachers API URL
  COACHING_API_SECRET: string  // Shared secret for API auth
  REALNAME_API_SECRET: string  // jungyoul.com/api/get_realnames.php X-Proxy-Secret
  AI_CALLBACK_SECRET: string   // /api/ai-callback webhook shared secret
}

const app = new Hono<{ Bindings: Bindings }>()
const _startTime = Date.now()

// P2-A2: 구조화 로깅 미들웨어 — Cloudflare Logpush 호환 JSON 로그
app.use('*', async (c, next) => {
  if (c.req.path === '/health') { await next(); return }
  const start = Date.now()
  await next()
  console.log(JSON.stringify({ ts: new Date().toISOString(), method: c.req.method, path: c.req.path, status: c.res.status, ms: Date.now() - start }))
})

// I10: 보안 헤더 미들웨어 — XSS, 클릭재킹, MIME 스니핑 방지
app.use('*', async (c, next) => {
  await next()
  c.res.headers.set('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
    "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "media-src 'self' blob:",
    "frame-ancestors 'self' https://credit-planner-v8.pages.dev",
  ].join('; '))
  c.res.headers.set('X-Content-Type-Options', 'nosniff')
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.res.headers.set('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()')
})

// I6: CORS 오리진을 실제 서비스 도메인으로 제한 (기존: 모든 도메인 허용 → CSRF 공격 가능)
app.use('/api/*', cors({
  origin: (origin) => {
    const allowed: (string | RegExp)[] = [
      'https://qa-tutoring-app.pages.dev',
      /^https:\/\/[a-z0-9]+\.qa-tutoring-app\.pages\.dev$/,
      'https://www.jungyoul.com',
      'https://jungyoul.com',
    ]
    if (!origin) return null as unknown as string
    for (const a of allowed) {
      if (typeof a === 'string' && a === origin) return origin
      if (a instanceof RegExp && a.test(origin)) return origin
    }
    return null as unknown as string
  },
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}))

// P3-S4: POST/PUT/PATCH 요청에 Content-Type 검증 (multipart 제외)
app.use('/api/*', async (c, next) => {
  const m = c.req.method
  if (m === 'POST' || m === 'PUT' || m === 'PATCH') {
    const ct = c.req.header('Content-Type') || ''
    if (!ct.includes('application/json') && !ct.includes('multipart/form-data')) {
      return c.json({ error: 'Content-Type must be application/json' }, 415)
    }
  }
  await next()
})

// P0-1: 글로벌 에러 핸들러 — 미처리 예외를 구조화된 500 JSON으로 반환 (Worker 크래시 방지)
app.onError((err, c) => {
  logErr('unhandled', err, { method: c.req.method, path: c.req.path })
  return c.json({ error: '서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요.' }, 500)
})

// P2-A1: /health 엔드포인트 — DB 연결 확인, 만료 세션 정리, active_sessions 반환
app.get('/health', async (c) => {
  try {
    const db = c.env.DB
    await db.prepare('SELECT 1').first()
    // P3-S5: 만료 세션 비차단 자동 정리
    c.executionCtx.waitUntil(db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run().catch(() => {}))
    // P3-P4: active_sessions 수 반환
    const sessRow = await db.prepare("SELECT COUNT(*) as cnt FROM sessions WHERE expires_at >= datetime('now')").first() as any
    return c.json({ status: 'ok', uptime: Math.floor((Date.now() - _startTime) / 1000), version: '3.0.0', timestamp: new Date().toISOString(), active_sessions: sessRow?.cnt || 0 })
  } catch (e) {
    return c.json({ status: 'degraded', uptime: Math.floor((Date.now() - _startTime) / 1000), version: '3.0.0', timestamp: new Date().toISOString(), error: 'DB connection failed' }, 503)
  }
})

// P1-12: HTML 새니타이징 — 닉네임, 제목에만 적용 (콘텐츠는 LaTeX 수식 보존을 위해 미적용)
function sanitizeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function logErr(ctx: string, err: any, extra?: Record<string, any>) {
  console.error(JSON.stringify({ ts: new Date().toISOString(), ctx, error: String(err?.message || err), ...extra }))
}

// D1에 AI 호출 로그 기록 (fire-and-forget)

// P2-15: 콘텐츠 생성 레이트 리밋 (per-isolate, 기존 AI 레이트 리밋과 동일 패턴)
const _contentRateLimit = new Map<string, number[]>() // "userId:type" → [timestamp, ...]
function checkContentRateLimit(userId: number, type: 'question' | 'answer' | 'reply'): { allowed: boolean, retryAfterMs?: number } {
  const limits = { question: 5, answer: 10, reply: 15 }
  const max = limits[type]
  const key = `${userId}:${type}`
  const now = Date.now()
  const timestamps = (_contentRateLimit.get(key) || []).filter(t => now - t < 60_000)
  if (timestamps.length >= max) {
    return { allowed: false, retryAfterMs: 60_000 - (now - timestamps[0]) }
  }
  timestamps.push(now)
  _contentRateLimit.set(key, timestamps)
  if (_contentRateLimit.size > 1000) {
    for (const [k, ts] of _contentRateLimit) {
      if (ts.every(t => now - t > 5 * 60_000)) _contentRateLimit.delete(k)
    }
  }
  return { allowed: true }
}

// ===== AI API Queue / Dedup / Retry Helpers =====
// In-flight dedup map: prevents duplicate AI calls for the same resource
const _aiInFlight = new Map<string, Promise<any>>()

// I2: 사용자당 AI API 호출 속도 제한 — 분당 5회 (abuse 방지)
const _aiRateLimit = new Map<number, number[]>() // userId → [timestamp, ...]
const AI_RATE_LIMIT_MAX = 5
const AI_RATE_LIMIT_WINDOW_MS = 60_000

function checkAiRateLimit(userId: number): { allowed: boolean, retryAfterMs?: number } {
  const now = Date.now()
  const timestamps = (_aiRateLimit.get(userId) || []).filter(t => now - t < AI_RATE_LIMIT_WINDOW_MS)
  if (timestamps.length >= AI_RATE_LIMIT_MAX) {
    const oldestInWindow = timestamps[0]
    return { allowed: false, retryAfterMs: AI_RATE_LIMIT_WINDOW_MS - (now - oldestInWindow) }
  }
  timestamps.push(now)
  _aiRateLimit.set(userId, timestamps)
  // GC: 5분 이상 비활성 사용자 정리
  if (_aiRateLimit.size > 500) {
    for (const [uid, ts] of _aiRateLimit) {
      if (ts.every(t => now - t > 5 * 60_000)) _aiRateLimit.delete(uid)
    }
  }
  return { allowed: true }
}
// Unified AI fetch with timeout + retry + dedup
async function callAI(
  url: string,
  body: any,
  opts: { timeoutMs?: number, retries?: number, dedupKey?: string } = {}
): Promise<{ ok: boolean, data?: any, error?: string }> {
  const { timeoutMs = 25000, retries = 1, dedupKey } = opts

  // Dedup: if same key is already in-flight, wait for it
  if (dedupKey && _aiInFlight.has(dedupKey)) {
    try { return await _aiInFlight.get(dedupKey)! } catch { /* fall through to fresh call */ }
  }

  const doCall = async (attempt: number): Promise<{ ok: boolean, data?: any, error?: string }> => {
    const controller = new AbortController()
    const tid = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: body._headers || { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify(body._body || body),
      })
      clearTimeout(tid)
      if (!res.ok) {
        const errText = await res.text().catch(() => '')
        if (attempt < retries && (res.status === 429 || res.status >= 500)) {
          await new Promise(r => setTimeout(r, 1000 * attempt))
          return doCall(attempt + 1)
        }
        return { ok: false, error: `AI API ${res.status}: ${errText.slice(0, 200)}` }
      }
      const data = await res.json()
      return { ok: true, data }
    } catch (e: any) {
      clearTimeout(tid)
      if (e.name === 'AbortError') {
        if (attempt < retries) {
          await new Promise(r => setTimeout(r, 500))
          return doCall(attempt + 1)
        }
        return { ok: false, error: 'AI API timeout' }
      }
      return { ok: false, error: e.message || 'AI fetch error' }
    }
  }

  const promise = doCall(0)
  if (dedupKey) {
    _aiInFlight.set(dedupKey, promise)
    promise.finally(() => { _aiInFlight.delete(dedupKey) })
  }
  return promise
}

// Helper: call Gemini with dedup + timeout + retry (supports proxy)
async function callGemini(
  geminiKey: string, model: string, contents: any[], genConfig: any,
  opts: { dedupKey?: string, timeoutMs?: number, proxy?: { url: string, secret: string, task?: string, questionId?: number, externalId?: string | null } } = {}
): Promise<{ ok: boolean, text?: string, error?: string }> {
  if (opts.proxy) {
    const proxyUrl = `${opts.proxy.url}/question-room/gemini`
    const parts: any[] = []
    for (const content of contents) {
      for (const p of (content.parts || [])) {
        if (p.inlineData) parts.push({ type: 'image', b64: p.inlineData.data, mime: p.inlineData.mimeType })
        else if (p.text) parts.push({ type: 'text', content: p.text })
      }
    }
    const config: any = {}
    if (genConfig?.temperature != null) config.temperature = genConfig.temperature
    if (genConfig?.maxOutputTokens != null) config.max_output_tokens = genConfig.maxOutputTokens
    if (genConfig?.thinkingConfig?.thinkingBudget != null) config.thinking_budget = genConfig.thinkingConfig.thinkingBudget
    config.response_mime_type = 'application/json'
    const result = await callAI(proxyUrl, {
      _headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${opts.proxy.secret}` },
      _body: { model, parts, config, task: opts.proxy.task, question_id: opts.proxy.questionId, external_id: opts.proxy.externalId },
    }, { timeoutMs: opts.timeoutMs || 55000, retries: 1, dedupKey: opts.dedupKey })
    if (!result.ok) return { ok: false, error: result.error }
    if (result.data?.ok === false) return { ok: false, error: result.data.error || 'Proxy error' }
    return { ok: true, text: result.data?.text || '' }
  }
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`
  const result = await callAI(url, {
    _headers: { 'Content-Type': 'application/json' },
    _body: { contents, generationConfig: { ...genConfig, responseMimeType: 'application/json' } },
  }, { timeoutMs: opts.timeoutMs || 55000, retries: 1, dedupKey: opts.dedupKey })
  if (!result.ok) return { ok: false, error: result.error }
  const allParts = result.data?.candidates?.[0]?.content?.parts || []
  let text = ''
  for (const p of allParts) { if (p.text && !p.thought) text += p.text }
  return { ok: true, text }
}

// Helper: call Claude with dedup + timeout + retry (supports proxy)
async function callClaude(
  apiKey: string, model: string, system: string, messages: any[], maxTokens: number,
  opts: { dedupKey?: string, timeoutMs?: number, proxy?: { url: string, secret: string, task?: string, questionId?: number, externalId?: string | null } } = {}
): Promise<{ ok: boolean, text?: string, error?: string }> {
  if (opts.proxy) {
    const proxyUrl = `${opts.proxy.url}/question-room/claude`
    const proxyMessages = messages.map((msg: any) => {
      if (typeof msg.content === 'string') return { role: msg.role, content: [{ type: 'text', content: msg.content }] }
      const blocks = (msg.content || []).map((b: any) => {
        if (b.type === 'image' && b.source?.data) return { type: 'image', b64: b.source.data, mime: b.source.media_type || 'image/jpeg' }
        if (b.type === 'text') return { type: 'text', content: b.text }
        return b
      })
      return { role: msg.role, content: blocks }
    })
    if (system) {
      const firstMsg = proxyMessages[0]
      if (firstMsg?.role === 'user' && Array.isArray(firstMsg.content)) firstMsg.content.unshift({ type: 'text', content: system })
      else proxyMessages.unshift({ role: 'user', content: [{ type: 'text', content: system }] })
    }
    const result = await callAI(proxyUrl, {
      _headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${opts.proxy.secret}` },
      _body: { model, messages: proxyMessages, config: { max_tokens: maxTokens, temperature: 0.3 }, task: opts.proxy.task, question_id: opts.proxy.questionId, external_id: opts.proxy.externalId },
    }, { timeoutMs: opts.timeoutMs || 30000, retries: 1, dedupKey: opts.dedupKey })
    if (!result.ok) return { ok: false, error: result.error }
    if (result.data?.ok === false) return { ok: false, error: result.data.error || 'Proxy error' }
    return { ok: true, text: result.data?.text || '' }
  }
  const url = 'https://api.anthropic.com/v1/messages'
  const result = await callAI(url, {
    _headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    _body: { model, max_tokens: maxTokens, system, messages },
  }, { timeoutMs: opts.timeoutMs || 30000, retries: 1, dedupKey: opts.dedupKey })
  if (!result.ok) return { ok: false, error: result.error }
  return { ok: true, text: result.data?.content?.[0]?.text || '' }
}

// Helper: build proxy config from env
function proxyOpts(env: any, task?: string, questionId?: number, externalId?: string | null): { url: string, secret: string, task?: string, questionId?: number, externalId?: string | null } | undefined {
  return (env?.AI_PROXY_URL && env?.AI_PROXY_SECRET) ? { url: env.AI_PROXY_URL, secret: env.AI_PROXY_SECRET, task, questionId, externalId } : undefined
}

// Helper: call OpenAI with dedup + timeout + retry (supports vision + proxy)
async function callOpenAI(
  apiKey: string, model: string, system: string, userContent: string | any[], maxTokens: number,
  opts: { dedupKey?: string, timeoutMs?: number, proxy?: { url: string, secret: string, task?: string, questionId?: number, externalId?: string | null } } = {}
): Promise<{ ok: boolean, text?: string, error?: string }> {
  if (opts.proxy) {
    const proxyUrl = `${opts.proxy.url}/question-room/openai`
    const contentBlocks: any[] = []
    if (typeof userContent === 'string') {
      contentBlocks.push({ type: 'text', content: userContent })
    } else {
      for (const part of userContent) {
        if (part.type === 'image_url' && part.image_url?.url) {
          const match = part.image_url.url.match(/^data:([^;]+);base64,(.+)$/)
          if (match) contentBlocks.push({ type: 'image', b64: match[2], mime: match[1] })
        } else if (part.type === 'text') {
          contentBlocks.push({ type: 'text', content: part.text })
        }
      }
    }
    const result = await callAI(proxyUrl, {
      _headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${opts.proxy.secret}` },
      _body: { model, messages: [{ role: 'system', content: [{ type: 'text', content: system }] }, { role: 'user', content: contentBlocks }], config: { max_tokens: maxTokens, temperature: 0.3, response_format: { type: 'json_object' } }, task: opts.proxy.task, question_id: opts.proxy.questionId, external_id: opts.proxy.externalId },
    }, { timeoutMs: opts.timeoutMs || 60000, retries: 1, dedupKey: opts.dedupKey })
    if (!result.ok) return { ok: false, error: result.error }
    if (result.data?.ok === false) return { ok: false, error: result.data.error || 'Proxy error' }
    return { ok: true, text: result.data?.text || '' }
  }
  const url = 'https://api.openai.com/v1/chat/completions'
  const userMessage = { role: 'user', content: userContent }
  const result = await callAI(url, {
    _headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    _body: { model, max_tokens: maxTokens, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: system }, userMessage] },
  }, { timeoutMs: opts.timeoutMs || 60000, retries: 1, dedupKey: opts.dedupKey })
  if (!result.ok) return { ok: false, error: result.error }
  return { ok: true, text: result.data?.choices?.[0]?.message?.content || '' }
}

// ===== Helper: Simple token auth via cookie =====
// I1: PBKDF2-SHA256 + 사용자별 랜덤 솔트 — 레인보우 테이블 공격 방지
async function hashPassword(pw: string, existingSalt?: string): Promise<string> {
  const salt = existingSalt || Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('')
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(pw), 'PBKDF2', false, ['deriveBits'])
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  )
  const hash = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2, '0')).join('')
  return `pbkdf2:${salt}:${hash}`
}

async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  if (stored.startsWith('pbkdf2:')) {
    // 새 PBKDF2 형식: "pbkdf2:salt:hash"
    const [, salt, expectedHash] = stored.split(':')
    const result = await hashPassword(pw, salt)
    return result === stored
  }
  // 레거시 SHA-256 호환: 기존 사용자도 로그인 가능
  const data = new TextEncoder().encode(pw + 'qa-salt-2026')
  const hash = await crypto.subtle.digest('SHA-256', data)
  const legacyHash = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
  return legacyHash === stored
}

function generateToken(): string {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

// === KST (Asia/Seoul, UTC+9) 헬퍼 ===
// D1(SQLite)의 datetime('now'), CURRENT_TIMESTAMP는 UTC 기준이므로
// 한국 시간이 필요한 곳에서는 이 함수들을 사용
function nowKST(): string {
  // 현재 UTC + 9시간 = KST, ISO 형식 반환 (YYYY-MM-DD HH:MM:SS)
  const d = new Date(Date.now() + 9 * 3600000)
  return d.toISOString().slice(0, 19).replace('T', ' ')
}
function todayStartKST(): string {
  // 한국 시간 기준 오늘 00:00:00
  const d = new Date(Date.now() + 9 * 3600000)
  return d.toISOString().slice(0, 10) + ' 00:00:00'
}
function nowPlusKST(days: number): string {
  // 한국 시간 기준 현재 + N일
  const d = new Date(Date.now() + 9 * 3600000 + days * 86400000)
  return d.toISOString().slice(0, 19).replace('T', ' ')
}

async function getUser(db: D1Database, token: string | undefined) {
  if (!token) return null
  // I11: 2쿼리 → 1쿼리 JOIN 통합 (매 API 호출마다 DB 왕복 1회 절약)
  return await db.prepare(
    "SELECT u.id, u.username, u.nickname, u.grade, u.external_id FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > datetime('now')"
  ).bind(token).first()
}

function getTokenFromReq(c: any): string | undefined {
  const cookie = c.req.header('Cookie') || ''
  const match = cookie.match(/qa_token=([^;]+)/)
  if (match) return match[1]
  const auth = c.req.header('Authorization') || ''
  if (auth.startsWith('Bearer ')) return auth.slice(7)
  return undefined
}

async function getAuthUser(c: any): Promise<any> {
  const token = getTokenFromReq(c)
  return await getUser(c.env.DB, token)
}

// ===== PWA Static Routes =====
app.get('/offline.html', (c) => {
  return c.html(`<!DOCTYPE html>
<html lang="ko">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>오프라인 - Q&A</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#141414;color:#e5e5e5;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:20px}.wrap{max-width:320px}.icon{font-size:64px;margin-bottom:20px;opacity:.5}h1{font-size:20px;font-weight:700;margin-bottom:8px;color:#fff}p{font-size:14px;color:#999;line-height:1.6;margin-bottom:24px}.btn{display:inline-block;padding:12px 32px;background:#e50914;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}.btn:hover{opacity:.9}</style></head>
<body><div class="wrap"><div class="icon">📡</div><h1>인터넷 연결 없음</h1><p>현재 오프라인 상태입니다.<br>인터넷에 연결되면 자동으로 복구됩니다.</p><button class="btn" onclick="location.reload()">다시 시도</button></div>
<script>window.addEventListener('online',()=>location.reload())</script></body></html>`)
})

// ===== API Routes =====

app.get('/api/init', async (c) => {
  // E1: 관리자 인증 — ADMIN_SECRET 헤더 필수
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT NOT NULL DEFAULT '학생',
    grade TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run()
  await db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`).run()
  await db.prepare(`CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
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
  )`).run()
  await db.prepare(`CREATE TABLE IF NOT EXISTS answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    user_id INTEGER,
    author_name TEXT NOT NULL DEFAULT '익명',
    author_grade TEXT DEFAULT '',
    content TEXT DEFAULT '',
    image_data TEXT,
    drawing_data TEXT,
    is_accepted INTEGER DEFAULT 0,
    acceptance_tags TEXT DEFAULT NULL,
    acceptance_review TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
  )`).run()
  await db.prepare(`CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    answer_id INTEGER NOT NULL,
    user_id INTEGER,
    author_name TEXT NOT NULL DEFAULT '익명',
    author_grade TEXT DEFAULT '',
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (answer_id) REFERENCES answers(id) ON DELETE CASCADE
  )`).run()
  
  // 1:1 튜터링 시간표 & 매칭
  await db.prepare(`CREATE TABLE IF NOT EXISTS tutoring_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    slot_time TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
  )`).run()
  await db.prepare(`CREATE TABLE IF NOT EXISTS tutoring_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    slot_id INTEGER NOT NULL,
    tutor_id INTEGER NOT NULL,
    tutor_name TEXT NOT NULL DEFAULT '익명',
    tutor_grade TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    held_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    confirmed_at DATETIME,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
    FOREIGN KEY (slot_id) REFERENCES tutoring_slots(id) ON DELETE CASCADE
  )`).run()

  // Migration: add acceptance columns if they don't exist (for existing DBs)
  try{await db.prepare('ALTER TABLE answers ADD COLUMN acceptance_tags TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE answers ADD COLUMN acceptance_review TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN reward_points INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN thumbnail_data TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE answers ADD COLUMN thumbnail_data TEXT DEFAULT NULL').run()}catch(e){}
  // R2 image key columns
  try{await db.prepare('ALTER TABLE questions ADD COLUMN image_key TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN thumbnail_key TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE answers ADD COLUMN image_key TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE answers ADD COLUMN thumbnail_key TEXT DEFAULT NULL').run()}catch(e){}
  // R2 drawing key column
  try{await db.prepare('ALTER TABLE answers ADD COLUMN drawing_key TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE answers ADD COLUMN voice_key TEXT DEFAULT NULL').run()}catch(e){} // 음성 녹음 R2 키
  try{await db.prepare('ALTER TABLE answers ADD COLUMN user_id INTEGER DEFAULT NULL').run()}catch(e){} // 답변 작성자 ID
  try{await db.prepare('ALTER TABLE tutoring_matches ADD COLUMN acceptance_tags TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE tutoring_matches ADD COLUMN acceptance_review TEXT DEFAULT NULL').run()}catch(e){}

  // === AI 분석 컬럼 ===
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_difficulty TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_tags TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_topic_main TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_topic_sub TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_description TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_grade_level TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_estimated_time INTEGER DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_analyzed INTEGER DEFAULT 0').run()}catch(e){}

  // === 질문 코칭 시스템 ===
  try{await db.prepare('ALTER TABLE questions ADD COLUMN question_type TEXT DEFAULT NULL').run()}catch(e){} // 7유형: 1-1,1-2,2-1,2-2,2-3,3-1,3-2
  try{await db.prepare('ALTER TABLE questions ADD COLUMN question_type_confidence REAL DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE questions ADD COLUMN student_question_text TEXT DEFAULT NULL').run()}catch(e){} // 이미지에서 OCR 인식한 학생 필기 질문
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_question_analysis TEXT DEFAULT NULL').run()}catch(e){} // AI 질문 분석 (질문의 깊이/의도 분석)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_coaching_comment TEXT DEFAULT NULL').run()}catch(e){} // AI 질문 코칭 코멘트
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_next_questions TEXT DEFAULT NULL').run()}catch(e){} // AI 다음 단계 질문 추천 (JSON)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_growth_coaching TEXT DEFAULT NULL').run()}catch(e){} // AI 성장 코칭 (JSON: wrong_attempt, discovery_hint, thinking_bridge)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_model TEXT DEFAULT NULL').run()}catch(e){} // 코칭 분석에 사용된 AI 모델 (gemini / claude)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_coaching_data TEXT DEFAULT NULL').run()}catch(e){} // 통합 코칭 데이터 (JSON: coaching_questions + growth_interactions)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_literature_genre TEXT DEFAULT NULL').run()}catch(e){} // 국어 문학 장르 (현대시/현대소설/고전시가/고전소설, 비문학이면 null)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN challenge_result TEXT DEFAULT NULL').run()}catch(e){} // 도전 결과 저장 (JSON)
  // === 선생님 도와주세요 스티커 ===
  try{await db.prepare('ALTER TABLE questions ADD COLUMN requested_teacher TEXT DEFAULT NULL').run()}catch(e){} // 선생님 도움 요청 여부
  try{await db.prepare('ALTER TABLE questions ADD COLUMN question_grade TEXT DEFAULT NULL').run()}catch(e){} // 문제 해당 학년 (중1~고3)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN ai_solution TEXT DEFAULT NULL').run()}catch(e){} // Gemini Pro 상세 해설 (AI튜터 참조용)
  try{await db.prepare('ALTER TABLE questions ADD COLUMN solution_stat INTEGER DEFAULT 0').run()}catch(e){} // 해설 상태: 0=미완료, 1=완료, 2=에러
  try{await db.prepare('ALTER TABLE questions ADD COLUMN practice_warm_stat INTEGER DEFAULT 0').run()}catch(e){} // 변형문제 사전생성: 0=미시도, 1=성공, 2=실패
  try{await db.prepare('ALTER TABLE questions ADD COLUMN image_keys TEXT DEFAULT NULL').run()}catch(e){} // 다중 이미지 R2 키 배열 (JSON: [{key, thumbnailKey}, ...])
  // === 국어 지문형 질문 ===
  try{await db.prepare('ALTER TABLE questions ADD COLUMN content_type TEXT DEFAULT \'normal\'').run()}catch(e){} // 질문 유형: 'normal' | 'passage'
  try{await db.prepare('ALTER TABLE questions ADD COLUMN passage_image_keys TEXT DEFAULT NULL').run()}catch(e){} // 지문 이미지 R2 키 배열 (JSON: [{key, thumbnailKey}, ...])
  // === 1:1 코칭 신청 상태 ===
  try{await db.prepare('ALTER TABLE questions ADD COLUMN coaching_requested INTEGER DEFAULT 0').run()}catch(e){} // 0=미신청, 1=신청(pending), 2=매칭(matched), 3=완료(completed), -1=취소

  // === 질문 코칭 로그 테이블 ===
  await db.prepare(`CREATE TABLE IF NOT EXISTS coaching_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    step TEXT NOT NULL,
    choice TEXT NOT NULL,
    time_spent_ms INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES questions(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`).run()

  // coaching_logs 확장: 이미지 키, 인식 텍스트
  try{await db.prepare('ALTER TABLE coaching_logs ADD COLUMN image_key TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE coaching_logs ADD COLUMN recognized_text TEXT DEFAULT NULL').run()}catch(e){}

  // === 취소 패널티 시스템 ===
  // 취소 기록 테이블
  await db.prepare(`CREATE TABLE IF NOT EXISTS cancel_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER NOT NULL,
    question_id INTEGER NOT NULL,
    cancelled_by INTEGER NOT NULL,
    cancel_role TEXT NOT NULL DEFAULT 'questioner',
    reason TEXT NOT NULL DEFAULT '기타',
    reason_detail TEXT DEFAULT '',
    penalty_type TEXT DEFAULT 'none',
    penalty_points INTEGER DEFAULT 0,
    warnings_added INTEGER DEFAULT 0,
    hours_before REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cancelled_by) REFERENCES users(id)
  )`).run()

  // 경고 테이블
  await db.prepare(`CREATE TABLE IF NOT EXISTS user_warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cancel_record_id INTEGER,
    warning_count INTEGER DEFAULT 1,
    reason TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`).run()

  // 이용 정지 테이블
  await db.prepare(`CREATE TABLE IF NOT EXISTS user_suspensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    total_warnings INTEGER DEFAULT 0,
    suspended_until DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`).run()

  // 상호 합의 취소 요청 테이블
  await db.prepare(`CREATE TABLE IF NOT EXISTS mutual_cancel_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER NOT NULL,
    requested_by INTEGER NOT NULL,
    reason TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    responded_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (match_id) REFERENCES tutoring_matches(id)
  )`).run()

  // users 테이블에 포인트/경고 컬럼 추가
  try{await db.prepare('ALTER TABLE users ADD COLUMN points INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN total_warnings INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN total_matches INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN completed_matches INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN cancelled_matches INTEGER DEFAULT 0').run()}catch(e){}
  // 외부 앱(정율톡) 연동용 external_id 컬럼
  try{await db.prepare('ALTER TABLE users ADD COLUMN external_id TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id)').run()}catch(e){}

  // === XP 시스템 (레거시 — 마이그레이션 후 cp_logs로 대체) ===
  try{await db.prepare('ALTER TABLE users ADD COLUMN xp INTEGER DEFAULT 0').run()}catch(e){}
  await db.prepare(`CREATE TABLE IF NOT EXISTS xp_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    question_id INTEGER,
    xp_amount INTEGER NOT NULL,
    xp_type TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (question_id) REFERENCES questions(id)
  )`).run()
  // I5: DB-level unique constraint to prevent duplicate XP via race condition
  try{await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_xp_unique ON xp_logs(user_id, question_id, xp_type)').run()}catch(e){}

  // === 크로켓포인트(CP) 시스템 ===
  try{await db.prepare('ALTER TABLE users ADD COLUMN cp_balance INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN earned_cp INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN answer_streak INTEGER DEFAULT 0').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN last_answer_date TEXT DEFAULT NULL').run()}catch(e){}
  try{await db.prepare('ALTER TABLE users ADD COLUMN cp_level INTEGER DEFAULT 1').run()}catch(e){}
  await db.prepare(`CREATE TABLE IF NOT EXISTS cp_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    question_id INTEGER,
    answer_id INTEGER,
    cp_amount INTEGER NOT NULL,
    cp_type TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`).run()
  try{await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_cp_unique ON cp_logs(user_id, question_id, answer_id, cp_type)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_cp_user ON cp_logs(user_id, created_at)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_cp_type ON cp_logs(cp_type)').run()}catch(e){}

  // CP 마이그레이션: 기존 XP/포인트 → CP 전환 (최초 1회만 실행)
  try {
    const migrated = await db.prepare("SELECT COUNT(*) as cnt FROM cp_logs WHERE cp_type = 'migration'").first() as any
    if (!migrated || migrated.cnt === 0) {
      // XP → earned_cp (10 XP = 1 CP)
      await db.prepare("UPDATE users SET earned_cp = ROUND(xp / 10.0) WHERE xp > 0 AND earned_cp = 0").run()
      // points → cp_balance (10P = 1 CP)
      await db.prepare("UPDATE users SET cp_balance = ROUND(points / 10.0) WHERE points > 0 AND cp_balance = 0").run()
      // 마이그레이션 완료 마커
      await db.prepare("INSERT OR IGNORE INTO cp_logs (user_id, question_id, answer_id, cp_amount, cp_type, description) VALUES (0, 0, 0, 0, 'migration', 'XP/포인트 → CP 마이그레이션 완료')").run()
    }
  } catch(e) {}

  // P0-2: 누락 인덱스 10개 — 인증·질문·답변·튜터링·코칭 성능 개선
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_questions_user_id ON questions(user_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_answers_user_id ON answers(user_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_tutoring_matches_tutor_id ON tutoring_matches(tutor_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_tutoring_matches_question_id ON tutoring_matches(question_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_tutoring_matches_status ON tutoring_matches(status)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_coaching_logs_user_question ON coaching_logs(user_id, question_id)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_cancel_records_cancelled_by ON cancel_records(cancelled_by)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_replies_answer_id ON replies(answer_id)').run()}catch(e){}

  // P2-A4: 페이지뷰 분석 테이블
  await db.prepare(`CREATE TABLE IF NOT EXISTS page_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run()
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_page_views_path ON page_views(path)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_page_views_created_at ON page_views(created_at)').run()}catch(e){}

  // P3-P3: 성능 인덱스 — admin/stats COUNT, 답변 페이지네이션 최적화
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_questions_created_at ON questions(created_at)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_answers_created_at ON answers(created_at)').run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_answers_question_id_created ON answers(question_id, created_at)').run()}catch(e){}

  // === ClassIn Teachers 계정 연동 테이블 ===
  try{await db.prepare(`CREATE TABLE IF NOT EXISTS account_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  teachers_email TEXT NOT NULL,
  verified INTEGER DEFAULT 0,
  linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`).run()}catch(e){}
  try{await db.prepare('CREATE INDEX IF NOT EXISTS idx_account_links_user_id ON account_links(user_id)').run()}catch(e){}

  return c.json({ success: true, message: 'Database initialized' })
})

// ===== External App Auto-Auth API (정율톡 연동) =====
app.post('/api/auth/external', async (c) => {
  const db = c.env.DB
  const body = await c.req.json()
  const { user_id, nick_name, timestamp, signature } = body
  if (!user_id) return c.json({ error: 'user_id is required' }, 400)

  // E2: HMAC 서명 검증 — 외부 앱에서 보낸 요청만 허용
  const extSecret = c.env.EXTERNAL_AUTH_SECRET
  if (extSecret) {
    if (!timestamp || !signature) {
      return c.json({ error: 'Missing signature or timestamp' }, 401)
    }
    // 5분 이내 요청만 허용 (replay attack 방지)
    const ts = Number(timestamp)
    if (isNaN(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return c.json({ error: 'Request expired' }, 401)
    }
    // HMAC-SHA256 검증: sign(user_id + timestamp, secret)
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(extSecret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    )
    const data = encoder.encode(`${user_id}:${timestamp}`)
    const sig = await crypto.subtle.sign('HMAC', key, data)
    const expected = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('')
    if (expected !== signature) {
      return c.json({ error: 'Invalid signature' }, 401)
    }
  }

  const extId = String(user_id)

  // 원격 DB(jungyoul.com)에서 실제 nick_name 조회하여 교체
  let resolvedNickName = nick_name
  try {
    const extRes = await fetch(`https://jungyoul.com/api/get_nickname.php?user_id=${encodeURIComponent(extId)}`)
    if (extRes.ok) {
      const extData = await extRes.json() as any
      if (extData.success && extData.nick_name) {
        resolvedNickName = extData.nick_name
      }
    }
  } catch (e) {
    // 원격 DB 조회 실패 시 파라미터로 전달된 nick_name 그대로 사용
  }

  // Try to find existing user by external_id
  let user = await db.prepare('SELECT id, username, nickname, grade FROM users WHERE external_id = ?').bind(extId).first() as any

  if (!user) {
    // Auto-register: create new user with external_id
    const nickname = resolvedNickName || ('사용자' + extId)
    const username = 'ext_' + extId
    // Check if username already exists (legacy accounts)
    const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
    if (existing) {
      // Link existing legacy account to external_id
      await db.prepare('UPDATE users SET external_id = ?, nickname = ? WHERE username = ?').bind(extId, nickname, username).run()
      user = await db.prepare('SELECT id, username, nickname, grade FROM users WHERE username = ?').bind(username).first() as any
    } else {
      const dummyHash = 'external_auth_no_password'
      const result = await db.prepare('INSERT INTO users (username, password_hash, nickname, grade, external_id) VALUES (?, ?, ?, ?, ?)').bind(username, dummyHash, nickname, '', extId).run()
      user = { id: result.meta.last_row_id, username, nickname, grade: '' }
    }
  } else if (resolvedNickName && resolvedNickName !== user.nickname) {
    // 원격 DB에서 가져온 닉네임이 다르면 업데이트
    await db.prepare('UPDATE users SET nickname = ? WHERE id = ?').bind(resolvedNickName, user.id).run()
    user.nickname = resolvedNickName
  }

  // Create session
  const token = generateToken()
  await db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime(\'now\', \'+30 days\'))').bind(user.id, token).run()

  return c.json({ success: true, token, user: { id: user.id, username: user.username, nickname: user.nickname, grade: user.grade || '', external_id: extId } })
})

// ===== 정율톡 푸시 알림 전송 헬퍼 =====
async function sendPush(senderExternalId: string, receiverExternalId: string, message: string, imageUrl?: string) {
  if (!senderExternalId || !receiverExternalId) return
  try {
    const body: any = { sender_id: senderExternalId, receiver_id: receiverExternalId, message }
    if (imageUrl) body.image_url = imageUrl
    await fetch('https://jungyoul.com/chat_server/api_id.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: Object.keys(body).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(body[k])).join('&')
    })
  } catch (e) {
    logErr('push/notification', e)
  }
}

// Get external_id from internal user id
async function getExternalId(db: D1Database, userId: number): Promise<string | null> {
  const row = await db.prepare('SELECT external_id FROM users WHERE id = ?').bind(userId).first() as any
  return row?.external_id || null
}

// ===== Auth API =====

app.post('/api/auth/register', async (c) => {
  try {
  const db = c.env.DB
  const { username, password, nickname, grade } = await c.req.json()
  if (!username || !password) return c.json({ error: '아이디와 비밀번호를 입력해주세요.' }, 400)
  if (username.length < 4) return c.json({ error: '아이디는 4자 이상이어야 합니다.' }, 400)
  if (password.length < 6) return c.json({ error: '비밀번호는 6자 이상이어야 합니다.' }, 400)
  if (!nickname || nickname.trim().length < 1) return c.json({ error: '닉네임을 입력해주세요.' }, 400)

  const existing = await db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()
  if (existing) return c.json({ error: '이미 사용 중인 아이디입니다.' }, 409)

  const hash = await hashPassword(password)
  const safeName = sanitizeHtml(nickname.trim())
  const result = await db.prepare('INSERT INTO users (username, password_hash, nickname, grade) VALUES (?, ?, ?, ?)').bind(username, hash, safeName, grade || '').run()

  const token = generateToken()
  const userId = result.meta.last_row_id
  await db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime(\'now\', \'+30 days\'))').bind(userId, token).run()

  return c.json({ success: true, token, user: { id: userId, username, nickname: safeName, grade: grade || '' } }, 201)
  } catch (e: any) { logErr('register', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// I12: 로그인 브루트포스 차단 — IP당 5회 실패 시 15분 잠금
const _loginFails = new Map<string, { count: number, lockedUntil: number }>()
const LOGIN_MAX_FAILS = 5
const LOGIN_LOCK_MS = 15 * 60 * 1000 // 15분

app.post('/api/auth/login', async (c) => {
  try {
  const db = c.env.DB
  const clientIp = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || 'unknown'

  // I12: 차단 상태 확인
  const fail = _loginFails.get(clientIp)
  if (fail && fail.lockedUntil > Date.now()) {
    const remainSec = Math.ceil((fail.lockedUntil - Date.now()) / 1000)
    return c.json({ error: `로그인 시도가 너무 많습니다. ${Math.ceil(remainSec / 60)}분 후 다시 시도해주세요.` }, 429)
  }

  const { username, password } = await c.req.json()
  if (!username || !password) return c.json({ error: '아이디와 비밀번호를 입력해주세요.' }, 400)

  // I1: verifyPassword로 변경 — PBKDF2 신규 + SHA-256 레거시 모두 지원
  const user = await db.prepare('SELECT id, username, nickname, grade, password_hash FROM users WHERE username = ?').bind(username).first() as any
  if (!user || !await verifyPassword(password, user.password_hash)) {
    // I12: 실패 카운트 증가, 5회 도달 시 15분 잠금
    const f = _loginFails.get(clientIp) || { count: 0, lockedUntil: 0 }
    f.count++
    if (f.count >= LOGIN_MAX_FAILS) {
      f.lockedUntil = Date.now() + LOGIN_LOCK_MS
      f.count = 0
    }
    _loginFails.set(clientIp, f)
    return c.json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' }, 401)
  }

  // 로그인 성공 → 실패 기록 초기화
  _loginFails.delete(clientIp)

  // 레거시 SHA-256 해시면 로그인 성공 시 PBKDF2로 자동 마이그레이션
  if (!user.password_hash.startsWith('pbkdf2:')) {
    const newHash = await hashPassword(password)
    await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, user.id).run()
  }

  const token = generateToken()
  await db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, datetime(\'now\', \'+30 days\'))').bind(user.id, token).run()

  return c.json({ success: true, token, user: { id: user.id, username: user.username, nickname: user.nickname, grade: user.grade } })
  } catch (e: any) { logErr('login', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

app.get('/api/auth/me', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: 'Not logged in' }, 401)
  // Get XP from users table
  const xpRow = await db.prepare('SELECT xp FROM users WHERE id = ?').bind(user.id).first() as any
  return c.json({ id: user.id, username: user.username, nickname: user.nickname, grade: user.grade, xp: xpRow?.xp || 0, external_id: user.external_id || null })
})

app.post('/api/auth/logout', async (c) => {
  const db = c.env.DB
  const token = getTokenFromReq(c)
  if (token) await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run()
  return c.json({ success: true })
})

app.patch('/api/auth/profile', async (c) => {
  try {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: 'Not logged in' }, 401)
  const { nickname, grade } = await c.req.json()
  // P1-11: 프로필 입력값 검증
  const allowedGrades = ['', '고1', '고2', '고3']
  if (grade !== undefined && !allowedGrades.includes(grade)) return c.json({ error: '유효하지 않은 학년입니다.' }, 400)
  if (nickname !== undefined && nickname.trim().length > 20) return c.json({ error: '닉네임은 20자 이내로 입력해주세요.' }, 400)
  const updates: string[] = []
  const params: any[] = []
  if (nickname !== undefined) { updates.push('nickname = ?'); params.push(sanitizeHtml(nickname.trim())) }
  if (grade !== undefined) { updates.push('grade = ?'); params.push(grade) }
  if (updates.length === 0) return c.json({ error: 'No updates' }, 400)
  params.push(user.id)
  await db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run()
  return c.json({ success: true })
  } catch (e: any) { logErr('profile', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// ===== R2 Image API =====

// Presigned URL for direct R2 upload (bypasses Workers)
app.post('/api/images/presign', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const { type, contentType: reqContentType, filename } = await c.req.json()
  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
  const contentType = allowedTypes.includes(reqContentType) ? reqContentType : 'image/jpeg'
  const ext = contentType === 'image/png' ? 'png' : contentType === 'image/webp' ? 'webp' : contentType === 'image/gif' ? 'gif' : 'jpg'
  const key = `images/${type || 'question'}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`
  const thumbnailKey = `thumbnails/${type || 'question'}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.jpg`

  // Check if R2 API credentials exist
  const accessKeyId = c.env.R2_ACCESS_KEY_ID
  const secretAccessKey = c.env.R2_SECRET_ACCESS_KEY
  const accountId = c.env.R2_ACCOUNT_ID

  if (!accessKeyId || !secretAccessKey || !accountId) {
    // Fallback: return that presign is not available, client should use legacy upload
    return c.json({ error: 'presign_not_available', fallback: true }, 501)
  }

  const r2Url = `https://${accountId}.r2.cloudflarestorage.com`
  const bucketName = 'jungyoul'

  const client = new AwsClient({
    accessKeyId,
    secretAccessKey,
    service: 's3',
    region: 'auto',
  })

  // Generate presigned PUT URL (3 min TTL)
  const signedReq = await client.sign(
    new Request(`${r2Url}/${bucketName}/${key}?X-Amz-Expires=180`, {
      method: 'PUT',
      headers: { 'Content-Type': contentType },
    }),
    { aws: { signQuery: true } }
  )

  // Generate presigned PUT for thumbnail
  const thumbSignedReq = await client.sign(
    new Request(`${r2Url}/${bucketName}/${thumbnailKey}?X-Amz-Expires=180`, {
      method: 'PUT',
      headers: { 'Content-Type': 'image/jpeg' },
    }),
    { aws: { signQuery: true } }
  )

  return c.json({
    uploadUrl: signedReq.url.toString(),
    thumbnailUploadUrl: thumbSignedReq.url.toString(),
    key,
    thumbnailKey,
    contentType,
    expiresIn: 180,
  })
})

// Upload image to R2 (legacy fallback - returns R2 key)
app.post('/api/images/upload', async (c) => {
  const db = c.env.DB
  const r2 = c.env.R2
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const body = await c.req.json()
  const { image_data, thumbnail_data, type, ref_id } = body
  // type: 'question' | 'answer', ref_id: optional

  if (!image_data) return c.json({ error: '이미지가 없습니다.' }, 400)

  // base64 → binary
  const base64 = image_data.replace(/^data:image\/\w+;base64,/, '')
  const binaryStr = atob(base64)
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i)

  const contentType = image_data.match(/^data:(image\/\w+);/)?.[1] || 'image/jpeg'
  const ext = contentType === 'image/png' ? 'png' : 'jpg'
  const key = `images/${type || 'question'}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`

  await r2.put(key, bytes.buffer, {
    httpMetadata: { contentType },
    customMetadata: { userId: String(user.id), type: type || 'question' }
  })

  // Upload thumbnail too
  let thumbnailKey = null
  if (thumbnail_data) {
    const tBase64 = thumbnail_data.replace(/^data:image\/\w+;base64,/, '')
    const tBin = atob(tBase64)
    const tBytes = new Uint8Array(tBin.length)
    for (let i = 0; i < tBin.length; i++) tBytes[i] = tBin.charCodeAt(i)
    thumbnailKey = `thumbnails/${type || 'question'}/${Date.now()}_${Math.random().toString(36).slice(2, 8)}.jpg`
    await r2.put(thumbnailKey, tBytes.buffer, {
      httpMetadata: { contentType: 'image/jpeg' },
      customMetadata: { userId: String(user.id), type: 'thumbnail' }
    })
  }

  return c.json({ key, thumbnailKey })
})

// Serve image from R2
app.get('/api/images/:key{.+}', async (c) => {
  const r2 = c.env.R2
  const key = c.req.param('key')
  const object = await r2.get(key)
  if (!object) return c.notFound()

  return new Response(object.body, {
    headers: {
      'Content-Type': object.httpMetadata?.contentType || 'image/jpeg',
      'Cache-Control': 'public, max-age=86400, s-maxage=604800',
      'CDN-Cache-Control': 'max-age=604800',
    }
  })
})

// ===== Questions API =====

// Migrate existing base64 images to R2
app.post('/api/admin/migrate-images', async (c) => {
  // E1: 관리자 인증 — ADMIN_SECRET 헤더 필수
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  const r2 = c.env.R2
  
  // Migrate questions
  const questions = await db.prepare("SELECT id, image_data, thumbnail_data FROM questions WHERE image_data IS NOT NULL AND image_data != '' AND (image_key IS NULL OR image_key = '')").all()
  let migrated = 0
  for (const q of (questions.results || []) as any[]) {
    try {
      const base64 = q.image_data.replace(/^data:image\/\w+;base64,/, '')
      const bin = atob(base64)
      const bytes = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      const ct = q.image_data.match(/^data:(image\/\w+);/)?.[1] || 'image/jpeg'
      const ext = ct === 'image/png' ? 'png' : 'jpg'
      const key = `images/question/${q.id}_${Date.now()}.${ext}`
      await r2.put(key, bytes.buffer, { httpMetadata: { contentType: ct } })
      
      let tKey: string | null = null
      if (q.thumbnail_data) {
        const tb = q.thumbnail_data.replace(/^data:image\/\w+;base64,/, '')
        const tBin = atob(tb)
        const tBytes = new Uint8Array(tBin.length)
        for (let i = 0; i < tBin.length; i++) tBytes[i] = tBin.charCodeAt(i)
        tKey = `thumbnails/question/${q.id}_${Date.now()}.jpg`
        await r2.put(tKey, tBytes.buffer, { httpMetadata: { contentType: 'image/jpeg' } })
      }
      
      // Update DB: set R2 keys and clear base64 data
      await db.prepare('UPDATE questions SET image_key = ?, thumbnail_key = ?, image_data = NULL, thumbnail_data = NULL WHERE id = ?').bind(key, tKey, q.id).run()
      migrated++
    } catch (e) { /* skip failed */ }
  }
  
  // Migrate answers
  const answers = await db.prepare("SELECT id, image_data FROM answers WHERE image_data IS NOT NULL AND image_data != '' AND (image_key IS NULL OR image_key = '')").all()
  let aMigrated = 0
  for (const a of (answers.results || []) as any[]) {
    try {
      const base64 = a.image_data.replace(/^data:image\/\w+;base64,/, '')
      const bin = atob(base64)
      const bytes = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      const ct = a.image_data.match(/^data:(image\/\w+);/)?.[1] || 'image/jpeg'
      const ext = ct === 'image/png' ? 'png' : 'jpg'
      const key = `images/answer/${a.id}_${Date.now()}.${ext}`
      await r2.put(key, bytes.buffer, { httpMetadata: { contentType: ct } })
      await db.prepare('UPDATE answers SET image_key = ?, image_data = NULL WHERE id = ?').bind(key, a.id).run()
      aMigrated++
    } catch (e) { /* skip failed */ }
  }
  
  return c.json({ success: true, questions_migrated: migrated, answers_migrated: aMigrated })
})

// Admin: 모든 이미지 삭제 (R2 + DB)
app.post('/api/admin/clear-all-images', async (c) => {
  // E1: 관리자 인증 — 파괴적 작업은 ADMIN_SECRET 미설정 시에도 차단
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  const r2 = c.env.R2
  let deleted = 0

  // 질문 이미지 R2 삭제
  const questions = await db.prepare("SELECT id, image_key, thumbnail_key FROM questions WHERE image_key IS NOT NULL AND image_key != ''").all()
  for (const q of (questions.results || []) as any[]) {
    try {
      if (q.image_key) await r2.delete(q.image_key)
      if (q.thumbnail_key) await r2.delete(q.thumbnail_key)
      deleted++
    } catch (e) { /* skip */ }
  }

  // 답변 이미지 R2 삭제
  const answers = await db.prepare("SELECT id, image_key FROM answers WHERE image_key IS NOT NULL AND image_key != ''").all()
  for (const a of (answers.results || []) as any[]) {
    try {
      if (a.image_key) await r2.delete(a.image_key)
      deleted++
    } catch (e) { /* skip */ }
  }

  // DB에서 이미지 관련 필드 모두 초기화
  await db.prepare("UPDATE questions SET image_data = NULL, thumbnail_data = NULL, image_key = NULL, thumbnail_key = NULL").run()
  await db.prepare("UPDATE answers SET image_data = NULL, image_key = NULL").run()

  return c.json({ success: true, r2_deleted: deleted, message: '모든 이미지가 삭제되었습니다' })
})

app.post('/api/admin/clear-all-data', async (c) => {
  // E1: 관리자 인증 — 파괴적 작업은 ADMIN_SECRET 미설정 시에도 차단
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  const r2 = c.env.R2

  // R2 이미지 먼저 삭제
  const qImgs = await db.prepare("SELECT image_key, thumbnail_key FROM questions WHERE image_key IS NOT NULL AND image_key != ''").all()
  for (const q of (qImgs.results || []) as any[]) {
    try { if (q.image_key) await r2.delete(q.image_key); if (q.thumbnail_key) await r2.delete(q.thumbnail_key) } catch(e) {}
  }
  const aImgs = await db.prepare("SELECT image_key FROM answers WHERE image_key IS NOT NULL AND image_key != ''").all()
  for (const a of (aImgs.results || []) as any[]) {
    try { if (a.image_key) await r2.delete(a.image_key) } catch(e) {}
  }

  // 테이블 데이터 삭제 (순서 중요: FK 의존성)
  // E7: 테이블명 수정 — CREATE TABLE은 'replies'인데 여기만 'answer_replies'로 잘못됨
  const tables = ['cancel_records','tutoring_slots','tutoring_matches','replies','answers','questions']
  for (const t of tables) {
    try { await db.prepare(`DELETE FROM ${t}`).run() } catch(e) {}
  }

  return c.json({ success: true, message: '모든 질문/답변 데이터가 삭제되었습니다' })
})

// P2-A3: /api/admin/stats — 서비스 통계 대시보드 (총 사용자/질문/답변, 오늘 활동, DAU)

app.get('/api/admin/stats', async (c) => {
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  const todayStart = todayStartKST()
  const results = await db.batch([
    db.prepare('SELECT COUNT(*) as cnt FROM users'),
    db.prepare('SELECT COUNT(*) as cnt FROM questions'),
    db.prepare('SELECT COUNT(*) as cnt FROM answers'),
    db.prepare('SELECT COUNT(*) as cnt FROM questions WHERE created_at >= ?').bind(todayStart),
    db.prepare('SELECT COUNT(*) as cnt FROM answers WHERE created_at >= ?').bind(todayStart),
    db.prepare('SELECT COUNT(DISTINCT user_id) as cnt FROM sessions WHERE expires_at > datetime(\'now\') AND created_at >= ?').bind(todayStart),
  ])
  return c.json({
    total_users: (results[0].results?.[0] as any)?.cnt || 0,
    total_questions: (results[1].results?.[0] as any)?.cnt || 0,
    total_answers: (results[2].results?.[0] as any)?.cnt || 0,
    today_questions: (results[3].results?.[0] as any)?.cnt || 0,
    today_answers: (results[4].results?.[0] as any)?.cnt || 0,
    dau: (results[5].results?.[0] as any)?.cnt || 0,
    timestamp: new Date().toISOString(),
  })
})

// 관리자용: ai_solution 리셋 (재생성 허용)
app.post('/api/admin/reset-solution/:id', async (c) => {
  const adminSecret = c.env.ADMIN_SECRET
  if (!adminSecret || c.req.header('X-Admin-Secret') !== adminSecret) {
    return c.json({ error: 'Forbidden: admin secret required' }, 403)
  }
  const db = c.env.DB
  const id = c.req.param('id')
  const q = await db.prepare('SELECT id, solution_stat FROM questions WHERE id = ?').bind(id).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)
  await db.prepare('UPDATE questions SET ai_solution = NULL, solution_stat = 0 WHERE id = ?').bind(id).run()
  return c.json({ id: Number(id), solution_stat: 0, message: 'Solution reset. Call POST /api/questions/:id/generate-solution to re-generate.' })
})

// P2-A4: 페이지뷰 분석 API — waitUntil()로 비차단 기록
app.post('/api/analytics/pageview', async (c) => {
  const db = c.env.DB
  const body = await c.req.json().catch(() => ({} as any))
  const path = String(body.path || '/').slice(0, 200)
  const user = await getAuthUser(c)
  const userId = (user as any)?.id || null
  c.executionCtx.waitUntil(
    db.prepare('INSERT INTO page_views (path, user_id, created_at) VALUES (?, ?, ?)').bind(path, userId, nowKST()).run()
  )
  return c.json({ ok: true })
})

// === Helper: enrich questions with user participation & match status ===
async function enrichQuestions(db: any, questions: any[], userId: number | null) {
  if (!userId) return
  // P1-7: N+1 최적화 — 4개 쿼리를 2개로 통합 (DB 왕복 50% 감소)
  const myAnsweredIds = new Set<number>()
  const myAcceptedIds = new Set<number>()
  // 1 query: answers with GROUP BY + MAX(is_accepted)
  const myAnswerAgg = await db.prepare('SELECT question_id, MAX(is_accepted) as max_accepted FROM answers WHERE user_id = ? GROUP BY question_id').bind(userId).all()
  for (const a of (myAnswerAgg.results || []) as any[]) {
    myAnsweredIds.add(a.question_id)
    if (a.max_accepted === 1) myAcceptedIds.add(a.question_id)
  }
  // 1 query: tutoring with DISTINCT question_id, status
  const myTutoringAgg = await db.prepare('SELECT DISTINCT question_id, status FROM tutoring_matches WHERE tutor_id = ?').bind(userId).all()
  for (const t of (myTutoringAgg.results || []) as any[]) {
    myAnsweredIds.add(t.question_id)
    if (t.status === 'accepted') myAcceptedIds.add(t.question_id)
  }
  // Batch fetch tutoring match statuses for all tutoring questions in one go
  const tutoringQIds = questions.filter((q: any) => q.difficulty === '1:1심화설명').map((q: any) => q.id)
  const pendingMap = new Map<number, any>()
  const confirmedMap = new Map<number, any>()
  const myMatchMap = new Map<number, any>()
  if (tutoringQIds.length > 0) {
    const placeholders = tutoringQIds.map(() => '?').join(',')
    const pendingAll = await db.prepare(`SELECT question_id, id, tutor_name FROM tutoring_matches WHERE question_id IN (${placeholders}) AND status = 'pending'`).bind(...tutoringQIds).all()
    for (const p of (pendingAll.results || []) as any[]) { if (!pendingMap.has(p.question_id)) pendingMap.set(p.question_id, p) }
    const confirmedAll = await db.prepare(`SELECT question_id, id, tutor_id FROM tutoring_matches WHERE question_id IN (${placeholders}) AND status = 'confirmed'`).bind(...tutoringQIds).all()
    for (const cm of (confirmedAll.results || []) as any[]) { if (!confirmedMap.has(cm.question_id)) confirmedMap.set(cm.question_id, cm) }
    if (userId) {
      const myMatches = await db.prepare(`SELECT question_id, id, status FROM tutoring_matches WHERE question_id IN (${placeholders}) AND tutor_id = ?`).bind(...tutoringQIds, userId).all()
      for (const m of (myMatches.results || []) as any[]) myMatchMap.set(m.question_id, m)
    }
  }
  for (const q of questions as any[]) {
    q.i_answered = myAnsweredIds.has(q.id) ? 1 : 0
    q.i_accepted = myAcceptedIds.has(q.id) ? 1 : 0
    if (q.difficulty === '1:1심화설명') {
      const pm = pendingMap.get(q.id)
      const cm = confirmedMap.get(q.id)
      q.has_pending_match = pm ? 1 : 0
      q.pending_tutor_name = pm ? pm.tutor_name : null
      q.has_confirmed_match = cm ? 1 : 0
      const myMatch = myMatchMap.get(q.id)
      q.my_match_status = myMatch ? myMatch.status : null
    }
  }
}

// === 오늘 해결(채택) 질문 수 API ===
app.get('/api/stats/today-solved', async (c) => {
  const db = c.env.DB
  try {
    // KST 기준 오늘 00:00:00을 UTC로 변환하여 비교 (created_at은 UTC로 저장됨)
    const kstMidnight = todayStartKST()
    // KST 자정을 UTC로: -9시간
    const utcEquiv = new Date(new Date(kstMidnight + 'Z').getTime() - 9 * 3600000).toISOString().slice(0, 19).replace('T', ' ')
    const row = await db.prepare("SELECT COUNT(*) as cnt FROM questions WHERE status = '채택 완료' AND created_at >= ?").bind(utcEquiv).first()
    return c.json({ count: row?.cnt || 0 })
  } catch(e) { return c.json({ count: 0 }) }
})

// === 내 질문 + 내 답변 질문 프리로드 API (로그인 필수) ===
app.get('/api/my-questions', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const userId = user.id

  // 내가 작성한 질문
  const myQ = await db.prepare(
    "SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != '') OR (image_key IS NOT NULL AND image_key != '') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, content_type, ai_difficulty, ai_tags, ai_analyzed, question_type, coaching_requested FROM questions WHERE user_id = ? ORDER BY created_at DESC LIMIT 200"
  ).bind(userId).all()

  // 내가 답변한 질문 ID 목록
  const myAns = await db.prepare(
    "SELECT DISTINCT question_id FROM answers WHERE user_id = ?"
  ).bind(userId).all()
  const answeredIds = new Set((myAns.results || []).map((r: any) => r.question_id))

  // 내가 채택 받은 질문 ID
  const myAccepted = await db.prepare(
    "SELECT DISTINCT question_id FROM answers WHERE user_id = ? AND is_accepted = 1"
  ).bind(userId).all()
  const acceptedIds = new Set((myAccepted.results || []).map((r: any) => r.question_id))

  // 내가 답변한 질문 중 myQ에 없는 것들 조회
  const myQIds = new Set((myQ.results || []).map((r: any) => r.id))
  const extraIds = [...answeredIds].filter(id => !myQIds.has(id))
  let answeredQuestions: any[] = []
  if (extraIds.length > 0) {
    // 최대 200개 제한
    const limited = extraIds.slice(0, 200)
    const placeholders = limited.map(() => '?').join(',')
    const extraQ = await db.prepare(
      "SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != '') OR (image_key IS NOT NULL AND image_key != '') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, content_type, ai_difficulty, ai_tags, ai_analyzed, question_type FROM questions WHERE id IN (" + placeholders + ") ORDER BY created_at DESC"
    ).bind(...limited).all()
    answeredQuestions = extraQ.results || []
  }

  // 결과에 i_answered, i_accepted 플래그 추가
  const myQuestions = (myQ.results || []).map((q: any) => ({
    ...q, i_answered: answeredIds.has(q.id), i_accepted: acceptedIds.has(q.id)
  }))
  const answeredOnly = answeredQuestions.map((q: any) => ({
    ...q, i_answered: true, i_accepted: acceptedIds.has(q.id)
  }))

  return c.json({ myQuestions, answeredOnly })
})

// === Cursor-based paginated questions API ===
app.get('/api/questions', async (c) => {
  const db = c.env.DB
  const subject = c.req.query('subject')
  const difficulty = c.req.query('difficulty')
  const category = c.req.query('category') // 'normal' | 'killer' | 'tutoring' | undefined(all)
  const search = c.req.query('search')
  const sort = c.req.query('sort') || 'latest'
  const cursor = c.req.query('cursor') // cursor: created_at of last seen item
  const cursorId = c.req.query('cursor_id') // tie-breaker: id of last seen item
  const limit = Math.min(parseInt(c.req.query('limit') || '35'), 100) // max 100
  const direction = c.req.query('direction') || 'older' // 'older' (default) or 'newer'

  let baseWhere = ' WHERE user_id != 252'
  const params: any[] = []

  // Category filter
  if (category === 'normal') {
    baseWhere += " AND (difficulty IS NULL OR (difficulty != '최상' AND difficulty != '1:1심화설명'))"
  } else if (category === 'killer') {
    baseWhere += " AND difficulty = '최상'"
  } else if (category === 'tutoring') {
    baseWhere += " AND difficulty = '1:1심화설명'"
  } else if (difficulty && difficulty !== '전체') {
    baseWhere += ' AND difficulty = ?'
    params.push(difficulty)
  }

  if (subject && subject !== '전체') {
    baseWhere += ' AND subject = ?'
    params.push(subject)
  }
  if (search) {
    baseWhere += ' AND content LIKE ?'
    params.push(`%${search}%`)
  }

  // Cursor-based pagination (keyset pagination)
  if (cursor) {
    if (direction === 'newer') {
      // Fetch items newer than cursor
      if (cursorId) {
        baseWhere += ' AND (created_at > ? OR (created_at = ? AND id > ?))'
        params.push(cursor, cursor, parseInt(cursorId))
      } else {
        baseWhere += ' AND created_at > ?'
        params.push(cursor)
      }
    } else {
      // Fetch items older than cursor (default scroll down)
      if (cursorId) {
        baseWhere += ' AND (created_at < ? OR (created_at = ? AND id < ?))'
        params.push(cursor, cursor, parseInt(cursorId))
      } else {
        baseWhere += ' AND created_at < ?'
        params.push(cursor)
      }
    }
  }

  const selectColsFull = 'SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, thumbnail_data, image_key, thumbnail_key, image_keys, content_type, ai_difficulty, ai_tags, ai_topic_main, ai_analyzed, requested_teacher, coaching_requested FROM questions'
  const selectColsFallback = 'SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, thumbnail_data, image_key, thumbnail_key, image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_analyzed FROM questions'

  function buildSortAndLimit(q: string) {
    if (sort === 'answers_asc') q += ' ORDER BY comment_count ASC, created_at DESC'
    else if (sort === 'points') q += ' ORDER BY reward_points DESC, created_at DESC'
    else if (sort === 'unanswered') q += ' ORDER BY CASE WHEN comment_count = 0 THEN 0 ELSE 1 END, created_at DESC'
    else {
      if (direction === 'newer') q += ' ORDER BY created_at ASC, id ASC'
      else q += ' ORDER BY created_at DESC, id DESC'
    }
    q += ' LIMIT ?'
    return q
  }

  const paramsWithLimit = [...params, limit + 1]

  let result
  try {
    result = await db.prepare(buildSortAndLimit(selectColsFull + baseWhere)).bind(...paramsWithLimit).all()
  } catch (e) {
    // Fallback: requested_teacher column may not exist yet
    try { await db.prepare('ALTER TABLE questions ADD COLUMN requested_teacher TEXT DEFAULT NULL').run() } catch(e2){}
    result = await db.prepare(buildSortAndLimit(selectColsFallback + baseWhere)).bind(...paramsWithLimit).all()
  }
  let questions = (result.results || []) as any[]
  
  // Check if there are more items
  const hasMore = questions.length > limit
  if (hasMore) questions = questions.slice(0, limit)
  
  // If direction=newer, reverse to keep DESC order for display
  if (direction === 'newer') questions.reverse()

  // Get current user for match status
  const currentApiUser = await getAuthUser(c) as any
  await enrichQuestions(db, questions, currentApiUser?.id || null)

  // Build next/prev cursors
  const nextCursor = hasMore && questions.length > 0 ? {
    cursor: questions[questions.length - 1].created_at,
    cursor_id: questions[questions.length - 1].id
  } : null

  return c.json({ questions, hasMore, nextCursor, limit })
})

// === Lightweight category counts API ===
app.get('/api/questions/counts', async (c) => {
  const db = c.env.DB
  const result = await db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN difficulty IS NULL OR (difficulty != '최상' AND difficulty != '1:1심화설명') THEN 1 ELSE 0 END) as normal_count,
      SUM(CASE WHEN difficulty = '최상' THEN 1 ELSE 0 END) as killer_count,
      SUM(CASE WHEN difficulty = '1:1심화설명' THEN 1 ELSE 0 END) as tutoring_count
    FROM questions WHERE user_id != 252
  `).first() as any
  return c.json({
    total: result?.total || 0,
    normal: result?.normal_count || 0,
    killer: result?.killer_count || 0,
    tutoring: result?.tutoring_count || 0
  })
})

// === Check for new questions (lightweight poll) ===
app.get('/api/questions/latest-id', async (c) => {
  const db = c.env.DB
  const row = await db.prepare('SELECT id, created_at FROM questions WHERE user_id != 252 ORDER BY created_at DESC LIMIT 1').first() as any
  return c.json({ id: row?.id || 0, created_at: row?.created_at || '' })
})

app.get('/api/questions/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  let question: any
  try {
    question = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, image_keys, content_type, passage_image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, ai_literature_genre, challenge_result, requested_teacher, solution_stat, practice_warm_stat FROM questions WHERE id = ?').bind(id).first()
  } catch (e) {
    // Ensure all columns exist
    try { await db.prepare('ALTER TABLE questions ADD COLUMN ai_next_questions TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN challenge_result TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN ai_growth_coaching TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN ai_coaching_data TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN requested_teacher TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN image_keys TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN ai_literature_genre TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN content_type TEXT DEFAULT \'normal\'').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN passage_image_keys TEXT DEFAULT NULL').run() } catch(e2){}
    try { await db.prepare('ALTER TABLE questions ADD COLUMN practice_warm_stat INTEGER DEFAULT 0').run() } catch(e2){}
    try {
      question = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, image_keys, content_type, passage_image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, ai_literature_genre, challenge_result, requested_teacher, solution_stat, practice_warm_stat FROM questions WHERE id = ?').bind(id).first()
    } catch(e3) {
      // Last fallback: query without newer columns
      question = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, solution_stat FROM questions WHERE id = ?').bind(id).first()
    }
  }
  if (!question) return c.json({ error: 'Not found' }, 404)

  // Polling-triggered recovery: 장시간 Gemini 호출로 generate-solution Worker가 죽어
  // D1 업데이트가 유실된 케이스를 프록시 저장분에서 회수.
  // stat=3(진행중)도 포함 — 락 걸린 채 Worker 중도 종료로 고립되는 케이스 방지 (60s threshold).
  if (question.ai_analyzed === 1 && (question.solution_stat === 0 || question.solution_stat === 2 || question.solution_stat === 3) && c.env.AI_PROXY_URL && c.env.AI_PROXY_SECRET) {
    const createdMs = new Date(question.created_at.replace(' ', 'T') + 'Z').getTime()
    const minAge = question.solution_stat === 3 ? 60000 : 30000   // stat=3는 진행중 가능성 → 더 긴 threshold
    if (Date.now() - createdMs > minAge) {
      console.log(`[polling-recovery] attempting q=${question.id} stat=${question.solution_stat}`)
      let _debugRecovery = 'none'
      try {
        const url = `${c.env.AI_PROXY_URL}/result?question_id=${question.id}&task=solution-primary`
        _debugRecovery = `url=${url.replace(c.env.AI_PROXY_URL || '', '<BASE>')}`
        const r = await fetch(url, { headers: { 'Authorization': `Bearer ${c.env.AI_PROXY_SECRET}` } })
        _debugRecovery += ` status=${r.status}`
        console.log(`[polling-recovery] q=${question.id} proxy status=${r.status}`)
        if (r.ok) {
          const data: any = await r.json().catch(() => null)
          _debugRecovery += ` found=${data?.found} model=${data?.model} textLen=${data?.response_text?.length || 0} tail=${(data?.response_text || '').slice(-120).replace(/[\r\n]/g, '\\n')}`
          console.log(`[polling-recovery] q=${question.id} proxy found=${data?.found} model=${data?.model}`)
          if (data?.found && data.response_text) {
            const m = data.response_text.match(/```(?:json)?\s*([\s\S]*?)```/)?.[1]?.trim() || data.response_text.match(/\{[\s\S]*\}/)?.[0]
            if (m) {
              try {
                const solution = safeJsonParse(m)
                await db.prepare('UPDATE questions SET ai_solution = ?, solution_stat = 1 WHERE id = ?').bind(JSON.stringify(solution), question.id).run()
                console.log(`Polling recovery: q=${question.id} model=${data.model} latency=${data.latency_ms}ms saved`)
                question.solution_stat = 1
                question.ai_solution = JSON.stringify(solution)
                _debugRecovery += ' SAVED'
              } catch (jsonErr) {
                _debugRecovery += ` JSON_ERR=${(jsonErr as any)?.message?.slice(0, 100)}`
                logErr('polling-recovery/json', jsonErr, { questionId: question.id })
              }
            } else {
              _debugRecovery += ' NO_JSON_MATCH'
            }
          }
        }
      } catch (e) {
        _debugRecovery += ` FETCH_ERR=${(e as any)?.message?.slice(0, 100)}`
        logErr('polling-recovery', e, { questionId: question.id })
      }
      c.header('X-Polling-Recovery', _debugRecovery)
    }
  }

  // 수학: ai_analyzed=1 + solution_stat=1이면 변형문제 사전 생성 (중복 호출 안전)
  if (question.ai_analyzed === 1 && question.solution_stat === 1 && question.subject === '수학' && c.env.AI_TUTOR_SECRET) {
    const extId = await db.prepare('SELECT external_id FROM users WHERE id = ?').bind(question.user_id).first() as any
    if (extId?.external_id) {
      c.executionCtx.waitUntil(
        fetch(`${c.env.AI_TUTOR_URL}/v1/practice/pre-warm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': c.env.AI_TUTOR_SECRET },
          body: JSON.stringify({ question_id: String(id), student_id: Number(extId.external_id) }),
        }).then(async r => {
          const stat = r.ok ? 1 : 2
          try { await db.prepare('UPDATE questions SET practice_warm_stat = ? WHERE id = ?').bind(stat, id).run() } catch (_) {}
        }).catch(async e => {
          try { await db.prepare('UPDATE questions SET practice_warm_stat = 2 WHERE id = ?').bind(id).run() } catch (_) {}
          console.error('Practice pre-warm error:', e)
        })
      )
    }
  }

  return c.json(question)
})

app.get('/api/questions/:id/image', async (c) => {
  const db = c.env.DB
  const r2 = c.env.R2
  const id = c.req.param('id')
  const type = c.req.query('type') // 'thumb' for thumbnail
  
  // Check for R2 key first
  const row = await db.prepare('SELECT image_data, thumbnail_data, image_key, thumbnail_key FROM questions WHERE id = ?').bind(id).first() as any
  if (!row) return c.json({ error: 'Not found' }, 404)
  
  // R2 path: serve directly from R2
  const r2Key = type === 'thumb' ? (row.thumbnail_key || row.image_key) : row.image_key
  if (r2Key) {
    const object = await r2.get(r2Key)
    if (object) {
      return new Response(object.body, {
        headers: {
          'Content-Type': object.httpMetadata?.contentType || 'image/jpeg',
          'Cache-Control': 'public, max-age=86400, s-maxage=604800',
        }
      })
    }
  }
  
  // Fallback: base64 from DB
  const data = type === 'thumb' ? (row.thumbnail_data || row.image_data) : row.image_data
  if (!data) return c.json({ error: 'Not found' }, 404)
  c.header('Cache-Control', 'public, max-age=86400, s-maxage=604800')
  return c.json({ data })
})

app.post('/api/questions', async (c) => {
  try {
  const db = c.env.DB
  const body = await c.req.json()
  const { content, image_data, thumbnail_data, image_key, thumbnail_key, image_keys, subject: userSubject, question_grade, is_killer, is_tutoring, requested_teacher, content_type, passage_image_keys } = body
  if (Array.isArray(image_keys) && image_keys.length > 3) return c.json({ error: '이미지는 최대 3장까지 첨부할 수 있습니다.' }, 400)
  if (Array.isArray(passage_image_keys) && passage_image_keys.length > 5) return c.json({ error: '지문 이미지는 최대 5장까지 첨부할 수 있습니다.' }, 400)

  // Auth check
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // P2-15: 질문 생성 레이트 리밋 (5회/분)
  const qlimit = checkContentRateLimit(user.id, 'question')
  if (!qlimit.allowed) return c.json({ error: '질문 등록이 너무 빠릅니다. 잠시 후 다시 시도해주세요.' }, 429)

  // Suspension check for 1:1 tutoring questions
  if (is_tutoring) {
    const suspended = await checkSuspension(db, user.id)
    if (suspended) return c.json({ error: '1:1 튜터링 이용이 정지되었습니다. (' + suspended + '까지)' }, 403)
  }

  if (!content || content.trim().length < 10) {
    return c.json({ error: '질문 내용을 10자 이상 작성해주세요.' }, 400)
  }
  // P1-10: 콘텐츠 길이 제한
  if (content.length > 10000) return c.json({ error: '질문 내용은 10,000자 이내로 작성해주세요.' }, 400)

  const title = sanitizeHtml(content.trim().length > 30 ? content.trim().slice(0, 30) + '...' : content.trim())

  let subject = userSubject || '기타'
  if (!userSubject) {
    const allText = content.toLowerCase()
    if (/영어|english|grammar|word|vocab|reading|listening|whose|which|likely/i.test(allText)) subject = '영어'
    else if (/수학|math|함수|방정식|미적분|확률|통계|기하|벡터|행렬|수열|극한/i.test(allText)) subject = '수학'
    else if (/국어|문학|비문학|독서|화법|작문|문법|고전|시|소설|수능국어/i.test(allText)) subject = '국어'
    else if (/과학|물리|화학|생물|생명|지구|천문|실험|과탐/i.test(allText)) subject = '과학'
  }

  let difficulty = '중'
  let reward_points = 0
  // CP 비용 차감: 튜터링/킬러 질문은 질문자가 CP를 선불 차감
  if (is_killer) {
    difficulty = '최상'
    reward_points = [10,20,30].includes(body.reward_points) ? body.reward_points : 0
    // 킬러 CP 비용 차감
    let cpCost = CP_CONFIG.KILLER_COST.low
    if (reward_points >= 20) cpCost = CP_CONFIG.KILLER_COST.mid
    if (reward_points >= 30) cpCost = CP_CONFIG.KILLER_COST.high
    const userRow = await db.prepare('SELECT cp_balance FROM users WHERE id = ?').bind(user.id).first() as any
    if (!userRow || (userRow.cp_balance || 0) < cpCost) {
      return c.json({ error: `크로켓포인트가 부족합니다. 필요: ${cpCost * 100} 크로켓포인트, 보유: ${(userRow?.cp_balance || 0) * 100} 크로켓포인트` }, 400)
    }
    await awardCP(db, user.id, null, null, -cpCost, 'killer_request', `킬러 문제 의뢰 비용 (-${cpCost * 100} 크로켓포인트)`)
  } else if (body.is_tutoring) {
    difficulty = '1:1심화설명'
    reward_points = [50,80,100].includes(body.reward_points) ? body.reward_points : 0
    // 튜터링 CP 비용 차감
    let cpCost = CP_CONFIG.TUTORING_COST.low
    if (reward_points >= 80) cpCost = CP_CONFIG.TUTORING_COST.mid
    if (reward_points >= 100) cpCost = CP_CONFIG.TUTORING_COST.high
    const userRow = await db.prepare('SELECT cp_balance FROM users WHERE id = ?').bind(user.id).first() as any
    if (!userRow || (userRow.cp_balance || 0) < cpCost) {
      return c.json({ error: `크로켓포인트가 부족합니다. 필요: ${cpCost * 100} 크로켓포인트, 보유: ${(userRow?.cp_balance || 0) * 100} 크로켓포인트` }, 400)
    }
    await awardCP(db, user.id, null, null, -cpCost, 'tutoring_request', `튜터링 의뢰 비용 (-${cpCost * 100} 크로켓포인트)`)
  } else {
    const allText = content.toLowerCase()
    if (/수능|모의고사|킬러|최상|ebs.*연계|고3.*모의/i.test(allText)) difficulty = '최상'
    else if (/심화|어려|고3|응용|서술형/i.test(allText)) difficulty = '상'
    else if (/기초|기본|쉬운|고1|개념/i.test(allText)) difficulty = '하'
  }

  // 선생님 도와주세요 스티커: 유효한 선생님 이름만 허용
  const VALID_TEACHERS = ['희성','우제','우현','윤동','성희','제이든','성웅','지영','서욱','지후','동현','성현']
  const teacherVal = (requested_teacher && VALID_TEACHERS.includes(requested_teacher)) ? requested_teacher : null

  const imageKeysJson = (Array.isArray(image_keys) && image_keys.length > 0) ? JSON.stringify(image_keys) : null
  const isPassage = content_type === 'passage' && subject !== '수학'
  const passageImageKeysJson = (isPassage && Array.isArray(passage_image_keys) && passage_image_keys.length > 0) ? JSON.stringify(passage_image_keys) : null
  const result = await db.prepare(
    'INSERT INTO questions (user_id, author_name, author_grade, title, content, image_data, thumbnail_data, image_key, thumbnail_key, image_keys, subject, difficulty, reward_points, requested_teacher, question_grade, content_type, passage_image_keys) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(user.id, user.nickname, user.grade, title, content.trim(), image_key ? null : (image_data || null), image_key ? null : (thumbnail_data || null), image_key || null, thumbnail_key || null, imageKeysJson, subject, difficulty, reward_points, teacherVal, question_grade || null, isPassage ? 'passage' : 'normal', passageImageKeysJson).run()

  // Save tutoring time slots
  const qId = result.meta.last_row_id
  if (body.is_tutoring && Array.isArray(body.tutoring_slots)) {
    for (const slot of body.tutoring_slots.slice(0, 3)) {
      await db.prepare('INSERT INTO tutoring_slots (question_id, slot_time) VALUES (?, ?)').bind(qId, String(slot)).run()
    }
  }

  // Trigger AI analysis asynchronously (non-blocking) with slight delay for R2 consistency
  const geminiKey = c.env.GEMINI_API_KEY
  if (geminiKey && (image_data || image_key || imageKeysJson || passageImageKeysJson)) {
    // Flash 분석 (자체 waitUntil)
    c.executionCtx.waitUntil(
      new Promise(r => setTimeout(r, 1500)).then(() =>
        analyzeQuestionWithAI(db, c.env, qId, subject, content.trim(), image_key, image_data, imageKeysJson, user.external_id || null, passageImageKeysJson)
      )
    )
    // Pro 해설 생성은 waitUntil에서 Worker 수명 제한으로 실패함
    // → 프론트엔드 폴링에서 /api/questions/:id/generate-solution 수동 엔드포인트를 호출하여 처리
    // 수동 엔드포인트는 독립 요청이라 타임아웃 제약 없이 안정적으로 동작
  }

  // Trigger question classification (대단원/중단원/소단원/문제유형) asynchronously
  // R2 이미지 업로드 완료 대기를 위해 3초 딜레이
  if (c.env.QC_API_KEY && (image_data || image_key || imageKeysJson || passageImageKeysJson)) {
    c.executionCtx.waitUntil(
      new Promise(r => setTimeout(r, 3000)).then(() =>
        fetch('https://jungyoul.com/api/question-classify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${c.env.QC_API_KEY}`,
          },
          body: JSON.stringify({ question_id: qId }),
        }).then(res => {
          if (!res.ok) res.text().then(t => console.error('classify 오류:', res.status, t))
        })
      ).catch((err) => console.error('classify 실패:', err))
    )
  }

  // 질문 등록 시 CP 지급 없음 (답변을 받는 것 자체가 보상)
  // 레거시 XP는 더 이상 지급하지 않음

  return c.json({ id: qId, subject, difficulty, message: 'Question created' }, 201)
  } catch (e: any) { logErr('questions/create', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// === AI Question Analysis with Gemini 3 Pro ===

const CURRICULUM_PROMPT = `당신은 한국 고등학교 교육과정 전문가이자 OCR 전문가입니다.

[가장 중요한 지시사항 - 이미지 속 필기 인식]
이미지에는 인쇄된 수학 문제와 함께 **학생이 손으로 쓴 필기(손글씨, 펜 메모, 형광펜 표시)**가 있을 수 있습니다.
반드시 다음 순서로 분석하세요:
1단계: 이미지에서 인쇄된 문제 텍스트를 읽으세요.
2단계: 이미지에서 **학생이 손으로 쓴 필기/메모/질문**을 찾아 읽으세요. (예: "이거 왜 이래?", "여기서 뭘 써야해?", "풀이 맞나요?", 물음표, 밑줄, 화살표 등)
3단계: 필기가 없으면 인쇄된 문제 자체를 학생의 질문으로 간주하세요.
4단계: 학생의 질문 의도를 파악하여 아래 7유형 중 하나로 분류하세요.

★★★ 필기 인식 핵심 규칙 ★★★
- student_question 필드에는 이미지에서 인식한 **학생의 실제 필기 내용을 원문 그대로** 적어주세요.
- 절대로 학생의 필기를 수정하거나 보정하지 마세요! 학생이 f(-x)라고 적었으면 f(-x)라고 적고, f(2-x)로 바꾸지 마세요.
- 학생이 쓴 글씨가 수학적으로 틀렸더라도, 학생이 쓴 그대로 인식하세요. AI가 해석/보정하면 안 됩니다.
- "이건뭘 의미하죠?"를 "이 조건의 의도는 무엇?"으로 바꾸지 마세요! 학생의 말투 그대로 적으세요.
- 필기가 여러 개일 경우, 각 필기를 ① ② ③ 번호를 매겨 **모두** 빠짐없이 기록하세요.
- 동그라미 번호, 화살표, 밑줄 등 표시도 함께 설명하세요.
- 글씨가 흐리거나 판독이 어려운 경우, 그 부분만 [판독불확실:추정내용] 형식으로 표시하세요.
- 예시: "f(x)가 [판독불확실:∫때문건] 나왔으지?" — 원문은 유지하되 불확실한 부분만 표시
필기가 없으면 "(필기 없음)"이라고 적어주세요.

[학생이 직접 입력한 질문 텍스트 활용]
아래 [질문 텍스트]에 학생이 폼에서 직접 타이핑한 질문이 포함되어 있습니다.
이 텍스트는 학생이 자신의 궁금증을 직접 서술한 것이므로 분석의 핵심 입력으로 사용하세요.
★ 반영 규칙 ★
1. student_question 필드: 이미지 필기가 있으면 필기 + 입력 텍스트 모두 기록. 형식: "① [필기] 이미지에서 인식한 필기 ② [입력] 학생이 직접 입력한 질문". 필기가 없으면 입력 텍스트만 기록.
2. question_analysis: 이미지 필기와 입력 텍스트를 종합하여 학생의 질문 의도를 분석하세요. 둘 다 있으면 통합적으로 해석하세요.
3. question_type 분류: 입력 텍스트의 질문 의도도 반드시 반영하여 유형을 판단하세요.
4. coaching_comment / coaching_questions: 학생이 직접 표현한 궁금증에 맞춰 코칭하세요.

[과목별 교육과정 체계]

■ 수학:
- 공통수학1: 다항식(연산,나머지정리,인수분해), 방정식과부등식(복소수,이차방정식,이차함수,고차방정식,부등식), 경우의수(합곱법칙,순열,조합), 행렬
- 공통수학2: 도형의방정식(평면좌표,직선,원,이동), 집합과명제(집합,명제), 함수와그래프(함수,유리함수,무리함수)
- 대수: 지수함수와로그함수(지수,로그,지수함수,로그함수), 삼각함수(호도법,삼각함수,그래프,사인코사인법칙), 수열(등차수열,등비수열,시그마,수학적귀납법)
- 미적분1: 함수의극한과연속, 미분(미분계수,도함수,활용), 적분(부정적분,정적분,활용)
- 확률과통계: 순열조합(중복순열,중복조합,이항정리), 확률(확률의뜻,조건부확률), 통계(확률분포,정규분포,통계적추정)
- 미적분2: 수열의극한, 급수, 여러가지미분법, 여러가지적분법
- 기하: 이차곡선, 벡터, 공간도형, 공간좌표
- 수학I(2015): 지수로그함수, 삼각함수, 수열
- 수학II(2015): 함수의극한과연속, 미분, 적분

■ 국어:
- 문학: 서정갈래(현대시,고전시가), 서사갈래(현대소설,고전소설), 극갈래(희곡,시나리오), 교술갈래(현대수필,고전수필), 갈래복합
- 독서와작문: 독서와작문의본질, 인문예술, 사회문화, 과학기술
- 화법과언어: 화법(강연,발표,연설,토의,토론), 언어(음운론,형태론,통사론,문법요소,중세국어,국어규범)
- 독서(2015): 독서이론, 인문예술, 사회문화, 과학기술, 복합지문
- 문학(2015): 서정(현대시,고전시가), 서사(현대소설,고전소설), 극(희곡,시나리오), 교술(수필), 갈래복합
- 언어와매체(2015): 음운론,형태론,통사론,의미론,중세국어,매체

■ 영어:
- 수능영어: 듣기, 기본독해(목적,심경,주장,일치불일치,도표), 구문독해(요지,주제,제목,어색한문장), 어법, 추론(함축의미,빈칸추론,어휘추론), 간접쓰기(순서배열,문장삽입,요약문), 장문독해
- 내신영어: 객관식(내용불일치,빈칸추론,순서,어법,어휘,요지,제목,주제), 서술형(영작,어법수정,어휘수정,요약문)

■ 과학:
- 통합과학1: 과학의기초(기본량측정,정보신호), 물질과규칙성(물질탄생,주기성,화학결합,자연구성물질), 시스템과상호작용(역학적시스템,지구시스템,생명시스템)
- 통합과학2: 변화와다양성(지질시대,화학변화), 환경과에너지(생태계,발전에너지), 과학과미래사회(감염병,과학기술윤리)
- 물리학: 힘과에너지(힘운동,에너지열), 전기와자기(전기,자기), 빛과물질(빛의성질,이중성,특수상대성이론)
- 화학: 화학의언어(몰,화학반응식), 물질의구조와성질(화학결합,분자구조), 화학평형(동적평형), 역동적인화학반응(산염기,중화반응)
- 생명과학: 생명시스템의구성(생명과학이해,구성단계,생태계), 항상성과조절(신경계,방어작용), 생명의연속성과다양성(세포분열,유전,진화)
- 지구과학: 대기와해양(해양변화,대기변화기후), 지구의역사와암석(지구역사,암석지질구조), 우주와별(태양계,별의특성진화,우주구조)

[분석 규칙]
1. 반드시 위 교육과정 체계에서 매칭되는 과목명, 대단원, 소단원을 찾으세요.
2. 태그는 인스타그램 해시태그 형식으로 생성 (예: #공통수학1, #이차방정식, #판별식)
3. 예상 풀이시간은 분 단위 정수

[★ 난이도 판정 기준 — 문제 자체의 객관적 난이도를 판단하세요 ★]
반드시 문제의 실질적 난이도를 정확히 평가하세요. ★3(보통)에 안주하지 마세요!

★1 (기초개념) — 정답률 90%↑:
  수학: 단순 사칙연산, 기초 공식 대입, 교과서 예제 수준
  국어: 직접적 내용 확인, 사실적 이해
  영어: 기초 어휘/문법, 짧은 문장 해석
  과학: 용어 정의, 단순 개념 확인

★2 (기본) — 정답률 70~89%:
  수학: 교과서 기본 문제, 단일 개념 적용, 기본 계산 문제
  국어: 핵심 내용 파악, 기본 추론, 명시적 근거 찾기
  영어: 기본 독해, 주제/요지 파악, 기초 문법
  과학: 기본 원리 적용, 단순 계산, 개념 연결

★3 (보통) — 정답률 50~69%:
  수학: 2개 이상 개념 결합, 학교 내신 중간 수준, 조건 해석 필요
  국어: 간접 추론, 비판적 이해, 관점 비교
  영어: 빈칸 추론, 문장 삽입, 중급 어휘
  과학: 다단계 계산, 개념 통합, 실험 결과 해석

★4 (심화) — 정답률 30~49%:
  수학: 수능 3~4점급, 다단계 풀이, 조건분석+전략선택 필요, 함수 합성/미적분 응용
  국어: 복합지문, 추상적 개념 비교, EBS 연계 고난도
  영어: 고난도 빈칸, 복잡한 논리 구조 파악, 함축 의미
  과학: 복합 개념, 실험 설계 분석, 정량적 추론

★5 (최상위/킬러) — 정답률 30%↓:
  수학: 수능 킬러문항(21번/22번/30번급), 수학적 직관+창의적 접근 필요, 함수·미적분·확률 복합
  국어: 수능 최고난도(비문학 마지막 문항급), 고도의 추론
  영어: 수능 최고난도(빈칸/순서 최상위), 학술 텍스트 심층 분석
  과학: 킬러문항, 높은 수학적 역량 요구, 복합 분석

주의사항:
- 문제 이미지를 꼼꼼히 분석하여 실제 풀이에 필요한 개념 수, 단계 수, 사고 깊이를 파악하세요
- 수능/모의고사 출처 문제는 실제 등급컷 기반으로 판단하세요 (킬러=★5, 준킬러=★4)
- 고1 공통수학 문제라도 복합적이면 ★4 이상 가능
- "이거 모르겠어요"라는 학생 반응에 속지 마세요 — 쉬운 문제도 학생이 모를 수 있음
- 절대 모든 문제를 ★3으로 주지 마세요. 반드시 변별력 있게 판단하세요
- 확신이 없으면 ★3이 아니라, 문제에 필요한 개념의 수와 풀이 단계를 세어보세요:
  · 개념 1개 + 단순 대입/계산 → ★1~★2
  · 개념 2개 결합 + 2~3단계 풀이 → ★3
  · 개념 3개↑ 결합 + 4단계↑ 풀이 + 조건 분석 → ★4
  · 수능 킬러/준킬러급 복합문항, 창의적 접근 필요 → ★5
- 이미지 속 문제를 실제로 풀어보는 것처럼 분석하세요. 몇 단계가 필요한지 세세요.

★★★ 수식 표기 규칙: 모든 수식은 반드시 LaTeX 문법으로 작성하세요!
인라인 수식: $x^2$, $f(x)$, $\\int_0^1 f(x)dx$, $\\sum_{k=1}^{n}$
독립 수식: $$\\int_0^2 f(x)dx = 1$$
예시: "$f(x)+f(2-x)=1$이 성립할 때", "적분값 $\\int_0^2 f(x)dx$를 구하면"

[질문 유형 분류 체계 — 2축 9단계]

★ 호기심축 (Curiosity Axis) — 궁금증의 깊이:
보기(See):
- "A-1" 뭐지?: 대상을 파악하는 질문 ("이 기호가 뭐예요?", "이거 뭐야?")
- "A-2" 어떻게?: 절차/방법을 묻는 질문 ("어떤 순서로 풀어요?", "모르겠어요", "풀어주세요")

파기(Dig):
- "B-1" 왜?: 이유/원리를 묻는 질문 ("왜 이 조건이 필요해?", "대입하는 건 아는데 근은 어떻게?")
- "B-2" 만약에?: 조건 변경/가정을 시도 ("만약 a+2=4이면?", "조건이 바뀌면 어떻게 돼?")

넓히기(Expand):
- "C-1" 뭐가 더 나아?: 방법 비교/평가 ("A방법이 B보다 나은 이유?")
- "C-2" 그러면?: 확장/응용/일반화 ("이걸 다른 문제에도 적용하면?", "유사 문제에서는?")

★ 성찰축 (Reflection Axis) — 자기 점검:
- "R-1" 어디서 틀렸지?: 오류 위치 식별 ("내 풀이 어디가 잘못됐어?")
- "R-2" 왜 틀렸지?: 오류 원인 분석 ("왜 이 접근이 안 됐지?")
- "R-3" 다음엔 어떻게?: 전략 수정/개선 ("다음에 비슷한 문제 나오면 뭘 먼저 할까?")

[3대 필수 조건 — B 이상(B-1, B-2, C-1, C-2) 요구]
① 구체적 대상: 문제의 어떤 부분인지 특정 (수식, 조건, 단계를 지목)
② 자기 생각: "나는 ~라고 생각하는데" / "~인 것 같은데" 등 자기 판단 존재
③ 맥락 연결: 지문/조건과 연결하여 질문
→ 하나라도 없으면 무조건 A 수준 (A-1 또는 A-2)
→ 3개 모두 충족 시 B 이상

분류 주의:
- "이거 모르겠어요", "질문이요" → A-2 (어떻게?)
- 필기 없이 문제만 찍은 경우 → A-2 (풀이 요청)
- 풀이 적혀있고 "맞나요?" → R-1 (어디서 틀렸지?)
- "~인 것 같은데 맞아?" + 구체적 조건 언급 → B-1 (왜?)
- "만약 ~이면?" + 자기 추론 → B-2 (만약에?)

[성장 경로 — 1~2단계만 올리세요, 3단계 이상 건너뛰기 금지]
호기심축: A-1→A-2 / A-2→B-1,B-2 / B-1→B-2,C-1 / B-2→C-1,C-2 / C-1→C-2
성찰축: R-1→R-2 / R-2→R-3
축 교차: A-2→R-1 / B-1→R-2 / R-1→B-1 / R-2→B-2

반드시 아래 JSON 형식으로만 응답하세요 (다른 텍스트 없이):
{
  "student_question": "이미지 필기와 입력 텍스트를 모두 기록. 형식: ① [필기] OCR 인식한 원문 그대로 ② [입력] 학생이 폼에서 직접 타이핑한 질문. 필기만 있으면 필기만, 입력만 있으면 입력만 기록. 필기 수정/보정 절대 금지. 판독 어려운 부분은 [판독불확실:추정내용]. 예: ① [필기] f(x)+f(-x)=1 이건뭘 의미하죠? ② [입력] 이 공식이 어떻게 유도되는지 모르겠어요",
  "problem_analysis": {
    "difficulty": 4,
    "grade": "고2",
    "estimated_time": 15,
    "unit": "대단원 > 소단원",
    "tags": ["#미적분1", "#함수의연속"],
    "summary": "이 문제가 무엇을 요구하는지 1~2문장 설명"
  },
  "question_analysis": {
    "original_question": "학생 질문 원문 그대로",
    "question_type": "B-1",
    "question_type_label": "왜?",
    "axis": "curiosity",
    "zone": "파기(Dig)",
    "confidence": 0.85,
    "interpretation": "학생이 궁금해하는 핵심이 무엇인지 1~2문장",
    "diagnosis": {
      "specific_target": {"met": true, "detail": "판단 근거 1문장"},
      "own_thinking": {"met": true, "detail": "판단 근거 1문장"},
      "context_connection": {"met": true, "detail": "판단 근거 1문장"}
    },
    "upgrade_hint": "다음 레벨로 올리려면 이렇게 질문해봐! (1~2문장)"
  },
  "coaching_comment": "학생의 현재 질문 수준을 인정하고 격려 + 구체적 성장 방향 (2~3문장, 친근한 톤)",
  "coaching_questions": [
    {
      "type": "B-2",
      "type_label": "만약에?",
      "growth_path": "B-1 왜? → B-2 만약에?",
      "question": "학생 혼잣말 스타일의 구체적 코칭질문",
      "why_important": "이 질문이 왜 중요한지 1문장"
    },
    {
      "type": "C-1",
      "type_label": "뭐가 더 나아?",
      "growth_path": "B-1 왜? → C-1 뭐가 더 나아?",
      "question": "학생 혼잣말 스타일의 구체적 코칭질문",
      "why_important": "이 질문이 왜 중요한지 1문장"
    }
  ],
  "growth_interactions": [
    {
      "target_coaching_index": 0,
      "target_type": "B-2",
      "target_label": "만약에?",
      "selection_button": "🔀 학생이 이해할 수 있는 쉬운 질문 형태의 선택 버튼",
      "wrong_attempt": {
        "setup": "이 문제의 핵심 조건을 잘못 적용한 구체적 시도 (실제 숫자/조건 사용, 2~3문장)",
        "question": "이거 괜찮을까요?",
        "choices": ["✅ 괜찮은 것 같아요", "❌ 뭔가 이상해요"]
      },
      "discovery_hint": {
        "on_correct": "좋아요! 어디서 문제가 생기는지 골라보세요.",
        "on_correct_choices": ["구체적 오류 선택지1", "구체적 오류 선택지2", "구체적 오류 선택지3", "잘 모르겠어요"],
        "on_wrong": "정말요? 🧐 ___을 확인해보세요!",
        "on_wrong_retry": "다시 생각해볼게요",
        "on_stuck": "힌트: 구체적 수치를 사용한 단계별 유도 힌트"
      },
      "thinking_bridge": {
        "steps": ["무엇을 시도했고", "무엇을 발견했고", "어떤 질문이 떠올랐는지"],
        "connection": "이게 바로 🔍 오류진단 질문이에요! 설명 한 문장."
      }
    }
  ],
  "selection_prompt": "아래 중 더 궁금한 걸 골라보세요!"
}

[핵심 생성 규칙]

1. coaching_questions: 2~3개 생성. 각각 서로 다른 유형이어야 함.
2. growth_interactions: coaching_questions와 1:1 대응 (모든 코칭질문에 인터랙션 생성)
3. wrong_attempt: 구체적 숫자/조건 사용. 추상적 설명 금지. 50% 확률로 발견 가능한 난이도.
4. discovery_hint: on_correct_choices는 정답1+오답2+잘모르겠어요 = 4개. 답을 직접 알려주지 말 것.
5. thinking_bridge: steps는 반드시 3개. connection에 이모지+질문유형 이름 포함.
6. 인터랙션 간 중복 금지: 서로 다른 사고 영역을 다룰 것.

★★★ 질문 톤 규칙 ★★★
- 코칭질문은 학생 혼잣말/독백 스타일 ("~거지?", "~건가?", "~일까?")
- 선생님 질문 스타일 절대 금지
- selection_button은 학생이 이해할 수 있는 쉬운 질문 형태`

// Preserve LaTeX math expressions — pass through unchanged
// (Previously stripped $ signs; now LaTeX is rendered by KaTeX on frontend)
function stripDollarSigns(s: string | null | undefined): string | null {
  if (!s) return null
  return s
}

// Fix LaTeX backslashes in JSON strings before parsing
// AI returns \int, \frac etc. which are invalid JSON escapes
function fixLatexInJson(jsonStr: string): string {
  // Inside JSON string values, replace unescaped backslashes that aren't valid JSON escapes
  // Valid JSON escapes: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX
  return jsonStr.replace(/\\(?!["\\/bfnrtu])/g, '\\\\')
}

function safeJsonParse(jsonStr: string): any {
  try {
    return JSON.parse(jsonStr)
  } catch (e) {
    // Try fixing LaTeX backslashes
    try {
      return JSON.parse(fixLatexInJson(jsonStr))
    } catch (e2) {
      throw e // throw original error
    }
  }
}

// 질문 레코드에서 문제/지문 이미지 키 분리 추출
function extractImageKeys(q: any): { problemKeys: string[], passageKeys: string[] } {
  let problemKeys: string[] = []
  let passageKeys: string[] = []
  if (q.image_keys) {
    try { const p = JSON.parse(q.image_keys); if (Array.isArray(p)) problemKeys = p.map((o: any) => o.key).filter(Boolean) } catch(e){}
  }
  if (problemKeys.length === 0 && q.image_key) problemKeys = [q.image_key]
  if (q.passage_image_keys) {
    try { const p = JSON.parse(q.passage_image_keys); if (Array.isArray(p)) passageKeys = p.map((o: any) => o.key).filter(Boolean) } catch(e){}
  }
  return { problemKeys, passageKeys }
}

// R2에서 키 배열을 읽어 {b64, mime} 배열로 반환 (raw 데이터)
async function readImagesFromR2(env: any, keys: string[]): Promise<{b64: string, mime: string}[]> {
  const images: {b64: string, mime: string}[] = []
  if (!env.R2 || keys.length === 0) return images
  for (const key of keys) {
    try {
      const obj = await env.R2.get(key)
      if (obj) {
        const buf = await obj.arrayBuffer()
        const bytes = new Uint8Array(buf)
        let binary = ''
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
        images.push({ b64: btoa(binary), mime: obj.httpMetadata?.contentType || 'image/jpeg' })
      }
    } catch (e) {}
  }
  return images
}

// 지문/문제 이미지를 라벨 구분하여 Gemini parts 배열 구성
async function buildLabeledImageParts(env: any, problemKeys: string[], passageKeys: string[], imageDataFallback: string | null = null): Promise<{type: 'image'|'text', b64?: string, mime?: string, content?: string}[]> {
  const passageImages = await readImagesFromR2(env, passageKeys)
  const problemImages = await readImagesFromR2(env, problemKeys)
  // Fallback: legacy single base64 image_data
  if (problemImages.length === 0 && imageDataFallback) {
    const match = imageDataFallback.match(/^data:([^;]+);base64,(.+)$/)
    if (match) problemImages.push({ b64: match[2], mime: match[1] })
  }
  const parts: {type: 'image'|'text', b64?: string, mime?: string, content?: string}[] = []
  if (passageImages.length > 0) {
    parts.push({ type: 'text', content: '=== [지문 이미지] 아래는 학생이 읽어야 하는 본문/지문입니다 ===' })
    for (const img of passageImages) parts.push({ type: 'image', b64: img.b64, mime: img.mime })
    parts.push({ type: 'text', content: '=== [문제 이미지] 아래는 위 지문을 바탕으로 풀어야 하는 문제입니다 ===' })
  }
  for (const img of problemImages) parts.push({ type: 'image', b64: img.b64, mime: img.mime })
  return parts
}

// R2에서 이미지 키 배열을 읽어 Gemini inlineData parts 배열로 반환
async function buildImagePartsFromR2(env: any, imageKeys: string[], imageDataFallback: string | null): Promise<any[]> {
  const parts: any[] = []
  if (env.R2 && imageKeys.length > 0) {
    for (const key of imageKeys) {
      try {
        const obj = await env.R2.get(key)
        if (obj) {
          const buf = await obj.arrayBuffer()
          const bytes = new Uint8Array(buf)
          let binary = ''
          for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
          const b64 = btoa(binary)
          const mime = obj.httpMetadata?.contentType || 'image/jpeg'
          parts.push({ inlineData: { mimeType: mime, data: b64 } })
        }
      } catch (e) {}
    }
  }
  // Fallback: single base64 image_data (legacy)
  if (parts.length === 0 && imageDataFallback) {
    const match = imageDataFallback.match(/^data:([^;]+);base64,(.+)$/)
    if (match) parts.push({ inlineData: { mimeType: match[1], data: match[2] } })
  }
  return parts
}

async function analyzeQuestionWithAI(db: any, env: any, questionId: number, subject: string, content: string, imageKey: string | null, imageData: string | null, imageKeysJson: string | null = null, externalId: string | null = null, passageImageKeysJson: string | null = null) {
  try {
    const geminiKey = env.GEMINI_API_KEY
    const claudeKey = env.ANTHROPIC_API_KEY
    if (!geminiKey && !claudeKey) {
      await db.prepare('UPDATE questions SET ai_analyzed = -1 WHERE id = ?').bind(questionId).run()
      return
    }

    // Build image parts — use all images if image_keys available, else fall back to single image_key
    let allKeys: string[] = []
    if (imageKeysJson) {
      try { const parsed = JSON.parse(imageKeysJson); if (Array.isArray(parsed)) allKeys = parsed.map((o: any) => o.key).filter(Boolean) } catch (e) {}
    }
    if (allKeys.length === 0 && imageKey) allKeys = [imageKey]

    // 지문 이미지 키 파싱
    let passageKeys: string[] = []
    if (passageImageKeysJson) {
      try { const parsed = JSON.parse(passageImageKeysJson); if (Array.isArray(parsed)) passageKeys = parsed.map((o: any) => o.key).filter(Boolean) } catch (e) {}
    }
    const hasPassage = passageKeys.length > 0

    // R2에서 이미지를 한 번만 읽어서 raw 데이터로 보관 (Gemini/Claude 양쪽에 사용)
    const rawImages: { b64: string, mime: string }[] = []
    if (env.R2 && allKeys.length > 0) {
      for (const key of allKeys) {
        try {
          const obj = await env.R2.get(key)
          if (obj) {
            const buf = await obj.arrayBuffer()
            const bytes = new Uint8Array(buf)
            let binary = ''
            for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
            rawImages.push({ b64: btoa(binary), mime: obj.httpMetadata?.contentType || 'image/jpeg' })
          }
        } catch (e) {}
      }
    }
    // Fallback: single base64 image_data (legacy)
    if (rawImages.length === 0 && imageData) {
      const match = imageData.match(/^data:([^;]+);base64,(.+)$/)
      if (match) rawImages.push({ b64: match[2], mime: match[1] })
    }

    // 지문 이미지 R2에서 로드
    const passageImages: { b64: string, mime: string }[] = await readImagesFromR2(env, passageKeys)

    // If no image available, mark as failed
    if (rawImages.length === 0 && passageImages.length === 0) {
      await db.prepare('UPDATE questions SET ai_analyzed = -1 WHERE id = ?').bind(questionId).run()
      return
    }

    const trimmedContent = content.trim().slice(0, 500)
    const promptText = '[과목]: ' + subject + (trimmedContent ? '\n[학생이 직접 입력한 질문]: ' + trimmedContent : '')

    // 과목별 추가 프롬프트
    let subjectPrompt = ''
    if (subject === '국어') {
      subjectPrompt = `\n\n[국어 문학 장르 분류]\nproblem_analysis.literature_genre에 문학 지문의 장르를 넣으세요.\n- "현대시": 현대 시/시조\n- "현대소설": 현대 소설/수필/희곡/시나리오\n- "고전시가": 고전 시가(시조,가사,향가,한시 등)\n- "고전소설": 고전 소설/산문/판소리계 소설\n- 비문학(독서/화법/작문/문법)이면 null`
    }
    if (hasPassage) {
      subjectPrompt += `\n\n[지문형 질문 분석 안내]\n"지문 이미지"와 "문제 이미지"가 분리되어 제공됩니다.\n1. 지문을 먼저 정독하고 핵심 내용/구조를 파악하세요.\n2. 문제가 지문의 어떤 부분을 묻고 있는지 연결하세요.\n3. problem_analysis.summary에 지문 요약 + 문제 요구사항을 모두 포함하세요.`
    }

    const fullPrompt = CURRICULUM_PROMPT + subjectPrompt
    let text = ''
    let usedModel = 'gemini-3-flash-preview'

    // === 1차: Gemini gemini-3-flash-preview ===
    // 지문 이미지가 있으면 라벨 구분하여 배치
    const geminiParts: {type: 'image'|'text', b64?: string, mime?: string, content?: string}[] = []
    if (hasPassage) {
      geminiParts.push({ type: 'text', content: '=== [지문 이미지] 아래는 학생이 읽어야 하는 본문/지문입니다 ===' })
      for (const img of passageImages) geminiParts.push({ type: 'image', b64: img.b64, mime: img.mime })
      geminiParts.push({ type: 'text', content: '=== [문제 이미지] 아래는 위 지문을 바탕으로 풀어야 하는 문제입니다 ===' })
    }
    for (const img of rawImages) geminiParts.push({ type: 'image', b64: img.b64, mime: img.mime })
    geminiParts.push({ type: 'text', content: fullPrompt + '\n\n' + promptText })
    const geminiResult = await callGemini(
      env.GEMINI_API_KEY || '', 'gemini-3-flash-preview',
      [{ parts: geminiParts.map(p => p.type === 'image' ? { inlineData: { mimeType: p.mime, data: p.b64 } } : { text: p.content }) }],
      { temperature: 0.3, maxOutputTokens: 8192, thinkingConfig: { thinkingBudget: 1024 } },
      { dedupKey: `analyze-q-${questionId}`, timeoutMs: 180000, proxy: proxyOpts(env, 'analyze', questionId, externalId) }
    )
    if (geminiResult.ok && geminiResult.text) {
      text = geminiResult.text
    } else {
      logErr('gemini/analyze', geminiResult.error, { questionId })

      // === 2차 폴백: OpenAI gpt-5.4-mini ===
      const openaiKey = env.OPENAI_API_KEY
      if (openaiKey) {
        usedModel = 'gpt-5.4-mini'
        const openaiContent: any[] = []
        if (hasPassage && passageImages.length > 0) {
          openaiContent.push({ type: 'text', text: '=== [지문 이미지] 아래는 학생이 읽어야 하는 본문/지문입니다 ===' })
          for (const img of passageImages) openaiContent.push({ type: 'image_url', image_url: { url: `data:${img.mime};base64,${img.b64}` } })
          openaiContent.push({ type: 'text', text: '=== [문제 이미지] 아래는 위 지문을 바탕으로 풀어야 하는 문제입니다 ===' })
        }
        for (const img of rawImages) openaiContent.push({ type: 'image_url', image_url: { url: `data:${img.mime};base64,${img.b64}` } })
        openaiContent.push({ type: 'text', text: promptText })
        const openaiResult = await callOpenAI(
          openaiKey, 'gpt-5.4-mini',
          fullPrompt,
          openaiContent,
          8192,
          { dedupKey: `analyze-q-fallback-${questionId}`, timeoutMs: 180000, proxy: proxyOpts(env, 'analyze-fallback', questionId, externalId) }
        )
        if (openaiResult.ok && openaiResult.text) {
          text = openaiResult.text
        } else {
          logErr('openai/analyze-fallback', openaiResult.error, { questionId })
        }
      }
    }

    if (!text) {
      await db.prepare('UPDATE questions SET ai_analyzed = -1 WHERE id = ?').bind(questionId).run()
      return
    }

    // Extract JSON: try code block first, then raw JSON
    let jsonStr = ''
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (codeBlockMatch) jsonStr = codeBlockMatch[1].trim()
    else { const m = text.match(/\{[\s\S]*\}/); if (m) jsonStr = m[0] }
    if (!jsonStr) {
      await db.prepare('UPDATE questions SET ai_analyzed = -1 WHERE id = ?').bind(questionId).run()
      return
    }
    
    const analysis = safeJsonParse(jsonStr)
    
    // === New spec: build coaching data JSON (coaching_questions + growth_interactions) ===
    const pa = analysis.problem_analysis || {}
    const qa = analysis.question_analysis || {}
    
    // Extract fields from new structure, with backward compat
    // Normalize difficulty to integer 1-5
    const rawDiff = pa.difficulty ?? analysis.ai_difficulty ?? null
    const diffMap: Record<string, number> = {'최하':1,'하':1,'중하':2,'중':3,'중상':4,'상':4,'최상':5}
    const difficulty = rawDiff !== null ? (parseInt(String(rawDiff).replace(/[^0-9]/g, '')) || diffMap[String(rawDiff)] || 3) : null
    const tags = Array.isArray(pa.tags) ? pa.tags.join(' ') : (analysis.ai_tags || null)
    const topicMain = pa.unit?.split('>')[0]?.trim() || analysis.ai_topic_main || null
    const topicSub = pa.unit?.split('>')?.slice(1)?.join('>').trim() || analysis.ai_topic_sub || null
    const description = pa.summary || analysis.ai_description || null
    const gradeLevel = pa.grade || analysis.ai_grade_level || null
    const estimatedTime = pa.estimated_time || analysis.ai_estimated_time || null
    const questionType = qa.question_type || analysis.question_type || null
    const questionTypeConf = qa.confidence || analysis.question_type_confidence || null
    const studentQ = analysis.student_question || qa.original_question || null
    const questionAnalysis = qa.interpretation || analysis.question_analysis || null
    const coachingComment = analysis.coaching_comment || null
    const literatureGenre = pa.literature_genre || null
    
    // Build unified coaching data JSON
    let coachingDataJson: string | null = null
    if (analysis.coaching_questions || analysis.growth_interactions) {
      const coachingData: any = {
        coaching_questions: (analysis.coaching_questions || []).map((cq: any) => ({
          type: cq.type || '', type_label: stripDollarSigns(cq.type_label) || '',
          growth_path: cq.growth_path || '', question: stripDollarSigns(cq.question) || '',
          why_important: stripDollarSigns(cq.why_important) || ''
        })),
        growth_interactions: (analysis.growth_interactions || []).map((gi: any) => ({
          target_coaching_index: gi.target_coaching_index ?? 0,
          target_type: gi.target_type || '', target_label: gi.target_label || '',
          selection_button: stripDollarSigns(gi.selection_button) || '',
          wrong_attempt: {
            setup: stripDollarSigns(gi.wrong_attempt?.setup) || '',
            question: gi.wrong_attempt?.question || '이거 괜찮을까요?',
            choices: gi.wrong_attempt?.choices || ['✅ 괜찮은 것 같아요', '❌ 뭔가 이상해요']
          },
          discovery_hint: {
            on_correct: stripDollarSigns(gi.discovery_hint?.on_correct) || '좋아요! 어디서 문제가 생기는지 골라보세요.',
            on_correct_choices: (gi.discovery_hint?.on_correct_choices || []).map((c: string) => stripDollarSigns(c) || c),
            on_wrong: stripDollarSigns(gi.discovery_hint?.on_wrong) || '',
            on_wrong_retry: gi.discovery_hint?.on_wrong_retry || '다시 생각해볼게요',
            on_stuck: stripDollarSigns(gi.discovery_hint?.on_stuck) || ''
          },
          thinking_bridge: {
            steps: (gi.thinking_bridge?.steps || []).map((s: string) => stripDollarSigns(s) || s),
            connection: stripDollarSigns(gi.thinking_bridge?.connection) || ''
          }
        })),
        selection_prompt: analysis.selection_prompt || '아래 중 더 궁금한 걸 골라보세요!',
        diagnosis: qa.diagnosis || null,
        upgrade_hint: qa.upgrade_hint || null,
      }
      coachingDataJson = JSON.stringify(coachingData)
    }

    // Determine difficulty level for hybrid routing
    const difficultyStr = difficulty || ''
    const difficultyNum = parseInt(String(difficultyStr).replace(/[^0-9]/g, '')) || 0
    const useGeminiOnly = difficultyNum < 4

    await db.prepare(`UPDATE questions SET
      ai_difficulty = ?, ai_tags = ?, ai_topic_main = ?, ai_topic_sub = ?,
      ai_description = ?, ai_grade_level = ?, ai_estimated_time = ?,
      question_type = ?, question_type_confidence = ?, student_question_text = ?,
      ai_question_analysis = ?, ai_coaching_comment = ?, ai_coaching_data = ?, ai_model = ?, ai_literature_genre = ?, ai_analyzed = 1
      WHERE id = ?`
    ).bind(
      stripDollarSigns(difficulty != null ? String(difficulty) : null), stripDollarSigns(tags),
      stripDollarSigns(topicMain), stripDollarSigns(topicSub),
      stripDollarSigns(description), stripDollarSigns(gradeLevel),
      estimatedTime, questionType, questionTypeConf,
      stripDollarSigns(studentQ), stripDollarSigns(questionAnalysis),
      stripDollarSigns(coachingComment), coachingDataJson,
      usedModel, literatureGenre, questionId
    ).run()

    // === HYBRID: ★4~5 → OpenAI enhances coaching ===
    if (!useGeminiOnly && env.OPENAI_API_KEY) {
      console.log(`Hybrid mode: ★${difficultyNum} detected — sending to OpenAI for enhanced coaching (question ${questionId})`)
      try {
        await enhanceCoachingWithOpenAI(db, env, questionId, {
          subject, content,
          difficulty: String(difficulty || ''),
          questionType: questionType || 'A-2',
          description: String(description || ''),
          studentQuestion: String(studentQ || '')
        }, rawImages.length > 0 ? rawImages[0].b64 : null, rawImages.length > 0 ? rawImages[0].mime : 'image/jpeg', externalId)
      } catch (claudeErr) {
        logErr('claude/enhance', claudeErr, { questionId })
      }
    }

  } catch (e) {
    logErr('ai/analysis', e, { questionId })
    try {
      await db.prepare('UPDATE questions SET ai_analyzed = -1 WHERE id = ?').bind(questionId).run()
    } catch (e2) {}
  }
}

// 프록시가 저장해둔 AI 응답 원문을 복구 조회해서 parseAndSave로 재시도한다.
// 프록시 미설정 환경(로컬 등)에선 자동 skip.
async function recoverFromProxy(
  env: any, questionId: number, task: string, model: string,
  parseAndSave: (text: string) => Promise<boolean>
): Promise<boolean> {
  if (!env?.AI_PROXY_URL || !env?.AI_PROXY_SECRET) return false
  const delayMs = Number(env.RECOVER_DELAY_MS) || 2000
  await new Promise(r => setTimeout(r, delayMs))
  try {
    const url = `${env.AI_PROXY_URL}/result?question_id=${questionId}&task=${encodeURIComponent(task)}&model=${encodeURIComponent(model)}`
    const r = await fetch(url, { headers: { 'Authorization': `Bearer ${env.AI_PROXY_SECRET}` } })
    if (!r.ok) return false
    const data: any = await r.json().catch(() => null)
    if (!data?.found || !data.response_text) return false
    const saved = await parseAndSave(data.response_text)
    if (saved) console.log(`Recovered solution from proxy: q=${questionId} task=${task} model=${data.model} latency=${data.latency_ms}ms called_at=${data.called_at}`)
    return saved
  } catch (e) {
    logErr('proxy/recovery', e, { questionId, task, model })
    return false
  }
}

// === Solution 생성: gemini-3.1-pro-preview → 실패시 gpt-5.4 폴백 ===
async function generateSolutionWithPro(
  db: any, env: any, questionId: number, subject: string, content: string,
  imageParts: any[], externalId: string | null = null
) {
  const solutionPrompt = `You are an expert in the Korean high-school curriculum. Solve the problem in the image completely. This solution is an internal reference for an AI tutor — never shown to the student directly. The tutor already handles coaching tone and student context, so focus only on the objective solution and common mistakes.

[Subject]: ${subject}
[Student question]: ${content.slice(0, 500)}

Respond ONLY with the JSON below:
{
  "solution_steps": [{"step": 1, "action": "이 단계에서 하는 일과 구체적인 계산 과정 (LaTeX 수식 포함)"}],
  "final_answer": "최종 정답 — 객관식이면 번호와 내용 모두 기재 (예: ④ C-A-B)",
  "self_verification": {
    "back_substitution": "최종 답을 문제에 다시 대입하여 처음부터 끝까지 검증한 결과",
    "eliminated_wrong_answer": "유력 오답 1~2개를 같은 방식으로 대입·검증하고 탈락 사유를 명시",
    "evidence_check": "풀이에서 사용한 핵심 근거가 원문/조건에 실제로 존재하는지 대조한 결과"
  },
  "common_mistakes": ["이 문제에서 학생들이 자주 하는 구체적인 실수 포인트"]
}

Rules:
- All JSON values MUST be written in Korean
- If the subject involves math or formulas, use LaTeX for all expressions. Inline: $x^2$, display: $$\\\\int_0^1 f(x)dx$$
- You MUST solve the problem completely and derive the final answer
- 객관식 문항의 final_answer에는 반드시 보기 번호(①②③④⑤)와 해당 내용을 함께 기재하라
- solution_steps action: cover every point where a student could get stuck
- common_mistakes: list each mistake as an independent, specific item (not generic advice)
- ★ Self-verification (필수): 최종 답을 확정하기 전에 반드시 아래 검증을 수행하고, 결과를 self_verification에 기재하라.
  1. 역대입 검증: 최종 답을 문제에 다시 대입하여, 처음부터 끝까지 모든 조건을 만족하는지 확인하라.
  2. 오답 소거: 가장 유력한 오답 1~2개에 대해서도 같은 방식으로 대입·검증하고, 왜 탈락하는지 설명하라. 설명할 수 없으면 정답 판단을 재검토하라.
  3. 근거 추적: 풀이에서 사용한 핵심 근거가 원문·조건에 실제로 존재하는지 원문 대조하라.
- ★ 검증 결과 모순이 발견되면 답을 수정한 뒤 다시 검증하라. 검증을 통과한 답만 final_answer에 기재하라.`

  async function parseAndSave(text: string): Promise<boolean> {
    let jsonStr = ''
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (codeBlockMatch) jsonStr = codeBlockMatch[1].trim()
    else { const m = text.match(/\{[\s\S]*\}/); if (m) jsonStr = m[0] }
    if (!jsonStr) return false
    let solution: any
    try {
      solution = safeJsonParse(jsonStr)
    } catch (e) {
      logErr('parseAndSave/json', e, { questionId, jsonPreview: jsonStr.slice(0, 300) })
      return false
    }
    await db.prepare('UPDATE questions SET ai_solution = ?, solution_stat = 1 WHERE id = ?')
      .bind(JSON.stringify(solution), questionId).run()

    return true
  }

  // === Phase 1 라우팅: GPT-5.4 primary, Claude → Gemini Pro 폴백 ===
  // 전 과목 동일. subjectModelMap/primaryModel 변수는 현재 로직에서 사용하지 않음 (폴백 체인 아래).
  // 향후 Phase 2+ 에서 AI Tutor 전환 완료되면 재평가.
  const sysMsg = 'You are a Korean high-school curriculum expert. Solve problems completely and return JSON only.'

  // Helper: OpenAI 호출
  async function tryOpenAI(tag: string): Promise<boolean> {
    const openaiKey = env.OPENAI_API_KEY
    if (!openaiKey) return false
    const openaiContent: any[] = imageParts.map((p: any) => p.inlineData ? { type: 'image_url', image_url: { url: `data:${p.inlineData.mimeType};base64,${p.inlineData.data}` } } : p.text ? { type: 'text', text: p.text } : null).filter(Boolean)
    openaiContent.push({ type: 'text', text: solutionPrompt })
    const r = await callOpenAI(openaiKey, 'gpt-5.4', sysMsg, openaiContent, 12000, { dedupKey: `solution-${tag}-${questionId}`, timeoutMs: 300000, proxy: proxyOpts(env, `solution-${tag}`, questionId, externalId) })
    if (r.ok && r.text && await parseAndSave(r.text)) { console.log(`OpenAI(${tag}) solution for question ${questionId}`); return true }
    if (r.ok) logErr(`openai/${tag}-no-json`, 'No JSON', { questionId, textPreview: r.text?.slice(0, 300) }); else logErr(`openai/${tag}`, r.error, { questionId })
    if (await recoverFromProxy(env, questionId, `solution-${tag}`, 'gpt-5.4', parseAndSave)) return true
    return false
  }
  // Helper: Gemini 호출
  async function tryGemini(tag: string): Promise<boolean> {
    const geminiContents = [{ parts: [...imageParts.map((p: any) => p.inlineData ? { inlineData: p.inlineData } : p.text ? { text: p.text } : null).filter(Boolean), { text: solutionPrompt }] }]
    const r = await callGemini(env.GEMINI_API_KEY || '', 'gemini-3.1-pro-preview', geminiContents, { temperature: 0.3, maxOutputTokens: 32000, thinkingConfig: { thinkingBudget: 8192 } }, { dedupKey: `solution-${tag}-${questionId}`, timeoutMs: 300000, proxy: proxyOpts(env, `solution-${tag}`, questionId, externalId) })
    if (r.ok && r.text && await parseAndSave(r.text)) { console.log(`Gemini(${tag}) solution for question ${questionId}`); return true }
    if (r.ok) logErr(`gemini/${tag}-no-json`, 'No JSON', { questionId, textPreview: r.text?.slice(0, 300) }); else logErr(`gemini/${tag}`, r.error, { questionId })
    if (await recoverFromProxy(env, questionId, `solution-${tag}`, 'gemini-3.1-pro-preview', parseAndSave)) return true
    return false
  }
  // Helper: Claude 호출
  async function tryClaude(tag: string): Promise<boolean> {
    const claudeKey = env.ANTHROPIC_API_KEY
    if (!claudeKey) return false
    const claudeMessages = [{ role: 'user' as const, content: [...imageParts.map((p: any) => p.inlineData ? { type: 'image' as const, source: { type: 'base64' as const, media_type: p.inlineData.mimeType, data: p.inlineData.data } } : p.text ? { type: 'text' as const, text: p.text } : null).filter(Boolean), { type: 'text' as const, text: solutionPrompt }] }]
    const r = await callClaude(claudeKey, 'claude-opus-4-6', sysMsg, claudeMessages, 16000, { dedupKey: `solution-${tag}-${questionId}`, timeoutMs: 300000, proxy: proxyOpts(env, `solution-${tag}`, questionId, externalId) })
    if (r.ok && r.text && await parseAndSave(r.text)) { console.log(`Claude(${tag}) solution for question ${questionId}`); return true }
    if (r.ok) logErr(`claude/${tag}-no-json`, 'No JSON', { questionId, textPreview: r.text?.slice(0, 300) }); else logErr(`claude/${tag}`, r.error, { questionId })
    if (await recoverFromProxy(env, questionId, `solution-${tag}`, 'claude-opus-4-6', parseAndSave)) return true
    return false
  }

  // Rollback from Phase 1: Gemini Pro 단일 모델, 폴백 없음.
  // 근거: GPT-5.4가 수능 킬러 수학에서 "hedge-then-commit"(풀이 도중 모순 인정하고도 답 확정)
  // 패턴으로 확신 있게 틀린 답을 반환하는 이슈 발견. 폴백 체인은 기술적 실패(timeout/HTTP/파싱)만
  // 잡고 정확도 오류는 못 잡아서 오히려 리스크 증폭. 정확도 critical한 one-shot 해설 생성에서는
  // "실패 → 학생 재시도"가 "확신 있게 틀린 답 전달"보다 안전함.
  if (await tryGemini('primary')) return

  // 전부 실패
  try {
    await db.prepare('UPDATE questions SET solution_stat = 2 WHERE id = ?').bind(questionId).run()
  } catch (e2) {}
}

// === Claude Sonnet 4.5 — 고난도 코칭 전용 (★4~5) ===
const CLAUDE_COACHING_PROMPT = `당신은 한국 고등학교 수학/과학 교육 전문가이자 학생 질문 코칭 전문가입니다.
Gemini가 이미 문제 분석(난이도, 태그, 유형 분류 등)을 완료했습니다.
당신의 역할은 **코칭 품질을 한 단계 높이는 것**입니다.

★★★ 수식 규칙: 모든 수식은 LaTeX로 작성. 인라인: $x^2$, 독립: $$\\int_0^1 f(x)dx$$
★★★ 질문 톤: 학생 혼잣말 스타일만 ("~거지?", "~건가?"). 선생님 질문 금지!

[질문 유형 — 2축 9단계]
호기심축: A-1(뭐지?), A-2(어떻게?), B-1(왜?), B-2(만약에?), C-1(뭐가 더 나아?), C-2(그러면?)
성찰축: R-1(어디서 틀렸지?), R-2(왜 틀렸지?), R-3(다음엔 어떻게?)

[성장 경로]
호기심축: A-1→A-2 / A-2→B-1,B-2 / B-1→B-2,C-1 / B-2→C-1,C-2 / C-1→C-2
성찰축: R-1→R-2 / R-2→R-3
축 교차: A-2→R-1 / B-1→R-2 / R-1→B-1 / R-2→B-2

반드시 아래 JSON 형식으로만 응답하세요:
{
  "coaching_comment": "격려 + 구체적 성장 방향 (2~3문장, 친근한 톤)",
  "coaching_questions": [
    {"type": "B-2", "type_label": "만약에?", "growth_path": "현재유형 → 목표유형", "question": "학생 혼잣말 스타일 질문", "why_important": "1문장 설명"},
    {"type": "C-1", "type_label": "뭐가 더 나아?", "growth_path": "현재유형 → 목표유형", "question": "학생 혼잣말 스타일 질문", "why_important": "1문장 설명"}
  ],
  "growth_interactions": [
    {
      "target_coaching_index": 0,
      "target_type": "B-2",
      "target_label": "만약에?",
      "selection_button": "🔀 학생이 이해할 수 있는 선택 버튼 텍스트",
      "wrong_attempt": {
        "setup": "구체적 숫자/조건을 사용한 틀린 시도 (2~3문장)",
        "question": "이거 괜찮을까요?",
        "choices": ["✅ 괜찮은 것 같아요", "❌ 뭔가 이상해요"]
      },
      "discovery_hint": {
        "on_correct": "좋아요! 어디서 문제가 생기는지 골라보세요.",
        "on_correct_choices": ["오류 선택지1", "오류 선택지2", "오류 선택지3", "잘 모르겠어요"],
        "on_wrong": "정말요? 🧐 ___을 확인해보세요!",
        "on_wrong_retry": "다시 생각해볼게요",
        "on_stuck": "힌트: 구체적 유도 힌트"
      },
      "thinking_bridge": {
        "steps": ["무엇을 시도했고", "무엇을 발견했고", "어떤 질문이 떠올랐는지"],
        "connection": "이게 바로 🔀 만약에? 질문이에요! 설명."
      }
    }
  ],
  "selection_prompt": "아래 중 더 궁금한 걸 골라보세요!"
}

[핵심 규칙]
- coaching_questions: 2~3개, 각각 다른 유형
- growth_interactions: coaching_questions와 1:1 대응
- wrong_attempt: 구체적 숫자 사용, 50% 발견 난이도
- on_correct_choices: 정답1+오답2+잘모르겠어요 = 4개
- thinking_bridge.steps: 반드시 3개
- 답을 직접 알려주지 말 것
- 인터랙션 간 중복 금지`

async function enhanceCoachingWithOpenAI(
  db: any, env: any, questionId: number,
  analysis: { subject: string, content: string, difficulty: string, questionType: string, description: string, studentQuestion: string },
  imageBase64: string | null, imageMime: string, externalId: string | null = null
) {
  try {
    const openaiKey = env.OPENAI_API_KEY
    if (!openaiKey) {
      console.log('No OpenAI key — skipping coaching for question', questionId)
      return false
    }

    // Build messages for OpenAI
    const contextText = `[분석 결과]
과목: ${analysis.subject}
난이도: ${analysis.difficulty}
질문 유형: ${analysis.questionType}
문제 설명: ${analysis.description}
학생 질문: ${analysis.studentQuestion}
질문 텍스트: ${analysis.content?.slice(0, 500) || ''}

위 분석 결과를 기반으로, 이 고난도 문제에 대해 더 깊이 있는 코칭을 제공해주세요.
현재 질문 유형(${analysis.questionType})에 맞는 업그레이드 경로를 따라 next_questions를 만들어주세요.`

    const openaiContent: any[] = []
    if (imageBase64) {
      openaiContent.push({
        type: 'image_url',
        image_url: { url: `data:${imageMime};base64,${imageBase64}` }
      })
    }
    openaiContent.push({ type: 'text', text: contextText })

    // Use callOpenAI wrapper with dedup + timeout + retry
    const openaiResult = await callOpenAI(
      openaiKey, 'gpt-5.4', CLAUDE_COACHING_PROMPT,
      openaiContent, 4096,
      { dedupKey: `openai-coach-${questionId}`, timeoutMs: 55000, proxy: proxyOpts(env, 'coaching', questionId, externalId) }
    )
    if (!openaiResult.ok || !openaiResult.text) {
      logErr('openai/coaching', openaiResult.error, { questionId })
      return false
    }

    // Extract JSON
    let jsonStr = ''
    const codeBlockMatch = openaiResult.text.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (codeBlockMatch) jsonStr = codeBlockMatch[1].trim()
    else { const m = openaiResult.text.match(/\{[\s\S]*\}/); if (m) jsonStr = m[0] }
    if (!jsonStr) return false

    const coaching = safeJsonParse(jsonStr)

    // Build unified coaching data JSON from OpenAI response
    let openaiCoachingData: string | null = null
    if (coaching.coaching_questions || coaching.growth_interactions) {
      openaiCoachingData = JSON.stringify({
        coaching_questions: (coaching.coaching_questions || []).map((cq: any) => ({
          type: cq.type || '', type_label: stripDollarSigns(cq.type_label) || '',
          growth_path: cq.growth_path || '', question: stripDollarSigns(cq.question) || '',
          why_important: stripDollarSigns(cq.why_important) || ''
        })),
        growth_interactions: (coaching.growth_interactions || []).map((gi: any) => ({
          target_coaching_index: gi.target_coaching_index ?? 0,
          target_type: gi.target_type || '', target_label: gi.target_label || '',
          selection_button: stripDollarSigns(gi.selection_button) || '',
          wrong_attempt: {
            setup: stripDollarSigns(gi.wrong_attempt?.setup) || '',
            question: gi.wrong_attempt?.question || '이거 괜찮을까요?',
            choices: gi.wrong_attempt?.choices || ['✅ 괜찮은 것 같아요', '❌ 뭔가 이상해요']
          },
          discovery_hint: {
            on_correct: stripDollarSigns(gi.discovery_hint?.on_correct) || '',
            on_correct_choices: (gi.discovery_hint?.on_correct_choices || []).map((c: string) => stripDollarSigns(c) || c),
            on_wrong: stripDollarSigns(gi.discovery_hint?.on_wrong) || '',
            on_wrong_retry: gi.discovery_hint?.on_wrong_retry || '다시 생각해볼게요',
            on_stuck: stripDollarSigns(gi.discovery_hint?.on_stuck) || ''
          },
          thinking_bridge: {
            steps: (gi.thinking_bridge?.steps || []).map((s: string) => stripDollarSigns(s) || s),
            connection: stripDollarSigns(gi.thinking_bridge?.connection) || ''
          }
        })),
        selection_prompt: coaching.selection_prompt || '아래 중 더 궁금한 걸 골라보세요!'
      })
    }

    // Update only coaching fields (keep analysis/difficulty/tags intact)
    await db.prepare(`UPDATE questions SET
      ai_coaching_comment = ?, ai_coaching_data = ?, ai_model = ?
      WHERE id = ?`
    ).bind(
      stripDollarSigns(coaching.coaching_comment) || null,
      openaiCoachingData,
      'openai',
      questionId
    ).run()

    console.log('OpenAI coaching enhanced for question', questionId)
    return true
  } catch (e) {
    logErr('openai/coaching', e, { questionId })
    return false
  }
}

// 특정 모델로 해설 테스트 (DB 저장 안 함, 응답만 반환)
app.post('/api/questions/:id/test-solution', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const model = c.req.query('model') || 'openai'
  const q = await db.prepare('SELECT q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys, q.passage_image_keys, u.external_id FROM questions q JOIN users u ON q.user_id = u.id WHERE q.id = ?').bind(id).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)
  const { problemKeys, passageKeys } = extractImageKeys(q)
  let imageParts: any[]
  if (passageKeys.length > 0) {
    const labeled = await buildLabeledImageParts(c.env, problemKeys, passageKeys, q.image_data)
    imageParts = labeled.map(p => p.type === 'image' ? { inlineData: { mimeType: p.mime, data: p.b64 } } : { text: p.content })
  } else {
    imageParts = await buildImagePartsFromR2(c.env, problemKeys, q.image_data)
  }
  if (imageParts.length === 0) return c.json({ error: 'No image found' }, 400)
  const subject = q.subject || '기타'
  const content = q.content || ''
  const solutionPrompt = `You are an expert in the Korean high-school curriculum. Solve the problem in the image completely. This solution is an internal reference for an AI tutor — never shown to the student directly. The tutor already handles coaching tone and student context, so focus only on the objective solution and common mistakes.

[Subject]: ${subject}
[Student question]: ${content.slice(0, 500)}

Respond ONLY with the JSON below:
{
  "solution_steps": [{"step": 1, "action": "이 단계에서 하는 일과 구체적인 계산 과정 (LaTeX 수식 포함)"}],
  "final_answer": "최종 정답 — 객관식이면 번호와 내용 모두 기재 (예: ④ C-A-B)",
  "self_verification": {
    "back_substitution": "최종 답을 문제에 다시 대입하여 처음부터 끝까지 검증한 결과",
    "eliminated_wrong_answer": "유력 오답 1~2개를 같은 방식으로 대입·검증하고 탈락 사유를 명시",
    "evidence_check": "풀이에서 사용한 핵심 근거가 원문/조건에 실제로 존재하는지 대조한 결과"
  },
  "common_mistakes": ["이 문제에서 학생들이 자주 하는 구체적인 실수 포인트"]
}

Rules:
- All JSON values MUST be written in Korean
- If the subject involves math or formulas, use LaTeX for all expressions. Inline: $x^2$, display: $$\\\\int_0^1 f(x)dx$$
- You MUST solve the problem completely and derive the final answer
- 객관식 문항의 final_answer에는 반드시 보기 번호(①②③④⑤)와 해당 내용을 함께 기재하라
- solution_steps action: cover every point where a student could get stuck
- common_mistakes: list each mistake as an independent, specific item (not generic advice)
- ★ Self-verification (필수): 최종 답을 확정하기 전에 반드시 아래 검증을 수행하고, 결과를 self_verification에 기재하라.
  1. 역대입 검증: 최종 답을 문제에 다시 대입하여, 처음부터 끝까지 모든 조건을 만족하는지 확인하라.
  2. 오답 소거: 가장 유력한 오답 1~2개에 대해서도 같은 방식으로 대입·검증하고, 왜 탈락하는지 설명하라. 설명할 수 없으면 정답 판단을 재검토하라.
  3. 근거 추적: 풀이에서 사용한 핵심 근거가 원문·조건에 실제로 존재하는지 원문 대조하라.
- ★ 검증 결과 모순이 발견되면 답을 수정한 뒤 다시 검증하라. 검증을 통과한 답만 final_answer에 기재하라.`
  const externalId = q.external_id || null
  let result: any = null
  if (model === 'openai') {
    const openaiKey = c.env.OPENAI_API_KEY
    if (!openaiKey) return c.json({ error: 'OPENAI_API_KEY not set' }, 500)
    const openaiContent: any[] = imageParts.map((p: any) => p.inlineData ? { type: 'image_url', image_url: { url: `data:${p.inlineData.mimeType};base64,${p.inlineData.data}` } } : p.text ? { type: 'text', text: p.text } : null).filter(Boolean)
    openaiContent.push({ type: 'text', text: solutionPrompt })
    result = await callOpenAI(openaiKey, 'gpt-5.4', 'You are a Korean high-school curriculum expert. Solve problems completely and return JSON only.', openaiContent, 12000, { timeoutMs: 300000, proxy: proxyOpts(c.env, 'test-solution', Number(id), externalId) })
  } else if (model === 'gemini') {
    const geminiContents = [{ parts: [...imageParts.map((p: any) => p.inlineData ? { inlineData: p.inlineData } : p.text ? { text: p.text } : null).filter(Boolean), { text: solutionPrompt }] }]
    result = await callGemini(c.env.GEMINI_API_KEY || '', 'gemini-3.1-pro-preview', geminiContents, { temperature: 0.3, maxOutputTokens: 16000 }, { timeoutMs: 300000, proxy: proxyOpts(c.env, 'test-solution', Number(id), externalId) })
  } else if (model === 'claude') {
    const claudeKey = c.env.ANTHROPIC_API_KEY
    if (!claudeKey) return c.json({ error: 'ANTHROPIC_API_KEY not set' }, 500)
    const claudeMessages = [{ role: 'user' as const, content: [...imageParts.map((p: any) => p.inlineData ? { type: 'image' as const, source: { type: 'base64' as const, media_type: p.inlineData.mimeType, data: p.inlineData.data } } : p.text ? { type: 'text' as const, text: p.text } : null).filter(Boolean), { type: 'text' as const, text: solutionPrompt }] }]
    result = await callClaude(claudeKey, 'claude-opus-4-6', 'You are a Korean high-school curriculum expert. Solve problems completely and return JSON only.', claudeMessages, 16000, { timeoutMs: 300000, proxy: proxyOpts(c.env, 'test-solution', Number(id), externalId) })
  } else {
    return c.json({ error: 'Invalid model. Use: openai, gemini, claude' }, 400)
  }
  if (!result?.ok) return c.json({ error: result?.error || 'Model call failed', model }, 500)
  let parsed = null
  try {
    const codeBlock = result.text?.match(/```(?:json)?\s*([\s\S]*?)```/)
    const jsonStr = codeBlock ? codeBlock[1].trim() : result.text?.match(/\{[\s\S]*\}/)?.[0] || ''
    parsed = JSON.parse(jsonStr)
  } catch (e) {}
  return c.json({ model, raw_text: result.text?.slice(0, 200), parsed })
})

// Pro 해설 단독 생성 (테스트용)
app.post('/api/questions/:id/generate-solution', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const q = await db.prepare('SELECT q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys, q.passage_image_keys, q.solution_stat, u.external_id FROM questions q JOIN users u ON q.user_id = u.id WHERE q.id = ?').bind(id).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)

  // 이미 해설 생성 완료(1) 또는 진행중이면 스킵
  const force = c.req.query('force') === 'true'
  if (q.solution_stat === 1 && !force) return c.json({ solution_stat: 1, skipped: true })

  const { problemKeys, passageKeys } = extractImageKeys(q)

  // 지문 이미지가 있으면 라벨 구분 파트 생성, 없으면 기존 방식
  let imageParts: any[]
  if (passageKeys.length > 0) {
    const labeled = await buildLabeledImageParts(c.env, problemKeys, passageKeys, q.image_data)
    imageParts = labeled.map(p => p.type === 'image' ? { inlineData: { mimeType: p.mime, data: p.b64 } } : { text: p.content })
  } else {
    imageParts = await buildImagePartsFromR2(c.env, problemKeys, q.image_data)
  }
  if (imageParts.length === 0) return c.json({ error: 'No image found' }, 400)

  // 원자적 락: stat=0(신규) 또는 force와 함께 stat=2(과거 실패) → stat=3(진행중)으로 전이.
  // 이미 누가 처리 중(stat=3)이거나 완료(stat=1)면 changes=0 → 중복 Gemini 호출 차단.
  const lockSql = force
    ? 'UPDATE questions SET solution_stat = 3 WHERE id = ? AND (solution_stat = 0 OR solution_stat = 2)'
    : 'UPDATE questions SET solution_stat = 3 WHERE id = ? AND solution_stat = 0'
  const lockResult = await db.prepare(lockSql).bind(id).run()
  if (!lockResult.meta?.changes) {
    const curr = await db.prepare('SELECT solution_stat FROM questions WHERE id = ?').bind(id).first() as any
    return c.json({ solution_stat: curr?.solution_stat ?? 0, skipped: true, reason: 'already-processing-or-done' })
  }

  // 락 확보됨 — 배경 처리. 학생 새로고침/이탈과 무관하게 Gemini 호출 끝까지 완주.
  // 성공 시 parseAndSave가 stat=3 → 1로 덮어씀. 실패 시 아래 catch + 내부 fallback이 stat=2로.
  c.executionCtx.waitUntil(
    generateSolutionWithPro(db, c.env, Number(id), q.subject, q.content, imageParts, q.external_id || null)
      .catch(async (e: any) => {
        logErr('generate-solution/bg', e, { questionId: Number(id) })
        // 예외로 Gemini 내부 fallback까지 못 가는 경우 락 해제(stat=3 → 2)
        try { await db.prepare('UPDATE questions SET solution_stat = 2 WHERE id = ? AND solution_stat = 3').bind(id).run() } catch {}
      })
  )

  return c.json({ accepted: true, solution_stat: 3, processing: true })
})

// AI 프록시 webhook: 프록시가 Gemini 성공 응답 받으면 여기로 POST → D1 직접 저장
// 프록시팀 합의 스펙:
//   Auth: Authorization: Bearer ${AI_CALLBACK_SECRET}
//   Body: { question_id, task, model, provider, response_text, called_at, latency_ms, success }
//   Retry: 프록시가 3회 지수 백오프. 우리는 5xx 반환 시 재시도 유도, 4xx/200 반환 시 재시도 중단.
//   Whitelist: 현재 task="solution-primary"만 처리. 그 외는 200 skipped로 조용히 승인.
//   Idempotent: solution_stat=1이면 skip. 같은 요청 재전송 안전.
// env AI_CALLBACK_SECRET이 설정되지 않으면 모든 요청 401 — 배포만 먼저 하고 secret 뒤에 세팅 가능.
app.post('/api/ai-callback', async (c) => {
  const db = c.env.DB

  // 1. Auth
  const secret = c.env.AI_CALLBACK_SECRET
  if (!secret) return c.json({ error: 'Webhook not configured' }, 401)
  const auth = c.req.header('Authorization') || ''
  if (auth !== `Bearer ${secret}`) return c.json({ error: 'Unauthorized' }, 401)

  // 2. Payload
  let payload: any
  try { payload = await c.req.json() } catch { return c.json({ error: 'Invalid JSON body' }, 400) }
  const { question_id, task, model, response_text, success } = payload
  if (!question_id || !task || success !== true || !response_text) {
    return c.json({ error: 'Missing required fields: question_id, task, response_text, success=true' }, 400)
  }

  // 3. Whitelist
  if (task !== 'solution-primary') {
    return c.json({ ok: true, skipped: true, reason: 'task-not-in-whitelist', task })
  }

  // 4. Idempotency check
  const curr = await db.prepare('SELECT solution_stat FROM questions WHERE id = ?').bind(question_id).first() as any
  if (!curr) return c.json({ error: 'Question not found' }, 404)
  if (curr.solution_stat === 1) {
    return c.json({ ok: true, skipped: true, reason: 'already-saved', question_id })
  }

  // 5. Parse & save — parseAndSave 로직 인라인 재구현 (generateSolutionWithPro 클로저 밖이라)
  try {
    const m = response_text.match(/```(?:json)?\s*([\s\S]*?)```/)?.[1]?.trim() || response_text.match(/\{[\s\S]*\}/)?.[0]
    if (!m) {
      logErr('ai-callback/no-json', 'No JSON in response_text', { questionId: question_id, textPreview: response_text.slice(0, 300) })
      // 명시적 실패 마킹 (stat=1은 건드리지 않음)
      try { await db.prepare('UPDATE questions SET solution_stat = 2 WHERE id = ? AND solution_stat != 1').bind(question_id).run() } catch {}
      return c.json({ ok: false, reason: 'no-json-match', question_id }, 200)   // 200이므로 proxy retry 안 함
    }
    const solution = safeJsonParse(m)
    await db.prepare('UPDATE questions SET ai_solution = ?, solution_stat = 1 WHERE id = ?')
      .bind(JSON.stringify(solution), question_id).run()
    console.log(`ai-callback: q=${question_id} task=${task} model=${model} latency=${payload.latency_ms}ms saved`)
    return c.json({ ok: true, saved: true, question_id })
  } catch (e: any) {
    logErr('ai-callback/parse-or-db', e, { questionId: question_id })
    // DB 일시 에러 가능성 → 5xx 반환해 proxy retry 유도
    return c.json({ error: 'Parse or DB error — retry please' }, 500)
  }
})

// Manual AI analysis trigger (for existing questions) — with debug info
app.post('/api/questions/:id/analyze', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const openaiKey = c.env.OPENAI_API_KEY
  if (!openaiKey) return c.json({ error: 'OpenAI API key not configured' }, 500)

  const q = await db.prepare('SELECT q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys, q.passage_image_keys, u.external_id FROM questions q JOIN users u ON q.user_id = u.id WHERE q.id = ?').bind(id).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)

  // Inline debug analysis
  try {
    const { problemKeys, passageKeys } = extractImageKeys(q)

    let debugInfo: any = { imageKey: q.image_key, imageKeysCount: problemKeys.length, passageKeysCount: passageKeys.length, hasImageData: !!q.image_data }

    let imageParts: any[]
    if (passageKeys.length > 0) {
      const labeled = await buildLabeledImageParts(c.env, problemKeys, passageKeys, q.image_data)
      imageParts = labeled.map(p => p.type === 'image' ? { inlineData: { mimeType: p.mime, data: p.b64 } } : { text: p.content })
    } else {
      imageParts = await buildImagePartsFromR2(c.env, problemKeys, q.image_data)
    }
    debugInfo.imagePartsCount = imageParts.length

    // Convert Gemini imageParts to OpenAI format
    const openaiContent: any[] = imageParts.map((p: any) => {
      if (p.inlineData) {
        return { type: 'image_url', image_url: { url: `data:${p.inlineData.mimeType};base64,${p.inlineData.data}` } }
      }
      if (p.text) return { type: 'text', text: p.text }
      return null
    }).filter(Boolean)
    openaiContent.push({ type: 'text', text: '[과목]: ' + q.subject + '\n[질문 텍스트]: ' + (q.content || '').slice(0, 500) })
    debugInfo.partsCount = openaiContent.length
    debugInfo.hasImage = imageParts.length > 0

    const openaiResult = await callOpenAI(
      openaiKey, 'gpt-5.4',
      CURRICULUM_PROMPT,
      openaiContent,
      8192,
      { dedupKey: `re-analyze-${id}`, timeoutMs: 55000, proxy: proxyOpts(c.env, 're-analyze', Number(id), q.external_id || null) }
    )

    if (!openaiResult.ok || !openaiResult.text) {
      debugInfo.openaiError = openaiResult.error
      return c.json({ success: false, debug: debugInfo })
    }
    let text = openaiResult.text
    debugInfo.rawResponse = text.slice(0, 2000)
    
    // Extract JSON: try code block first, then raw JSON
    let jsonStr = ''
    const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (codeBlockMatch) jsonStr = codeBlockMatch[1].trim()
    else { const m = text.match(/\{[\s\S]*\}/); if (m) jsonStr = m[0] }
    if (!jsonStr) {
      debugInfo.parseError = 'No JSON found in response'
      return c.json({ success: false, debug: debugInfo })
    }
    debugInfo.extractedJson = jsonStr.slice(0, 500)
    
    const analysis = safeJsonParse(jsonStr)
    debugInfo.parsedAnalysis = analysis
    
    // Build coaching data JSON (new spec)
    const pa2 = analysis.problem_analysis || {}
    const qa2 = analysis.question_analysis || {}
    let coachingData2: string | null = null
    if (analysis.coaching_questions || analysis.growth_interactions) {
      coachingData2 = JSON.stringify({
        coaching_questions: (analysis.coaching_questions || []).map((cq: any) => ({
          type: cq.type || '', type_label: stripDollarSigns(cq.type_label) || '',
          growth_path: cq.growth_path || '', question: stripDollarSigns(cq.question) || '',
          why_important: stripDollarSigns(cq.why_important) || ''
        })),
        growth_interactions: (analysis.growth_interactions || []).map((gi: any) => ({
          target_coaching_index: gi.target_coaching_index ?? 0,
          target_type: gi.target_type || '', target_label: gi.target_label || '',
          selection_button: stripDollarSigns(gi.selection_button) || '',
          wrong_attempt: { setup: stripDollarSigns(gi.wrong_attempt?.setup) || '', question: gi.wrong_attempt?.question || '이거 괜찮을까요?', choices: gi.wrong_attempt?.choices || ['✅ 괜찮은 것 같아요', '❌ 뭔가 이상해요'] },
          discovery_hint: { on_correct: stripDollarSigns(gi.discovery_hint?.on_correct) || '', on_correct_choices: (gi.discovery_hint?.on_correct_choices || []).map((c: string) => stripDollarSigns(c) || c), on_wrong: stripDollarSigns(gi.discovery_hint?.on_wrong) || '', on_wrong_retry: gi.discovery_hint?.on_wrong_retry || '다시 생각해볼게요', on_stuck: stripDollarSigns(gi.discovery_hint?.on_stuck) || '' },
          thinking_bridge: { steps: (gi.thinking_bridge?.steps || []).map((s: string) => stripDollarSigns(s) || s), connection: stripDollarSigns(gi.thinking_bridge?.connection) || '' }
        })),
        selection_prompt: analysis.selection_prompt || '아래 중 더 궁금한 걸 골라보세요!',
        diagnosis: (analysis.question_analysis || {}).diagnosis || null,
        upgrade_hint: (analysis.question_analysis || {}).upgrade_hint || null,
      })
    }
    
    const diff2 = pa2.difficulty || analysis.ai_difficulty || ''
    const tags2 = Array.isArray(pa2.tags) ? pa2.tags.join(' ') : (analysis.ai_tags || null)
    const diffNum = parseInt(String(diff2).replace(/[^0-9]/g, '')) || 0
    const isHard = diffNum >= 4

    await db.prepare(`UPDATE questions SET 
      ai_difficulty = ?, ai_tags = ?, ai_topic_main = ?, ai_topic_sub = ?,
      ai_description = ?, ai_grade_level = ?, ai_estimated_time = ?,
      question_type = ?, question_type_confidence = ?, student_question_text = ?,
      ai_question_analysis = ?, ai_coaching_comment = ?, ai_coaching_data = ?, ai_model = ?, ai_analyzed = 1
      WHERE id = ?`
    ).bind(
      stripDollarSigns(diff2) || null,
      stripDollarSigns(tags2) || null,
      stripDollarSigns(pa2.unit?.split('>')[0]?.trim() || analysis.ai_topic_main) || null,
      stripDollarSigns(pa2.unit?.split('>')?.slice(1)?.join('>').trim() || analysis.ai_topic_sub) || null,
      stripDollarSigns(pa2.summary || analysis.ai_description) || null,
      stripDollarSigns(pa2.grade || analysis.ai_grade_level) || null,
      pa2.estimated_time || analysis.ai_estimated_time || null,
      qa2.question_type || analysis.question_type || null,
      qa2.confidence || analysis.question_type_confidence || null,
      stripDollarSigns(analysis.student_question || qa2.original_question) || null,
      stripDollarSigns(qa2.interpretation || analysis.question_analysis) || null,
      stripDollarSigns(analysis.coaching_comment) || null,
      coachingData2,
      'gemini',
      q.id
    ).run()

    // === HYBRID: ★4~5 → OpenAI enhanced coaching ===
    let openaiEnhanced = false
    if (isHard && c.env.OPENAI_API_KEY) {
      debugInfo.hybridMode = true
      debugInfo.difficulty = diffNum
      try {
        openaiEnhanced = await enhanceCoachingWithOpenAI(db, c.env, parseInt(id), {
          subject: q.subject, content: q.content || '',
          difficulty: String(diff2 || ''),
          questionType: qa2.question_type || analysis.question_type || 'A-2',
          description: pa2.summary || analysis.ai_description || '',
          studentQuestion: analysis.student_question || qa2.original_question || ''
        }, imageParts.length > 0 && imageParts[0].inlineData ? imageParts[0].inlineData.data : null, imageParts.length > 0 && imageParts[0].inlineData ? imageParts[0].inlineData.mimeType : 'image/jpeg')
        debugInfo.openaiEnhanced = openaiEnhanced
      } catch (ce) {
        debugInfo.openaiError = (ce as Error).message
      }
    }
    
    const updated = await db.prepare('SELECT ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, question_type_confidence, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, challenge_result FROM questions WHERE id = ?').bind(id).first()
    return c.json({ success: true, analysis: updated, debug: debugInfo })
  } catch (e: any) {
    return c.json({ success: false, error: e.message, stack: e.stack?.slice(0, 300) })
  }
})

// Batch analyze all unanalyzed questions
app.post('/api/questions/analyze-all', async (c) => {
  const db = c.env.DB
  const geminiKey = c.env.GEMINI_API_KEY
  if (!geminiKey) return c.json({ error: 'Gemini API key not configured' }, 500)
  
  // Re-analyze: unanalyzed OR force re-analyze all
  const reanalyze = c.req.query('force') === '1'
  const sql = reanalyze
    ? "SELECT q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys, q.passage_image_keys, u.external_id FROM questions q JOIN users u ON q.user_id = u.id ORDER BY q.id DESC LIMIT 5"
    : "SELECT q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys, q.passage_image_keys, u.external_id FROM questions q JOIN users u ON q.user_id = u.id WHERE q.ai_analyzed = 0 OR q.ai_analyzed IS NULL ORDER BY q.id DESC LIMIT 5"
  const unanalyzed = await db.prepare(sql).all()
  const ids = ((unanalyzed.results || []) as any[]).map(q => q.id)

  for (const q of (unanalyzed.results || []) as any[]) {
    await analyzeQuestionWithAI(db, c.env, q.id, q.subject, q.content, q.image_key, q.image_data, q.image_keys || null, q.external_id || null, q.passage_image_keys || null)
  }
  
  return c.json({ success: true, analyzed: ids.length, ids })
})

app.patch('/api/questions/:id', async (c) => {
  try {
  const db = c.env.DB
  const id = c.req.param('id')
  // E5: 인증 + 본인 소유 확인 — 누구든 타인 질문 조작 방지
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  const question = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(id).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.user_id !== user.id) return c.json({ error: '본인의 질문만 수정할 수 있습니다.' }, 403)

  // 답변이 달린 질문이나 채택 완료된 질문은 수정 불가
  const qCheck = await db.prepare('SELECT comment_count, status FROM questions WHERE id = ?').bind(id).first() as any
  if (qCheck && (qCheck.comment_count || 0) > 0) return c.json({ error: '답변이 달린 질문은 수정할 수 없습니다.' }, 400)
  if (qCheck && qCheck.status === '채택 완료') return c.json({ error: '채택 완료된 질문은 수정할 수 없습니다.' }, 400)

  const body = await c.req.json()
  const { subject, difficulty, status, content } = body
  // P1-9: 입력값 검증 — 허용 목록으로 제한
  const allowedSubjects = ['수학', '영어', '국어', '과학', '기타']
  const allowedDifficulties = ['하', '중', '상', '최상', '1:1심화설명']
  const allowedStatuses = ['채택 대기 중', '채택 완료', '매칭 확정', '수업 완료']
  if (subject && !allowedSubjects.includes(subject)) return c.json({ error: '유효하지 않은 과목입니다.' }, 400)
  if (difficulty && !allowedDifficulties.includes(difficulty)) return c.json({ error: '유효하지 않은 난이도입니다.' }, 400)
  if (status && !allowedStatuses.includes(status)) return c.json({ error: '유효하지 않은 상태입니다.' }, 400)
  if (content !== undefined && typeof content === 'string') {
    if (content.trim().length === 0) return c.json({ error: '질문 내용을 입력해주세요.' }, 400)
    if (content.length > 2000) return c.json({ error: '질문 내용은 2000자 이내여야 합니다.' }, 400)
  }
  const updates: string[] = []
  const params: any[] = []
  if (subject) { updates.push('subject = ?'); params.push(subject) }
  if (difficulty) { updates.push('difficulty = ?'); params.push(difficulty) }
  if (status) { updates.push('status = ?'); params.push(status) }
  if (content !== undefined && typeof content === 'string' && content.trim().length > 0) { updates.push('content = ?'); params.push(content.trim()) }
  if (updates.length === 0) return c.json({ error: 'No updates' }, 400)
  params.push(id)
  await db.prepare(`UPDATE questions SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run()
  return c.json({ success: true })
  } catch (e: any) { logErr('questions/update', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// DELETE fallback via POST (some mobile browsers have issues with DELETE method)
app.post('/api/questions/:id/delete', async (c) => {
  // Redirect to the delete handler logic
  const db = c.env.DB
  const id = c.req.param('id')
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const question = await db.prepare('SELECT user_id, comment_count, status, difficulty, image_key, thumbnail_key FROM questions WHERE id = ?').bind(id).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.user_id != (user as any).id) return c.json({ error: '본인의 질문만 삭제할 수 있습니다.' }, 403)
  if ((question.comment_count || 0) > 0) return c.json({ error: '답변이 달린 질문은 삭제할 수 없습니다.' }, 400)
  if (question.status === '채택 완료') return c.json({ error: '채택 완료된 질문은 삭제할 수 없습니다.' }, 400)
  if (question.status === '매칭 확정') return c.json({ error: '매칭 확정된 질문은 삭제할 수 없습니다.' }, 400)
  if (question.difficulty === '1:1심화설명') {
    const match = await db.prepare("SELECT id FROM tutoring_matches WHERE question_id = ? AND status IN ('pending','confirmed') LIMIT 1").bind(id).first()
    if (match) return c.json({ error: '매칭 진행 중인 질문은 삭제할 수 없습니다.' }, 400)
  }
  try {
    if (question.image_key && c.env.R2) try { await c.env.R2.delete(question.image_key) } catch(e){}
    if (question.thumbnail_key && c.env.R2) try { await c.env.R2.delete(question.thumbnail_key) } catch(e){}
  } catch(e){}
  try { await db.prepare('DELETE FROM tutoring_slots WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM coaching_logs WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM xp_logs WHERE question_id = ?').bind(id).run() } catch(e){}
  await db.prepare('DELETE FROM questions WHERE id = ?').bind(id).run()
  return c.json({ success: true })
})

app.delete('/api/questions/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const question = await db.prepare('SELECT user_id, comment_count, status, difficulty FROM questions WHERE id = ?').bind(id).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.user_id != user.id) return c.json({ error: '본인의 질문만 삭제할 수 있습니다.' }, 403)
  if ((question.comment_count || 0) > 0) return c.json({ error: '답변이 달린 질문은 삭제할 수 없습니다.' }, 400)
  if (question.status === '채택 완료') return c.json({ error: '채택 완료된 질문은 삭제할 수 없습니다.' }, 400)
  if (question.status === '매칭 확정') return c.json({ error: '매칭 확정된 질문은 삭제할 수 없습니다. 상대방과의 약속입니다.' }, 400)
  // Check for any pending/confirmed tutoring match
  if (question.difficulty === '1:1심화설명') {
    const match = await db.prepare("SELECT id FROM tutoring_matches WHERE question_id = ? AND status IN ('pending','confirmed') LIMIT 1").bind(id).first()
    if (match) return c.json({ error: '매칭 진행 중인 질문은 삭제할 수 없습니다.' }, 400)
  }

  // Clean up R2 images if present
  try {
    const qData = await db.prepare('SELECT image_key, thumbnail_key FROM questions WHERE id = ?').bind(id).first() as any
    if (qData) {
      if (qData.image_key && c.env.R2) try { await c.env.R2.delete(qData.image_key) } catch(e){}
      if (qData.thumbnail_key && c.env.R2) try { await c.env.R2.delete(qData.thumbnail_key) } catch(e){}
    }
  } catch(e){}
  
  // Delete related data first (FK)
  try { await db.prepare('DELETE FROM tutoring_slots WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM coaching_logs WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM xp_logs WHERE question_id = ?').bind(id).run() } catch(e){}

  await db.prepare('DELETE FROM questions WHERE id = ?').bind(id).run()

  // ai_tutor 측에도 soft-delete 알림 (대시보드 집계에서 제외)
  if (c.env.AI_TUTOR_URL && c.env.AI_TUTOR_SECRET) {
    try {
      await fetch(`${c.env.AI_TUTOR_URL}/v1/platform/questions/${id}`, {
        method: 'DELETE',
        headers: { 'X-Proxy-Secret': c.env.AI_TUTOR_SECRET },
      })
    } catch (e) { logErr('aiTutor delete notify', e, { questionId: id }) }
  }

  return c.json({ success: true })
})

// Admin force delete question (bypasses answer/status checks)
app.delete('/api/admin/questions/:id/force', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  // Admin only (user_id = 1)
  if (user.id !== 1) return c.json({ error: '관리자만 사용할 수 있습니다.' }, 403)

  const question = await db.prepare('SELECT id, image_key, thumbnail_key FROM questions WHERE id = ?').bind(id).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)

  // Clean up answer R2 assets
  try {
    const answers = await db.prepare('SELECT image_key, thumbnail_key, drawing_key, voice_key FROM answers WHERE question_id = ?').bind(id).all()
    if (answers.results && c.env.R2) {
      for (const ans of answers.results as any[]) {
        if (ans.image_key) try { await c.env.R2.delete(ans.image_key) } catch(e){}
        if (ans.thumbnail_key) try { await c.env.R2.delete(ans.thumbnail_key) } catch(e){}
        if (ans.drawing_key) try { await c.env.R2.delete(ans.drawing_key) } catch(e){}
        if (ans.voice_key) try { await c.env.R2.delete(ans.voice_key) } catch(e){}
      }
    }
  } catch(e){}

  // Clean up question R2 assets
  try {
    if (question.image_key && c.env.R2) try { await c.env.R2.delete(question.image_key) } catch(e){}
    if (question.thumbnail_key && c.env.R2) try { await c.env.R2.delete(question.thumbnail_key) } catch(e){}
  } catch(e){}

  // Delete related data
  try { await db.prepare('DELETE FROM answers WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM tutoring_slots WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM tutoring_matches WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM coaching_logs WHERE question_id = ?').bind(id).run() } catch(e){}
  try { await db.prepare('DELETE FROM xp_logs WHERE question_id = ?').bind(id).run() } catch(e){}

  await db.prepare('DELETE FROM questions WHERE id = ?').bind(id).run()

  // ai_tutor 측에도 soft-delete 알림
  if (c.env.AI_TUTOR_URL && c.env.AI_TUTOR_SECRET) {
    try {
      await fetch(`${c.env.AI_TUTOR_URL}/v1/platform/questions/${id}`, {
        method: 'DELETE',
        headers: { 'X-Proxy-Secret': c.env.AI_TUTOR_SECRET },
      })
    } catch (e) { logErr('aiTutor delete notify', e, { questionId: id }) }
  }

  return c.json({ success: true, message: `질문 ${id}이(가) 강제 삭제되었습니다.` })
})

// ===== Tutoring Matching API =====

// Get tutoring slots & match status for a question
app.get('/api/questions/:id/tutoring', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  const slots = await db.prepare('SELECT id, slot_time FROM tutoring_slots WHERE question_id = ? ORDER BY id ASC').bind(qId).all()
  const matches = await db.prepare('SELECT id, slot_id, tutor_id, tutor_name, tutor_grade, status, held_at, confirmed_at, acceptance_tags, acceptance_review FROM tutoring_matches WHERE question_id = ? ORDER BY held_at ASC').bind(qId).all()
  return c.json({ slots: slots.results || [], matches: matches.results || [] })
})

// Tutor checks a time slot (answer volunteer)
app.post('/api/questions/:id/tutoring/check', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Suspension check
  const suspended = await checkSuspension(db, user.id)
  if (suspended) return c.json({ error: '1:1 튜터링 이용이 정지되었습니다. (' + suspended + '까지)' }, 403)

  const { slot_id } = await c.req.json()
  const question = await db.prepare('SELECT user_id, difficulty FROM questions WHERE id = ?').bind(qId).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.difficulty !== '1:1심화설명') return c.json({ error: '1:1 튜터링 질문이 아닙니다.' }, 400)
  if (question.user_id === user.id) return c.json({ error: '본인 질문에는 신청할 수 없습니다.' }, 400)

  // Check if already has a confirmed match
  const confirmed = await db.prepare('SELECT id FROM tutoring_matches WHERE question_id = ? AND status = ?').bind(qId, 'confirmed').first()
  if (confirmed) return c.json({ error: '이미 매칭이 확정되었습니다.' }, 400)

  // Check if this user already checked
  const existing = await db.prepare('SELECT id FROM tutoring_matches WHERE question_id = ? AND tutor_id = ?').bind(qId, user.id).first()
  if (existing) return c.json({ error: '이미 신청하셨습니다.' }, 400)

  // Check for pending hold (first come first serve)
  const pending = await db.prepare("SELECT id, held_at FROM tutoring_matches WHERE question_id = ? AND status = 'pending'").bind(qId).first() as any
  if (pending) {
    // Check if hold expired (15 min)
    const heldTime = new Date(pending.held_at + 'Z').getTime()
    const now = Date.now()
    if (now - heldTime < 15 * 60 * 1000) {
      return c.json({ error: '현재 다른 답변자가 우선 대기 중입니다. 잠시 후 다시 시도해주세요.' }, 400)
    }
    // Expired - remove old hold
    await db.prepare("DELETE FROM tutoring_matches WHERE id = ?").bind(pending.id).run()
  }

  // I4: INSERT ... WHERE NOT EXISTS — 동시 요청 시 중복 매칭 방지 (race condition 제거)
  const insertResult = await db.prepare(`
    INSERT INTO tutoring_matches (question_id, slot_id, tutor_id, tutor_name, tutor_grade, status)
    SELECT ?, ?, ?, ?, ?, 'pending'
    WHERE NOT EXISTS (
      SELECT 1 FROM tutoring_matches
      WHERE question_id = ? AND (tutor_id = ? OR status = 'confirmed')
    )
  `).bind(qId, slot_id, user.id, user.nickname, user.grade || '', qId, user.id).run()

  if (!insertResult.meta.changes || insertResult.meta.changes === 0) {
    return c.json({ error: '이미 신청했거나 매칭이 확정되었습니다.' }, 400)
  }

  // 정율톡 푸시: 질문자에게 튜터링 신청 알림
  try {
    const senderExtId = await getExternalId(db, user.id)
    const receiverExtId = await getExternalId(db, question.user_id)
    if (senderExtId && receiverExtId) {
      const msg = `🎓 [Q&A 튜터링] ${user.nickname}님이 1:1 튜터링을 신청했습니다! 확정해주세요.\nhttps://qa-tutoring-app.pages.dev/question/${qId}?user_id=${receiverExtId}`
      c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
    }
  } catch(e: any) { logErr('push/tutoring-check', e) }

  return c.json({ success: true, message: '신청 완료! 질문자 확정을 기다려주세요. (15분 우선권)' })
})

// Questioner confirms a match
app.post('/api/questions/:id/tutoring/confirm', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const { match_id } = await c.req.json()
  const question = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(qId).first() as any
  if (!question || question.user_id != user.id) return c.json({ error: '질문 작성자만 확정할 수 있습니다.' }, 403)

  if (!match_id) return c.json({ error: '매칭 ID가 필요합니다.' }, 400)
  const match = await db.prepare('SELECT id, status FROM tutoring_matches WHERE id = ? AND question_id = ?').bind(match_id, qId).first() as any
  if (!match) return c.json({ error: '매칭을 찾을 수 없습니다.' }, 404)
  if (match.status === 'confirmed') return c.json({ error: '이미 확정되었습니다.' }, 400)

  // I3: db.batch() 트랜잭션 — 3개 쿼리를 원자적으로 실행 (중간 실패 시 불일치 방지)
  await db.batch([
    db.prepare("UPDATE tutoring_matches SET status = 'confirmed', confirmed_at = ? WHERE id = ?").bind(nowKST(), match_id),
    db.prepare("UPDATE questions SET status = '매칭 확정' WHERE id = ?").bind(qId),
    db.prepare("DELETE FROM tutoring_matches WHERE question_id = ? AND id != ? AND status = 'pending'").bind(qId, match_id),
  ])

  // 정율톡 푸시: 튜터에게 확정 알림
  try {
    const confirmedMatch = await db.prepare('SELECT tutor_id, tutor_name FROM tutoring_matches WHERE id = ?').bind(match_id).first() as any
    if (confirmedMatch) {
      const senderExtId = await getExternalId(db, user.id)
      const receiverExtId = await getExternalId(db, confirmedMatch.tutor_id)
      if (senderExtId && receiverExtId) {
        const msg = `✅ [Q&A 튜터링] ${user.nickname}님이 1:1 튜터링을 확정했습니다! 수업을 준비해주세요.\nhttps://qa-tutoring-app.pages.dev/question/${qId}?user_id=${receiverExtId}`
        c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
      }
    }
  } catch(e: any) { logErr('push/tutoring-confirm', e) }

  return c.json({ success: true, message: '매칭이 확정되었습니다!' })
})

// Tutor declines
app.post('/api/questions/:id/tutoring/decline', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Just remove the user's match
  await db.prepare('DELETE FROM tutoring_matches WHERE question_id = ? AND tutor_id = ?').bind(qId, user.id).run()
  return c.json({ success: true })
})

// Update tutoring slots (only if no confirmed match exists)
app.put('/api/questions/:id/tutoring/slots', async (c) => {
  try {
  const db = c.env.DB
  const qId = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Check question ownership
  const question = await db.prepare('SELECT user_id, difficulty FROM questions WHERE id = ?').bind(qId).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.user_id !== user.id) return c.json({ error: '본인의 질문만 수정할 수 있습니다.' }, 403)
  if (question.difficulty !== '1:1심화설명') return c.json({ error: '1:1 튜터링 질문만 시간 수정이 가능합니다.' }, 400)

  // Check if confirmed match exists
  const confirmedMatch = await db.prepare("SELECT id FROM tutoring_matches WHERE question_id = ? AND status = 'confirmed'").bind(qId).first()
  if (confirmedMatch) return c.json({ error: '매칭이 확정된 질문은 시간을 수정할 수 없습니다.' }, 400)

  const { slots } = await c.req.json() as any
  if (!slots || !Array.isArray(slots) || slots.length === 0 || slots.length > 5) {
    return c.json({ error: '시간은 1~5개까지 선택할 수 있습니다.' }, 400)
  }

  // Delete pending matches (they chose old slots)
  await db.prepare("DELETE FROM tutoring_matches WHERE question_id = ? AND status = 'pending'").bind(qId).run()
  // Delete old slots
  await db.prepare('DELETE FROM tutoring_slots WHERE question_id = ?').bind(qId).run()
  // Insert new slots
  for (const slot of slots) {
    if (slot && typeof slot === 'string' && slot.trim()) {
      await db.prepare('INSERT INTO tutoring_slots (question_id, slot_time) VALUES (?, ?)').bind(qId, slot.trim()).run()
    }
  }

  return c.json({ success: true, message: '시간이 수정되었습니다. 기존 신청은 초기화되었습니다.' })
  } catch (e: any) { logErr('tutoring/slots', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// Accept tutor after completed session (1:1 튜터링 채택)
app.post('/api/questions/:id/tutoring/accept', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Check question ownership
  const question = await db.prepare('SELECT user_id, status, reward_points FROM questions WHERE id = ?').bind(qId).first() as any
  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)
  if (question.user_id !== user.id) return c.json({ error: '질문 작성자만 채택할 수 있습니다.' }, 403)

  // Check for completed match
  const match = await db.prepare(`
    SELECT m.id, m.tutor_id, m.tutor_name, m.status, s.slot_time
    FROM tutoring_matches m
    JOIN tutoring_slots s ON m.slot_id = s.id
    WHERE m.question_id = ? AND m.status IN ('confirmed', 'completed')
    ORDER BY m.id DESC LIMIT 1
  `).bind(qId).first() as any
  if (!match) return c.json({ error: '매칭된 답변자를 찾을 수 없습니다.' }, 404)

  // Check if session time has passed
  const slotDate = parseSlotTimeToDate(match.slot_time)
  if (slotDate && slotDate.getTime() > Date.now()) {
    return c.json({ error: '수업 시간이 지난 후에 채택할 수 있습니다.' }, 400)
  }

  const body = await c.req.json().catch(() => ({})) as any
  const review = body.review || ''
  const tags = body.tags || []
  const tagsJson = Array.isArray(tags) ? JSON.stringify(tags) : '[]'

  // I3: db.batch() 트랜잭션 — 매칭 확정 + 질문 상태 (포인트는 CP로 대체)
  const batchStmts = [
    db.prepare("UPDATE tutoring_matches SET status = 'accepted', acceptance_tags = ?, acceptance_review = ? WHERE id = ?").bind(tagsJson, review || null, match.id),
    db.prepare("UPDATE questions SET status = '채택 완료' WHERE id = ?").bind(qId),
  ]
  await db.batch(batchStmts)

  // === 크로켓포인트 보상: 튜터링 채택 ===
  let tutorCp = 0
  let questionerCp = 0
  try {
    // 튜터링 CP 보상 결정 (기존 reward_points → CP 변환)
    const pts = question.reward_points || 0
    let cpReward = CP_CONFIG.TUTORING_ACCEPTED.mid // 기본 15 CP
    if (pts <= 50) cpReward = CP_CONFIG.TUTORING_ACCEPTED.low       // 10 CP
    else if (pts <= 80) cpReward = CP_CONFIG.TUTORING_ACCEPTED.mid  // 15 CP
    else cpReward = CP_CONFIG.TUTORING_ACCEPTED.high                // 20 CP

    // 1) 튜터에게 CP 지급
    const got1 = await awardCP(db, match.tutor_id, parseInt(qId), null, cpReward, 'tutoring_accepted', `튜터링 채택 보상 (+${cpReward * 100} 크로켓포인트)`)
    if (got1) tutorCp = cpReward
    // 2) 질문자에게 채택 행위 보상 1 CP
    const got2 = await awardCP(db, user.id, parseInt(qId), null, CP_CONFIG.ACCEPT_ACTION, 'accept_action', '채택 행위 보상')
    if (got2) questionerCp = CP_CONFIG.ACCEPT_ACTION
  } catch(e: any) { logErr('cp/tutoring-accept', e) }

  // 정율톡 푸시: 튜터에게 채택 + CP 알림
  try {
    const senderExtId = await getExternalId(db, user.id)
    const receiverExtId = await getExternalId(db, match.tutor_id)
    if (senderExtId && receiverExtId) {
      const cpMsg = tutorCp > 0 ? `+${tutorCp * 100} 크로켓포인트 획득! ` : ''
      const msg = `🏆 [Q&A 튜터링] ${user.nickname}님이 1:1 튜터링을 채택했습니다! ${cpMsg}🎉\nhttps://qa-tutoring-app.pages.dev/question/${qId}?user_id=${receiverExtId}`
      c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
    }
  } catch(e: any) { logErr('push/tutoring-accept', e) }

  return c.json({ success: true, tutor_cp: tutorCp, questioner_cp: questionerCp, message: match.tutor_name + '님을 채택했습니다! (' + (tutorCp * 100) + ' 크로켓포인트 지급)' })
})

// ===== Schedule API =====

app.get('/api/schedule', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Get all confirmed + completed matches where user is questioner OR tutor
  const matches = await db.prepare(`
    SELECT m.id, m.question_id, m.slot_id, m.tutor_id, m.tutor_name, m.tutor_grade,
           m.status, m.held_at, m.confirmed_at,
           s.slot_time, q.title, q.content, q.subject, q.reward_points,
           q.user_id as questioner_id, q.author_name as questioner_name, q.author_grade as questioner_grade
    FROM tutoring_matches m
    JOIN tutoring_slots s ON m.slot_id = s.id
    JOIN questions q ON m.question_id = q.id
    WHERE m.status IN ('confirmed', 'completed') AND (q.user_id = ? OR m.tutor_id = ?)
    ORDER BY s.slot_time ASC
  `).bind(user.id, user.id).all()

  return c.json({
    user_id: user.id,
    schedules: matches.results || []
  })
})

// === Helper: Parse slot_time to Date (KST → UTC) ===
// Slot times are in Korean Standard Time (UTC+9)
// Server runs in UTC, so we must subtract 9 hours to get correct UTC timestamp
function parseSlotTimeToDate(slotTime: string): Date | null {
  try {
    const parts = slotTime.trim().split(' ')
    if (parts.length < 3) return null
    const dateParts = parts[1].split('/')
    const timeParts = parts[2].split(':')
    const now = new Date()
    const year = now.getFullYear()
    // Create date as KST, then convert to UTC by subtracting 9 hours
    const kstDate = new Date(year, parseInt(dateParts[0]) - 1, parseInt(dateParts[1]), parseInt(timeParts[0]), parseInt(timeParts[1] || '0'))
    const utcDate = new Date(kstDate.getTime() - 9 * 3600000)
    if (utcDate.getTime() < now.getTime() - 180 * 86400000) utcDate.setTime(utcDate.getTime() + 365 * 86400000)
    return utcDate
  } catch (e) { return null }
}

// === Helper: Check suspension ===
async function checkSuspension(db: D1Database, userId: number): Promise<string | null> {
  const suspension = await db.prepare(
    // suspended_until은 UTC로 저장되어 있으므로 UTC 비교 유지
    "SELECT suspended_until, reason FROM user_suspensions WHERE user_id = ? AND suspended_until > datetime('now') ORDER BY suspended_until DESC LIMIT 1"
  ).bind(userId).first() as any
  if (!suspension) return null
  return suspension.suspended_until
}

// === Helper: Apply warnings & check suspension thresholds ===
async function applyWarnings(db: D1Database, userId: number, warningCount: number, cancelRecordId: number, reason: string) {
  // Add warning record
  await db.prepare('INSERT INTO user_warnings (user_id, cancel_record_id, warning_count, reason) VALUES (?, ?, ?, ?)').bind(userId, cancelRecordId, warningCount, reason).run()
  // Update user total
  await db.prepare('UPDATE users SET total_warnings = total_warnings + ? WHERE id = ?').bind(warningCount, userId).run()
  
  // Check 24-hour rolling window: count warnings in last 24 hours
  const recent = await db.prepare(
    "SELECT SUM(warning_count) as cnt FROM user_warnings WHERE user_id = ? AND created_at > datetime('now', '-24 hours')"
  ).bind(userId).first() as any
  const recentCount = recent?.cnt || 0

  // 24시간 내 경고 3회 이상 → 48시간 이용 정지
  if (recentCount >= 3) {
    // KST 기준으로 정지 종료 시간 계산 (UTC로 저장)
    const until = new Date(Date.now() + 48 * 3600000).toISOString().replace('T', ' ').slice(0, 19)
    // Check if already suspended
    const existing = await checkSuspension(db, userId)
    if (!existing) {
      await db.prepare('INSERT INTO user_suspensions (user_id, reason, total_warnings, suspended_until) VALUES (?, ?, ?, ?)').bind(userId, '24시간 내 경고 ' + recentCount + '회 누적', recentCount, until).run()
    }
  }
}

// Cancel a tutoring match (with penalty system)
app.post('/api/schedule/:matchId/cancel', async (c) => {
  const db = c.env.DB
  const matchId = c.req.param('matchId')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  // Check suspension
  const suspendedUntil = await checkSuspension(db, user.id)
  if (suspendedUntil) return c.json({ error: '1:1 튜터링 이용이 정지되었습니다. (' + suspendedUntil + '까지)' }, 403)

  const match = await db.prepare(`
    SELECT m.id, m.question_id, m.tutor_id, m.status, m.confirmed_at, s.slot_time,
           q.user_id as questioner_id, q.reward_points
    FROM tutoring_matches m
    JOIN tutoring_slots s ON m.slot_id = s.id
    JOIN questions q ON m.question_id = q.id
    WHERE m.id = ?
  `).bind(matchId).first() as any
  if (!match) return c.json({ error: '매칭을 찾을 수 없습니다.' }, 404)
  if (match.status !== 'confirmed') return c.json({ error: '확정된 매칭만 취소할 수 있습니다.' }, 400)

  const isQuestioner = match.questioner_id === user.id
  const isTutor = match.tutor_id === user.id
  if (!isQuestioner && !isTutor) return c.json({ error: '매칭 당사자만 취소할 수 있습니다.' }, 403)

  const body = await c.req.json().catch(() => ({})) as any
  const reason = body.reason || '기타'
  const reasonDetail = body.reason_detail || ''
  const isMutual = body.mutual === true

  // If mutual cancel request
  if (isMutual) {
    // Check if there's already a pending mutual cancel from the OTHER side
    const existing = await db.prepare(
      "SELECT id, requested_by FROM mutual_cancel_requests WHERE match_id = ? AND status = 'pending'"
    ).bind(matchId).first() as any
    
    if (existing && existing.requested_by !== user.id) {
      // P0-4: db.batch() 트랜잭션 — 상호 합의 취소를 원자적으로 처리
      await db.batch([
        db.prepare("UPDATE mutual_cancel_requests SET status = 'accepted', responded_at = ? WHERE id = ?").bind(nowKST(), existing.id),
        db.prepare("UPDATE tutoring_matches SET status = 'cancelled' WHERE id = ?").bind(matchId),
        db.prepare("UPDATE questions SET status = '채택 대기 중' WHERE id = ?").bind(match.question_id),
        db.prepare('INSERT INTO cancel_records (match_id, question_id, cancelled_by, cancel_role, reason, reason_detail, penalty_type, penalty_points, warnings_added, hours_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(matchId, match.question_id, user.id, 'mutual', reason, reasonDetail, 'none', 0, 0, 0),
      ])
      // 정율톡 푸시: 요청자에게 상호 합의 승인 알림
      try {
        const senderExtId = await getExternalId(db, user.id)
        const receiverExtId = await getExternalId(db, existing.requested_by)
        if (senderExtId && receiverExtId) {
          const msg = `🤝 [Q&A 튜터링] ${user.nickname}님이 상호 합의 취소를 승인했습니다. 패널티 없이 취소되었습니다.\nhttps://qa-tutoring-app.pages.dev/question/${match.question_id}?user_id=${receiverExtId}`
          c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
        }
      } catch(e: any) { logErr('push/mutual-cancel-accepted', e) }
      return c.json({ success: true, message: '상호 합의로 매칭이 취소되었습니다. 패널티가 없습니다.', penalty: 'none', mutual: true })
    } else if (existing && existing.requested_by === user.id) {
      return c.json({ error: '이미 상호 합의 취소를 요청했습니다. 상대방의 승인을 기다려주세요.' }, 400)
    } else {
      // Create mutual cancel request
      await db.prepare('INSERT INTO mutual_cancel_requests (match_id, requested_by, reason) VALUES (?, ?, ?)').bind(matchId, user.id, reason).run()
      // 정율톡 푸시: 상대방에게 상호 합의 요청 알림
      try {
        const senderExtId = await getExternalId(db, user.id)
        const receiverId = isQuestioner ? match.tutor_id : match.questioner_id
        const receiverExtId = await getExternalId(db, receiverId)
        if (senderExtId && receiverExtId) {
          const msg = `🙏 [Q&A 튜터링] ${user.nickname}님이 상호 합의 취소를 요청했습니다. 승인하시면 패널티 없이 취소됩니다.\nhttps://qa-tutoring-app.pages.dev/question/${match.question_id}?user_id=${receiverExtId}`
          c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
        }
      } catch(e: any) { logErr('push/mutual-cancel-request', e) }
      return c.json({ success: true, message: '상호 합의 취소를 요청했습니다. 상대방이 승인하면 패널티 없이 취소됩니다.', pending_mutual: true })
    }
  }

  // === One-sided cancel: apply penalties ===
  const slotDate = parseSlotTimeToDate(match.slot_time)
  let hoursUntilSession = -1
  if (slotDate) hoursUntilSession = (slotDate.getTime() - Date.now()) / 3600000

  // Check if within 2h of confirmation (grace period)
  let isGracePeriod = false
  if (match.confirmed_at) {
    const confirmedTime = new Date(match.confirmed_at + 'Z').getTime()
    isGracePeriod = (Date.now() - confirmedTime) < 2 * 3600000
  }

  let penaltyType = 'none'
  let penaltyPoints = 0
  let warningsAdded = 0
  const rewardPts = match.reward_points || 0

  if (isGracePeriod && hoursUntilSession > 24) {
    // Grace period + far enough → free cancel for both
    penaltyType = 'none'
  } else if (isQuestioner) {
    // === 질문자: 포인트 차감만, 경고 없음 ===
    if (hoursUntilSession > 24) {
      penaltyType = 'none' // 24시간 전: 자유 취소
    } else if (hoursUntilSession > 1) {
      penaltyType = 'half'
      penaltyPoints = Math.floor(rewardPts * 0.5) // 50% 차감
    } else {
      penaltyType = 'full'
      penaltyPoints = rewardPts // 100% 차감
    }
  } else {
    // === 답변자: 경고 누적, 포인트 차감 없음 ===
    if (hoursUntilSession > 24) {
      penaltyType = 'warning'
      warningsAdded = 1
    } else if (hoursUntilSession > 1) {
      penaltyType = 'warning'
      warningsAdded = 1
    } else {
      penaltyType = 'warning'
      warningsAdded = 2 // 1시간 이내: 경고 2회
    }
  }

  // P0-5: db.batch() 트랜잭션 — 일방 취소 상태 변경을 원자적으로 처리
  const cancelBatchResults = await db.batch([
    db.prepare("UPDATE tutoring_matches SET status = 'cancelled' WHERE id = ?").bind(matchId),
    db.prepare("UPDATE questions SET status = '채택 대기 중' WHERE id = ?").bind(match.question_id),
    db.prepare('UPDATE users SET cancelled_matches = cancelled_matches + 1 WHERE id = ?').bind(user.id),
    db.prepare('INSERT INTO cancel_records (match_id, question_id, cancelled_by, cancel_role, reason, reason_detail, penalty_type, penalty_points, warnings_added, hours_before) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(matchId, match.question_id, user.id, isQuestioner ? 'questioner' : 'tutor', reason, reasonDetail, penaltyType, penaltyPoints, warningsAdded, Math.max(0, hoursUntilSession)),
  ])
  const cancelRecordId = (cancelBatchResults[3] as any)?.meta?.last_row_id || 0

  // Apply warnings if any
  if (warningsAdded > 0) {
    await applyWarnings(db, user.id, warningsAdded, cancelRecordId, reason)
  }

  // CP 환불/패널티 처리
  if (isQuestioner && penaltyPoints > 0) {
    // 질문자 취소: 튜터에게 위로금으로 50% CP 지급
    try {
      const consolationCp = Math.max(1, Math.floor(penaltyPoints * 0.5 / 10)) // 기존 포인트→CP 환산
      await awardCP(db, match.tutor_id, parseInt(match.question_id), null, consolationCp, 'tutoring_refund', `튜터링 취소 위로금 (+${consolationCp * 100} 크로켓포인트)`)
    } catch(e: any) { logErr('cp/cancel-consolation', e) }
  } else if (isTutor && penaltyPoints > 0) {
    // 튜터 취소: 질문자에게 CP 전액 환불
    try {
      const refundPts = match.reward_points || 0
      let refundCp = CP_CONFIG.TUTORING_COST.low
      if (refundPts >= 80) refundCp = CP_CONFIG.TUTORING_COST.mid
      if (refundPts >= 100) refundCp = CP_CONFIG.TUTORING_COST.high
      if (match.questioner_id) {
        await awardCP(db, match.questioner_id, parseInt(String(match.question_id), 10), null, refundCp, 'tutoring_refund', `튜터링 취소 환불 (+${refundCp * 100} 크로켓포인트)`)
      }
    } catch(e: any) { logErr('cp/cancel-refund', e) }
  }

  // Build response message
  let message = '매칭이 취소되었습니다.'
  if (penaltyType === 'none') message += ' (패널티 없음)'
  else if (isQuestioner) {
    // 질문자: 포인트 차감만 표시
    if (penaltyPoints > 0) message += ' (' + (penaltyPoints * 100) + ' 크로켓포인트 차감)'
  } else {
    // 답변자: 경고만 표시
    message += ' (경고 ' + warningsAdded + '회 부여)'
  }

  // 정율톡 푸시: 상대방에게 취소 알림
  try {
    const senderExtId = await getExternalId(db, user.id)
    const receiverId = isQuestioner ? match.tutor_id : match.questioner_id
    const receiverExtId = await getExternalId(db, receiverId)
    if (senderExtId && receiverExtId) {
      const cancellerRole = isQuestioner ? '질문자' : '튜터'
      const msg = `❌ [Q&A 튜터링] ${user.nickname}님(${cancellerRole})이 1:1 튜터링을 취소했습니다.\nhttps://qa-tutoring-app.pages.dev/question/${match.question_id}?user_id=${receiverExtId}`
      c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
    }
  } catch(e: any) { logErr('push/tutoring-cancel', e) }

  return c.json({
    success: true,
    message,
    penalty: penaltyType,
    penalty_points: penaltyPoints,
    warnings_added: warningsAdded,
    cancelled_by: isQuestioner ? 'questioner' : 'tutor'
  })
})

// Get pending mutual cancel requests for a match
app.get('/api/schedule/:matchId/cancel-status', async (c) => {
  const db = c.env.DB
  const matchId = c.req.param('matchId')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const pending = await db.prepare(
    "SELECT id, requested_by, reason, created_at FROM mutual_cancel_requests WHERE match_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1"
  ).bind(matchId).first() as any

  return c.json({
    has_pending_request: !!pending,
    requested_by_me: pending ? pending.requested_by === user.id : false,
    request: pending || null
  })
})

// Get user's penalty/warning info
app.get('/api/user/penalty-info', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const userInfo = await db.prepare('SELECT total_warnings, total_matches, completed_matches, cancelled_matches FROM users WHERE id = ?').bind(user.id).first() as any
  const suspension = await checkSuspension(db, user.id)
  const recentCancels = await db.prepare(
    'SELECT reason, penalty_type, penalty_points, warnings_added, created_at FROM cancel_records WHERE cancelled_by = ? ORDER BY created_at DESC LIMIT 5'
  ).bind(user.id).all()

  const totalM = (userInfo?.total_matches || 0) + (userInfo?.completed_matches || 0) + (userInfo?.cancelled_matches || 0)
  const completedM = userInfo?.completed_matches || 0
  const fulfillRate = totalM > 0 ? Math.round((completedM / totalM) * 100) : 100

  return c.json({
    total_warnings: userInfo?.total_warnings || 0,
    total_matches: totalM,
    completed_matches: completedM,
    cancelled_matches: userInfo?.cancelled_matches || 0,
    fulfill_rate: fulfillRate,
    suspended_until: suspension,
    recent_cancels: recentCancels.results || []
  })
})

// === 외부 앱용: user_id(external_id)로 질문수/답변수 조회 ===
app.get('/api/user/stats-by-extid', async (c) => {
  const db = c.env.DB
  const extUserId = c.req.query('user_id')
  if (!extUserId) return c.json({ error: 'user_id is required' }, 400)

  // external_id로 내부 사용자 조회
  const user = await db.prepare('SELECT id, nickname FROM users WHERE external_id = ?').bind(String(extUserId)).first() as any
  if (!user) return c.json({ success: true, user_id: extUserId, question_count: 0, answer_count: 0, message: 'User not found in QA system' })

  // 질문 수
  const qRow = await db.prepare('SELECT COUNT(*) as cnt FROM questions WHERE user_id = ?').bind(user.id).first() as any
  // 답변 수
  const aRow = await db.prepare('SELECT COUNT(*) as cnt FROM answers WHERE user_id = ?').bind(user.id).first() as any

  return c.json({
    success: true,
    user_id: extUserId,
    nickname: user.nickname,
    question_count: qRow?.cnt || 0,
    answer_count: aRow?.cnt || 0
  })
})

// === 외부 앱용: user_id(external_id)로 과목별 질문수/답변수 조회 ===
app.get('/api/user/subject-stats-by-extid', async (c) => {
  const db = c.env.DB
  const extUserId = c.req.query('user_id')
  if (!extUserId) return c.json({ error: 'user_id is required' }, 400)

  // external_id로 내부 사용자 조회
  const user = await db.prepare('SELECT id, nickname FROM users WHERE external_id = ?').bind(String(extUserId)).first() as any
  if (!user) return c.json({ success: true, user_id: extUserId, subjects: [], message: 'User not found in QA system' })

  // 과목별 질문 수
  const qRows = await db.prepare(
    `SELECT subject, COUNT(*) as cnt FROM questions WHERE user_id = ? GROUP BY subject ORDER BY cnt DESC`
  ).bind(user.id).all() as any

  // 과목별 답변 수 (answers 테이블에는 subject 없으므로 questions JOIN)
  const aRows = await db.prepare(
    `SELECT q.subject, COUNT(*) as cnt FROM answers a JOIN questions q ON a.question_id = q.id WHERE a.user_id = ? GROUP BY q.subject ORDER BY cnt DESC`
  ).bind(user.id).all() as any

  // 과목 목록 합치기
  const subjectMap: Record<string, { question_count: number; answer_count: number }> = {}
  for (const r of (qRows.results || [])) {
    const s = r.subject || '기타'
    if (!subjectMap[s]) subjectMap[s] = { question_count: 0, answer_count: 0 }
    subjectMap[s].question_count = r.cnt
  }
  for (const r of (aRows.results || [])) {
    const s = r.subject || '기타'
    if (!subjectMap[s]) subjectMap[s] = { question_count: 0, answer_count: 0 }
    subjectMap[s].answer_count = r.cnt
  }

  // 총합 계산
  let totalQuestions = 0, totalAnswers = 0
  const subjects = Object.entries(subjectMap).map(([subject, counts]) => {
    totalQuestions += counts.question_count
    totalAnswers += counts.answer_count
    return { subject, ...counts }
  })

  return c.json({
    success: true,
    user_id: extUserId,
    nickname: user.nickname,
    total_question_count: totalQuestions,
    total_answer_count: totalAnswers,
    subjects
  })
})

// === 외부 앱용: 여러 user_id 한 번에 과목별 질문수/답변수 조회 (POST) ===
app.post('/api/user/subject-stats-batch', async (c) => {
  const db = c.env.DB
  let body: any
  try { body = await c.req.json() } catch { return c.json({ error: 'Invalid JSON body' }, 400) }

  const userIds: string[] = body.user_ids
  if (!Array.isArray(userIds) || userIds.length === 0) return c.json({ error: 'user_ids array is required' }, 400)
  if (userIds.length > 100) return c.json({ error: 'Maximum 100 user_ids per request' }, 400)

  // external_id → 내부 id 매핑 (IN 절 사용)
  const placeholders = userIds.map(() => '?').join(',')
  const userRows = await db.prepare(
    `SELECT id, nickname, external_id FROM users WHERE external_id IN (${placeholders})`
  ).bind(...userIds.map(String)).all() as any

  const userMap: Record<string, { id: number; nickname: string; external_id: string }> = {}
  const internalIds: number[] = []
  for (const u of (userRows.results || [])) {
    userMap[String(u.external_id)] = u
    internalIds.push(u.id)
  }

  // 등록되지 않은 사용자 결과 미리 준비
  const resultMap: Record<string, any> = {}
  for (const extId of userIds) {
    if (!userMap[String(extId)]) {
      resultMap[String(extId)] = {
        user_id: String(extId),
        nickname: null,
        total_question_count: 0,
        total_answer_count: 0,
        subjects: [],
        message: 'User not found in QA system'
      }
    } else {
      resultMap[String(extId)] = {
        user_id: String(extId),
        nickname: userMap[String(extId)].nickname,
        total_question_count: 0,
        total_answer_count: 0,
        subjects: []
      }
    }
  }

  if (internalIds.length > 0) {
    const idPlaceholders = internalIds.map(() => '?').join(',')

    // 과목별 질문 수 (전체 사용자 한 번에)
    const qRows = await db.prepare(
      `SELECT user_id, subject, COUNT(*) as cnt FROM questions WHERE user_id IN (${idPlaceholders}) GROUP BY user_id, subject`
    ).bind(...internalIds).all() as any

    // 과목별 답변 수 (전체 사용자 한 번에)
    const aRows = await db.prepare(
      `SELECT a.user_id, q.subject, COUNT(*) as cnt FROM answers a JOIN questions q ON a.question_id = q.id WHERE a.user_id IN (${idPlaceholders}) GROUP BY a.user_id, q.subject`
    ).bind(...internalIds).all() as any

    // internal_id → external_id 역매핑
    const idToExt: Record<number, string> = {}
    for (const extId of Object.keys(userMap)) {
      idToExt[userMap[extId].id] = extId
    }

    // 과목별 집계
    const subjectMaps: Record<string, Record<string, { question_count: number; answer_count: number }>> = {}
    for (const r of (qRows.results || [])) {
      const extId = idToExt[r.user_id]
      if (!extId) continue
      if (!subjectMaps[extId]) subjectMaps[extId] = {}
      const s = r.subject || '기타'
      if (!subjectMaps[extId][s]) subjectMaps[extId][s] = { question_count: 0, answer_count: 0 }
      subjectMaps[extId][s].question_count = r.cnt
    }
    for (const r of (aRows.results || [])) {
      const extId = idToExt[r.user_id]
      if (!extId) continue
      if (!subjectMaps[extId]) subjectMaps[extId] = {}
      const s = r.subject || '기타'
      if (!subjectMaps[extId][s]) subjectMaps[extId][s] = { question_count: 0, answer_count: 0 }
      subjectMaps[extId][s].answer_count = r.cnt
    }

    // 결과에 반영
    for (const extId of Object.keys(subjectMaps)) {
      let totalQ = 0, totalA = 0
      const subjects = Object.entries(subjectMaps[extId]).map(([subject, counts]) => {
        totalQ += counts.question_count
        totalA += counts.answer_count
        return { subject, ...counts }
      })
      resultMap[extId].total_question_count = totalQ
      resultMap[extId].total_answer_count = totalA
      resultMap[extId].subjects = subjects
    }
  }

  return c.json({
    success: true,
    count: userIds.length,
    users: userIds.map(id => resultMap[String(id)])
  })
})

// Mark a tutoring session as completed
app.post('/api/schedule/:matchId/complete', async (c) => {
  const db = c.env.DB
  const matchId = c.req.param('matchId')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

  const match = await db.prepare(`
    SELECT m.id, m.question_id, m.tutor_id, m.status, q.user_id as questioner_id
    FROM tutoring_matches m
    JOIN questions q ON m.question_id = q.id
    WHERE m.id = ?
  `).bind(matchId).first() as any
  if (!match) return c.json({ error: '매칭을 찾을 수 없습니다.' }, 404)
  if (match.questioner_id !== user.id && match.tutor_id !== user.id) return c.json({ error: '매칭 당사자만 완료 처리할 수 있습니다.' }, 403)

  // P0-3: db.batch() 트랜잭션 — 수업 완료 상태 + 사용자 통계를 원자적으로 처리
  await db.batch([
    db.prepare("UPDATE tutoring_matches SET status = 'completed' WHERE id = ?").bind(matchId),
    db.prepare("UPDATE questions SET status = '수업 완료' WHERE id = ?").bind(match.question_id),
    db.prepare('UPDATE users SET completed_matches = completed_matches + 1, total_matches = total_matches + 1 WHERE id = ?').bind(match.questioner_id),
    db.prepare('UPDATE users SET completed_matches = completed_matches + 1, total_matches = total_matches + 1 WHERE id = ?').bind(match.tutor_id),
  ])

  return c.json({ success: true, message: '수업이 완료되었습니다!' })
})

app.get('/api/questions/:id/answers', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const page = Math.max(0, parseInt(c.req.query('page') || '0', 10) || 0)
  const limit = 50
  const offset = page * limit
  const ansQuery = `SELECT id, question_id, user_id, author_name, author_grade, content, is_accepted, acceptance_tags, acceptance_review, created_at, CASE WHEN (drawing_data IS NOT NULL AND drawing_data != '') OR (drawing_key IS NOT NULL AND drawing_key != '') THEN 1 ELSE 0 END as has_drawing, CASE WHEN (image_data IS NOT NULL AND image_data != '') OR (image_key IS NOT NULL AND image_key != '') THEN 1 ELSE 0 END as has_image, image_key, drawing_key, voice_key FROM answers WHERE question_id = ? ORDER BY created_at ASC LIMIT ${limit + 1} OFFSET ${offset}`
  let result: any
  try {
    result = await db.prepare(ansQuery).bind(id).all()
  } catch (e) {
    try { await db.prepare('ALTER TABLE answers ADD COLUMN drawing_key TEXT DEFAULT NULL').run() } catch(e2){}
    result = await db.prepare(ansQuery).bind(id).all()
  }
  const rows = result.results || []
  const hasMore = rows.length > limit
  if (hasMore) rows.pop()
  return c.json({ answers: rows, hasMore, page })
})

// Serve individual answer media (drawing/image) on demand
app.get('/api/answers/:id/drawing', async (c) => {
  const db = c.env.DB
  const r2 = c.env.R2
  const id = c.req.param('id')
  const row = await db.prepare('SELECT drawing_data, drawing_key FROM answers WHERE id = ?').bind(id).first() as any
  if (!row) return c.json({ error: 'Not found' }, 404)

  // R2 path: serve directly as binary image
  if (row.drawing_key && r2) {
    try {
      const object = await r2.get(row.drawing_key)
      if (object) {
        return new Response(object.body, {
          headers: {
            'Content-Type': object.httpMetadata?.contentType || 'image/png',
            'Cache-Control': 'public, max-age=86400, s-maxage=604800',
          }
        })
      }
    } catch (e) {}
  }

  // Fallback: base64 from DB
  if (!row.drawing_data) return c.json({ error: 'Not found' }, 404)
  return c.json({ data: row.drawing_data })
})

app.get('/api/answers/:id/image', async (c) => {
  const db = c.env.DB
  const r2 = c.env.R2
  const id = c.req.param('id')
  const row = await db.prepare('SELECT image_data, image_key FROM answers WHERE id = ?').bind(id).first() as any
  if (!row) return c.json({ error: 'Not found' }, 404)
  
  // R2 path
  if (row.image_key) {
    const object = await r2.get(row.image_key)
    if (object) {
      return new Response(object.body, {
        headers: {
          'Content-Type': object.httpMetadata?.contentType || 'image/jpeg',
          'Cache-Control': 'public, max-age=86400, s-maxage=604800',
        }
      })
    }
  }
  
  // Fallback: base64
  if (!row.image_data) return c.json({ error: 'Not found' }, 404)
  c.header('Cache-Control', 'public, max-age=86400, s-maxage=604800')
  return c.json({ data: row.image_data })
})

// === Voice recording upload ===
app.post('/api/voice/upload', async (c) => {
  try {
    const r2 = c.env.R2
    if (!r2) return c.json({ error: 'Storage not available' }, 500)
    const user = await getAuthUser(c) as any
    if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)

    const formData = await c.req.formData()
    const file = formData.get('voice') as any
    if (!file) return c.json({ error: '음성 파일이 없습니다.' }, 400)

    const buf = await file.arrayBuffer()
    if (buf.byteLength === 0) return c.json({ error: '빈 음성 파일입니다.' }, 400)
    const ext = file.type?.includes('webm') ? 'webm' : file.type?.includes('mp4') ? 'mp4' : file.type?.includes('ogg') ? 'ogg' : 'webm'
    const key = `voice/answer/${Date.now()}_${Math.random().toString(36).slice(2,8)}.${ext}`
    await r2.put(key, buf, { httpMetadata: { contentType: file.type || 'audio/webm' } })
    return c.json({ voice_key: key })
  } catch (e: any) {
    return c.json({ error: '음성 업로드 중 오류: ' + (e?.message || String(e)) }, 500)
  }
})

// === Serve voice recording from R2 ===
app.get('/api/voice/:key{.+}', async (c) => {
  const r2 = c.env.R2
  const key = c.req.param('key')
  if (!r2 || !key) return c.json({ error: 'Not found' }, 404)
  const obj = await r2.get(key)
  if (!obj) return c.json({ error: 'Not found' }, 404)
  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'audio/webm',
      'Cache-Control': 'public, max-age=86400',
      'Accept-Ranges': 'bytes',
    }
  })
})

app.post('/api/questions/:id/answers', async (c) => {
  try {
  const db = c.env.DB
  const r2 = c.env.R2
  const questionId = c.req.param('id')
  const body = await c.req.json()
  const { content, image_data, drawing_data, voice_key } = body

  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  // P2-15: 답변 생성 레이트 리밋 (10회/분)
  const alimit = checkContentRateLimit(user.id, 'answer')
  if (!alimit.allowed) return c.json({ error: '답변 등록이 너무 빠릅니다. 잠시 후 다시 시도해주세요.' }, 429)
  // P1-10: 답변 콘텐츠 길이 제한
  if (content && content.length > 10000) return c.json({ error: '답변 내용은 10,000자 이내로 작성해주세요.' }, 400)

  // Insert answer first to get the ID
  const result = await db.prepare(
    'INSERT INTO answers (question_id, user_id, author_name, author_grade, content, image_data, voice_key) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(questionId, user.id, user.nickname, user.grade, content || '', image_data || null, voice_key || null).run()
  const answerId = result.meta.last_row_id

  // Save drawing to R2 if present
  if (drawing_data && r2) {
    try {
      const base64Match = drawing_data.match(/^data:([^;]+);base64,(.+)$/)
      if (base64Match) {
        const ct = base64Match[1]
        const b64 = base64Match[2]
        const bytes = Uint8Array.from(atob(b64), ch => ch.charCodeAt(0))
        const ext = ct.includes('png') ? 'png' : 'jpg'
        const drawingKey = `drawings/answer/${answerId}_${Date.now()}.${ext}`
        await r2.put(drawingKey, bytes.buffer, { httpMetadata: { contentType: ct } })
        await db.prepare('UPDATE answers SET drawing_key = ? WHERE id = ?').bind(drawingKey, answerId).run()
      } else {
        // Fallback: save raw data to DB if not base64 format
        await db.prepare('UPDATE answers SET drawing_data = ? WHERE id = ?').bind(drawing_data, answerId).run()
      }
    } catch (e) {
      // Fallback: try saving to DB directly (may fail for large data)
      try {
        await db.prepare('UPDATE answers SET drawing_data = ? WHERE id = ?').bind(drawing_data, answerId).run()
      } catch (e2) {
        logErr('answers/save-drawing', e2)
      }
    }
  }

  await db.prepare('UPDATE questions SET comment_count = (SELECT COUNT(*) FROM answers WHERE question_id = ?) WHERE id = ?').bind(questionId, questionId).run()

  // 정율톡 푸시: 질문자에게 답변 알림
  try {
    const q = await db.prepare('SELECT user_id, title, subject FROM questions WHERE id = ?').bind(questionId).first() as any
    if (q && q.user_id !== user.id) {
      const senderExtId = await getExternalId(db, user.id)
      const receiverExtId = await getExternalId(db, q.user_id)
      if (senderExtId && receiverExtId) {
        const title = (q.title || '').slice(0, 20)
        const msg = `📝 [Q&A 튜터링] ${user.nickname}님이 "${title}" 질문에 답변했습니다.\nhttps://qa-tutoring-app.pages.dev?user_id=${receiverExtId}`
        c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
      }
    }
  } catch(e: any) { logErr('push/answer', e) }

  // === 크로켓포인트 보상: 답변 등록 ===
  let cpAwarded = 0
  try {
    const q = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(questionId).first() as any
    const isSelfAnswer = q && q.user_id === user.id
    const hasQuality = (content && content.length >= CP_CONFIG.MIN_TEXT_LENGTH) || image_data || voice_key
    if (!isSelfAnswer && hasQuality) {
      // 1) 답변 등록 보상 (1 CP)
      const ansId = typeof answerId === 'number' ? answerId : parseInt(String(answerId), 10)
      const got = await awardCP(db, user.id, parseInt(String(questionId), 10), ansId, CP_CONFIG.ANSWER_SUBMIT, 'answer_submit', '답변 등록 보상')
      if (got) cpAwarded += CP_CONFIG.ANSWER_SUBMIT
      // 2) 첫 답변 보너스 (1 CP) — 오늘 첫 답변인지 체크
      const today = new Date().toISOString().slice(0, 10)
      const todayFirst = await db.prepare(
        "SELECT COUNT(*) as cnt FROM cp_logs WHERE user_id = ? AND cp_type = 'first_answer_bonus' AND DATE(created_at) = ?"
      ).bind(user.id, today).first() as any
      if (!todayFirst || todayFirst.cnt === 0) {
        const gotBonus = await awardCP(db, user.id, null, null, CP_CONFIG.FIRST_ANSWER_BONUS, 'first_answer_bonus', '오늘 첫 답변 보너스')
        if (gotBonus) cpAwarded += CP_CONFIG.FIRST_ANSWER_BONUS
      }
      // 3) 스트릭 갱신
      const streakResult = await updateStreak(db, user.id)
      if (streakResult.bonusAwarded > 0) cpAwarded += streakResult.bonusAwarded
    }
  } catch(e: any) { logErr('cp/answer-submit', e) }

  return c.json({ id: answerId, message: 'Answer created', cp_awarded: cpAwarded }, 201)
  } catch (e: any) { logErr('answers/create', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

// ===== Replies (대댓글) API =====

app.get('/api/answers/:id/replies', async (c) => {
  const db = c.env.DB
  const answerId = c.req.param('id')
  const result = await db.prepare('SELECT id, user_id, author_name, author_grade, content, created_at FROM replies WHERE answer_id = ? ORDER BY created_at ASC LIMIT 100').bind(answerId).all()
  return c.json(result.results || [])
})

app.post('/api/answers/:id/replies', async (c) => {
  try {
  const db = c.env.DB
  const answerId = c.req.param('id')
  const { content } = await c.req.json()
  if (!content || content.trim().length < 1) return c.json({ error: '내용을 입력해주세요.' }, 400)
  // P1-10: 댓글 콘텐츠 길이 제한
  if (content.length > 2000) return c.json({ error: '댓글은 2,000자 이내로 작성해주세요.' }, 400)

  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  // P2-15: 댓글 생성 레이트 리밋 (15회/분)
  const rlimit = checkContentRateLimit(user.id, 'reply')
  if (!rlimit.allowed) return c.json({ error: '댓글 등록이 너무 빠릅니다. 잠시 후 다시 시도해주세요.' }, 429)

  const result = await db.prepare(
    'INSERT INTO replies (answer_id, user_id, author_name, author_grade, content) VALUES (?, ?, ?, ?, ?)'
  ).bind(answerId, user.id, user.nickname, user.grade, content.trim()).run()

  // 정율톡 푸시: 답변자에게 댓글 알림
  try {
    const ans = await db.prepare('SELECT user_id, question_id FROM answers WHERE id = ?').bind(answerId).first() as any
    if (ans && ans.user_id !== user.id) {
      const senderExtId = await getExternalId(db, user.id)
      const receiverExtId = await getExternalId(db, ans.user_id)
      if (senderExtId && receiverExtId) {
        const msg = `💬 [Q&A 튜터링] ${user.nickname}님이 답변에 댓글을 남겼습니다: "${content.trim().slice(0, 30)}"\nhttps://qa-tutoring-app.pages.dev/question/${ans.question_id}?user_id=${receiverExtId}`
        c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
      }
    }
    // 질문자에게도 알림 (답변자와 다른 경우)
    if (ans) {
      const q = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(ans.question_id).first() as any
      if (q && q.user_id !== user.id && q.user_id !== ans.user_id) {
        const senderExtId = await getExternalId(db, user.id)
        const receiverExtId = await getExternalId(db, q.user_id)
        if (senderExtId && receiverExtId) {
          const msg = `💬 [Q&A 튜터링] ${user.nickname}님이 질문의 댓글에 답했습니다.\nhttps://qa-tutoring-app.pages.dev/question/${ans.question_id}?user_id=${receiverExtId}`
          c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
        }
      }
    }
  } catch(e: any) { logErr('push/reply', e) }

  return c.json({ id: result.meta.last_row_id, message: 'Reply created' }, 201)
  } catch (e: any) { logErr('replies/create', e); return c.json({ error: '서버 오류가 발생했습니다.' }, 500) }
})

app.delete('/api/replies/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  const reply = await db.prepare('SELECT user_id FROM replies WHERE id = ?').bind(id).first() as any
  if (!reply) return c.json({ error: 'Not found' }, 404)
  if (reply.user_id != user.id) return c.json({ error: '권한이 없습니다.' }, 403)
  await db.prepare('DELETE FROM replies WHERE id = ?').bind(id).run()
  return c.json({ success: true })
})

app.delete('/api/answers/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  const answer = await db.prepare('SELECT user_id, question_id FROM answers WHERE id = ?').bind(id).first() as any
  if (!answer) return c.json({ error: 'Not found' }, 404)
  if (answer.user_id != user.id) return c.json({ error: '권한이 없습니다.' }, 403)
  // P0-6: db.batch() 트랜잭션 — 댓글 삭제 + 답변 삭제 + 카운트 갱신을 원자적으로 처리
  await db.batch([
    db.prepare('DELETE FROM replies WHERE answer_id = ?').bind(id),
    db.prepare('DELETE FROM answers WHERE id = ?').bind(id),
    db.prepare('UPDATE questions SET comment_count = (SELECT COUNT(*) FROM answers WHERE question_id = ? AND id != ?) WHERE id = ?').bind(answer.question_id, id, answer.question_id),
  ])
  return c.json({ success: true })
})

app.patch('/api/answers/:id/accept', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: '로그인이 필요합니다.' }, 401)
  const id = c.req.param('id')
  const body = await c.req.json() as any
  const { tags, review } = body || {}
  const answer = await db.prepare('SELECT question_id, user_id FROM answers WHERE id = ?').bind(id).first() as any
  if (!answer) return c.json({ error: 'Not found' }, 404)
  // Verify the requester is the question author
  const question = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(answer.question_id).first() as any
  if (!question || question.user_id != user.id) return c.json({ error: '질문 작성자만 채택할 수 있습니다.' }, 403)
  // 자기 채택 방지: 질문자 = 답변자인 경우 채택 차단
  if (answer.user_id === user.id) return c.json({ error: '본인의 답변은 채택할 수 없습니다.' }, 400)

  // I3: db.batch() 트랜잭션 — 이전 채택 초기화 + 새 채택 + 질문 상태를 원자적으로 처리
  const tagsJson = tags && tags.length > 0 ? JSON.stringify(tags) : null
  await db.batch([
    db.prepare('UPDATE answers SET is_accepted = 0, acceptance_tags = NULL, acceptance_review = NULL WHERE question_id = ?').bind(answer.question_id),
    db.prepare('UPDATE answers SET is_accepted = 1, acceptance_tags = ?, acceptance_review = ? WHERE id = ?').bind(tagsJson, review || null, id),
    db.prepare('UPDATE questions SET status = ? WHERE id = ?').bind('채택 완료', answer.question_id),
  ])

  // === 크로켓포인트 보상: 채택 ===
  let answererCp = 0
  let questionerCp = 0
  try {
    // 1) 답변자에게 5 CP (answer_accepted = 500원)
    const got1 = await awardCP(db, answer.user_id, answer.question_id, parseInt(id), CP_CONFIG.ANSWER_ACCEPTED, 'answer_accepted', '답변 채택 보상')
    if (got1) answererCp = CP_CONFIG.ANSWER_ACCEPTED
    // 2) 질문자에게 1 CP (accept_action = 100원)
    const got2 = await awardCP(db, user.id, answer.question_id, parseInt(id), CP_CONFIG.ACCEPT_ACTION, 'accept_action', '채택 행위 보상')
    if (got2) questionerCp = CP_CONFIG.ACCEPT_ACTION
  } catch(e: any) { logErr('cp/answer-accept', e) }

  // 정율톡 푸시: 답변자에게 채택 + CP 알림
  try {
    if (answer.user_id !== user.id) {
      const senderExtId = await getExternalId(db, user.id)
      const receiverExtId = await getExternalId(db, answer.user_id)
      if (senderExtId && receiverExtId) {
        const cpMsg = answererCp > 0 ? ` +${answererCp * 100} 크로켓포인트 획득!` : ''
        const msg = `⭐ [Q&A 튜터링] ${user.nickname}님이 회원님의 답변을 채택했습니다!${cpMsg} 🎉\nhttps://qa-tutoring-app.pages.dev/question/${answer.question_id}?user_id=${receiverExtId}`
        c.executionCtx.waitUntil(sendPush(senderExtId, receiverExtId, msg))
      }
    }
  } catch(e: any) { logErr('push/accept', e) }

  return c.json({ success: true, answerer_cp: answererCp, questioner_cp: questionerCp })
})

// ===== Ranking API =====

app.get('/api/ranking', async (c) => {
  const db = c.env.DB
  const type = c.req.query('type') || 'cp' // 'cp', 'accepted', 'weekly', 'xp'(레거시)

  if (type === 'cp') {
    // 총 CP 랭킹: 누적 획득 CP 기준
    const result = await db.prepare(`
      SELECT id as user_id, nickname, grade, earned_cp as score, cp_level as level
      FROM users
      WHERE earned_cp > 0
      ORDER BY earned_cp DESC, id ASC
      LIMIT 50
    `).all()
    return c.json({ type: 'cp', ranking: result.results || [] })
  } else if (type === 'accepted') {
    // 채택왕 랭킹: 일반 + 튜터링 통합 채택 횟수
    const result = await db.prepare(`
      SELECT u.id as user_id, u.nickname, u.grade, u.cp_level as level,
        (SELECT COUNT(*) FROM answers a WHERE a.user_id = u.id AND a.is_accepted = 1) +
        (SELECT COUNT(*) FROM tutoring_matches m WHERE m.tutor_id = u.id AND m.status = 'accepted') as accept_count
      FROM users u
      HAVING accept_count > 0
      ORDER BY accept_count DESC, u.id ASC
      LIMIT 50
    `).all()
    return c.json({ type: 'accepted', ranking: result.results || [] })
  } else if (type === 'weekly') {
    // 이번 주 MVP: 이번 주 획득 CP 기준
    const weekStart = new Date()
    weekStart.setDate(weekStart.getDate() - weekStart.getDay() + 1) // 월요일
    weekStart.setHours(0, 0, 0, 0)
    const weekStartStr = weekStart.toISOString()
    const result = await db.prepare(`
      SELECT cl.user_id, u.nickname, u.grade, u.cp_level as level,
             SUM(cl.cp_amount) as score
      FROM cp_logs cl
      JOIN users u ON cl.user_id = u.id
      WHERE cl.cp_amount > 0 AND cl.created_at >= ? AND cl.cp_type != 'migration'
      GROUP BY cl.user_id
      ORDER BY score DESC, cl.user_id ASC
      LIMIT 50
    `).bind(weekStartStr).all()
    return c.json({ type: 'weekly', ranking: result.results || [] })
  } else if (type === 'xp') {
    // 레거시 XP 랭킹 (하위 호환)
    const result = await db.prepare(`
      SELECT id as user_id, nickname, grade, xp as score
      FROM users WHERE xp > 0 ORDER BY xp DESC, id ASC LIMIT 50
    `).all()
    return c.json({ type: 'xp', ranking: result.results || [] })
  } else {
    // 기본: CP 랭킹
    const result = await db.prepare(`
      SELECT id as user_id, nickname, grade, earned_cp as score, cp_level as level
      FROM users WHERE earned_cp > 0 ORDER BY earned_cp DESC, id ASC LIMIT 50
    `).all()
    return c.json({ type: 'cp', ranking: result.results || [] })
  }
})

// ===== Debug: check worker colo =====
app.get('/api/debug/colo', async (c) => {
  const cf = (c.req.raw as any).cf || {}
  return c.json({ colo: cf.colo, country: cf.country, city: cf.city, region: cf.region, placement: cf.placement })
})

// Debug: 최근 질문의 AI 분석 상태 확인
app.get('/api/debug/ai-status', async (c) => {
  const db = c.env.DB
  const rows = await db.prepare('SELECT id, ai_analyzed, ai_model, ai_difficulty, solution_stat, created_at FROM questions ORDER BY id DESC LIMIT 5').all()
  return c.json({ questions: rows.results, deployedAnalysisModel: 'gemini-3-flash-preview (with Claude fallback)' })
})

// Debug: pre-warm 강제 테스트 (await로 결과 직접 반환)
app.get('/api/debug/pre-warm-test/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const u = await db.prepare('SELECT external_id FROM users WHERE id = (SELECT user_id FROM questions WHERE id = ?)').bind(id).first() as any
  if (!u?.external_id) return c.json({ error: 'no external_id', user: u })
  if (!c.env.AI_TUTOR_SECRET) return c.json({ error: 'no AI_TUTOR_SECRET' })
  try {
    const r = await fetch(`${c.env.AI_TUTOR_URL}/v1/practice/pre-warm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': c.env.AI_TUTOR_SECRET },
      body: JSON.stringify({ question_id: String(id), student_id: Number(u.external_id) }),
    })
    const body = await r.text()
    return c.json({ ok: r.ok, status: r.status, body, external_id: u.external_id })
  } catch (e: any) {
    return c.json({ error: e.message })
  }
})

// ===== Frontend Routes =====

app.get('/', async (c) => {
  const db = c.env.DB
  // SSR: Only load first page (35 items) for fast initial render
  // coaching_requested 컬럼 자동 마이그레이션 (아직 /api/init 안 돌렸을 수 있음)
  try { await db.prepare('ALTER TABLE questions ADD COLUMN coaching_requested INTEGER DEFAULT 0').run() } catch(e) {}
  const result = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, thumbnail_data, coaching_requested FROM questions WHERE user_id != 252 ORDER BY created_at DESC, id DESC LIMIT 35').all()
  const questions = (result.results || []) as any[]
  
  // Get current user for match status in SSR
  const ssrUser = await getAuthUser(c) as any
  await enrichQuestions(db, questions, ssrUser?.id || null)

  // SSR: Load CP balance for logged-in user
  let ssrCpBalance: number | null = null
  if (ssrUser) {
    const cpRow = await db.prepare('SELECT cp_balance FROM users WHERE id = ?').bind(ssrUser.id).first() as any
    ssrCpBalance = cpRow?.cp_balance ?? 0
  }

  // Get category counts (lightweight single query)
  const counts = await db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN difficulty IS NULL OR (difficulty != '최상' AND difficulty != '1:1심화설명') THEN 1 ELSE 0 END) as normal_count,
      SUM(CASE WHEN difficulty = '최상' THEN 1 ELSE 0 END) as killer_count,
      SUM(CASE WHEN difficulty = '1:1심화설명' THEN 1 ELSE 0 END) as tutoring_count
    FROM questions WHERE user_id != 252
  `).first() as any
  return c.html(mainPageHTML(questions, counts, ssrUser, ssrCpBalance))
})
app.get('/question/:id', async (c) => {
  const db = c.env.DB
  const qId = c.req.param('id')
  let q: any
  try {
    q = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, image_keys, content_type, passage_image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, challenge_result, requested_teacher, solution_stat, coaching_requested FROM questions WHERE id = ?').bind(qId).first()
  } catch (e) {
    // Fallback: column may not exist yet, auto-migrate
    try { await db.prepare('ALTER TABLE questions ADD COLUMN ai_next_questions TEXT DEFAULT NULL').run() } catch(e2){}
    q = await db.prepare('SELECT id, user_id, title, author_name, author_grade, content, subject, difficulty, comment_count, status, reward_points, created_at, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, thumbnail_key, image_keys, content_type, passage_image_keys, ai_difficulty, ai_tags, ai_topic_main, ai_topic_sub, ai_description, ai_grade_level, ai_estimated_time, ai_analyzed, question_type, student_question_text, ai_question_analysis, ai_coaching_comment, ai_next_questions, ai_growth_coaching, ai_model, ai_coaching_data, challenge_result, requested_teacher, solution_stat, coaching_requested FROM questions WHERE id = ?').bind(qId).first()
  }
  let answers: any
  const ssrAnsQuery = 'SELECT id, question_id, user_id, author_name, author_grade, content, is_accepted, acceptance_tags, acceptance_review, created_at, CASE WHEN (drawing_data IS NOT NULL AND drawing_data != \'\') OR (drawing_key IS NOT NULL AND drawing_key != \'\') THEN 1 ELSE 0 END as has_drawing, CASE WHEN (image_data IS NOT NULL AND image_data != \'\') OR (image_key IS NOT NULL AND image_key != \'\') THEN 1 ELSE 0 END as has_image, image_key, drawing_key, voice_key FROM answers WHERE question_id = ? ORDER BY created_at ASC LIMIT 51'
  try {
    answers = await db.prepare(ssrAnsQuery).bind(qId).all()
  } catch (e) {
    try { await db.prepare('ALTER TABLE answers ADD COLUMN drawing_key TEXT DEFAULT NULL').run() } catch(e2){}
    answers = await db.prepare(ssrAnsQuery).bind(qId).all()
  }
  const ansRows = answers.results || []
  const ssrHasMore = ansRows.length > 50
  if (ssrHasMore) ansRows.pop()
  return c.html(questionDetailHTML(q, ansRows, ssrHasMore))
})
app.get('/new', (c) => c.html(newQuestionHTML()))
app.get('/favicon.ico', (c) => new Response(null, { status: 204 }))
app.get('/login', (c) => c.redirect('/'))
app.get('/register', (c) => c.redirect('/'))
app.get('/mypage', (c) => c.html(mypageHTML()))
app.get('/cp', (c) => c.html(cpPageHTML()))
app.get('/my/dashboard', (c) => c.html(myDashboardHTML()))
app.get('/my/bookmarks', (c) => c.html(myBookmarksHTML()))
app.get('/my/history', (c) => c.html(myHistoryHTML()))
app.get('/my/history/:questionId', (c) => c.html(myHistoryDetailHTML(c.req.param('questionId'))))

// ===== BFF Proxy: /api/platform/* → ai_tutor /v1/platform/* =====
// 프론트는 이 BFF만 호출. AI_TUTOR_SECRET은 브라우저에 노출되지 않음.
// external_id = users.external_id 를 URL에 자동 주입.

async function aiTutorFetch(c: any, subPath: string, init: RequestInit & { forwardQuery?: boolean } = {}): Promise<Response> {
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const ext = user.external_id
  if (!ext) return c.json({ error: 'No external_id linked for this account' }, 403)
  const base = c.env.AI_TUTOR_URL
  const secret = c.env.AI_TUTOR_SECRET
  if (!base || !secret) return c.json({ error: 'AI_TUTOR_URL/SECRET not configured' }, 500)
  let url = `${base}/v1/platform/students/${encodeURIComponent(ext)}${subPath}`
  if (init.forwardQuery) {
    const qs = c.req.url.split('?')[1]
    if (qs) url += (url.includes('?') ? '&' : '?') + qs
  }
  const headers: Record<string, string> = {
    'X-Proxy-Secret': secret,
    'Accept': 'application/json',
    ...((init.headers as Record<string, string>) || {}),
  }
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json'
  try {
    const resp = await fetch(url, {
      method: init.method || 'GET',
      headers,
      body: init.body,
    })
    return resp
  } catch (e: any) {
    logErr('aiTutorFetch', e, { url, method: init.method || 'GET' })
    return c.json({ error: 'AI tutor unreachable', detail: String(e?.message || e) }, 503)
  }
}

// Helper: 응답 JSON 받아서 mutate 후 재생성
async function passThroughJSON(resp: Response, mutate?: (data: any) => Promise<any> | any): Promise<Response> {
  const ct = resp.headers.get('content-type') || ''
  if (!resp.ok || !ct.includes('application/json')) {
    return new Response(resp.body, { status: resp.status, headers: { 'Content-Type': ct || 'text/plain' } })
  }
  let data: any
  try { data = await resp.json() } catch (e) { return new Response('Invalid JSON from upstream', { status: 502 }) }
  if (mutate) data = (await mutate(data)) ?? data
  return new Response(JSON.stringify(data), { status: resp.status, headers: { 'Content-Type': 'application/json' } })
}

// Helper: 우리 DB에서 질문 메타 조회 → thumbnail_url/question_url 생성
async function enrichHistoryItems(db: D1Database, items: any[]): Promise<void> {
  if (!Array.isArray(items) || items.length === 0) return
  const ids = items.map(it => Number(it.question_id)).filter(n => Number.isFinite(n))
  if (ids.length === 0) return
  const placeholders = ids.map(() => '?').join(',')
  const rows = await db.prepare(`SELECT id, title, subject, thumbnail_key, thumbnail_data, CASE WHEN (image_data IS NOT NULL AND image_data != '') OR (image_key IS NOT NULL AND image_key != '') THEN 1 ELSE 0 END as has_image FROM questions WHERE id IN (${placeholders})`).bind(...ids).all()
  const byId: Record<string, any> = {}
  for (const r of (rows.results || []) as any[]) byId[String(r.id)] = r
  for (const it of items) {
    const q = byId[String(it.question_id)]
    if (q) {
      if (q.thumbnail_key) it.thumbnail_url = `/api/images/${q.thumbnail_key}`
      else if (q.thumbnail_data) it.thumbnail_url = q.thumbnail_data
      else it.thumbnail_url = null
      // 우리 DB 값으로 덮어씀 (ai_tutor 쪽 stale 방지)
      if (q.title) it.title = q.title
      if (q.subject) it.our_subject = q.subject
    } else {
      // 우리 DB에 없는 질문 = 삭제됨
      it._deleted = true
    }
    it.question_url = `/question/${it.question_id}`
  }
}

// 0. 활동 히트맵 (12주 잔디)
app.get('/api/dashboard/activity-heatmap', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ days: [] })
  const rows = await db.prepare(
    `SELECT DATE(created_at) as day, COUNT(*) as actions,
            SUM(CASE WHEN cp_amount > 0 THEN cp_amount ELSE 0 END) as cp_earned
     FROM cp_logs WHERE user_id = ? AND created_at >= date('now', '-84 days')
       AND cp_type != 'migration'
     GROUP BY DATE(created_at) ORDER BY day ASC`
  ).bind(user.id).all() as any
  return c.json({ days: rows.results || [] })
})

// 1. 대시보드
app.get('/api/platform/dashboard', async (c) => {
  const resp = await aiTutorFetch(c, '/dashboard', { forwardQuery: true })
  return passThroughJSON(resp)
})

// 2. 찜한 문제
app.get('/api/platform/bookmarks', async (c) => {
  const resp = await aiTutorFetch(c, '/bookmarks', { forwardQuery: true })
  return passThroughJSON(resp, async (data) => {
    // groups[].items[] 또는 items[] 둘 다 가능. 원 질문 메타를 주입하고 싶다면 여기서.
    // 찜 목록은 item 단위라 question 메타는 groups 레벨에 이미 있어서 skip.
    return data
  })
})

// 3. 질문 히스토리 리스트
app.get('/api/platform/question-history', async (c) => {
  const resp = await aiTutorFetch(c, '/question-history', { forwardQuery: true })
  return passThroughJSON(resp, async (data) => {
    if (data && Array.isArray(data.items)) {
      await enrichHistoryItems(c.env.DB, data.items)
      // 우리 DB에서 삭제된 질문은 히스토리에서 제외
      data.items = data.items.filter((it: any) => !it._deleted)
    }
    return data
  })
})

// 4. 질문 히스토리 상세
app.get('/api/platform/question-history/:questionId', async (c) => {
  const qid = c.req.param('questionId')
  const resp = await aiTutorFetch(c, `/question-history/${encodeURIComponent(qid)}`)
  return passThroughJSON(resp, async (data) => {
    // 최상위 객체에도 우리 DB의 원 질문 메타 주입
    if (data && data.question_id) {
      await enrichHistoryItems(c.env.DB, [data])
    }
    return data
  })
})

// 5. 찜 토글
app.post('/api/platform/bookmark', async (c) => {
  let body: any = {}
  try { body = await c.req.json() } catch (e) { return c.json({ error: 'Invalid JSON body' }, 400) }
  const resp = await aiTutorFetch(c, '/bookmark', {
    method: 'POST',
    body: JSON.stringify({ item_id: body.item_id, practice_id: body.practice_id }),
  })
  return passThroughJSON(resp)
})
app.get('/coaching', (c) => c.html(coachingPageHTML()))
app.get('/coaching/:userId', (c) => c.html(coachingPageHTML()))
app.get('/schedule', (c) => c.html(schedulePageHTML()))

// Helper: award XP to user (with duplicate prevention) — 레거시, 기존 코칭 코드 호환용
async function awardXP(db: any, userId: number, questionId: number | null, amount: number, type: string, description: string) {
  if (amount <= 0) return false
  if (questionId) {
    const res = await db.prepare(
      'INSERT OR IGNORE INTO xp_logs (user_id, question_id, xp_amount, xp_type, description) VALUES (?, ?, ?, ?, ?)'
    ).bind(userId, questionId, amount, type, description).run()
    if (!res.meta.changes) return false
  } else {
    await db.prepare(
      'INSERT INTO xp_logs (user_id, question_id, xp_amount, xp_type, description) VALUES (?, ?, ?, ?, ?)'
    ).bind(userId, questionId, amount, type, description).run()
  }
  await db.prepare('UPDATE users SET xp = xp + ? WHERE id = ?').bind(amount, userId).run()
  return true
}

// ====================================================================
// 크로켓포인트(CP) 시스템 — 1 CP = 100원
// ====================================================================

const CP_CONFIG = {
  // 기본 보상
  ANSWER_SUBMIT: 1,           // 답변 등록 (100원)
  FIRST_ANSWER_BONUS: 1,      // 첫 답변 보너스 (100원)
  ANSWER_ACCEPTED: 10,          // 일반 답변 채택됨 (1000원)
  ACCEPT_ACTION: 1,            // 채택 행위 보상 — 질문자 (100원)

  // 튜터링 보상 (난이도별)
  TUTORING_ACCEPTED: { low: 10, mid: 15, high: 20 } as Record<string, number>,
  KILLER_ACCEPTED: { low: 3, mid: 5, high: 8 } as Record<string, number>,

  // 튜터링/킬러 비용 (질문자 차감)
  TUTORING_COST: { low: 10, mid: 15, high: 20 } as Record<string, number>,
  KILLER_COST: { low: 3, mid: 5, high: 8 } as Record<string, number>,

  // 좋아요 마일스톤
  LIKE_MILESTONE_5: 1,
  LIKE_MILESTONE_10: 1,

  // 스트릭 보너스
  STREAK_BONUS: { 3: 2, 7: 5, 14: 10, 30: 20 } as Record<number, number>,

  // 챌린지 (레벨별)
  CHALLENGE: {
    'A-1': 2, 'A-2': 3, 'B-1': 4, 'B-2': 5,
    'C-1': 6, 'C-2': 8, 'R-1': 4, 'R-2': 5, 'R-3': 6
  } as Record<string, number>,
  TIER2_STEP: 2,

  // 패널티
  REPORT_PENALTY: -10,

  // 레벨 테이블
  LEVELS: [
    { level: 1, cp: 0, title: '새싹' },
    { level: 2, cp: 30, title: '학습자' },
    { level: 3, cp: 100, title: '조력자' },
    { level: 4, cp: 250, title: '멘토' },
    { level: 5, cp: 500, title: '마스터' },
    { level: 6, cp: 1000, title: '전설' },
  ],

  // 품질 기준
  MIN_TEXT_LENGTH: 20,
  CP_TO_WON: 100,
}

// Helper: CP 지급 (중복 방지 포함)
async function awardCP(
  db: any, userId: number, questionId: number | null, answerId: number | null,
  amount: number, cpType: string, description: string
): Promise<boolean> {
  if (amount === 0) return false
  const qId = questionId || 0
  const aId = answerId || 0

  // 차감 시 잔액 체크
  if (amount < 0) {
    const user = await db.prepare('SELECT cp_balance FROM users WHERE id = ?').bind(userId).first() as any
    if (!user || (user.cp_balance || 0) < Math.abs(amount)) {
      return false // 잔액 부족
    }
  }

  // 반복 가능한 cp_type: 중복 방지 없이 매번 INSERT
  const REPEATABLE_TYPES = ['killer_request', 'tutoring_request', 'first_answer_bonus', 'streak_3', 'streak_7', 'streak_14', 'streak_30']
  const isRepeatable = REPEATABLE_TYPES.includes(cpType)

  const kstNow = new Date(Date.now() + 9 * 3600000).toISOString().slice(0, 19).replace('T', ' ')
  const sql = isRepeatable
    ? 'INSERT INTO cp_logs (user_id, question_id, answer_id, cp_amount, cp_type, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    : 'INSERT OR IGNORE INTO cp_logs (user_id, question_id, answer_id, cp_amount, cp_type, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  const res = await db.prepare(sql).bind(userId, qId, aId, amount, cpType, description, kstNow).run()
  if (!res.meta.changes) return false // 이미 지급됨 (1회성 타입만 해당)

  // cp_balance와 earned_cp 갱신
  if (amount > 0) {
    await db.prepare('UPDATE users SET cp_balance = cp_balance + ?, earned_cp = earned_cp + ? WHERE id = ?').bind(amount, amount, userId).run()
  } else {
    // 차감은 cp_balance만 (earned_cp는 누적 획득이므로 차감 안 함)
    await db.prepare('UPDATE users SET cp_balance = MAX(0, cp_balance + ?) WHERE id = ?').bind(amount, userId).run()
  }
  // 레벨 체크 & 갱신
  await updateLevel(db, userId)
  return true
}

// Helper: 레벨 계산 및 갱신
async function updateLevel(db: any, userId: number): Promise<number> {
  const user = await db.prepare('SELECT earned_cp, cp_level FROM users WHERE id = ?').bind(userId).first() as any
  if (!user) return 1
  let newLevel = 1
  for (const lv of CP_CONFIG.LEVELS) {
    if (user.earned_cp >= lv.cp) newLevel = lv.level
  }
  if (newLevel !== user.cp_level) {
    await db.prepare('UPDATE users SET cp_level = ? WHERE id = ?').bind(newLevel, userId).run()
  }
  return newLevel
}

// Helper: 레벨 정보 가져오기
function getLevelInfo(earnedCp: number) {
  let current = CP_CONFIG.LEVELS[0]
  let next = CP_CONFIG.LEVELS[1] || null
  for (let i = 0; i < CP_CONFIG.LEVELS.length; i++) {
    if (earnedCp >= CP_CONFIG.LEVELS[i].cp) {
      current = CP_CONFIG.LEVELS[i]
      next = CP_CONFIG.LEVELS[i + 1] || null
    }
  }
  return { current, next }
}

// Helper: 스트릭 갱신 및 보너스 지급
async function updateStreak(db: any, userId: number): Promise<{ streak: number, bonusAwarded: number }> {
  const user = await db.prepare('SELECT answer_streak, last_answer_date FROM users WHERE id = ?').bind(userId).first() as any
  if (!user) return { streak: 0, bonusAwarded: 0 }

  const today = new Date().toISOString().slice(0, 10) // YYYY-MM-DD
  const lastDate = user.last_answer_date || ''

  if (lastDate === today) {
    // 오늘 이미 답변함 → 스트릭 변경 없음
    return { streak: user.answer_streak, bonusAwarded: 0 }
  }

  let newStreak: number
  if (lastDate) {
    const lastD = new Date(lastDate + 'T00:00:00Z')
    const todayD = new Date(today + 'T00:00:00Z')
    const diffDays = Math.floor((todayD.getTime() - lastD.getTime()) / 86400000)
    if (diffDays === 1) {
      newStreak = (user.answer_streak || 0) + 1
    } else {
      newStreak = 1 // 연속 끊김
    }
  } else {
    newStreak = 1
  }

  await db.prepare('UPDATE users SET answer_streak = ?, last_answer_date = ? WHERE id = ?')
    .bind(newStreak, today, userId).run()

  // 스트릭 마일스톤 보너스 체크
  let bonusAwarded = 0
  const bonus = CP_CONFIG.STREAK_BONUS[newStreak]
  if (bonus) {
    const awarded = await awardCP(db, userId, null, null, bonus, `streak_${newStreak}`, `${newStreak}일 연속 답변 보너스`)
    if (awarded) bonusAwarded = bonus
  }
  return { streak: newStreak, bonusAwarded }
}

// === CP API Endpoints (크로켓포인트) ===

// GET /api/cp — 사용자 CP 정보 조회
app.get('/api/cp', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ cp_balance: 0, earned_cp: 0, level: 1, level_title: '새싹' })

  const row = await db.prepare('SELECT cp_balance, earned_cp, cp_level, answer_streak, last_answer_date FROM users WHERE id = ?').bind(user.id).first() as any
  const cpBalance = row?.cp_balance || 0
  const earnedCp = row?.earned_cp || 0
  const level = row?.cp_level || 1
  const streak = row?.answer_streak || 0
  const { current, next } = getLevelInfo(earnedCp)
  const progressPercent = next ? Math.min(100, Math.floor((earnedCp - current.cp) / (next.cp - current.cp) * 100)) : 100

  // 오늘 획득 CP
  const today = new Date().toISOString().slice(0, 10)
  const todayRow = await db.prepare(
    "SELECT COALESCE(SUM(cp_amount), 0) as today_earned FROM cp_logs WHERE user_id = ? AND cp_amount > 0 AND DATE(created_at) = ? AND cp_type != 'migration'"
  ).bind(user.id, today).first() as any
  const todayAnswers = await db.prepare(
    "SELECT COUNT(*) as cnt FROM cp_logs WHERE user_id = ? AND cp_type = 'answer_submit' AND DATE(created_at) = ?"
  ).bind(user.id, today).first() as any

  return c.json({
    cp_balance: cpBalance,
    earned_cp: earnedCp,
    level,
    level_title: current.title,
    next_level_cp: next?.cp || null,
    progress_percent: progressPercent,
    answer_streak: streak,
    today_earned: todayRow?.today_earned || 0,
    today_answers: todayAnswers?.cnt || 0,
  })
})

// GET /api/cp/history — CP 변동 이력
app.get('/api/cp/history', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ logs: [], total: 0, page: 1 })

  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '20'), 50)
  const offset = (page - 1) * limit

  const totalRow = await db.prepare(
    "SELECT COUNT(*) as cnt FROM cp_logs WHERE user_id = ? AND cp_type != 'migration'"
  ).bind(user.id).first() as any
  const total = totalRow?.cnt || 0

  const logs = await db.prepare(
    "SELECT id, cp_amount, cp_type, description, created_at FROM cp_logs WHERE user_id = ? AND cp_type != 'migration' ORDER BY created_at DESC LIMIT ? OFFSET ?"
  ).bind(user.id, limit, offset).all() as any

  return c.json({ logs: logs.results || [], total, page })
})

// GET /api/cp/question/:id — 특정 질문에서 얻은 CP
app.get('/api/cp/question/:id', async (c) => {
  const db = c.env.DB
  const questionId = parseInt(c.req.param('id'))
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ totalCp: 0, questionCp: 0, logs: [] })

  const row = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(user.id).first() as any
  const logs = await db.prepare(
    'SELECT cp_amount, cp_type, description, created_at FROM cp_logs WHERE user_id = ? AND question_id = ? ORDER BY created_at DESC LIMIT 20'
  ).bind(user.id, questionId).all() as any

  const questionCp = (logs.results || []).reduce((sum: number, l: any) => sum + (l.cp_amount || 0), 0)
  return c.json({ totalCp: row?.earned_cp || 0, questionCp, logs: logs.results || [] })
})

// 레거시 XP API (하위 호환 — CP로 포워딩)
app.get('/api/xp/question/:id', async (c) => {
  const db = c.env.DB
  const questionId = parseInt(c.req.param('id'))
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ totalXp: 0, questionXp: 0, logs: [] })
  const row = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(user.id).first() as any
  const logs = await db.prepare(
    'SELECT cp_amount as xp_amount, cp_type as xp_type, description, created_at FROM cp_logs WHERE user_id = ? AND question_id = ? ORDER BY created_at DESC LIMIT 20'
  ).bind(user.id, questionId).all() as any
  const questionXp = (logs.results || []).reduce((sum: number, l: any) => sum + (l.xp_amount || 0), 0)
  return c.json({ totalXp: row?.earned_cp || 0, questionXp, logs: logs.results || [] })
})

app.get('/api/xp', async (c) => {
  const db = c.env.DB
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ totalXp: 0, recentLogs: [] })
  const row = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(user.id).first() as any
  const logs = await db.prepare(
    "SELECT cp_amount as xp_amount, cp_type as xp_type, description, created_at FROM cp_logs WHERE user_id = ? AND cp_type != 'migration' ORDER BY created_at DESC LIMIT 30"
  ).bind(user.id).all() as any
  return c.json({ totalXp: row?.earned_cp || 0, recentLogs: logs.results || [] })
})

// === Coaching API ===
app.get('/api/coaching/stats', async (c) => {
  const db = c.env.DB
  let userId: number | null = null
  let viewerName = ''

  // Check if specific user is requested via query param
  const targetUserId = c.req.query('userId')
  if (targetUserId) {
    userId = parseInt(targetUserId)
    const targetUser = await db.prepare('SELECT id, nickname FROM users WHERE id = ?').bind(userId).first() as any
    if (!targetUser) return c.json({ error: 'User not found' }, 404)
    viewerName = targetUser.nickname
  } else {
    // Fallback to authenticated user
    const token = c.req.header('Authorization')?.replace('Bearer ', '')
    if (!token) return c.json({ error: 'Unauthorized' }, 401)
    const session = await db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')').bind(token).first() as any
    if (!session) return c.json({ error: 'Unauthorized' }, 401)
    userId = session.user_id
    const user = await db.prepare('SELECT nickname FROM users WHERE id = ?').bind(userId).first() as any
    viewerName = user?.nickname || ''
  }

  // P1-8: 코칭 통계 쿼리 최적화 — 7개 쿼리를 2개로 통합 (DB 왕복 71% 감소)
  // Query 1: 전체 질문 (타입 + 날짜) — counts + weekly trend를 JS에서 계산
  const questions = await db.prepare(
    'SELECT question_type, created_at FROM questions WHERE user_id = ? AND question_type IS NOT NULL ORDER BY created_at DESC'
  ).bind(userId).all() as any

  const counts: Record<string, number> = { 'A-1': 0, 'A-2': 0, 'B-1': 0, 'B-2': 0, 'C-1': 0, 'C-2': 0, 'R-1': 0, 'R-2': 0, 'R-3': 0 }
  for (const q of (questions.results || [])) {
    if (q.question_type && counts[q.question_type] !== undefined) {
      counts[q.question_type]++
    }
  }

  // Query 2: 최근 10개 질문 상세
  const recent = await db.prepare(
    'SELECT id, title, content, question_type, subject, student_question_text, created_at FROM questions WHERE user_id = ? AND question_type IS NOT NULL ORDER BY created_at DESC LIMIT 10'
  ).bind(userId).all() as any

  // Weekly trend: JS 날짜 버킷팅 (기존 5개 쿼리 루프 제거)
  const weights: Record<string, number> = { 'A-1': 1, 'A-2': 2, 'B-1': 5, 'B-2': 7, 'C-1': 8, 'C-2': 10, 'R-1': 4, 'R-2': 6, 'R-3': 8 }
  const now = Date.now()
  const DAY_MS = 86400000
  const weekBuckets: Record<string, number>[] = Array.from({ length: 5 }, () => ({ 'A-1': 0, 'A-2': 0, 'B-1': 0, 'B-2': 0, 'C-1': 0, 'C-2': 0, 'R-1': 0, 'R-2': 0, 'R-3': 0 }))
  for (const q of (questions.results || []) as any[]) {
    if (!q.question_type || !q.created_at) continue
    const age = now - new Date(q.created_at + (q.created_at.endsWith('Z') ? '' : 'Z')).getTime()
    const weekIdx = Math.floor(age / (7 * DAY_MS))
    if (weekIdx >= 0 && weekIdx < 5 && weekBuckets[weekIdx][q.question_type] !== undefined) {
      weekBuckets[weekIdx][q.question_type]++
    }
  }
  const weeklyScores: any[] = []
  for (let w = 4; w >= 0; w--) {
    const wCounts = weekBuckets[w]
    const total = Object.values(wCounts).reduce((a, b) => a + b, 0)
    let weighted = 0
    Object.entries(wCounts).forEach(([k, v]) => { weighted += (weights[k] || 0) * v })
    const score = total === 0 ? 0 : Math.min(100, Math.round((weighted / (total * 10)) * 100))
    weeklyScores.push({ week: w === 0 ? '이번주' : w + '주전', score, total })
  }

  // Total questions for this user (all, not just typed)
  const totalRes = await db.prepare('SELECT COUNT(*) as cnt FROM questions WHERE user_id = ?').bind(userId).first() as any
  
  return c.json({
    counts,
    recentQuestions: (recent.results || []).map((q: any) => ({
      id: q.id, text: q.student_question_text || q.title || q.content, cat: q.question_type, subject: q.subject, date: q.created_at, studentQ: q.student_question_text
    })),
    weeklyScores,
    totalQuestions: totalRes?.cnt || 0,
    userName: viewerName,
    userId: userId
  })
})

// Coaching: upgrade suggestion — OpenAI
app.post('/api/coaching/upgrade', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime(\'now\')').bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)

  const { questionId, questionText, questionType, subject, difficulty } = await c.req.json()
  const openaiKey = c.env.OPENAI_API_KEY

  if (!openaiKey) return c.json({ error: 'No AI API key configured' }, 500)

  const upgradeExternalId = await getExternalId(db, session.user_id)

  const typeNames: Record<string, string> = {
    '1-1': '뭐지?', '1-2': '어떻게?', '2-1': '왜?', '2-2': '만약에?',
    '2-3': '어디서 틀렸지?', '3-1': '뭐가 더 나아?', '3-2': '그러면?',
    'A-1': '뭐지?', 'A-2': '어떻게?', 'B-1': '왜?', 'B-2': '만약에?',
    'C-1': '뭐가 더 나아?', 'C-2': '그러면?', 'R-1': '어디서 틀렸지?', 'R-2': '왜 틀렸지?', 'R-3': '다음엔 어떻게?'
  }
  const upgradeMap: Record<string, string[]> = {
    'A-1': ['A-2','B-1'], 'A-2': ['B-1','B-2'], 'B-1': ['B-2','C-1'],
    'B-2': ['C-1','C-2'], 'C-1': ['C-2'], 'C-2': ['C-2'],
    'R-1': ['R-2','B-1'], 'R-2': ['R-3','B-2'], 'R-3': ['R-3'],
    '1-1': ['A-2','B-1'], '1-2': ['B-1','R-1'], '2-1': ['B-2','C-1'],
    '2-2': ['B-2','C-1'], '2-3': ['R-1','R-2'], '3-1': ['C-2'], '3-2': ['C-2']
  }
  const targets = upgradeMap[questionType] || ['2-1']

  const prompt = `당신은 고등학생 질문 코칭 전문가입니다.

★★★ 질문 톤 규칙: 추천 질문은 학생 혼잣말/궁금증 스타일로 작성! (선생님 질문 금지)
좋은 예: "근데 왜 여기서 치환을 쓰는 거지?", "내 풀이 어디가 틀린 거야?"
수식은 LaTeX로 작성: 인라인 $x^2$, 독립 $$\\int f(x)dx$$

학생의 원래 질문: "${questionText}"
현재 질문 유형: ${questionType} (${typeNames[questionType] || '미분류'})
과목: ${subject || '수학'}

이 질문을 더 높은 수준으로 업그레이드하여 학생의 사고력을 향상시켜주세요.

다음 유형들로 업그레이드된 질문 예시를 각각 만들어주세요:
${targets.map(t => `- ${t} (${typeNames[t]})`).join('\n')}

반드시 아래 JSON 형식으로만 응답하세요:
{
  "upgrades": [
    {
      "targetType": "B-1",
      "targetTypeName": "왜?",
      "upgradedQuestion": "학생 혼잣말 스타일의 업그레이드된 질문",
      "explanation": "왜 이 질문이 더 좋은지 한 줄 설명",
      "tip": "이런 질문을 하면 좋은 이유 팁"
    }
  ],
  "model": "openai"
}`

  try {
    const result = await callOpenAI(
      openaiKey, 'gpt-5.4',
      '당신은 고등학생 질문 코칭 전문가입니다. JSON 형식으로만 응답하세요.',
      prompt, 4096,
      { dedupKey: `upgrade-${questionId}`, timeoutMs: 30000, proxy: proxyOpts(c.env, 'upgrade', questionId, upgradeExternalId) }
    )
    if (!result.ok || !result.text) throw new Error(result.error || 'OpenAI failed')

    let jsonStr = ''
    const cbm = result.text.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (cbm) jsonStr = cbm[1].trim()
    else { const m = result.text.match(/\{[\s\S]*\}/); if (m) jsonStr = m[0] }
    if (!jsonStr) throw new Error('No JSON in OpenAI response')

    const resultJson = safeJsonParse(jsonStr)
    resultJson.model = 'openai'
    return c.json(resultJson)
  } catch (e: any) {
    return c.json({ error: e.message }, 500)
  }
})

// === Coaching Log API ===
app.post('/api/coaching/log', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)
  const { questionId, step, choice, timeSpentMs, imageKey, recognizedText } = await c.req.json()
  if (!questionId || !step || !choice) return c.json({ error: 'Missing fields' }, 400)
  await db.prepare('INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms, image_key, recognized_text) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(questionId, session.user_id, step, choice, timeSpentMs || 0, imageKey || null, recognizedText || null).run()
  return c.json({ success: true })
})

// === 코칭 로그 조회 API (리뷰용) ===
app.get('/api/coaching/logs/:questionId', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)
  const questionId = c.req.param('questionId')
  const logs = await db.prepare(
    'SELECT step, choice, time_spent_ms, created_at FROM coaching_logs WHERE question_id = ? AND user_id = ? ORDER BY created_at ASC'
  ).bind(questionId, session.user_id).all()
  return c.json({ success: true, logs: logs.results || [] })
})

// === 코칭 로그 초기화 API (다시하기용) ===
app.post('/api/coaching/logs/:questionId/reset', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)
  const questionId = c.req.param('questionId')
  await db.prepare('DELETE FROM coaching_logs WHERE question_id = ? AND user_id = ?').bind(questionId, session.user_id).run()
  return c.json({ success: true })
})

// === 도전! 질문 진단 API (이미지+텍스트) ===
app.post('/api/coaching/challenge', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)

  const { questionId, challengeText, challengeImageKey } = await c.req.json()
  if (!questionId) return c.json({ error: 'Missing questionId' }, 400)
  if (!challengeText && !challengeImageKey) return c.json({ error: '질문 텍스트나 이미지를 제출해주세요' }, 400)

  const openaiKey = c.env.OPENAI_API_KEY
  if (!openaiKey) return c.json({ error: 'AI key not configured' }, 500)

  // Get original question info
  const q = await db.prepare('SELECT q.user_id, q.question_type, q.student_question_text, q.content, q.subject, q.ai_difficulty, q.challenge_result, u.external_id FROM questions q JOIN users u ON q.user_id = u.id WHERE q.id = ?').bind(questionId).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)

  // Only the question author can challenge
  if (q.user_id !== session.user_id) {
    return c.json({ error: '질문을 올린 학생만 도전할 수 있습니다.' }, 403)
  }

  // Only one challenge per question
  if (q.challenge_result) {
    return c.json({ error: '이 질문에 대해 이미 도전을 완료했습니다.' }, 409)
  }

  const currentLevel = q.question_type || 'A-1'
  const originalText = q.student_question_text || q.content || ''

  try {
    let imageBase64 = null
    let imageMime = 'image/jpeg'

    // If image key provided, get from R2
    if (challengeImageKey && c.env.R2) {
      const obj = await c.env.R2.get(challengeImageKey)
      if (obj) {
        const buf = await obj.arrayBuffer()
        // E3: 청크 단위 base64 변환 — spread 연산자는 큰 버퍼에서 스택 오버플로우 발생
        const bytes = new Uint8Array(buf); let binary = ''
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
        imageBase64 = btoa(binary)
        imageMime = obj.httpMetadata?.contentType || 'image/jpeg'
      }
    }

    const challengePrompt = imageBase64
      ? `학생이 도전 질문을 손으로 써서 사진으로 제출했습니다.

1단계: 이미지에서 학생의 필기를 인식하세요.
2단계: 인식된 텍스트를 기반으로 2축 9단계 엄격 기준으로 진단하세요.

원래 질문 수준: ${currentLevel}
원래 질문 내용: ${originalText.slice(0, 300)}

[2축 9단계]
호기심축: A-1(뭐지?), A-2(어떻게?), B-1(왜?), B-2(만약에?), C-1(뭐가 더 나아?), C-2(그러면?)
성찰축: R-1(어디서 틀렸지?), R-2(왜 틀렸지?), R-3(다음엔 어떻게?)

[3대 필수 조건 - B 이상 요구]
① 구체적 대상: 문제의 어떤 부분인지 특정
② 자기 생각: "나는 ~라고 생각하는데" 존재 여부
③ 맥락 연결: 지문/조건과 연결
→ 하나라도 없으면 무조건 A 수준

★★★ 수식은 LaTeX로: 인라인 $x^2$, 독립 $$\\int f(x)dx$$

반드시 JSON만 응답:
{
  "recognized_text": "이미지에서 인식한 학생의 필기 내용",
  "question_level": "B-1",
  "axis": "curiosity 또는 reflection",
  "diagnosis": {
    "specific_target": {"met": true, "detail": "근거"},
    "own_thinking": {"met": true, "detail": "근거"},
    "context_connection": {"met": true, "detail": "근거"}
  },
  "feedback": "진단 결과 피드백 (격려 포함, 2~3문장)",
  "upgrade_hint": "다음 레벨로 가려면 이렇게! (1~2문장)"
}`
      : `학생이 도전 질문을 텍스트로 제출했습니다.

2축 9단계 엄격 기준으로 진단하세요.

원래 질문 수준: ${currentLevel}
원래 질문 내용: ${originalText.slice(0, 300)}
도전 질문: ${challengeText}

[2축 9단계]
호기심축: A-1(뭐지?), A-2(어떻게?), B-1(왜?), B-2(만약에?), C-1(뭐가 더 나아?), C-2(그러면?)
성찰축: R-1(어디서 틀렸지?), R-2(왜 틀렸지?), R-3(다음엔 어떻게?)

[3대 필수 조건 - B 이상 요구]
① 구체적 대상: 문제의 어떤 부분인지 특정
② 자기 생각: "나는 ~라고 생각하는데" 존재 여부
③ 맥락 연결: 지문/조건과 연결
→ 하나라도 없으면 무조건 A 수준

★★★ 수식은 LaTeX로: 인라인 $x^2$, 독립 $$\\int f(x)dx$$

반드시 JSON만 응답:
{
  "recognized_text": null,
  "question_level": "B-1",
  "axis": "curiosity 또는 reflection",
  "diagnosis": {
    "specific_target": {"met": true, "detail": "근거"},
    "own_thinking": {"met": true, "detail": "근거"},
    "context_connection": {"met": true, "detail": "근거"}
  },
  "feedback": "진단 결과 피드백 (격려 포함, 2~3문장)",
  "upgrade_hint": "다음 레벨로 가려면 이렇게! (1~2문장)"
}`

    // Call OpenAI
    const openaiContent: any[] = []
    if (imageBase64) {
      openaiContent.push({ type: 'image_url', image_url: { url: `data:${imageMime};base64,${imageBase64}` } })
    }
    openaiContent.push({ type: 'text', text: challengePrompt })

    const challengeResult = await callOpenAI(
      openaiKey, 'gpt-5.4',
      '학생 질문 진단 전문가입니다. JSON 형식으로만 응답하세요.',
      openaiContent,
      2000,
      { dedupKey: `challenge-diag-${questionId}`, timeoutMs: 30000, proxy: proxyOpts(c.env, 'challenge', questionId, q.external_id || null) }
    )

    if (!challengeResult.ok) {
      logErr('openai/challenge', challengeResult.error)
      return c.json({ error: 'AI 서비스 오류' }, 500)
    }

    const text = challengeResult.text || ''
    let result: any = null
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/)
      if (jsonMatch) result = safeJsonParse(jsonMatch[0])
    } catch (e) {
      logErr('challenge/json-parse', e, { raw: text.slice(0, 200) })
    }

    if (!result) return c.json({ error: 'AI 분석 결과를 파싱할 수 없습니다. 다시 시도해주세요.' }, 500)

    // Log the challenge attempt (with error handling for missing columns)
    try {
      await db.prepare(
        'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms, image_key, recognized_text) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).bind(
        questionId, session.user_id, 'challenge',
        challengeText || '(이미지 도전)',
        0,
        challengeImageKey || null,
        result.recognized_text || null
      ).run()
    } catch (logErr: any) {
      // If image_key/recognized_text columns don't exist, try without them
      try {
        await db.prepare(
          'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms) VALUES (?, ?, ?, ?, ?)'
        ).bind(questionId, session.user_id, 'challenge', challengeText || '(이미지 도전)', 0).run()
      } catch (e2) {
        logErr('challenge/log-insert', e2)
      }
    }

    // Calculate CP reward (based on achieved level)
    const upgraded = (CP_CONFIG.CHALLENGE[result.question_level] || 2) > (CP_CONFIG.CHALLENGE[currentLevel] || 2)
    const bonusCp = upgraded
      ? (CP_CONFIG.CHALLENGE[result.question_level] || 2)
      : Math.max(1, Math.floor((CP_CONFIG.CHALLENGE[currentLevel] || 2) / 2))

    // Award CP to user
    const cpDesc = upgraded
      ? `도전 성공! ${currentLevel} → ${result.question_level} 레벨업`
      : `도전 보너스 (${currentLevel} 유지)`
    try {
      await awardCP(db, session.user_id, questionId, null, bonusCp, 'challenge', cpDesc)
    } catch(e) { logErr('cp/award-challenge', e) }

    // Get updated total CP
    const updatedCpRow = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(session.user_id).first() as any

    // Save challenge result to question for public display
    const challengeResultData = JSON.stringify({
      challenge_text: challengeText || result.recognized_text || '',
      question_level: result.question_level,
      previous_level: currentLevel,
      upgraded,
      diagnosis: result.diagnosis,
      feedback: result.feedback,
      upgrade_hint: result.upgrade_hint,
      cp: bonusCp,
      xp: bonusCp, // backward compat for old clients
      created_at: new Date().toISOString()
    })
    try {
      await db.prepare('UPDATE questions SET challenge_result = ? WHERE id = ?').bind(challengeResultData, questionId).run()
    } catch(e) {
      // If column doesn't exist, try creating it
      try {
        await db.prepare('ALTER TABLE questions ADD COLUMN challenge_result TEXT DEFAULT NULL').run()
        await db.prepare('UPDATE questions SET challenge_result = ? WHERE id = ?').bind(challengeResultData, questionId).run()
      } catch(e2) { logErr('challenge/result-save', e2) }
    }

    return c.json({
      success: true,
      ...result,
      previous_level: currentLevel,
      upgraded,
      cp: bonusCp,
      xp: bonusCp, // backward compat
      totalCp: updatedCpRow?.earned_cp || bonusCp,
      totalXp: updatedCpRow?.earned_cp || bonusCp, // backward compat
      challenge_text: challengeText || null
    })
  } catch (e: any) {
    return c.json({ error: e.message || 'Challenge analysis failed' }, 500)
  }
})

// === 2단계 소크라테스 코칭 답변 API (이미지+텍스트) ===
app.post('/api/coaching/tier2-answer', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)

  // I2: AI Rate Limiting — 사용자당 분당 5회 제한
  const rl3 = checkAiRateLimit(session.user_id)
  if (!rl3.allowed) return c.json({ error: `AI 요청 제한: ${Math.ceil((rl3.retryAfterMs||0)/1000)}초 후 다시 시도해주세요.` }, 429)

  const { questionId, stepIndex, answerText, answerImageKey } = await c.req.json()
  // E8: && → || — 둘 다 필수 필드이므로 하나라도 없으면 거부해야 함
  if (!questionId || stepIndex === undefined) return c.json({ error: 'Missing fields' }, 400)
  if (!answerText && !answerImageKey) return c.json({ error: '답변을 입력해주세요' }, 400)

  const tier2ExternalId = await getExternalId(db, session.user_id)

  const openaiKey = c.env.OPENAI_API_KEY
  let recognizedText = answerText || ''

  // If image provided, OCR with OpenAI
  if (answerImageKey && c.env.R2 && openaiKey) {
    try {
      const obj = await c.env.R2.get(answerImageKey)
      if (obj) {
        const buf = await obj.arrayBuffer()
        // E3: 청크 단위 base64 변환 — spread 연산자는 큰 버퍼에서 스택 오버플로우 발생
        const bytes2 = new Uint8Array(buf); let bin2 = ''
        for (let i = 0; i < bytes2.length; i++) bin2 += String.fromCharCode(bytes2[i])
        const imageBase64 = btoa(bin2)
        const imageMime = obj.httpMetadata?.contentType || 'image/jpeg'

        const ocrPrompt = `학생이 AI 튜터의 질문에 대해 풀이를 손으로 써서 사진으로 답변했습니다.
이미지에서 학생이 쓴 풀이/답변 내용을 정확히 인식하세요.
특히 수식, 그래프, 계산 과정에 주의하세요.

★★★ 수식은 LaTeX로: 인라인 $x^2$, 독립 $$\\int f(x)dx$$

반드시 JSON만 응답:
{
  "recognized_text": "이미지에서 인식한 학생의 풀이/답변 전체 내용",
  "contains_math": true,
  "math_expressions": ["x²=a+2", "a+2=4", "x=±2"],
  "student_reasoning": "학생이 어떤 논리로 답변했는지 1줄 요약"
}`

        const ocrResult = await callOpenAI(
          openaiKey, 'gpt-5.4',
          '학생 필기 OCR 전문가입니다. JSON 형식으로만 응답하세요.',
          [
            { type: 'image_url', image_url: { url: `data:${imageMime};base64,${imageBase64}` } },
            { type: 'text', text: ocrPrompt }
          ],
          1000,
          { dedupKey: `tier2-ocr-${questionId}-${stepIndex}`, timeoutMs: 20000, proxy: proxyOpts(c.env, 'ocr', questionId, tier2ExternalId) }
        )
        if (ocrResult.ok && ocrResult.text) {
          try {
            const jsonMatch = ocrResult.text.match(/\{[\s\S]*\}/)
            if (jsonMatch) {
              const parsed = safeJsonParse(jsonMatch[0])
              recognizedText = parsed.recognized_text || answerText || ''
            }
          } catch (e) {}
        }
      }
    } catch (e) {
      console.log('OCR failed, using text answer:', e)
    }
  }

  // Log to coaching_logs
  try {
    await db.prepare(
      'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms, image_key, recognized_text) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      questionId, session.user_id,
      'tier2_q' + stepIndex,
      recognizedText || '(이미지 답변)',
      0,
      answerImageKey || null,
      recognizedText || null
    ).run()
  } catch(e) {
    try {
      await db.prepare(
        'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms) VALUES (?, ?, ?, ?, ?)'
      ).bind(questionId, session.user_id, 'tier2_q' + stepIndex, recognizedText || '(이미지 답변)', 0).run()
    } catch(e2) {}
  }

  // Generate dynamic feedback based on student's actual answer FIRST (before awarding XP)
  let dynamicFeedback = ''
  let quality = 'partial'
  let warningCount = 0

  if (openaiKey) {
    try {
      const q = await db.prepare('SELECT content, subject, ai_coaching_data, challenge_result FROM questions WHERE id = ?').bind(questionId).first() as any
      let teacherQuestion = ''
      let expectedAnswer = ''
      let hint = ''
      if (q?.ai_coaching_data) {
        try {
          const cData = JSON.parse(q.ai_coaching_data)
          const tier2 = cData.tier2 || {}
          const questions = tier2.questions || []
          if (questions[stepIndex]) {
            teacherQuestion = questions[stepIndex].q || questions[stepIndex].text || ''
            expectedAnswer = questions[stepIndex].expected || questions[stepIndex].goodAnswer || ''
            hint = questions[stepIndex].hint || ''
          }
        } catch(e) {}
      }

      const feedbackPrompt = `당신은 따뜻하지만 정직한 수학/과학 선생님입니다.
학생이 선생님의 질문에 답변했습니다. 학생의 실제 답변 내용을 꼼꼼히 읽고 적절한 피드백을 주세요.

[선생님 질문]
${teacherQuestion}

[기대하는 좋은 답변 방향]
${expectedAnswer}

[학생의 실제 답변]
${recognizedText}

★★★ 반드시 JSON으로만 응답하세요:
{
  "quality": "good" | "partial" | "off_track" | "no_attempt",
  "feedback": "학생 답변에 대한 구체적 피드백 (2~3문장, 친근한 톤)",
  "hint": "부족한 부분이 있다면 힌트 (1~2문장). 잘 했으면 빈 문자열",
  "encouragement": "격려 한마디 (1문장)"
}

★ quality 판정 기준:
- "good": 핵심을 정확히 파악하고 논리적으로 답변함
- "partial": 방향은 맞지만 핵심이 빠졌거나 설명이 부족함
- "off_track": 질문 의도와 다른 방향의 답변
- "no_attempt": "모르겠어요", "ㅜㅜ", 의미없는 답변, 장난스러운 답변, 한글자/두글자만 쓴 경우, "ㅋㅋ", "ㅎㅎ" 같은 무의미 텍스트

★ 피드백 규칙:
- "no_attempt"일 때: 무조건 칭찬하지 마세요! "진지하게 답변해주세요"로 시작하세요
- "off_track"일 때: 틀린 부분을 부드럽게 지적하고 올바른 방향으로 안내하세요
- "partial"일 때: 맞는 부분을 인정하고, 빠진 부분을 힌트로 알려주세요
- "good"일 때만: 구체적으로 어떤 점이 좋았는지 칭찬하세요
- ★★★ 수식은 LaTeX로: 인라인 $x^2$, 독립 $$\\int f(x)dx$$`

      const fbRes = await callOpenAI(
        openaiKey, 'gpt-5.4-mini',
        '학생 답변 피드백 전문가입니다. JSON 형식으로만 응답하세요.',
        feedbackPrompt,
        500,
        { dedupKey: `tier2-fb-${questionId}-${stepIndex}`, timeoutMs: 20000, proxy: proxyOpts(c.env, 'feedback', questionId, tier2ExternalId) }
      )
      if (fbRes.ok && fbRes.text) {
        try {
          const fbMatch = fbRes.text.match(/\{[\s\S]*\}/)
          if (fbMatch) {
            const fb = JSON.parse(fbMatch[0])
            quality = fb.quality || 'partial'
            dynamicFeedback = fb.feedback || ''
            if (fb.hint) dynamicFeedback += ' ' + fb.hint
            if (fb.encouragement) dynamicFeedback += ' ' + fb.encouragement
          }
        } catch(e) {}
      }
    } catch(e) {
      logErr('feedback/generate', e)
    }
  }

  // If no_attempt: NO XP, issue warning, terminate flow
  if (quality === 'no_attempt') {
    // Record warning in user_warnings
    try {
      await db.prepare(
        'INSERT INTO user_warnings (user_id, reason, warning_count, created_at) VALUES (?, ?, 1, datetime(\'now\'))'
      ).bind(session.user_id, '선생님과 함께하기: 의미없는 답변 (' + (recognizedText || '').slice(0, 50) + ')').run()
      await db.prepare('UPDATE users SET total_warnings = total_warnings + 1 WHERE id = ?').bind(session.user_id).run()
      const warnRow = await db.prepare('SELECT total_warnings FROM users WHERE id = ?').bind(session.user_id).first() as any
      warningCount = warnRow?.total_warnings || 1
    } catch(e) { logErr('warning/record', e) }

    const updatedCpWarn = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(session.user_id).first() as any
    return c.json({
      success: true,
      recognizedText,
      imageKey: answerImageKey || null,
      cpEarned: 0,
      xpEarned: 0, // backward compat
      totalCp: updatedCpWarn?.earned_cp || 0,
      totalXp: updatedCpWarn?.earned_cp || 0, // backward compat
      feedback: dynamicFeedback || '진지하게 답변해주세요. 의미없는 답변은 CP가 지급되지 않으며 경고가 기록됩니다.',
      quality: 'no_attempt',
      terminated: true,
      warning: true,
      warningCount
    })
  }

  // Award CP for answering a tier2 question (2 CP per step, deduplicated)
  const stepCp = CP_CONFIG.TIER2_STEP
  let cpAwarded = false
  try {
    cpAwarded = await awardCP(db, session.user_id, questionId, null, stepCp, 'tier2_step_' + (stepIndex || 0), `선생님 질문 ${(stepIndex||0)+1}번 답변`) as boolean
  } catch(e) { logErr('tier2/cp-award', e) }

  // Get updated total CP
  const updatedCp = await db.prepare('SELECT earned_cp FROM users WHERE id = ?').bind(session.user_id).first() as any

  return c.json({
    success: true,
    recognizedText,
    imageKey: answerImageKey || null,
    cpEarned: cpAwarded ? stepCp : 0,
    xpEarned: cpAwarded ? stepCp : 0, // backward compat
    totalCp: updatedCp?.earned_cp || 0,
    totalXp: updatedCp?.earned_cp || 0, // backward compat
    feedback: dynamicFeedback,
    quality,
    terminated: false,
    warning: false
  })
})

// === 2단계 소크라테스 코칭 질문 생성 API ===
app.post('/api/coaching/tier2-generate', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)

  // I2: AI Rate Limiting — 사용자당 분당 5회 제한
  const rl4 = checkAiRateLimit(session.user_id)
  if (!rl4.allowed) return c.json({ error: `AI 요청 제한: ${Math.ceil((rl4.retryAfterMs||0)/1000)}초 후 다시 시도해주세요.` }, 429)

  const { questionId } = await c.req.json()
  if (!questionId) return c.json({ error: 'Missing questionId' }, 400)

  // Verify the requesting user is the question author
  const qOwner = await db.prepare('SELECT user_id FROM questions WHERE id = ?').bind(questionId).first() as any
  if (!qOwner) return c.json({ error: 'Question not found' }, 404)
  if (qOwner.user_id !== session.user_id) {
    return c.json({ error: '질문을 올린 학생만 "선생님과 함께 하기"를 사용할 수 있습니다.' }, 403)
  }

  // Check if tier2 already completed for this question by this user
  const tier2Done = await db.prepare(
    "SELECT id FROM coaching_logs WHERE question_id = ? AND user_id = ? AND step = 'tier2_completed'"
  ).bind(questionId, session.user_id).first()
  if (tier2Done) {
    return c.json({ error: '이 질문에 대해 이미 "선생님과 함께 하기"를 완료했습니다. 같은 질문에 대해 한 번만 사용할 수 있습니다.' }, 409)
  }

  // Check if tier2 was already started (prevent duplicate generation on refresh)
  const tier2Started = await db.prepare(
    "SELECT id FROM coaching_logs WHERE question_id = ? AND user_id = ? AND step = 'tier2_generate'"
  ).bind(questionId, session.user_id).first()

  const q = await db.prepare('SELECT content, subject, ai_difficulty, question_type, student_question_text, ai_description, ai_coaching_data, ai_coaching_comment FROM questions WHERE id = ?').bind(questionId).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)

  const openaiKey = c.env.OPENAI_API_KEY
  if (!openaiKey) return c.json({ error: 'AI key not configured' }, 500)
  const claudeKey = c.env.ANTHROPIC_API_KEY
  const tier2ExternalId = await getExternalId(db, session.user_id)
  const difficulty = parseInt((q.ai_difficulty || '3').replace(/[^0-9]/g, '')) || 3
  const curType = q.question_type || 'A-1'

  // Get image if available
  let imageBase64 = null
  let imageMime = 'image/jpeg'
  const imageKey = await db.prepare('SELECT image_key FROM questions WHERE id = ?').bind(questionId).first() as any
  if (imageKey?.image_key && c.env.R2) {
    try {
      const obj = await c.env.R2.get(imageKey.image_key)
      if (obj) {
        const buf = await obj.arrayBuffer()
        // E3: 청크 단위 base64 변환 — spread 연산자는 큰 버퍼에서 스택 오버플로우 발생
        const bytes3 = new Uint8Array(buf); let bin3 = ''
        for (let i = 0; i < bytes3.length; i++) bin3 += String.fromCharCode(bytes3[i])
        imageBase64 = btoa(bin3)
        imageMime = obj.httpMetadata?.contentType || 'image/jpeg'
      }
    } catch(e) {}
  }

  const tier2Prompt = `당신은 열정적인 수학/과학 선생님입니다.
학생이 올린 문제를 직접 풀어주면서, 동시에 학생의 "질문하는 능력"을 한 단계 업그레이드시키는 것이 목표입니다.

═══════════════════════════════════
[문제 정보]
과목: ${q.subject || '수학'}
난이도: ★${difficulty}
현재 학생 질문 수준: ${curType}
문제 내용: ${(q.content || q.student_question_text || '').slice(0, 800)}
학생 원래 질문: ${q.student_question_text || '(풀이 요청)'}
AI 분석: ${q.ai_description || ''}
═══════════════════════════════════

[핵심 설계 원칙]
1. 선생님이 문제를 직접 풀어줍니다 (단계별 풀이)
2. 각 풀이 단계마다 학생에게 "생각해볼 질문"을 던집니다
3. 이 질문들은 현재 수준(${curType})에서 시작해서 점점 고도화됩니다
4. 최종적으로 학생이 "이런 식으로 질문하면 더 깊이 이해할 수 있구나"를 체화하도록 합니다

[질문 고도화 사다리]
호기심축: A-1(뭐지?) → A-2(어떻게?) → B-1(왜?) → B-2(만약에?) → C-1(뭐가 더 나아?) → C-2(그러면?)
성찰축: R-1(어디서 틀렸지?) → R-2(왜 틀렸지?) → R-3(다음엔 어떻게?)

[단계별 질문 설계]
- step 1: 현재 수준 또는 한 단계 위 (쉽게 시작)
- step 2: 한두 단계 위 (살짝 도전)
- step 3~4: 더 높은 단계 (깊은 사고 유도)
- 마무리: 최고 수준의 "성찰 질문" 또는 "확장 질문"

[톤 & 스타일]
- 친근한 반말 ("~해봐", "~지?", "~거야!", "~같아?")
- 격려와 칭찬 자연스럽게 섞기
- 각 단계에서 "이 풀이를 보면서 이런 질문이 떠오르지 않아?" 식으로 연결

★★★ 수식은 LaTeX로: 인라인 $x^2$, 독립 $$\\int f(x)dx$$, ÷, ×, ≠, ≤, ≥, ∞

반드시 JSON만 응답:
{
  "intro": "시작 인사 (학생의 질문을 칭찬하면서 시작. 2~3문장)",
  "steps": [
    {
      "title": "풀이 단계 제목 (간결하게)",
      "explanation": "이 단계의 풀이 설명 (선생님이 직접 풀어주는 내용. 구체적으로 수식/과정 포함. 3~5문장)",
      "question": {
        "level": "B-1",
        "label": "왜?",
        "text": "이 풀이 과정을 보면서 학생에게 던지는 고도화된 질문 (질문하는 법을 가르치는 질문)",
        "hint": "학생이 막힐 때 보여줄 힌트 (1~2문장)",
        "goodAnswer": "좋은 답변 예시",
        "teacherResponse": "학생이 답했을 때 선생님의 반응 + 칭찬 + 다음 연결 (2~3문장)"
      }
    }
  ],
  "summary": {
    "fullSolution": "전체 풀이 요약 (핵심만 3~5줄)",
    "keyInsight": "이 문제에서 가장 중요한 포인트 (1~2문장)",
    "upgradedQuestion": "학생이 이제 할 수 있는 고도화된 질문 예시 (${curType}보다 2단계 이상 높은 질문)",
    "upgradedLevel": "C-1",
    "closingMessage": "마무리 격려 메시지 (2~3문장)"
  }
}`

  try {
    let result: any = null

    // Build OpenAI content (including image if available)
    const openaiContent: any[] = []
    if (imageBase64) {
      openaiContent.push({ type: 'image_url', image_url: { url: `data:${imageMime};base64,${imageBase64}` } })
    }
    openaiContent.push({ type: 'text', text: tier2Prompt })

    const openaiRes = await callOpenAI(
      openaiKey, 'gpt-5.4',
      '당신은 소크라테스식 수학/과학 튜터입니다. 문제를 풀어주면서 학생의 질문력을 고도화시킵니다. 반드시 JSON 형식으로만 응답하세요.',
      openaiContent,
      6000,
      { dedupKey: `tier2-gen-${questionId}`, timeoutMs: 55000, proxy: proxyOpts(c.env, 'tutor', questionId, tier2ExternalId) }
    )

    if (!openaiRes.ok) {
      logErr('openai/tier2', openaiRes.error)
      return c.json({ error: 'AI 서비스 오류' }, 500)
    }

    const text = openaiRes.text || ''
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/)
      if (jsonMatch) result = safeJsonParse(jsonMatch[0])
    } catch(e) {
      logErr('openai/tier2-json-parse', e, { raw: text.slice(0, 200) })
    }

    if (!result) return c.json({ error: 'AI 생성 실패. 다시 시도해주세요.' }, 500)

    // Log to coaching
    try {
      await db.prepare(
        'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms) VALUES (?, ?, ?, ?, ?)'
      ).bind(questionId, session.user_id, 'tier2_generate', 'started', 0).run()
    } catch(e) {}

    // Return flat response (spread result directly)
    return c.json({
      success: true,
      model: (difficulty >= 4 && claudeKey && result) ? 'claude' : 'gemini',
      ...result
    })
  } catch (e: any) {
    logErr('tier2/generate', e)
    return c.json({ error: e.message || 'Generation failed' }, 500)
  }
})

app.get('/ranking', (c) => c.html(rankingPageHTML()))

// === Tier2 Status Check API ===
app.get('/api/coaching/tier2-status/:questionId', async (c) => {
  const db = c.env.DB
  const questionId = parseInt(c.req.param('questionId'))
  const user = await getAuthUser(c) as any
  if (!user) return c.json({ completed: false, started: false })

  const completed = await db.prepare(
    "SELECT id FROM coaching_logs WHERE question_id = ? AND user_id = ? AND step = 'tier2_completed'"
  ).bind(questionId, user.id).first()

  const started = await db.prepare(
    "SELECT id FROM coaching_logs WHERE question_id = ? AND user_id = ? AND step = 'tier2_generate'"
  ).bind(questionId, user.id).first()

  // Count warnings
  const warnRow = await db.prepare('SELECT total_warnings FROM users WHERE id = ?').bind(user.id).first() as any

  return c.json({
    completed: !!completed,
    started: !!started,
    warningCount: warnRow?.total_warnings || 0
  })
})

// === Tier2 Complete Marker API ===
app.post('/api/coaching/tier2-complete', async (c) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const session = await db.prepare("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first() as any
  if (!session) return c.json({ error: 'Unauthorized' }, 401)

  const { questionId } = await c.req.json()
  if (!questionId) return c.json({ error: 'Missing questionId' }, 400)

  // Check not already marked complete
  const existing = await db.prepare(
    "SELECT id FROM coaching_logs WHERE question_id = ? AND user_id = ? AND step = 'tier2_completed'"
  ).bind(questionId, session.user_id).first()
  if (existing) return c.json({ success: true, alreadyCompleted: true })

  await db.prepare(
    'INSERT INTO coaching_logs (question_id, user_id, step, choice, time_spent_ms) VALUES (?, ?, ?, ?, ?)'
  ).bind(questionId, session.user_id, 'tier2_completed', 'completed', 0).run()

  return c.json({ success: true })
})
app.get('/category/:name', (c) => c.html(categoryPageHTML(c.req.param('name'))))

// ==================== ClassIn Teachers 1:1 코칭 연동 ====================

// GET /api/account-link/status — 계정 연결 상태 확인
app.get('/api/account-link/status', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const link = await c.env.DB.prepare(
    'SELECT teachers_email, verified FROM account_links WHERE user_id = ?'
  ).bind(user.id).first() as any

  return c.json({
    linked: !!(link?.verified),
    teachers_email: link?.teachers_email || null
  })
})

// POST /api/account-link/verify — 계정 연결 (ClassIn Teachers 인증)
app.post('/api/account-link/verify', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const { email, password } = await c.req.json()
  if (!email || !password) return c.json({ error: '이메일과 비밀번호를 입력해주세요.' }, 400)

  const teachersUrl = c.env.TEACHERS_API_URL || ''
  const apiSecret = c.env.COACHING_API_SECRET || ''

  if (!teachersUrl) return c.json({ error: 'Teachers API URL not configured' }, 500)

  try {
    const res = await fetch(teachersUrl + '/api/link/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Coaching-Secret': apiSecret
      },
      body: JSON.stringify({
        external_user_id: user.external_id || String(user.id),
        email,
        password
      })
    })
    const data = await res.json() as any

    if (!data.success) {
      return c.json({ error: data.error || '인증 실패' }, res.status as any)
    }

    // Save to local account_links
    const nowISO = new Date().toISOString()
    await c.env.DB.prepare(`
      INSERT INTO account_links (user_id, teachers_email, verified, linked_at)
      VALUES (?, ?, 1, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        teachers_email = excluded.teachers_email,
        verified = 1,
        linked_at = excluded.linked_at
    `).bind(user.id, email, nowISO).run()

    return c.json({
      success: true,
      teachers_email: email,
      teachers_name: data.teachers_name
    })
  } catch (e: any) {
    return c.json({ error: '서버 연결 실패. 잠시 후 다시 시도해주세요.' }, 500)
  }
})

// POST /api/questions/:id/coaching-request — 1:1 코칭 신청
app.post('/api/questions/:id/coaching-request', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const questionId = parseInt(c.req.param('id'))
  const { duration } = await c.req.json()

  const teachersUrl = c.env.TEACHERS_API_URL || ''
  const apiSecret = c.env.COACHING_API_SECRET || ''
  if (!teachersUrl) return c.json({ error: 'Teachers API URL not configured' }, 500)

  const extId = user.external_id || String(user.id)

  // Check account link — 미연결 시 회원가입 유도
  const link = await c.env.DB.prepare(
    'SELECT teachers_email, verified FROM account_links WHERE user_id = ? AND verified = 1'
  ).bind(user.id).first() as any

  if (!link) {
    return c.json({ error: 'ClassIn Teachers 계정을 먼저 연결해주세요.', need_link: true }, 400)
  }

  // Get question data
  const question = await c.env.DB.prepare(
    'SELECT id, title, content, subject, difficulty, image_data, image_key, image_keys FROM questions WHERE id = ?'
  ).bind(questionId).first() as any

  if (!question) return c.json({ error: '질문을 찾을 수 없습니다.' }, 404)

  // Get existing answers
  const answers = await c.env.DB.prepare(
    'SELECT author_name, content, image_data FROM answers WHERE question_id = ? ORDER BY created_at ASC LIMIT 10'
  ).bind(questionId).all()

  const existingAnswers = (answers.results || []).map((a: any) => ({
    author: a.author_name,
    content: a.content || '',
    has_image: !!a.image_data
  }))

  // Build image URLs — 절대 URL로 변환 (Teachers에서도 접근 가능하도록)
  // image_keys (복수, JSON배열) > image_key (단수) > image_data (레거시) 순서로 확인
  const qaBaseUrl = new URL(c.req.url).origin
  const imageUrls: string[] = []
  const toAbsUrl = (src: string) => src.startsWith('http') ? src : qaBaseUrl + '/api/images/' + src

  if (question.image_keys) {
    try {
      const keys = JSON.parse(question.image_keys) as { key: string; thumbnailKey?: string }[]
      for (const k of keys) {
        if (k.key) imageUrls.push(toAbsUrl(k.key))
      }
    } catch (e) {}
  }
  if (imageUrls.length === 0) {
    const imgSrc = question.image_key || question.image_data
    if (imgSrc) imageUrls.push(toAbsUrl(imgSrc))
  }

  try {
    const res = await fetch(teachersUrl + '/api/coaching/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Coaching-Secret': apiSecret
      },
      body: JSON.stringify({
        requester_ext_id: extId,
        qa_question_id: questionId,
        title: question.title,
        content: question.content || '',
        subject: question.subject || '기타',
        difficulty: question.difficulty || '중',
        image_urls: imageUrls,
        existing_answers: existingAnswers,
        duration: duration === 30 ? 30 : 15
      })
    })
    const data = await res.json() as any

    if (!data.success) {
      return c.json({ error: data.error || '코칭 신청 실패' }, res.status as any)
    }

    // OTT 발급 — Teachers 자동 로그인용
    let ottToken = ''
    try {
      const ottRes = await fetch(teachersUrl + '/api/auth/ott-generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Coaching-Secret': apiSecret },
        body: JSON.stringify({ external_user_id: extId, coaching_request_id: data.request_id })
      })
      const ottData = await ottRes.json() as any
      if (ottData.success) ottToken = ottData.ott
      else console.error('OTT generation failed:', ottData.error, 'extId:', extId)
    } catch (e: any) {
      console.error('OTT generation error:', e.message)
    }

    const coachingUrl = teachersUrl + '/coaching/' + data.request_id + (ottToken ? '?token=' + ottToken : '')

    // 로컬 DB에 코칭 신청 상태 저장
    try { await c.env.DB.prepare('UPDATE questions SET coaching_requested = 1 WHERE id = ?').bind(questionId).run() } catch(e) {}

    return c.json({
      success: true,
      request_id: data.request_id,
      coaching_url: coachingUrl,
      message: '1:1 코칭이 신청되었습니다!'
    })
  } catch (e: any) {
    return c.json({ error: '서버 연결 실패. 잠시 후 다시 시도해주세요.' }, 500)
  }
})

// POST /api/questions/:id/coaching-cancel — 코칭 취소 (질문자)
app.post('/api/questions/:id/coaching-cancel', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const questionId = parseInt(c.req.param('id'))
  const teachersUrl = c.env.TEACHERS_API_URL || ''
  const apiSecret = c.env.COACHING_API_SECRET || ''
  if (!teachersUrl) return c.json({ error: 'Teachers API URL not configured' }, 500)

  const extId = user.external_id || String(user.id)

  try {
    // Teachers에서 이 질문의 코칭 요청 조회
    const listRes = await fetch(teachersUrl + '/api/coaching/list?qa_question_id=' + questionId, {
      headers: { 'X-Coaching-Secret': apiSecret }
    })
    const listData = await listRes.json() as any
    const requests = listData.requests || []
    // == 사용: DB에서 INTEGER로 반환되는 requester_ext_id와 string extId 비교 호환
    const myRequest = requests.find((r: any) => String(r.requester_ext_id) === String(extId) && (r.status === 'pending' || r.status === 'matched'))

    if (!myRequest) {
      console.log('coaching-cancel: no matching request found. extId:', extId, 'requests:', requests.map((r: any) => ({ id: r.id, ext: r.requester_ext_id, status: r.status })))
      return c.json({ error: '취소할 코칭 요청이 없습니다.' }, 404)
    }

    // Teachers에 취소 요청
    const cancelRes = await fetch(teachersUrl + '/api/coaching/requests/' + myRequest.id + '/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Coaching-Secret': apiSecret },
      body: JSON.stringify({ user_id: myRequest.requester_user_id })
    })
    const cancelData = await cancelRes.json() as any

    if (!cancelData.success) {
      console.log('coaching-cancel: Teachers API failed:', cancelRes.status, cancelData)
      return c.json({ error: cancelData.error || '취소 실패' }, cancelRes.status >= 400 ? cancelRes.status as any : 500)
    }

    // 로컬 DB에 코칭 취소 상태 반영
    try { await c.env.DB.prepare('UPDATE questions SET coaching_requested = 0 WHERE id = ?').bind(questionId).run() } catch(e) {}

    return c.json({ success: true, message: '코칭 신청이 취소되었습니다.' })
  } catch (e: any) {
    return c.json({ error: '서버 연결 실패. 잠시 후 다시 시도해주세요.' }, 500)
  }
})

// GET /api/questions/:id/coaching-status — 코칭 신청 상태 조회
app.get('/api/questions/:id/coaching-status', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const questionId = parseInt(c.req.param('id'))
  const teachersUrl = c.env.TEACHERS_API_URL || ''
  const apiSecret = c.env.COACHING_API_SECRET || ''

  // 로컬 DB에서 캐시된 상태 먼저 반환
  const q = await c.env.DB.prepare('SELECT coaching_requested, user_id FROM questions WHERE id = ?').bind(questionId).first() as any
  if (!q) return c.json({ error: 'Question not found' }, 404)
  if (q.user_id !== user.id) return c.json({ coaching_requested: 0 })

  // Teachers API가 설정되어 있으면 실시간 동기화
  if (teachersUrl) {
    try {
      const extId = user.external_id || String(user.id)
      const listRes = await fetch(teachersUrl + '/api/coaching/list?qa_question_id=' + questionId, {
        headers: { 'X-Coaching-Secret': apiSecret }
      })
      const listData = await listRes.json() as any
      const requests = listData.requests || []
      // 활성(pending/matched/in_progress) 우선, 없으면 가장 최근 completed 표시
      // cancelled/expired는 무시 (기본 신청 버튼 복원)
      const myRequests = requests.filter((r: any) => String(r.requester_ext_id) === String(extId))
      const activeRequest = myRequests.find((r: any) => r.status === 'pending' || r.status === 'matched' || r.status === 'in_progress')
      const completedRequest = !activeRequest
        ? myRequests.filter((r: any) => r.status === 'completed').sort((a: any, b: any) => String(b.created_at || '').localeCompare(String(a.created_at || '')))[0]
        : null
      const myRequest = activeRequest || completedRequest

      const newStatus = activeRequest
        ? (activeRequest.status === 'pending' ? 1 : 2) // matched/in_progress 모두 2로 통일
        : (completedRequest ? 3 : 0)
      // 로컬 DB 동기화
      if (newStatus !== q.coaching_requested) {
        try { await c.env.DB.prepare('UPDATE questions SET coaching_requested = ? WHERE id = ?').bind(newStatus, questionId).run() } catch(e) {}
      }

      // OTT 발급 — Teachers 자동 로그인용 코칭 URL 생성
      let coachingUrl = ''
      if (myRequest) {
        try {
          const ottRes = await fetch(teachersUrl + '/api/auth/ott-generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Coaching-Secret': apiSecret },
            body: JSON.stringify({ external_user_id: extId, coaching_request_id: myRequest.id })
          })
          const ottData = await ottRes.json() as any
          const ottToken = ottData.success ? ottData.ott : ''
          coachingUrl = teachersUrl + '/coaching/' + myRequest.id + (ottToken ? '?token=' + ottToken : '')
        } catch(e) {
          coachingUrl = teachersUrl + '/coaching/' + myRequest.id
        }
      }

      return c.json({
        coaching_requested: newStatus,
        request_id: myRequest?.id || null,
        status: myRequest?.status || null,
        coaching_url: coachingUrl || null
      })
    } catch(e) {
      // Teachers API 실패 시 로컬 캐시 반환
    }
  }

  return c.json({ coaching_requested: q.coaching_requested || 0 })
})

// POST /api/questions/:id/coaching-apply — 코칭 참여하기 (답변자)
app.post('/api/questions/:id/coaching-apply', async (c) => {
  const user = await getAuthUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  const questionId = parseInt(c.req.param('id'))

  // Check account link
  const link = await c.env.DB.prepare(
    'SELECT teachers_email, verified FROM account_links WHERE user_id = ? AND verified = 1'
  ).bind(user.id).first() as any

  if (!link) return c.json({ error: 'ClassIn Teachers 계정을 먼저 연결해주세요.', need_link: true }, 400)

  const teachersUrl = c.env.TEACHERS_API_URL || ''
  const apiSecret = c.env.COACHING_API_SECRET || ''

  if (!teachersUrl) return c.json({ error: 'Teachers API URL not configured' }, 500)

  try {
    // Find the coaching request for this question
    const res = await fetch(teachersUrl + '/api/coaching/list?qa_question_id=' + questionId, {
      headers: { 'X-Coaching-Secret': apiSecret }
    })
    const data = await res.json() as any
    const matchingRequest = (data.requests || []).find((r: any) => String(r.qa_question_id) === String(questionId))

    if (!matchingRequest) {
      return c.json({ error: '이 질문에 대한 코칭 요청이 없습니다.' }, 404)
    }

    return c.json({
      success: true,
      coaching_url: teachersUrl + '/coaching/' + matchingRequest.id,
      request_id: matchingRequest.id
    })
  } catch (e: any) {
    return c.json({ error: '서버 연결 실패' }, 500)
  }
})

// ============================================================================
// ===== 어드민 대시보드 (Admin Dashboard) =====
// ============================================================================

async function ensureAdminSessionsTable(db: D1Database) {
  try {
    await db.prepare(`CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL
    )`).run()
  } catch (e) {}
}

function getAdminToken(c: any): string | undefined {
  const cookie = c.req.header('Cookie') || ''
  const m = cookie.match(/admin_session=([^;]+)/)
  return m ? m[1] : undefined
}

async function verifyAdminSession(_c: any): Promise<boolean> {
  // TEMP: 인증 비활성화 — 누구나 /admin 접근 가능. 복구는 git에서 이 블록 되돌리기.
  return true
}

async function requireAdminSession(_c: any): Promise<boolean> {
  // TEMP: 인증 비활성화 — 모든 /api/admin/* 공개. 복구는 git에서 이 블록 되돌리기.
  return true
}

type AdminFilters = { from: string; to: string; prevFrom: string; prevTo: string; days: number; fromDate: string; toDate: string; subject?: string; grade?: string }
function parseAdminRange(c: any): AdminFilters {
  const url = new URL(c.req.url)
  const qFrom = url.searchParams.get('from')
  const qTo = url.searchParams.get('to')
  const kstNowMs = Date.now() + 9 * 3600000
  const kstToday = new Date(kstNowMs).toISOString().slice(0, 10)
  const fromDate = qFrom || new Date(kstNowMs - 6 * 86400000).toISOString().slice(0, 10)
  const toDate = qTo || kstToday
  const fromKstMs = new Date(fromDate + 'T00:00:00+09:00').getTime()
  const toKstMs = new Date(toDate + 'T23:59:59+09:00').getTime()
  const days = Math.max(1, Math.round((toKstMs - fromKstMs) / 86400000) + 1)
  const prevToMs = fromKstMs - 1000
  const prevFromMs = fromKstMs - days * 86400000
  const toUtc = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ')
  const subjectRaw = url.searchParams.get('subject')
  const gradeRaw = url.searchParams.get('grade')
  return {
    from: toUtc(fromKstMs),
    to: toUtc(toKstMs),
    prevFrom: toUtc(prevFromMs),
    prevTo: toUtc(prevToMs),
    days, fromDate, toDate,
    subject: subjectRaw && subjectRaw !== 'all' ? subjectRaw : undefined,
    grade: gradeRaw && gradeRaw !== 'all' ? gradeRaw : undefined,
  }
}

// 테스트/제외 external_id 목록 (관리자 눈에 보이면 안 되는 계정)
const EXCLUDED_EXT_IDS = ['68251']  // David (테스트 계정)
const EXCLUDED_EXT_SQL = EXCLUDED_EXT_IDS.map(id => "'" + id.replace(/'/g, "''") + "'").join(',')

function buildQuestionFilter(f: AdminFilters, userAlias = 'u'): { sql: string; binds: any[]; needUserJoin: boolean } {
  // 기본: 테스트 계정 제외 → users JOIN 항상 필요
  const parts: string[] = [
    `(${userAlias}.external_id IS NULL OR ${userAlias}.external_id NOT IN (${EXCLUDED_EXT_SQL}))`
  ]
  const binds: any[] = []
  let needUserJoin = true
  if (f.subject) {
    parts.push("COALESCE(NULLIF(q.subject,''),'기타') = ?")
    binds.push(f.subject)
  }
  if (f.grade) {
    if (f.grade === '미분류') {
      parts.push(`(q.question_grade IS NULL OR q.question_grade = '') AND (${userAlias}.grade IS NULL OR ${userAlias}.grade = '')`)
    } else {
      parts.push(`COALESCE(NULLIF(q.question_grade,''), NULLIF(${userAlias}.grade,'')) = ?`)
      binds.push(f.grade)
    }
  }
  return { sql: ' AND ' + parts.join(' AND '), binds, needUserJoin }
}
function filterCacheKey(f: AdminFilters): string {
  return (f.subject || 'all') + ':' + (f.grade || 'all')
}

const adminCache = new Map<string, { data: any; expiresAt: number }>()
const ADMIN_CACHE_TTL = 5 * 60 * 1000
function adminCacheGet(key: string): any | null {
  const v = adminCache.get(key)
  if (!v) return null
  if (v.expiresAt < Date.now()) { adminCache.delete(key); return null }
  return v.data
}
function adminCacheSet(key: string, data: any) {
  adminCache.set(key, { data, expiresAt: Date.now() + ADMIN_CACHE_TTL })
}

// 실명 배치 조회 — jungyoul.com/api/get_realnames.php
// 5분 단위로 userId별 개별 캐시. API 호출은 한 번에 묶어서 수행.
const REALNAME_API_URL = 'https://jungyoul.com/api/get_realnames.php'
const realnameCache = new Map<string, { name: string | null; expiresAt: number }>()
const REALNAME_CACHE_TTL = 5 * 60 * 1000

async function fetchRealnames(env: Bindings, externalIds: (string | number | null | undefined)[]): Promise<Record<string, string>> {
  const now = Date.now()
  const result: Record<string, string> = {}
  const toFetch: string[] = []

  // 중복 제거 + 캐시 조회
  const seen = new Set<string>()
  for (const raw of externalIds) {
    if (raw == null) continue
    const id = String(raw)
    if (!id || seen.has(id)) continue
    seen.add(id)
    const cached = realnameCache.get(id)
    if (cached && cached.expiresAt > now) {
      if (cached.name) result[id] = cached.name
    } else {
      toFetch.push(id)
    }
  }

  if (toFetch.length === 0 || !env.REALNAME_API_SECRET) return result

  try {
    // 한 번에 최대 500개 제한이라 청크로 분할
    for (let i = 0; i < toFetch.length; i += 500) {
      const chunk = toFetch.slice(i, i + 500)
      const res = await fetch(REALNAME_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': env.REALNAME_API_SECRET },
        body: JSON.stringify({ user_ids: chunk }),
      })
      if (!res.ok) {
        console.log(`[realnames] HTTP ${res.status}`)
        // 실패해도 캐시 스탬프(null)는 찍어서 반복 호출 방지
        for (const id of chunk) realnameCache.set(id, { name: null, expiresAt: now + REALNAME_CACHE_TTL })
        continue
      }
      const data = await res.json().catch(() => ({})) as Record<string, string>
      for (const id of chunk) {
        const name = data[id] || null
        realnameCache.set(id, { name, expiresAt: now + REALNAME_CACHE_TTL })
        if (name) result[id] = name
      }
    }
  } catch (e) {
    console.log(`[realnames] error: ${(e as any)?.message}`)
  }
  return result
}

// users 배열의 각 항목에 real_name 필드 주입
async function enrichWithRealnames(env: Bindings, users: any[]): Promise<void> {
  if (!Array.isArray(users) || users.length === 0) return
  const ids = users.map(u => u?.external_id).filter(Boolean)
  if (ids.length === 0) return
  const nameMap = await fetchRealnames(env, ids)
  for (const u of users) {
    const id = u?.external_id != null ? String(u.external_id) : ''
    if (id && nameMap[id]) u.real_name = nameMap[id]
  }
}

app.post('/api/admin/login', async (c) => {
  const body = await c.req.json().catch(() => ({} as any))
  const secret = String(body.secret || '')
  if (!c.env.ADMIN_SECRET || secret !== c.env.ADMIN_SECRET) {
    return c.json({ error: 'Invalid credentials' }, 403)
  }
  const db = c.env.DB
  await ensureAdminSessionsTable(db)
  const token = generateToken()
  await db.prepare("INSERT INTO admin_sessions (token, expires_at) VALUES (?, datetime('now', '+12 hours'))").bind(token).run()
  const secure = c.req.url.startsWith('https://') ? '; Secure' : ''
  c.header('Set-Cookie', `admin_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200${secure}`)
  return c.json({ success: true })
})

app.post('/api/admin/logout', async (c) => {
  const token = getAdminToken(c)
  if (token) {
    try { await c.env.DB.prepare('DELETE FROM admin_sessions WHERE token = ?').bind(token).run() } catch (e) {}
  }
  const secure = c.req.url.startsWith('https://') ? '; Secure' : ''
  c.header('Set-Cookie', `admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`)
  return c.json({ success: true })
})

app.get('/api/admin/overview', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, prevFrom, prevTo, fromDate, toDate } = f
  const cacheKey = `overview:${from}:${to}:${filterCacheKey(f)}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const filter = buildQuestionFilter(f)
  const hasFilter = !!(f.subject || f.grade)
  const userJoin = filter.needUserJoin ? ' LEFT JOIN users u ON u.id = q.user_id' : ''
  const activeUsersSql = hasFilter
    ? `SELECT COUNT(DISTINCT q.user_id) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ?${filter.sql}`
    : `SELECT COUNT(DISTINCT s.user_id) as cnt FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE s.created_at BETWEEN ? AND ? AND (u.external_id IS NULL OR u.external_id NOT IN (${EXCLUDED_EXT_SQL}))`
  const questionsSql = `SELECT COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ?${filter.sql}`
  const answersSql = `SELECT COUNT(*) as cnt FROM answers a JOIN questions q ON q.id = a.question_id${userJoin} WHERE a.created_at BETWEEN ? AND ?${filter.sql}`
  // 1:1 튜터 신청: questions.coaching_requested >= 1 (취소 제외). tutoring_matches 테이블은 비어있어 쓸 수 없음
  const tutoringSql = `SELECT COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ? AND q.coaching_requested IS NOT NULL AND q.coaching_requested >= 1${filter.sql}`

  const r = await db.batch([
    db.prepare(activeUsersSql).bind(from, to, ...filter.binds),
    db.prepare(questionsSql).bind(from, to, ...filter.binds),
    db.prepare(answersSql).bind(from, to, ...filter.binds),
    db.prepare(tutoringSql).bind(from, to, ...filter.binds),
    db.prepare(activeUsersSql).bind(prevFrom, prevTo, ...filter.binds),
    db.prepare(questionsSql).bind(prevFrom, prevTo, ...filter.binds),
    db.prepare(answersSql).bind(prevFrom, prevTo, ...filter.binds),
    db.prepare(tutoringSql).bind(prevFrom, prevTo, ...filter.binds),
  ])
  const g = (i: number) => (r[i].results?.[0] as any)?.cnt || 0
  const data = {
    active_users: { current: g(0), previous: g(4), note: hasFilter ? '필터 적용: 해당 조건의 질문 작성자 수' : null },
    questions: { current: g(1), previous: g(5) },
    answers: { current: g(2), previous: g(6) },
    tutoring_matches: { current: g(3), previous: g(7) },
    range: { from: fromDate, to: toDate },
    filters: { subject: f.subject || null, grade: f.grade || null },
  }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/trend', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const url = new URL(c.req.url)
  const unit = (url.searchParams.get('unit') || 'day') as 'day' | 'week' | 'month'
  const fmt = unit === 'month' ? '%Y-%m' : unit === 'week' ? '%Y-W%W' : '%Y-%m-%d'
  const cacheKey = `trend:${from}:${to}:${unit}:${filterCacheKey(f)}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const filter = buildQuestionFilter(f)
  const hasFilter = !!(f.subject || f.grade)
  const userJoin = filter.needUserJoin ? ' LEFT JOIN users u ON u.id = q.user_id' : ''
  const qBucket = `strftime('${fmt}', datetime(q.created_at, '+9 hours'))`
  const aBucket = `strftime('${fmt}', datetime(a.created_at, '+9 hours'))`
  const tBucket = `strftime('${fmt}', datetime(tm.held_at, '+9 hours'))`
  const sBucket = `strftime('${fmt}', datetime(created_at, '+9 hours'))`
  const activeUsersSql = hasFilter
    ? `SELECT ${qBucket} as bucket, COUNT(DISTINCT q.user_id) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ?${filter.sql} GROUP BY bucket ORDER BY bucket`
    : `SELECT ${sBucket.replace('created_at', 's.created_at')} as bucket, COUNT(DISTINCT s.user_id) as cnt FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE s.created_at BETWEEN ? AND ? AND (u.external_id IS NULL OR u.external_id NOT IN (${EXCLUDED_EXT_SQL})) GROUP BY bucket ORDER BY bucket`

  const r = await db.batch([
    db.prepare(`SELECT ${qBucket} as bucket, COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ?${filter.sql} GROUP BY bucket ORDER BY bucket`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT ${aBucket} as bucket, COUNT(*) as cnt FROM answers a JOIN questions q ON q.id = a.question_id${userJoin} WHERE a.created_at BETWEEN ? AND ?${filter.sql} GROUP BY bucket ORDER BY bucket`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT ${tBucket} as bucket, COUNT(*) as cnt FROM tutoring_matches tm JOIN questions q ON q.id = tm.question_id${userJoin} WHERE tm.held_at BETWEEN ? AND ? AND tm.status != 'cancelled'${filter.sql} GROUP BY bucket ORDER BY bucket`).bind(from, to, ...filter.binds),
    db.prepare(activeUsersSql).bind(from, to, ...filter.binds),
    db.prepare(`SELECT ${qBucket} as bucket, COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ? AND q.coaching_requested IS NOT NULL AND q.coaching_requested >= 1${filter.sql} GROUP BY bucket ORDER BY bucket`).bind(from, to, ...filter.binds),
  ])
  const toMap = (rs: any) => {
    const o: Record<string, number> = {}
    for (const x of (rs.results || []) as any[]) o[x.bucket] = x.cnt
    return o
  }
  const data = {
    unit,
    questions: toMap(r[0]),
    answers: toMap(r[1]),
    tutoring_matches: toMap(r[2]),
    active_users: toMap(r[3]),
    coaching_requests: toMap(r[4]),
    range: { from: fromDate, to: toDate },
    filters: { subject: f.subject || null, grade: f.grade || null },
  }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/segments', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const cacheKey = `segments:${from}:${to}:${filterCacheKey(f)}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const filter = buildQuestionFilter(f)
  const r = await db.batch([
    db.prepare(`SELECT subject, grade, COUNT(*) as cnt FROM (
                  SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject,
                         COALESCE(NULLIF(q.question_grade,''), NULLIF(u.grade,''),'미분류') as grade
                  FROM questions q LEFT JOIN users u ON u.id = q.user_id
                  WHERE q.created_at BETWEEN ? AND ?${filter.sql}
                ) GROUP BY subject, grade`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject,
                       COALESCE(NULLIF(q.difficulty,''),'중') as difficulty, COUNT(*) as cnt
                FROM questions q LEFT JOIN users u ON u.id = q.user_id
                WHERE q.created_at BETWEEN ? AND ?${filter.sql}
                GROUP BY subject, difficulty`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject, COUNT(*) as cnt
                FROM questions q LEFT JOIN users u ON u.id = q.user_id
                WHERE q.created_at BETWEEN ? AND ?${filter.sql}
                GROUP BY subject ORDER BY cnt DESC`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject,
                       COUNT(a.id) as answers,
                       SUM(CASE WHEN a.is_accepted=1 THEN 1 ELSE 0 END) as accepted
                FROM answers a JOIN questions q ON q.id=a.question_id LEFT JOIN users u ON u.id = q.user_id
                WHERE a.created_at BETWEEN ? AND ?${filter.sql}
                GROUP BY subject`).bind(from, to, ...filter.binds),
  ])
  const data = {
    subject_grade: r[0].results || [],
    subject_difficulty: r[1].results || [],
    subject_questions: r[2].results || [],
    subject_answers: r[3].results || [],
    range: { from: fromDate, to: toDate },
    filters: { subject: f.subject || null, grade: f.grade || null },
  }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/feature-usage', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const cacheKey = `feature-usage:${from}:${to}:${filterCacheKey(f)}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const filter = buildQuestionFilter(f)
  const userJoin = filter.needUserJoin ? ' LEFT JOIN users u ON u.id = q.user_id' : ''

  const r = await db.batch([
    db.prepare(`SELECT COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ?${filter.sql}`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COUNT(*) as cnt FROM answers a JOIN questions q ON q.id = a.question_id${userJoin} WHERE a.created_at BETWEEN ? AND ?${filter.sql}`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COUNT(*) as cnt FROM answers a JOIN questions q ON q.id = a.question_id${userJoin} WHERE a.is_accepted=1 AND a.created_at BETWEEN ? AND ?${filter.sql}`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT tm.status, COUNT(*) as cnt FROM tutoring_matches tm JOIN questions q ON q.id = tm.question_id${userJoin} WHERE tm.held_at BETWEEN ? AND ?${filter.sql} GROUP BY tm.status`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject, COUNT(*) as cnt FROM tutoring_matches tm JOIN questions q ON q.id=tm.question_id${userJoin} WHERE tm.held_at BETWEEN ? AND ?${filter.sql} GROUP BY subject ORDER BY cnt DESC`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT q.coaching_requested as stage, COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ? AND q.coaching_requested IS NOT NULL AND q.coaching_requested != 0${filter.sql} GROUP BY q.coaching_requested`).bind(from, to, ...filter.binds),
    db.prepare(`SELECT COALESCE(NULLIF(q.subject,''),'기타') as subject, COUNT(*) as cnt FROM questions q${userJoin} WHERE q.created_at BETWEEN ? AND ? AND q.coaching_requested IS NOT NULL AND q.coaching_requested >= 1${filter.sql} GROUP BY subject ORDER BY cnt DESC`).bind(from, to, ...filter.binds),
  ])
  const g = (i: number) => (r[i].results?.[0] as any)?.cnt || 0
  const statusMap: Record<string, number> = {}
  let totalMatches = 0
  for (const row of (r[3].results || []) as any[]) {
    statusMap[row.status] = row.cnt
    totalMatches += row.cnt
  }
  const coachingStageMap: Record<string, number> = { pending: 0, matched: 0, completed: 0, cancelled: 0 }
  let coachingTotal = 0
  for (const row of (r[5].results || []) as any[]) {
    const s = row.stage
    if (s === 1) coachingStageMap.pending += row.cnt
    else if (s === 2) coachingStageMap.matched += row.cnt
    else if (s === 3) coachingStageMap.completed += row.cnt
    else if (s === -1) coachingStageMap.cancelled += row.cnt
    if (s >= 1) coachingTotal += row.cnt
  }
  const data = {
    question_room: { questions: g(0), answers: g(1), accepted: g(2) },
    tutoring: {
      coaching: { by_stage: coachingStageMap, by_subject: r[6].results || [], total: coachingTotal },
      by_status: statusMap, by_subject: r[4].results || [],
      total: totalMatches, cancelled: statusMap.cancelled || 0,
    },
    range: { from: fromDate, to: toDate },
    filters: { subject: f.subject || null, grade: f.grade || null },
  }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/top-users', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const url = new URL(c.req.url)
  const type = (url.searchParams.get('type') || 'question') as 'question' | 'answer' | 'accepted'
  const limit = Math.min(20, Math.max(1, parseInt(url.searchParams.get('limit') || '10', 10)))
  const cacheKey = `top-users:${type}:${limit}:${from}:${to}:${filterCacheKey(f)}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const useQuAlias = type === 'answer' || type === 'accepted'
  const filter = useQuAlias ? buildQuestionFilter(f, 'qu') : buildQuestionFilter(f)
  let sql: string
  if (type === 'accepted') {
    sql = `SELECT u.id, u.nickname, u.grade, u.external_id, COUNT(a.id) as cnt
           FROM answers a JOIN questions q ON q.id = a.question_id LEFT JOIN users qu ON qu.id = q.user_id JOIN users u ON u.id = a.user_id
           WHERE a.is_accepted = 1 AND a.created_at BETWEEN ? AND ? AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filter.sql}
           GROUP BY u.id ORDER BY cnt DESC LIMIT ?`
  } else if (type === 'answer') {
    sql = `SELECT u.id, u.nickname, u.grade, u.external_id, COUNT(a.id) as cnt
           FROM answers a JOIN questions q ON q.id = a.question_id LEFT JOIN users qu ON qu.id = q.user_id JOIN users u ON u.id = a.user_id
           WHERE a.created_at BETWEEN ? AND ? AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filter.sql}
           GROUP BY u.id ORDER BY cnt DESC LIMIT ?`
  } else {
    sql = `SELECT u.id, u.nickname, u.grade, u.external_id, COUNT(q.id) as cnt
           FROM questions q JOIN users u ON u.id = q.user_id
           WHERE q.created_at BETWEEN ? AND ? AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filter.sql}
           GROUP BY u.id ORDER BY cnt DESC LIMIT ?`
  }
  const rs = await db.prepare(sql).bind(from, to, ...filter.binds, limit).all()
  const users = (rs.results || []) as any[]
  await enrichWithRealnames(c.env, users)
  const data = { type, users, range: { from: fromDate, to: toDate }, filters: { subject: f.subject || null, grade: f.grade || null } }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/question-types', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const url = new URL(c.req.url)
  const perTypeLimit = Math.min(30, Math.max(5, parseInt(url.searchParams.get('per_type_limit') || '20', 10)))
  const cacheKey = `question-types:${from}:${to}:${filterCacheKey(f)}:${perTypeLimit}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  const filter = buildQuestionFilter(f)
  const userJoin = filter.needUserJoin ? ' LEFT JOIN users u ON u.id = q.user_id' : ''

  const typeCountsRes = await db.prepare(
    `SELECT q.question_type as type, COUNT(*) as cnt
     FROM questions q${userJoin}
     WHERE q.created_at BETWEEN ? AND ? AND q.question_type IS NOT NULL AND q.question_type != ''${filter.sql}
     GROUP BY q.question_type ORDER BY cnt DESC`
  ).bind(from, to, ...filter.binds).all()
  const typeCounts: Record<string, number> = {}
  for (const row of (typeCountsRes.results || []) as any[]) typeCounts[row.type] = row.cnt

  const userJoinU = filter.needUserJoin ? '' : ' LEFT JOIN users u ON u.id = q.user_id'
  const usersBlockSql =
    `WITH ranked AS (
       SELECT q.question_type as type, u.id as user_id, u.nickname as nickname, u.grade as grade, u.external_id as external_id,
              COUNT(*) as cnt, MAX(q.id) as last_question_id,
              ROW_NUMBER() OVER (PARTITION BY q.question_type ORDER BY COUNT(*) DESC, u.id ASC) as rn
       FROM questions q${userJoin}${userJoinU}
       WHERE q.created_at BETWEEN ? AND ? AND q.question_type IS NOT NULL AND q.question_type != '' AND u.id IS NOT NULL AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filter.sql}
       GROUP BY q.question_type, u.id
     )
     SELECT type, user_id, nickname, grade, external_id, cnt, last_question_id
     FROM ranked WHERE rn <= ? ORDER BY type ASC, cnt DESC`
  const usersRes = await db.prepare(usersBlockSql).bind(from, to, ...filter.binds, perTypeLimit).all()
  const usersByType: Record<string, any[]> = {}
  for (const row of (usersRes.results || []) as any[]) {
    const t = row.type
    if (!usersByType[t]) usersByType[t] = []
    usersByType[t].push({
      user_id: row.user_id, nickname: row.nickname, grade: row.grade,
      external_id: row.external_id, cnt: row.cnt, last_question_id: row.last_question_id,
    })
  }

  // 모든 유형별 사용자 목록을 한 번에 enrichment (중복 user는 캐시가 알아서 처리)
  const allUsers: any[] = []
  for (const t of Object.keys(usersByType)) for (const u of usersByType[t]) allUsers.push(u)
  await enrichWithRealnames(c.env, allUsers)

  const data = {
    type_counts: typeCounts, users_by_type: usersByType, per_type_limit: perTypeLimit,
    range: { from: fromDate, to: toDate },
    filters: { subject: f.subject || null, grade: f.grade || null },
  }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

app.get('/api/admin/tutoring-users', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const db = c.env.DB
  const f = parseAdminRange(c)
  const { from, to, fromDate, toDate } = f
  const url = new URL(c.req.url)
  const role = (url.searchParams.get('role') || 'tutee') as 'tutor' | 'tutee'
  const limit = Math.min(30, Math.max(5, parseInt(url.searchParams.get('limit') || '20', 10)))
  const cacheKey = `tutoring-users:${role}:${from}:${to}:${filterCacheKey(f)}:${limit}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  let users: any[] = []
  if (role === 'tutee') {
    const filter = buildQuestionFilter(f)
    const rs = await db.prepare(
      `SELECT u.id as user_id, u.nickname, u.grade, u.external_id, COUNT(*) as cnt
       FROM questions q JOIN users u ON u.id = q.user_id
       WHERE q.created_at BETWEEN ? AND ? AND q.coaching_requested IS NOT NULL AND q.coaching_requested >= 1 AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filter.sql}
       GROUP BY u.id ORDER BY cnt DESC LIMIT ?`
    ).bind(from, to, ...filter.binds, limit).all()
    users = (rs.results || []) as any[]
  } else {
    const filterTutor = buildQuestionFilter(f, 'qu')
    const quJoin = filterTutor.needUserJoin ? ' LEFT JOIN users qu ON qu.id = q.user_id' : ''
    const rs = await db.prepare(
      `SELECT u.id as user_id, u.nickname, u.grade, u.external_id, COUNT(*) as cnt
       FROM tutoring_matches tm JOIN questions q ON q.id = tm.question_id${quJoin} JOIN users u ON u.id = tm.tutor_id
       WHERE tm.held_at BETWEEN ? AND ? AND u.id != 252 AND (u.external_id IS NULL OR u.external_id != '68251')${filterTutor.sql}
       GROUP BY u.id ORDER BY cnt DESC LIMIT ?`
    ).bind(from, to, ...filterTutor.binds, limit).all()
    users = (rs.results || []) as any[]
  }

  await enrichWithRealnames(c.env, users)
  const data = { role, users, range: { from: fromDate, to: toDate }, filters: { subject: f.subject || null, grade: f.grade || null } }
  adminCacheSet(cacheKey, data)
  return c.json(data)
})

// ----- AI 튜터 (정율 선생님) 실데이터 연동 -----
// 외부: https://jungyoul.com/api/ai_tutor_stats.php
// 인증: REALNAME_API_SECRET 재활용 (관리자 전용)
app.get('/api/admin/ai-tutor', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const f = parseAdminRange(c)
  const { fromDate, toDate } = f
  const cacheKey = `ai-tutor:${fromDate}:${toDate}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  if (!c.env.REALNAME_API_SECRET) {
    return c.json({ connected: false, error: 'secret not configured', range: { from: fromDate, to: toDate } })
  }

  try {
    const res = await fetch('https://jungyoul.com/api/ai_tutor_stats.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': c.env.REALNAME_API_SECRET },
      body: JSON.stringify({ from: fromDate, to: toDate }),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      return c.json({ connected: false, error: `upstream ${res.status}`, detail: txt.slice(0, 200), range: { from: fromDate, to: toDate } }, 502)
    }
    const data = await res.json() as any
    // 외부 응답 그대로 통과 (구조는 명세와 일치한다고 가정)
    const out = { ...data, connected: true, range: { from: fromDate, to: toDate } }
    adminCacheSet(cacheKey, out)
    return c.json(out)
  } catch (e: any) {
    return c.json({ connected: false, error: 'fetch failed', detail: String(e?.message || e).slice(0, 200), range: { from: fromDate, to: toDate } }, 502)
  }
})

// ----- 수학 문제 풀이 통계 (jungyoul.com/api/math_practice_stats.php) -----
app.get('/api/admin/math-practice', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  const f = parseAdminRange(c)
  const { fromDate, toDate } = f
  const url = new URL(c.req.url)
  const subject = url.searchParams.get('subject')
  const cacheKey = `math-practice:${fromDate}:${toDate}:${subject || 'all'}`
  const cached = adminCacheGet(cacheKey)
  if (cached) return c.json(cached)

  if (!c.env.REALNAME_API_SECRET) {
    return c.json({ connected: false, error: 'secret not configured', range: { from: fromDate, to: toDate } })
  }

  try {
    const body: any = { from: fromDate, to: toDate }
    if (subject && subject !== 'all') body.subject = subject
    const res = await fetch('https://jungyoul.com/api/math_practice_stats.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Proxy-Secret': c.env.REALNAME_API_SECRET },
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      const txt = await res.text().catch(() => '')
      return c.json({ connected: false, error: `upstream ${res.status}`, detail: txt.slice(0, 200), range: { from: fromDate, to: toDate } }, 502)
    }
    const data = await res.json() as any
    // top_students.user_id → external_id 미러링 후 실명 enrichment
    const topStudents = (data.top_students || []).map((s: any) => ({ ...s, external_id: s.user_id }))
    await enrichWithRealnames(c.env, topStudents)
    const out = { ...data, top_students: topStudents, connected: true, range: { from: fromDate, to: toDate } }
    adminCacheSet(cacheKey, out)
    return c.json(out)
  } catch (e: any) {
    return c.json({ connected: false, error: 'fetch failed', detail: String(e?.message || e).slice(0, 200), range: { from: fromDate, to: toDate } }, 502)
  }
})

app.post('/api/admin/cache/purge', async (c) => {
  if (!(await requireAdminSession(c))) return c.json({ error: 'Unauthorized' }, 401)
  adminCache.clear()
  return c.json({ success: true, purged: true })
})

app.get('/admin/login', (c) => c.html(adminLoginHTML()))
app.get('/admin', async (c) => {
  if (!(await verifyAdminSession(c))) return c.redirect('/admin/login')
  return c.html(adminDashboardHTML())
})

export default app

// P2-B3: 공통 HTML head 헬퍼 — 7개 페이지의 보일러플레이트 통합
function htmlHead(title: string) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>${title}</title>
${pwaHead()}
${katexHead()}
<style>
${sharedCSS()}`
}

// ===== PWA Meta Tags =====

function katexHead() {
  return `<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.21/dist/katex.min.css" crossorigin="anonymous">
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.21/dist/katex.min.js" crossorigin="anonymous"></script>
<script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.21/dist/contrib/auto-render.min.js" crossorigin="anonymous"></script>
<style>.katex{font-size:1.05em!important;color:inherit!important}.katex-display{margin:.6em 0!important;overflow-x:auto;overflow-y:hidden;padding:4px 0}.katex-display>.katex{text-align:left}</style>`
}

function pwaHead() {
  return `<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#0B0E14">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Q&A">
<link rel="apple-touch-icon" href="/icon-192.svg">
<meta name="mobile-web-app-capable" content="yes">`
}

function pwaScript() {
  return `<script>
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/sw.js').catch(()=>{});
}
</script>`
}

// ===== Shared CSS =====

function sharedCSS() {
  return `
@import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css');
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&display=swap');
@import url('https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css');
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
:root{
  /* === CLAUDE.md 다크 테마 색상 시스템 === */
  --bg-base:#0d1117;--bg-primary:#161b22;--bg-secondary:#1c2333;--bg-tertiary:#242d3d;--bg-elevated:#2d3548;
  --bg-overlay:rgba(0,0,0,0.6);
  /* 기존 별칭 유지 (하위 호환) */
  --bg:#0d1117;--bg2:#1c2333;--bg3:#242d3d;--bg4:#2d3548;

  /* 텍스트 */
  --text-primary:#f0f6fc;--text-secondary:#8b949e;--text-muted:#484f58;--text-link:#58a6ff;
  --text:#f0f6fc;--dim:#8b949e;--muted:#484f58;--white:#f0f6fc;

  /* 보더 */
  --border-default:rgba(255,255,255,0.08);--border:rgba(255,255,255,0.08);

  /* 액센트 */
  --accent-primary:#7c6aef;--accent-like:#ff6b6b;--accent-success:#2dd4a8;--accent-warning:#fbbf24;--accent-gold:#f59e0b;
  --accent:#7c6aef;--accent-cyan:#06B6D4;
  --accent-gradient:linear-gradient(135deg,#7c6aef,#06B6D4);
  --red:#EF4444;--green:#2dd4a8;--gold:#fbbf24;

  /* 과목별 태그 컬러 */
  --tag-korean:#ef6351;--tag-math:#7c6aef;--tag-english:#00d2d3;--tag-social:#fbbf24;
  --tag-science:#2dd4a8;--tag-history:#ec4899;--tag-vocation:#f472b6;--tag-language2:#a78bfa;--tag-etc:#8b949e;
  --subj-korean:#ef6351;--subj-math:#7c6aef;--subj-english:#00d2d3;--subj-science:#2dd4a8;--subj-other:#8b949e;

  /* 글래스모피즘 */
  --glass-bg:rgba(22,27,34,0.8);--glass-border:rgba(255,255,255,0.08);--glass-blur:blur(20px) saturate(180%);
  --focus-ring:0 0 0 3px rgba(124,106,239,0.5);

  /* 레이아웃 */
  --sidebar-width:260px;--header-height:56px;--filter-bar-height:100px;

  /* 간격 */
  --sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:20px;--sp-6:24px;--sp-8:32px;--sp-10:40px;

  /* 반경 */
  --radius-sm:6px;--radius-md:10px;--radius-lg:14px;--radius-xl:20px;--radius-full:9999px;

  /* 그림자 */
  --shadow-sm:0 1px 3px rgba(0,0,0,0.3);--shadow-md:0 4px 12px rgba(0,0,0,0.4);--shadow-lg:0 8px 30px rgba(0,0,0,0.5);

  /* 트랜지션 */
  --transition-fast:0.15s ease;--transition-normal:0.3s cubic-bezier(0.4,0,0.2,1);--transition-spring:0.5s cubic-bezier(0.34,1.56,0.64,1);
  --spring:cubic-bezier(0.34,1.56,0.64,1);--ease-out-expo:cubic-bezier(0.16,1,0.3,1);

  /* 폰트 */
  --font-display:'Outfit','Pretendard',-apple-system,sans-serif;
  --font-body:'Pretendard',-apple-system,sans-serif;
  --font-mono:'SF Mono','Fira Code',monospace;
}
html{scroll-behavior:smooth;-webkit-text-size-adjust:100%}
body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;overflow-x:hidden;touch-action:manipulation;-webkit-tap-highlight-color:transparent;padding-bottom:env(safe-area-inset-bottom)}
a{color:inherit;text-decoration:none}
button{cursor:pointer;font-family:inherit;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
input,textarea,select{font-family:inherit}
button,a,[role="button"],input[type="submit"]{min-height:44px;min-width:44px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.1);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.2)}
::selection{background:rgba(139,92,246,0.3);color:#fff}
@keyframes springBounce{0%{transform:scale(0.9);opacity:0}60%{transform:scale(1.02)}100%{transform:scale(1);opacity:1}}
@keyframes springIn{0%{transform:translateY(20px);opacity:0}100%{transform:translateY(0);opacity:1}}
@keyframes fadeInUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulseGlow{0%,100%{box-shadow:0 0 20px rgba(139,92,246,0.2)}50%{box-shadow:0 0 40px rgba(139,92,246,0.4)}}
@keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
@keyframes gradientShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
@keyframes confettiFall{0%{transform:translateY(-10px) rotate(0deg);opacity:1}100%{transform:translateY(100vh) rotate(720deg);opacity:0}}
@keyframes coachingPulse{0%,100%{box-shadow:0 2px 8px rgba(16,185,129,.4)}50%{box-shadow:0 2px 16px rgba(16,185,129,.7),0 0 24px rgba(16,185,129,.3)}}
.confetti-piece{position:fixed;top:-10px;width:8px;height:8px;border-radius:2px;z-index:99999;pointer-events:none;animation:confettiFall 2s var(--spring) forwards}
@keyframes heartPop{0%{transform:scale(0);opacity:1}50%{transform:scale(1.3)}100%{transform:scale(1);opacity:1}}
.toast-container{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;padding-top:env(safe-area-inset-top)}
.toast{padding:12px 24px;border-radius:14px;font-size:14px;font-weight:600;color:#fff;pointer-events:auto;animation:toastSpringIn .4s var(--spring),toastOut .3s ease 2.7s forwards;max-width:90vw;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.4);backdrop-filter:blur(12px)}
.toast--error{background:linear-gradient(135deg,#EF4444,#DC2626)}
.toast--success{background:linear-gradient(135deg,#10B981,#059669)}
.toast--warn{background:linear-gradient(135deg,#F59E0B,#D97706)}
.toast--info{background:linear-gradient(135deg,#8B5CF6,#7C3AED)}
@keyframes toastSpringIn{0%{opacity:0;transform:translateY(-20px) scale(0.9)}100%{opacity:1;transform:translateY(0) scale(1)}}
@keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateY(-12px) scale(0.95)}}
.skeleton{background:var(--glass-bg);border-radius:16px;aspect-ratio:4/3;position:relative;overflow:hidden;border:1px solid var(--glass-border)}
.skeleton::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.06),transparent);animation:shimmer 1.5s infinite}
.skeleton__bar{height:12px;border-radius:6px;background:rgba(255,255,255,.06);margin:12px}
.skeleton__bar--short{width:60%}
.skeleton__bar--long{width:85%}
.error-state{grid-column:1/-1;text-align:center;padding:48px;color:var(--dim)}
.error-state__btn{margin-top:16px;padding:10px 24px;background:var(--glass-bg);color:var(--text);border:1px solid var(--glass-border);border-radius:12px;font-size:14px;cursor:pointer;transition:all .2s var(--spring);backdrop-filter:var(--glass-blur)}
.error-state__btn:hover{background:rgba(255,255,255,0.1);border-color:rgba(255,255,255,0.2);transform:translateY(-2px)}
.confirm-modal-overlay{position:fixed;inset:0;z-index:99998;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:20px;animation:cmFadeIn .2s ease;backdrop-filter:blur(8px)}
.confirm-modal{background:var(--bg2);border:1px solid var(--glass-border);border-radius:20px;padding:28px;max-width:380px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,.5);animation:modalSpringIn .3s var(--spring);backdrop-filter:var(--glass-blur)}
.confirm-modal__msg{font-size:15px;line-height:1.7;color:var(--text);margin-bottom:24px;white-space:pre-line}
.confirm-modal__btns{display:flex;gap:12px;justify-content:flex-end}
.confirm-modal__btn{padding:10px 24px;border-radius:12px;font-size:14px;font-weight:600;border:none;cursor:pointer;transition:all .2s var(--spring);min-height:44px}
.confirm-modal__btn--cancel{background:var(--bg3);color:var(--dim)}
.confirm-modal__btn--cancel:hover{background:var(--bg4);color:var(--text)}
.confirm-modal__btn--ok{background:var(--accent-gradient);color:#fff}
.confirm-modal__btn--ok:hover{opacity:.9;transform:scale(1.02)}
.confirm-modal__btn--danger{background:linear-gradient(135deg,#EF4444,#DC2626);color:#fff}
.confirm-modal__btn--danger:hover{opacity:.9;transform:scale(1.02)}
.tutor-mode-overlay{position:fixed;inset:0;z-index:99998;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:20px;animation:cmFadeIn .2s ease;backdrop-filter:blur(8px)}
.tutor-mode-popup{background:var(--bg2);border:1px solid var(--glass-border);border-radius:20px;padding:28px;max-width:340px;width:100%;box-shadow:0 24px 80px rgba(0,0,0,.5);animation:modalSpringIn .3s var(--spring);backdrop-filter:var(--glass-blur)}
.tutor-mode-title{font-size:16px;font-weight:700;color:var(--text);text-align:center;margin-bottom:20px}
.tutor-mode-cards{display:flex;flex-direction:column;gap:12px}
.tutor-mode-card{display:flex;align-items:flex-start;gap:14px;padding:16px;border-radius:14px;border:1.5px solid var(--glass-border);background:var(--bg3);cursor:pointer;transition:all .2s var(--spring)}
.tutor-mode-card:hover{border-color:#a29bfe;background:rgba(108,92,231,.1);transform:translateY(-1px)}
.tutor-mode-card:active{transform:scale(.97)}
.tutor-mode-icon{font-size:24px;flex-shrink:0;margin-top:2px}
.tutor-mode-label{font-size:15px;font-weight:700;color:var(--text);margin-bottom:4px}
.tutor-mode-desc{font-size:13px;color:var(--dim);line-height:1.5}
@media(min-width:768px){.tutor-mode-popup{max-width:400px;padding:32px}.tutor-mode-label{font-size:17px}.tutor-mode-desc{font-size:14px}}
@keyframes cmFadeIn{from{opacity:0}to{opacity:1}}
@keyframes modalSpringIn{0%{opacity:0;transform:scale(0.9) translateY(10px)}100%{opacity:1;transform:scale(1) translateY(0)}}
@media(min-width:768px){
  body{font-size:18px}
  .toast{font-size:16px;padding:14px 28px;border-radius:16px}
  .confirm-modal{max-width:420px;padding:32px}
  .confirm-modal__msg{font-size:17px}
  .confirm-modal__btn{padding:12px 28px;font-size:16px}
}
@supports(padding-bottom:env(safe-area-inset-bottom)){
  .bottom-bar,.fab{padding-bottom:calc(8px + env(safe-area-inset-bottom))}
}
`
}

// ===== Shared Auth JS =====
function sharedAuthJS() {
  return `
function getToken(){return localStorage.getItem('qa_token')}
function setToken(t){localStorage.setItem('qa_token',t)}
function clearToken(){localStorage.removeItem('qa_token');localStorage.removeItem('qa_user')}
function getUser(){try{return JSON.parse(localStorage.getItem('qa_user'))}catch(e){return null}}
function setUser(u){localStorage.setItem('qa_user',JSON.stringify(u))}
function authHeaders(){const t=getToken();return t?{'Authorization':'Bearer '+t,'Content-Type':'application/json'}:{'Content-Type':'application/json'}}

// === Presigned URL upload helper ===
// Tries presigned URL first, falls back to legacy base64 upload
async function uploadImageSmart(base64Data, thumbnailBase64, type) {
  // Extract content type from base64
  var ctMatch = base64Data.match(/^data:(image\\/\\w+);base64,/);
  var contentType = ctMatch ? ctMatch[1] : 'image/jpeg';

  // 1) Try presigned URL
  try {
    var presignRes = await fetch('/api/images/presign', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ type: type || 'question', contentType: contentType })
    });
    if (presignRes.ok) {
      var presign = await presignRes.json();
      if (presign.uploadUrl) {
        // Convert base64 to binary
        var raw = base64Data.replace(/^data:image\\/\\w+;base64,/, '');
        var binStr = atob(raw);
        var bytes = new Uint8Array(binStr.length);
        for (var i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);

        // Upload directly to R2 via presigned URL
        var putRes = await fetch(presign.uploadUrl, {
          method: 'PUT',
          headers: { 'Content-Type': contentType },
          body: bytes.buffer
        });
        if (putRes.ok) {
          // Upload thumbnail if exists
          var thumbKey = null;
          if (thumbnailBase64 && presign.thumbnailUploadUrl) {
            try {
              var tRaw = thumbnailBase64.replace(/^data:image\\/\\w+;base64,/, '');
              var tBin = atob(tRaw);
              var tBytes = new Uint8Array(tBin.length);
              for (var j = 0; j < tBin.length; j++) tBytes[j] = tBin.charCodeAt(j);
              var tPutRes = await fetch(presign.thumbnailUploadUrl, {
                method: 'PUT',
                headers: { 'Content-Type': 'image/jpeg' },
                body: tBytes.buffer
              });
              if (tPutRes.ok) thumbKey = presign.thumbnailKey;
            } catch(e) { console.warn('Thumb presign upload failed, skipping', e); }
          }
          return { key: presign.key, thumbnailKey: thumbKey || presign.thumbnailKey };
        }
      }
    }
  } catch(e) { console.warn('Presigned upload failed, trying legacy', e); }

  // 2) Fallback: legacy base64 upload via Workers
  var upRes = await fetch('/api/images/upload', {
    method: 'POST', headers: authHeaders(),
    body: JSON.stringify({ image_data: base64Data, thumbnail_data: thumbnailBase64 || null, type: type || 'question' })
  });
  var upData = await upRes.json();
  if (upRes.ok && upData.key) return { key: upData.key, thumbnailKey: upData.thumbnailKey || null };
  throw new Error(upData.error || '이미지 업로드 실패');
}

async function checkAuth(){
  // 1) URL 파라미터에서 user_id 확인 (정율톡에서 호출)
  const params=new URLSearchParams(location.search);
  const extUserId=params.get('user_id');
  const extNickName=params.get('nick_name');
  if(extUserId){
    try{
      const r=await fetch('/api/auth/external',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:extUserId,nick_name:extNickName||undefined})});
      if(r.ok){
        const d=await r.json();
        setToken(d.token);setUser(d.user);
        // URL에서 파라미터 제거 (깔끔한 URL)
        const clean=location.pathname+(params.toString()?'':'');
        params.delete('user_id');params.delete('nick_name');
        const newUrl=location.pathname+(params.toString()?'?'+params.toString():'');
        history.replaceState(null,'',newUrl);
        return d.user;
      }
    }catch(e){}
  }
  // 2) 기존 토큰 확인
  const t=getToken();if(!t)return null;
  try{const r=await fetch('/api/auth/me',{headers:{'Authorization':'Bearer '+t}});if(!r.ok){clearToken();return null}const u=await r.json();setUser(u);return u}
  catch(e){return null}
}
function requireAuth(){const t=getToken();if(!t){return false}return true}
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(()=>{})}
function timeAgo(d){if(!d)return'';const ms=Date.now()-new Date(d+'Z').getTime(),m=Math.floor(ms/60000);if(m<1)return'방금 전';if(m<60)return m+'분 전';const h=Math.floor(m/60);if(h<24)return h+'시간 전';return Math.floor(h/24)+'일 전'}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function showToast(msg,type){type=type||'info';var c=document.querySelector('.toast-container');if(!c){c=document.createElement('div');c.className='toast-container';document.body.prepend(c)}var t=document.createElement('div');t.className='toast toast--'+type;t.textContent=msg;c.appendChild(t);setTimeout(function(){t.remove();if(c&&!c.children.length)c.remove()},3000)}
function showConfirmModal(msg,onConfirm,opts){
  opts=opts||{};
  var ov=document.createElement('div');ov.className='confirm-modal-overlay';
  var okClass=opts.danger?'confirm-modal__btn confirm-modal__btn--danger':'confirm-modal__btn confirm-modal__btn--ok';
  ov.innerHTML='<div class="confirm-modal"><div class="confirm-modal__msg">'+esc(msg)+'</div><div class="confirm-modal__btns"><button class="confirm-modal__btn confirm-modal__btn--cancel">'+(opts.cancelText||'취소')+'</button><button class="'+okClass+'">'+(opts.confirmText||'확인')+'</button></div></div>';
  function close(){ov.remove()}
  ov.addEventListener('click',function(e){if(e.target===ov)close()});
  ov.querySelector('.confirm-modal__btn--cancel').addEventListener('click',close);
  var okBtn=ov.querySelector('.confirm-modal__btn--ok')||ov.querySelector('.confirm-modal__btn--danger');
  okBtn.addEventListener('click',function(){close();onConfirm()});
  document.addEventListener('keydown',function handler(e){if(e.key==='Escape'){close();document.removeEventListener('keydown',handler)}});
  document.body.appendChild(ov);
}
function showTutorModePopup(onSelect){
  var ov=document.createElement('div');ov.className='tutor-mode-overlay';
  ov.innerHTML='<div class="tutor-mode-popup"><div class="tutor-mode-title">모드를 선택해주세요</div><div class="tutor-mode-cards"><div class="tutor-mode-card" data-mode="normal"><div class="tutor-mode-icon">\u{1F4D6}</div><div><div class="tutor-mode-label">실력 UP</div><div class="tutor-mode-desc">질문을 따라가며 직접 답을 찾아봐요<br><span style="color:#10B981;font-size:11px;margin-top:4px;display:inline-block">\u2B50 풀이 과정이 진짜 내 실력이 돼요</span></div></div></div><div class="tutor-mode-card" data-mode="quick"><div class="tutor-mode-icon">\u26A1</div><div><div class="tutor-mode-label">빠른 해결</div><div class="tutor-mode-desc">궁금한 건 바로바로, 답과 풀이를 빠르게 확인해요<br><span style="color:#a29bfe;font-size:11px;margin-top:4px;display:inline-block">* 시험 기간 한정 — 평소엔 실력 UP 모드를 추천해요</span></div></div></div></div></div>';
  function close(){ov.remove();document.removeEventListener('keydown',handler)}
  function handler(e){if(e.key==='Escape')close()}
  ov.addEventListener('click',function(e){if(e.target===ov)close()});
  ov.querySelectorAll('.tutor-mode-card').forEach(function(card){card.addEventListener('click',function(){var mode=card.getAttribute('data-mode');close();onSelect(mode)})});
  document.addEventListener('keydown',handler);
  document.body.appendChild(ov);
}
function showConfetti(){
  var colors=['#8B5CF6','#06B6D4','#EC4899','#FBBF24','#10B981','#F97316'];
  for(var i=0;i<30;i++){
    var el=document.createElement('div');
    el.className='confetti-piece';
    el.style.left=Math.random()*100+'vw';
    el.style.background=colors[Math.floor(Math.random()*colors.length)];
    el.style.animationDelay=Math.random()*0.5+'s';
    el.style.animationDuration=(1.5+Math.random())+'s';
    document.body.appendChild(el);
    setTimeout(function(){el.remove()},3000);
  }
}
function showHeartPop(el){
  var heart=document.createElement('span');
  heart.textContent='\u{1F49A}';
  heart.style.cssText='position:absolute;font-size:32px;pointer-events:none;animation:heartPop .5s cubic-bezier(0.34,1.56,0.64,1) forwards;z-index:9999;';
  el.style.position='relative';
  el.appendChild(heart);
  setTimeout(function(){heart.remove()},600);
}
fetch('/api/analytics/pageview',{method:'POST',headers:authHeaders(),body:JSON.stringify({path:location.pathname})}).catch(function(){});
`
}

// ===== Main Page (Grid Gallery) =====

function mainPageHTML(questions: any[] = [], counts: any = {}, ssrUser: any = null, ssrCpBalance: number | null = null) {
  const isLoggedIn = !!ssrUser
  const ssrNickname = ssrUser?.nickname || ''
  const ssrCpDisplay = ssrCpBalance !== null ? ((ssrCpBalance || 0) * 100).toLocaleString() : '-'
  return `${htmlHead('Q&A')}

/* === Header (Top Bar) === */
.nav{position:sticky;top:0;z-index:200;height:var(--header-height);display:flex;align-items:center;padding:0 var(--sp-6);background:var(--bg-primary);border-bottom:1px solid var(--border-default);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);padding-top:env(safe-area-inset-top);flex-shrink:0}
.nav__menu-btn{width:44px;height:44px;display:flex;align-items:center;justify-content:center;background:none;border:none;color:var(--text-secondary);font-size:18px;border-radius:var(--radius-md);transition:all var(--transition-fast);margin-right:var(--sp-2);flex-shrink:0}
.nav__menu-btn:hover{color:var(--text-primary);background:rgba(255,255,255,.06)}
.nav__logo{font-family:var(--font-display);font-size:24px;font-weight:900;background:var(--accent-gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-0.5px;flex-shrink:0}
.nav__right{display:flex;align-items:center;gap:var(--sp-2);margin-left:auto}
.nav__search-wrap{position:relative;display:flex;align-items:center;height:40px}
.nav__search{width:0;padding:0;border:none;background:transparent;color:var(--text-primary);font-size:14px;outline:none;transition:width .3s var(--ease-out-expo),padding .3s,border .3s,background .3s;border-radius:var(--radius-md);position:absolute;right:0}
.nav__search.open{width:220px;padding:8px 16px;border:1px solid var(--border-default);background:var(--bg-secondary);backdrop-filter:blur(12px)}
.nav__search-icon{font-size:16px;color:var(--text-secondary);cursor:pointer;width:40px;height:40px;display:flex;align-items:center;justify-content:center;border-radius:var(--radius-md);transition:all var(--transition-fast)}
.nav__search-icon:hover{color:var(--text-primary);background:rgba(255,255,255,.06)}
.nav__bell{width:40px;height:40px;display:flex;align-items:center;justify-content:center;color:var(--text-secondary);font-size:16px;border-radius:var(--radius-md);transition:all var(--transition-fast);background:none;border:none;position:relative}
.nav__bell:hover{color:var(--text-primary);background:rgba(255,255,255,.06)}
.nav__btn{padding:8px 20px;font-size:14px;font-weight:700;color:#fff;background:var(--accent-gradient);border:none;border-radius:var(--radius-md);transition:all .2s var(--spring);white-space:nowrap;box-shadow:var(--shadow-md);letter-spacing:.3px}
.nav__btn:hover{box-shadow:0 6px 24px rgba(124,106,239,.4);transform:translateY(-1px) scale(1.02)}
.nav__btn:active{transform:scale(0.97)}
.nav__user-btn{padding:8px 14px;font-size:13px;font-weight:600;color:var(--text-secondary);background:var(--bg-secondary);border:1px solid var(--border-default);border-radius:var(--radius-md);transition:all var(--transition-fast);display:flex;align-items:center;gap:6px;white-space:nowrap}
.nav__user-btn:hover{color:var(--text-primary);border-color:rgba(255,255,255,.15);background:var(--bg-tertiary)}
.nav__aux{display:flex;align-items:center;gap:var(--sp-1);margin-left:var(--sp-1)}
.nav__aux a:not(.teachers-badge){font-size:13px;color:var(--text-secondary);text-decoration:none;display:flex;align-items:center;gap:6px;padding:8px 12px;border-radius:var(--radius-md);transition:all var(--transition-fast);white-space:nowrap}
.nav__aux a:not(.teachers-badge):hover{color:var(--text-primary);background:rgba(255,255,255,.06)}
.nav__brand{display:flex;align-items:center;flex-shrink:0;text-decoration:none;margin-right:auto;padding:2px 0 2px 6px;transition:opacity .2s}
.nav__brand:hover{opacity:.85}

/* === Sidebar Panel (Push-aside flex layout) === */
.app-shell{display:flex;height:100dvh;overflow:hidden}
.sidebar{width:0;overflow:hidden;background:rgba(22,27,34,.95);backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);border-right:1px solid rgba(255,255,255,.06);transition:width .3s var(--ease-out-expo);flex-shrink:0}
.sidebar.open{width:var(--sidebar-width)}
.sidebar__inner{width:var(--sidebar-width);min-width:var(--sidebar-width);display:flex;flex-direction:column;height:100%;padding-top:env(safe-area-inset-top);overflow-y:auto;overscroll-behavior:contain}
.main-wrap{flex:1;display:flex;flex-direction:column;overflow-y:auto;min-width:0}
.sidebar__header{padding:var(--sp-5) var(--sp-5) var(--sp-4);display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.06)}
.sidebar__title{font-family:var(--font-display);font-size:20px;font-weight:800;color:var(--text-primary)}
.sidebar__close{width:36px;height:36px;display:flex;align-items:center;justify-content:center;background:none;border:none;color:var(--text-secondary);font-size:16px;border-radius:var(--radius-sm);cursor:pointer;transition:all var(--transition-fast)}
.sidebar__close:hover{color:var(--text-primary);background:rgba(255,255,255,.06)}
.sidebar__section{padding:var(--sp-4) var(--sp-5)}
.sidebar__section-title{font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:var(--sp-3)}
.sidebar__divider{height:1px;background:rgba(255,255,255,.06);margin:0 var(--sp-5)}
.sidebar__item{display:flex;align-items:center;gap:var(--sp-3);padding:10px var(--sp-3);border-radius:var(--radius-md);color:var(--text-secondary);font-size:14px;font-weight:500;cursor:pointer;transition:all var(--transition-fast);border:none;background:none;width:100%;text-align:left}
.sidebar__item:hover{color:var(--text-primary);background:rgba(255,255,255,.04)}
.sidebar__item.active{color:var(--accent-primary);background:rgba(124,106,239,.08)}
.sidebar__item-icon{width:20px;text-align:center;font-size:15px;flex-shrink:0}
.sidebar__item-count{margin-left:auto;font-size:12px;font-weight:600;color:var(--text-muted);background:rgba(255,255,255,.06);padding:2px 8px;border-radius:var(--radius-full);min-width:24px;text-align:center}
.sidebar__stats{display:grid;grid-template-columns:1fr 1fr;gap:var(--sp-2);padding:var(--sp-4) var(--sp-5)}
.sidebar__stat{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:var(--radius-md);padding:var(--sp-3);text-align:center}
.sidebar__stat-num{font-family:var(--font-display);font-size:22px;font-weight:800;color:var(--text-primary)}
.sidebar__stat-label{font-size:11px;color:var(--text-secondary);margin-top:2px}
.sidebar__cta{margin:var(--sp-4) var(--sp-5);padding:12px;font-size:15px;font-weight:700;color:#fff;background:var(--accent-gradient);border:none;border-radius:var(--radius-md);cursor:pointer;transition:all .2s var(--spring);display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:var(--shadow-md)}
.sidebar__cta:hover{transform:translateY(-1px);box-shadow:var(--shadow-lg)}

/* === Main Content Area === */
.app-layout{display:flex;flex-direction:column;flex:1}

/* === Main Content === */
.main{flex:1;padding:var(--sp-4) var(--sp-6) var(--sp-10);max-width:1400px;margin:0 auto;width:100%}

/* === Schedule Banner === */
.today-sch-banner{margin-bottom:var(--sp-4);background:var(--bg-secondary);border:1px solid rgba(251,191,36,.12);border-radius:var(--radius-lg);padding:14px 18px;display:flex;align-items:center;gap:14px;cursor:pointer;transition:all .2s var(--spring)}
.today-sch-banner:hover{border-color:rgba(251,191,36,.25);transform:translateY(-2px);box-shadow:var(--shadow-md)}
.today-sch-banner__icon{width:42px;height:42px;border-radius:50%;background:rgba(251,191,36,.08);display:flex;align-items:center;justify-content:center;font-size:18px;color:var(--accent-warning);flex-shrink:0;animation:ring 2s ease infinite}
.today-sch-banner__info{flex:1;min-width:0}
.today-sch-banner__title{font-size:13px;font-weight:700;color:var(--text-primary);margin-bottom:2px}
.today-sch-banner__sub{font-size:12px;color:var(--text-muted)}
.today-sch-banner__time{font-size:18px;font-weight:800;color:var(--accent-warning);flex-shrink:0;font-family:var(--font-display)}
.today-sch-banner__countdown{font-size:10px;color:var(--text-muted);text-align:right;margin-top:2px}

/* === Filter Bar (Sticky) — NO overflow:hidden === */
.filter-bar{position:sticky;top:var(--header-height);z-index:100;background:var(--bg-base);padding:var(--sp-3) 0 0;margin:0 calc(-1 * var(--sp-6));padding-left:var(--sp-6);padding-right:var(--sp-6);border-bottom:1px solid var(--border-default)}

/* === Subject Chips (Row 1 of filter bar) === */
.filter-row1{display:flex;align-items:center;gap:var(--sp-2);padding-bottom:var(--sp-2)}
.subj-bar{display:flex;gap:var(--sp-2);align-items:center;flex:1;min-width:0}
.subj-chip{padding:6px 16px;border-radius:var(--radius-full);font-size:13px;font-weight:600;border:1px solid var(--border-default);background:transparent;color:var(--text-secondary);cursor:pointer;transition:all .25s var(--spring);white-space:nowrap}
.subj-chip:hover{border-color:rgba(255,255,255,.15);color:var(--text-primary);transform:translateY(-1px)}
.subj-chip.active{background:var(--accent-primary);color:#fff;border-color:transparent;box-shadow:0 2px 12px rgba(124,106,239,.35);animation:chipBounce .4s var(--spring)}
.subj-chip.active:hover{transform:scale(1.05) translateY(-1px)}
.subj-chip[data-subj="\uAD6D\uC5B4"].active{background:var(--tag-korean);box-shadow:0 2px 12px rgba(239,99,81,.3)}
.subj-chip[data-subj="\uC218\uD559"].active{background:var(--tag-math);box-shadow:0 2px 12px rgba(124,106,239,.3)}
.subj-chip[data-subj="\uC601\uC5B4"].active{background:var(--tag-english);box-shadow:0 2px 12px rgba(0,210,211,.3)}
.subj-chip[data-subj="\uACFC\uD559"].active{background:var(--tag-science);box-shadow:0 2px 12px rgba(45,212,168,.3)}
.subj-chip[data-subj="\uAE30\uD0C0"].active{background:var(--tag-etc);box-shadow:0 2px 12px rgba(139,148,158,.3)}

/* === Row 2: My chips + view toggle + sort === */
.filter-row2{display:flex;align-items:center;gap:var(--sp-2);padding-bottom:var(--sp-3)}
.my-bar{display:flex;gap:var(--sp-2);align-items:center}
.my-chip{padding:6px 16px;border-radius:var(--radius-full);font-size:13px;font-weight:600;border:1px solid rgba(124,106,239,.2);background:transparent;color:var(--accent-primary);cursor:pointer;transition:all .2s var(--spring);display:flex;align-items:center;gap:6px}
.my-chip:hover{border-color:var(--accent-primary);background:rgba(124,106,239,.06)}
.my-chip.active{background:var(--accent-primary);color:#fff;border-color:var(--accent-primary);box-shadow:0 2px 12px rgba(124,106,239,.3)}
.my-chip--ans{border-color:rgba(0,210,211,.2);color:var(--tag-english)}
.my-chip--ans:hover{border-color:var(--tag-english);background:rgba(0,210,211,.06)}
.my-chip--ans.active{background:var(--tag-english);color:#fff;border-color:var(--tag-english);box-shadow:0 2px 12px rgba(0,210,211,.3)}
.teachers-badge{display:inline-flex;align-items:center;gap:8px;padding:4px 10px 4px 6px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:10px;text-decoration:none;transition:all .2s}
.teachers-badge:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.15);transform:translateY(-1px)}
.teachers-badge__icon{width:28px;height:28px;border-radius:7px;background:linear-gradient(135deg,#ef4444,#dc2626);display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px;flex-shrink:0}
.teachers-badge__text{display:flex;flex-direction:column;line-height:1}
.teachers-badge__text strong{font-size:13px;font-weight:800;color:#fff;letter-spacing:-.2px}
.teachers-badge__text small{font-size:9px;font-weight:600;color:#8b949e;margin-top:1px;letter-spacing:.2px}
.subj-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-shrink:0}
.view-toggle{display:flex;align-items:center;background:var(--bg-secondary);border:1px solid var(--border-default);border-radius:var(--radius-md);overflow:hidden}
.view-toggle__btn{padding:6px 10px;font-size:14px;color:var(--text-muted);background:none;border:none;cursor:pointer;transition:all var(--transition-fast);display:flex;align-items:center;justify-content:center}
.view-toggle__btn:hover{color:var(--text-secondary)}
.view-toggle__btn.active{color:var(--accent-primary);background:rgba(124,106,239,.12)}
.subj-right select{background:var(--bg-secondary);color:var(--text-secondary);border:1px solid var(--border-default);border-radius:var(--radius-md);padding:6px 12px;font-size:13px;outline:none;cursor:pointer;transition:all var(--transition-fast)}
.subj-right select:focus{border-color:var(--accent-primary);box-shadow:var(--focus-ring)}

/* === Grid Layout === */
.qgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:var(--sp-4);min-height:200px}
.qgrid.list-view{grid-template-columns:1fr;gap:var(--sp-3)}

/* === Card Styles (New Instagram-inspired design) === */
.card{display:flex;flex-direction:column;border-radius:var(--radius-lg);overflow:hidden;position:relative;cursor:pointer;background:var(--bg-secondary);transition:transform .3s cubic-bezier(.4,0,.2,1),box-shadow .3s cubic-bezier(.4,0,.2,1);text-decoration:none;border:1px solid var(--border-default);box-shadow:var(--shadow-sm);will-change:transform;animation:cardFadeIn .4s ease both}
.card:hover{transform:translateY(-4px);box-shadow:var(--shadow-lg),0 0 0 1px rgba(124,106,239,.1)}
.card:active{transform:scale(0.98);transition-duration:.1s}
.card--accepted{border:2px solid var(--accent-gold);box-shadow:0 0 20px rgba(245,158,11,.15),var(--shadow-sm);animation:cardFadeIn .4s ease both,aha-glow 3s ease-in-out infinite .4s}

/* --- Card Header (Author) --- */
.card__header{display:flex;align-items:center;gap:8px;padding:10px 12px 6px}
.card__avatar{width:32px;height:32px;border-radius:50%;background:var(--bg-tertiary);display:flex;align-items:center;justify-content:center;font-size:13px;color:var(--text-secondary);flex-shrink:0;overflow:hidden}
.card__author-info{flex:1;min-width:0}
.card__author-name{font-size:13px;font-weight:700;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card__author-meta{font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:4px}
.card__grade-chip{font-size:10px;font-weight:700;color:var(--accent-primary);background:rgba(124,106,239,.1);padding:1px 6px;border-radius:var(--radius-sm)}
.card__status-badge{font-size:10px;font-weight:700;padding:2px 8px;border-radius:var(--radius-sm);display:inline-flex;align-items:center;gap:3px;flex-shrink:0}
.card__status--solved{background:rgba(45,212,168,.12);color:var(--accent-success)}
.card__status--waiting{background:rgba(251,191,36,.12);color:var(--accent-warning)}
.card__status--popular{background:rgba(245,158,11,.12);color:var(--accent-gold)}

/* --- Card Image --- */
.card__img-wrap{width:100%;position:relative;overflow:hidden;aspect-ratio:4/3}
.card__img{width:100%;height:100%;object-fit:cover;transition:transform .4s var(--ease-out-expo)}
.card:hover .card__img{transform:scale(1.03)}
.card__ph{width:100%;height:100%;background:linear-gradient(145deg,var(--bg-secondary) 0%,var(--bg-tertiary) 50%,var(--bg-secondary) 100%);display:flex;align-items:center;justify-content:center;color:var(--text-secondary);font-size:14px;font-weight:500;padding:24px 18px;text-align:center;line-height:1.7;position:relative;overflow:hidden}
.card__ph::before{content:'\\201C';position:absolute;top:8px;left:14px;font-size:56px;font-weight:900;color:rgba(124,106,239,.06);font-family:Georgia,serif;line-height:1}
.card__ph::after{content:'\\201D';position:absolute;bottom:28px;right:14px;font-size:56px;font-weight:900;color:rgba(124,106,239,.06);font-family:Georgia,serif;line-height:1}

/* --- Card Badges (on image) --- */
.card__badge{position:absolute;font-size:11px;font-weight:700;padding:4px 10px;background:var(--accent-gradient);color:#fff;border-radius:var(--radius-sm);z-index:2}
.card__badge--done{top:8px;right:8px;left:auto;transform:none;background:linear-gradient(135deg,var(--accent-warning),var(--accent-gold));color:var(--bg-base);display:flex;align-items:center;gap:4px;font-weight:800;padding:5px 12px;box-shadow:0 2px 12px rgba(245,158,11,.3);font-size:11px;letter-spacing:.3px;border-radius:var(--radius-sm)}
.card__badge--killer{top:8px;left:8px;background:linear-gradient(135deg,#F97316,#FB923C);color:#fff;display:flex;align-items:center;gap:4px;border-radius:var(--radius-sm)}
.card__badge--tutor{top:8px;left:8px;background:linear-gradient(135deg,#7c6aef,#a78bfa);color:#fff;display:flex;align-items:center;gap:4px;font-weight:700;border-radius:var(--radius-sm)}
.card__ans-overlay{position:absolute;top:8px;right:8px;font-size:12px;font-weight:600;padding:4px 10px;background:rgba(0,0,0,.55);color:#fff;border-radius:var(--radius-sm);display:flex;align-items:center;gap:4px;z-index:2;backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.08)}
.card__subject-bar{position:absolute;bottom:0;left:0;right:0;padding:8px 10px;display:flex;align-items:center;gap:5px;flex-wrap:nowrap;z-index:3;font-size:12px;overflow:hidden}
.card__subject-bar span{display:inline-block;padding:2px 8px;border-radius:var(--radius-sm);font-weight:600;line-height:1.3}
.card__subj-name{color:#fff;font-size:12px;font-weight:800;flex-shrink:0;font-family:var(--font-display)}
.card__subj-tag{background:rgba(255,255,255,.15);color:rgba(255,255,255,.9);font-size:11px;font-weight:600;backdrop-filter:blur(4px);white-space:nowrap;padding:2px 8px;border-radius:var(--radius-sm)}
.card__subj-tag.extra{display:none}
.card:hover .card__subj-tag.extra{display:inline-block}
.card__match-badge{position:absolute;top:8px;right:8px;margin-top:30px;font-size:11px;font-weight:700;padding:4px 10px;border-radius:var(--radius-sm);z-index:2;display:flex;align-items:center;gap:4px}
.card__match--pending{background:linear-gradient(135deg,var(--accent-warning),var(--accent-gold));color:#111}
.card__match--confirmed{background:linear-gradient(135deg,var(--accent-success),#34D399);color:#111}
.card__match--my-pending{background:linear-gradient(135deg,#7c6aef,#a78bfa);color:#fff}

/* --- Card Body (question text) --- */
.card__body{padding:8px 12px 4px}
.card__text{font-size:13px;color:var(--text-primary);line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;text-overflow:ellipsis;word-break:break-word;min-height:20px}

/* --- Meta / Tags / Labels (hidden in grid, shown in list) --- */
.card__meta{display:none}
.card__meta-item{font-size:12px;font-weight:500;color:var(--text-muted);display:inline-flex;align-items:center;gap:4px}
.card__meta-item i{font-size:10px}
.card__tags{display:none}
.card__tag{font-size:11px;font-weight:600;padding:2px 10px;border-radius:var(--radius-full);background:rgba(124,106,239,.08);color:var(--accent-primary);border:1px solid rgba(124,106,239,.12);white-space:nowrap}
.card__action-label{display:none}
.card__ans-link{display:none}

/* --- Interaction Bar (Instagram-style) --- */
.card__actions{display:flex;align-items:center;padding:4px 12px 4px;gap:2px}
.card__action-btn{background:none;border:none;cursor:pointer;color:var(--text-secondary);font-size:16px;padding:6px 8px;border-radius:var(--radius-sm);transition:all .15s ease;display:flex;align-items:center;gap:4px;-webkit-tap-highlight-color:transparent}
.card__action-btn:hover{color:var(--text-primary);background:rgba(255,255,255,.04)}
.card__action-btn .count{font-size:12px;font-weight:600}
.card__action-btn--like.liked{color:var(--accent-like)}
.card__action-btn--like.liked i{animation:heartPulse .4s var(--spring)}
.card__action-btn--bookmark.saved{color:var(--accent-warning)}
.card__action-btn--bookmark.saved i{animation:heartPulse .3s var(--spring)}
.card__actions-right{margin-left:auto;display:flex;align-items:center;gap:2px}
.card__ans-count{font-size:12px;font-weight:600;color:var(--accent-primary);display:flex;align-items:center;gap:3px;padding:4px 8px}

/* --- Comment Preview --- */
.card__comments{padding:0 12px 10px;border-top:1px solid rgba(255,255,255,.04);margin-top:2px}
.card__comment-item{font-size:12px;color:var(--text-secondary);line-height:1.5;padding-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card__comment-item strong{color:var(--text-primary);font-weight:700;margin-right:4px}
.card__comment-more{font-size:11px;color:var(--text-muted);padding-top:4px;display:block}
.card__comment-empty{font-size:12px;color:var(--text-muted);padding-top:6px;font-style:italic}

/* --- Double-tap Big Heart overlay --- */
.card__big-heart{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) scale(0);font-size:72px;color:#fff;filter:drop-shadow(0 4px 20px rgba(255,107,107,.5));z-index:10;pointer-events:none;opacity:0;transition:none}
.card__big-heart.pop{animation:bigHeartPop .8s var(--spring) forwards}

/* --- 선생님 도와주세요 히어로 스티커 --- */
@import url('https://fonts.googleapis.com/css2?family=Gamja+Flower&display=swap');
.card__teacher-sticker{position:relative;margin:0 10px 8px;border-radius:16px;padding:20px 16px;text-align:center;overflow:hidden;transform:rotate(-1.5deg);box-shadow:0 4px 20px rgba(0,0,0,.4)}
.card__teacher-sticker::before{content:'';position:absolute;inset:0;opacity:.12;pointer-events:none}
/* 수학 - 우주/별빛 */
.card__teacher-sticker--수학{background:linear-gradient(135deg,#0a0e2a 0%,#1a1040 40%,#2d1b69 100%)}
.card__teacher-sticker--수학::before{background:radial-gradient(circle at 20% 30%,#fff 1px,transparent 1px),radial-gradient(circle at 80% 20%,#fff 0.5px,transparent 0.5px),radial-gradient(circle at 50% 70%,#fff 1px,transparent 1px),radial-gradient(circle at 10% 80%,#fff 0.5px,transparent 0.5px),radial-gradient(circle at 90% 60%,#fff 1px,transparent 1px);opacity:.3}
.card__teacher-sticker--수학 .sticker__name{color:#e0d4ff;text-shadow:0 0 20px rgba(124,106,239,.8),0 0 40px rgba(124,106,239,.4)}
.card__teacher-sticker--수학 .sticker__msg{color:#c4b5fd}
/* 영어 - 네온/사이버 */
.card__teacher-sticker--영어{background:linear-gradient(135deg,#051f20 0%,#0a2e3a 40%,#0d3b4a 100%);border:1px solid rgba(0,210,211,.15)}
.card__teacher-sticker--영어::before{background:linear-gradient(90deg,transparent,rgba(0,210,211,.06),transparent);animation:neonScan 3s ease-in-out infinite}
.card__teacher-sticker--영어 .sticker__name{color:#5eead4;text-shadow:0 0 20px rgba(0,210,211,.8),0 0 40px rgba(0,210,211,.4)}
.card__teacher-sticker--영어 .sticker__msg{color:#99f6e4}
@keyframes neonScan{0%,100%{opacity:.05}50%{opacity:.15}}
/* 국어 - 수묵화/동양 */
.card__teacher-sticker--국어{background:linear-gradient(135deg,#1a1014 0%,#2a1a22 40%,#1a1520 100%)}
.card__teacher-sticker--국어::before{background:radial-gradient(ellipse at 30% 50%,rgba(236,72,153,.08),transparent 60%),radial-gradient(ellipse at 70% 50%,rgba(245,158,11,.06),transparent 60%);opacity:.4}
.card__teacher-sticker--국어 .sticker__name{color:#fcd34d;text-shadow:0 0 16px rgba(245,158,11,.6),0 2px 4px rgba(0,0,0,.5);font-style:italic}
.card__teacher-sticker--국어 .sticker__msg{color:#fbbf24}
/* 과학 - 매트릭스/실험실 */
.card__teacher-sticker--과학{background:linear-gradient(135deg,#021a0a 0%,#0a2a15 40%,#0d3320 100%)}
.card__teacher-sticker--과학::before{background:repeating-linear-gradient(0deg,transparent,transparent 20px,rgba(45,212,168,.03) 20px,rgba(45,212,168,.03) 21px);opacity:.5}
.card__teacher-sticker--과학 .sticker__name{color:#6ee7b7;text-shadow:0 0 20px rgba(45,212,168,.8),0 0 40px rgba(45,212,168,.4)}
.card__teacher-sticker--과학 .sticker__msg{color:#a7f3d0}
/* 공통 스티커 텍스트 */
.sticker__name{font-family:'Gamja Flower',cursive;font-size:32px;font-weight:700;line-height:1.2;margin-bottom:4px;letter-spacing:1px}
.sticker__msg{font-family:'Gamja Flower',cursive;font-size:20px;opacity:.85;line-height:1.3}
.sticker__emoji{font-size:18px;margin:0 2px}
/* 리스트 뷰에서 스티커 */
.qgrid.list-view .card__teacher-sticker{margin:0 0 8px;padding:14px 12px}
.qgrid.list-view .sticker__name{font-size:24px}
.qgrid.list-view .sticker__msg{font-size:16px}

/* --- Delete Button (legacy, hidden) --- */
.card__del{display:none}

/* --- More Menu (···) --- */
.card__more{position:relative;margin-left:auto;width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--text-secondary);transition:background .2s,color .2s;flex-shrink:0;-webkit-tap-highlight-color:transparent}
.card__more:hover{background:rgba(255,255,255,.08);color:var(--text-primary)}
.card__more i{font-size:14px}
.card__more-menu{display:none;position:absolute;top:100%;right:0;min-width:140px;background:var(--bg-elevated);border:1px solid var(--glass-border);border-radius:var(--radius-md);box-shadow:var(--shadow-lg);z-index:50;overflow:hidden;animation:menuFadeIn .15s ease}
.card__more.open .card__more-menu{display:block}
.card__more-item{display:flex;align-items:center;gap:8px;width:100%;padding:10px 14px;border:none;background:none;color:var(--text-primary);font-size:13px;font-weight:500;cursor:pointer;transition:background .15s;text-align:left}
.card__more-item:hover{background:rgba(255,255,255,.06)}
.card__more-item i{font-size:12px;width:16px;text-align:center;color:var(--text-secondary)}
.card__more-item--danger{color:var(--accent-like)}
.card__more-item--danger i{color:var(--accent-like)}
.card__more-item--danger:hover{background:rgba(239,68,68,.1)}
@keyframes menuFadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}

/* --- Edit Modal --- */
.edit-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:1000;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeIn .2s ease}
.edit-modal{width:100%;max-width:480px;background:var(--bg-secondary);border:1px solid var(--glass-border);border-radius:var(--radius-lg);overflow:hidden;animation:modalSlideUp .25s cubic-bezier(.4,0,.2,1)}
.edit-modal__header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border-default)}
.edit-modal__title{font-size:16px;font-weight:700;color:var(--text-primary)}
.edit-modal__close{width:32px;height:32px;border-radius:50%;border:none;background:none;color:var(--text-secondary);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:16px;transition:background .15s}
.edit-modal__close:hover{background:rgba(255,255,255,.08)}
.edit-modal__body{padding:20px}
.edit-modal__label{display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.edit-modal__textarea{width:100%;min-height:120px;padding:12px;border-radius:var(--radius-md);border:1px solid var(--border-default);background:var(--bg-tertiary);color:var(--text-primary);font-size:14px;line-height:1.6;resize:vertical;font-family:inherit;transition:border-color .2s}
.edit-modal__textarea:focus{outline:none;border-color:var(--accent-primary)}
.edit-modal__char-count{text-align:right;font-size:11px;color:var(--text-muted);margin-top:4px}
.edit-modal__char-count.over{color:var(--accent-like)}
.edit-modal__select-wrap{margin-top:16px}
.edit-modal__select{width:100%;padding:10px 12px;border-radius:var(--radius-md);border:1px solid var(--border-default);background:var(--bg-tertiary);color:var(--text-primary);font-size:14px;font-family:inherit;cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%238b949e'%3E%3Cpath d='M6 8L1 3h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center}
.edit-modal__select:focus{outline:none;border-color:var(--accent-primary)}
.edit-modal__footer{display:flex;justify-content:flex-end;gap:8px;padding:16px 20px;border-top:1px solid var(--border-default)}
.edit-modal__btn{padding:8px 20px;border-radius:var(--radius-md);border:none;font-size:13px;font-weight:600;cursor:pointer;transition:background .15s,transform .1s}
.edit-modal__btn--cancel{background:var(--bg-tertiary);color:var(--text-secondary)}
.edit-modal__btn--cancel:hover{background:var(--bg-elevated)}
.edit-modal__btn--save{background:var(--accent-primary);color:#fff}
.edit-modal__btn--save:hover{background:#6b59de}
.edit-modal__btn--save:active{transform:scale(.97)}
.edit-modal__btn--save:disabled{opacity:.5;cursor:not-allowed}
@keyframes modalSlideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

/* --- My Badge --- */
.card__my-badge{position:absolute;bottom:6px;left:6px;font-size:11px;font-weight:700;padding:3px 8px;border-radius:3px;z-index:2}

/* === List View Card (3-Column Grid) === */
.qgrid.list-view{gap:12px}
.qgrid.list-view .card{aspect-ratio:auto;max-width:1000px;margin:0 auto;width:100%;border-left:3px solid var(--border-default);transition:border-color .25s,background .25s,transform .3s cubic-bezier(.4,0,.2,1),box-shadow .3s}
.qgrid.list-view .card:hover{transform:translateY(-2px);border-left-color:var(--accent-primary);background:rgba(255,255,255,.02)}
.qgrid.list-view .card[data-subj="수학"]{border-left-color:#3B82F620}.qgrid.list-view .card[data-subj="수학"]:hover{border-left-color:#3B82F6}
.qgrid.list-view .card[data-subj="영어"]{border-left-color:#10B98120}.qgrid.list-view .card[data-subj="영어"]:hover{border-left-color:#10B981}
.qgrid.list-view .card[data-subj="국어"]{border-left-color:#EC489920}.qgrid.list-view .card[data-subj="국어"]:hover{border-left-color:#EC4899}
.qgrid.list-view .card[data-subj="과학"]{border-left-color:#8B5CF620}.qgrid.list-view .card[data-subj="과학"]:hover{border-left-color:#8B5CF6}
.qgrid.list-view .card[data-subj="기타"]{border-left-color:#F9731620}.qgrid.list-view .card[data-subj="기타"]:hover{border-left-color:#F97316}
.qgrid.list-view .card--accepted{border-left-color:var(--accent-gold)}
/* -- Header: author left, status right -- */
.qgrid.list-view .card__header{padding:12px 16px 8px;border-bottom:1px solid rgba(255,255,255,.04)}
.qgrid.list-view .card__status-badge{position:absolute;top:14px;right:16px}
/* -- Content: 3-column grid (image | body | actions) -- */
.qgrid.list-view .card__content{display:grid;grid-template-columns:180px 1fr 140px;min-height:160px}
/* -- Col 1: Image -- */
.qgrid.list-view .card__img-wrap{width:auto;height:auto;aspect-ratio:auto;border-radius:0;overflow:hidden;border-right:1px solid rgba(255,255,255,.04)}
.qgrid.list-view .card__img{width:100%;height:100%;object-fit:cover;border-radius:0}
.qgrid.list-view .card__ph{width:100%;height:100%;border-radius:0;display:flex;align-items:center;justify-content:center}
.qgrid.list-view .card__ph::before,.qgrid.list-view .card__ph::after{display:none}
.qgrid.list-view .card__img-wrap .card__badge{display:none}
.qgrid.list-view .card__img-wrap .card__subject-bar{display:none}
.qgrid.list-view .card__img-wrap .card__ans-overlay{display:none}
.qgrid.list-view .card__img-wrap .card__match-badge{display:none}
.qgrid.list-view .card__img-wrap .card__my-badge{display:none}
/* -- Col 2: Body (text + meta + tags + answer link) -- */
.qgrid.list-view .card__body{padding:16px;display:flex;flex-direction:column;justify-content:flex-start;gap:8px;min-width:0}
.qgrid.list-view .card__text{font-size:15px;font-weight:700;line-height:1.5;-webkit-line-clamp:2}
.qgrid.list-view .card__meta{display:flex;flex-wrap:wrap;gap:12px}
.qgrid.list-view .card__tags{display:flex;flex-wrap:wrap;gap:6px}
.qgrid.list-view .card__ans-link{display:flex;align-items:center;gap:4px;font-size:12px;color:var(--accent-primary);font-weight:600;margin-top:auto}
/* -- Col 3: Actions (vertical sidebar) -- */
.qgrid.list-view .card__actions{flex-direction:column;justify-content:center;gap:0;padding:12px 16px;border-top:none;border-left:1px solid rgba(255,255,255,.04);margin-top:0}
.qgrid.list-view .card__action-btn{width:100%;justify-content:flex-start;padding:8px 4px;gap:8px;font-size:14px;border-radius:var(--radius-sm)}
.qgrid.list-view .card__action-btn:hover{background:rgba(255,255,255,.04)}
.qgrid.list-view .card__action-label{display:inline;font-size:13px;font-weight:500;color:var(--text-secondary)}
.qgrid.list-view .card__action-btn .count{font-size:12px;color:var(--text-muted);margin-left:auto}
.qgrid.list-view .card__actions-right{display:none}
/* -- Footer: comments -- */
.qgrid.list-view .card__comments{padding:0 16px 12px;border-top:1px solid rgba(255,255,255,.04)}
.qgrid.list-view .card__big-heart{display:none}
/* list-view more menu positioning handled by card__header flex */

/* === Pagination === */
.pager{display:flex;justify-content:center;align-items:center;gap:6px;margin-top:var(--sp-6);padding-bottom:var(--sp-5)}
.pager__btn{width:38px;height:38px;border-radius:var(--radius-md);border:1px solid var(--border-default);background:var(--bg-secondary);color:var(--text-secondary);font-size:13px;font-weight:600;font-family:var(--font-display);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s var(--spring)}
.pager__btn:hover{border-color:rgba(255,255,255,.15);color:var(--text-primary);transform:translateY(-1px)}
.pager__btn.active{background:var(--accent-gradient);color:#fff;border-color:transparent;box-shadow:0 2px 12px rgba(124,106,239,.3)}
.pager__btn:disabled{opacity:.3;cursor:default}
.pager__dots{color:var(--text-muted);font-size:14px;padding:0 4px}

.empty{text-align:center;padding:64px 0;color:var(--text-muted);font-size:15px;font-family:var(--font-display)}
.loading-spinner{text-align:center;padding:64px 0;color:var(--text-muted);font-size:13px}

/* === FAB === */
.fab{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:var(--accent-gradient);color:#fff;border:none;font-size:20px;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 32px rgba(124,106,239,.35);z-index:100;transition:transform .2s var(--spring),box-shadow .2s;margin-bottom:env(safe-area-inset-bottom)}
.fab:hover{transform:scale(1.1);box-shadow:0 12px 40px rgba(124,106,239,.45)}
.fab:active{transform:scale(0.9)}
@media(min-width:768px){.fab{display:none}}

/* === Search Results Grid === */
.search-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:var(--sp-4);min-height:200px}

/* === Keyframe Animations === */
@keyframes cardFadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes chipBounce{0%{transform:scale(1)}40%{transform:scale(1.12)}70%{transform:scale(0.95)}100%{transform:scale(1.03)}}
@keyframes heartPulse{0%{transform:scale(1)}30%{transform:scale(1.35)}60%{transform:scale(0.9)}100%{transform:scale(1)}}
@keyframes bigHeartPop{0%{opacity:1;transform:translate(-50%,-50%) scale(0)}15%{opacity:1;transform:translate(-50%,-50%) scale(1.2)}30%{transform:translate(-50%,-50%) scale(0.95)}45%{transform:translate(-50%,-50%) scale(1.05)}60%{opacity:1;transform:translate(-50%,-50%) scale(1)}100%{opacity:0;transform:translate(-50%,-50%) scale(1)}}
@keyframes aha-glow{0%,100%{box-shadow:0 0 20px rgba(245,158,11,.15),var(--shadow-sm)}50%{box-shadow:0 0 32px rgba(245,158,11,.25),var(--shadow-md)}}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideDown{from{opacity:0;transform:translateX(-50%) translateY(-20px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
@keyframes ring{0%{transform:rotate(0)}15%{transform:rotate(15deg)}30%{transform:rotate(-15deg)}45%{transform:rotate(10deg)}60%{transform:rotate(-10deg)}75%{transform:rotate(5deg)}100%{transform:rotate(0)}}

/* === Mobile (375px+) === */
@media(max-width:700px){
  .subj-bar{flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;padding-bottom:2px}
  .subj-bar::-webkit-scrollbar{display:none}
  .nav__aux{display:none}
  .main{padding:var(--sp-3) var(--sp-3) var(--sp-8)}
  .filter-bar{margin:0 calc(-1 * var(--sp-3));padding-left:var(--sp-3);padding-right:var(--sp-3)}
  .qgrid{grid-template-columns:repeat(2,1fr);gap:var(--sp-2)}
  .qgrid.list-view{grid-template-columns:1fr}
  .qgrid.list-view .card__content{grid-template-columns:1fr;min-height:auto}
  .qgrid.list-view .card__img-wrap{height:160px;border-right:none;border-bottom:1px solid rgba(255,255,255,.04)}
  .qgrid.list-view .card__header{padding:10px 12px 6px}
  .qgrid.list-view .card__body{padding:12px}
  .qgrid.list-view .card__text{font-size:14px}
  .qgrid.list-view .card__actions{flex-direction:row;border-left:none;border-top:1px solid rgba(255,255,255,.04);padding:6px 12px}
  .qgrid.list-view .card__action-label{display:none}
  .qgrid.list-view .card__action-btn{width:auto;padding:6px 8px}
  .qgrid.list-view .card__actions-right{display:flex}
  .qgrid.list-view .card__comments{padding:0 12px 8px}
  .qgrid.list-view .card__tag{font-size:10px;padding:1px 8px}
  .card__header{padding:8px 10px 4px}
  .card__body{padding:4px 10px 2px}
  .card__actions{padding:2px 10px 2px}
  .card__comments{padding:0 10px 8px}
  .view-toggle{display:none}
}
/* === Tablet (768px+) === */
@media(min-width:768px) and (max-width:1024px){
  .qgrid{grid-template-columns:repeat(3,1fr);gap:var(--sp-4)}
  .qgrid.list-view{grid-template-columns:1fr}
}
/* === Desktop (1280px+) === */
@media(min-width:1280px){
  .qgrid{grid-template-columns:repeat(5,1fr)}
  .qgrid.list-view{grid-template-columns:1fr}
}
/* === Wide Desktop (1600px+) === */
@media(min-width:1600px){
  .qgrid{grid-template-columns:repeat(6,1fr)}
}

/* ===== CP Header Badge (항상 보이는 콤팩트 뱃지) ===== */
.nav-cp{display:flex;align-items:center;gap:6px;padding:4px 12px 4px 8px;background:linear-gradient(135deg,rgba(124,106,239,.12),rgba(162,155,254,.06));border:1px solid rgba(124,106,239,.25);border-radius:var(--radius-full);cursor:pointer;transition:all .25s var(--spring);position:relative;user-select:none;flex-shrink:0;text-decoration:none}
.nav-cp:hover{background:linear-gradient(135deg,rgba(124,106,239,.2),rgba(162,155,254,.1));transform:scale(1.03)}
.nav-cp:active{transform:scale(.97)}
.nav-cp__icon{font-size:18px;line-height:1}
.nav-cp__val{font-size:14px;font-weight:800;color:#a29bfe;font-family:var(--font-display);line-height:1}
.nav-cp__unit{font-size:10px;font-weight:600;color:rgba(162,155,254,.7);line-height:1}
.nav-cp__arrow{font-size:10px;color:rgba(162,155,254,.5);transition:transform .3s var(--ease-out-expo);margin-left:2px}
.nav-cp.open .nav-cp__arrow{transform:rotate(180deg)}
.nav-cp.nav-cp--gain{animation:navCpPop .5s var(--spring)}
@keyframes navCpPop{0%{transform:scale(1)}25%{transform:scale(1.15)}50%{transform:scale(.95)}100%{transform:scale(1)}}
.nav-cp__plus{position:absolute;top:-8px;right:-4px;font-size:11px;font-weight:900;color:#2dd4a8;pointer-events:none;animation:cpFloatUp .8s ease forwards;opacity:0}
@keyframes cpFloatUp{0%{opacity:1;transform:translateY(0)}100%{opacity:0;transform:translateY(-18px)}}
.nav-cp{border:1px solid rgba(124,106,239,.25);font-family:inherit;color:inherit}
.nav-cp__chev{font-size:9px;color:rgba(162,155,254,.5);margin-left:2px;transition:transform .2s}
.nav-cp-wrap.open .nav-cp__chev{transform:rotate(180deg)}
.nav-cp-guide{position:absolute;top:calc(100% + 8px);right:0;min-width:280px;background:rgba(22,27,34,.98);backdrop-filter:blur(10px);border:1px solid rgba(124,106,239,.25);border-radius:12px;padding:14px;box-shadow:0 8px 32px rgba(0,0,0,.5);z-index:1000;animation:navCpGuideIn .2s ease}
@keyframes navCpGuideIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
.nav-cp-guide__title{font-size:12px;font-weight:700;color:#fff;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,.06)}
.nav-cp-guide__row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;font-size:12px;color:#bbb}
.nav-cp-guide__row strong{color:#a29bfe;font-family:var(--font-display);font-weight:800}
.nav-cp-guide__hint{color:#555;font-size:10px}
.nav-cp-guide__note{margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.06);font-size:10px;color:#666}
.nav-cp-guide__link{display:block;margin-top:10px;padding:8px;text-align:center;font-size:12px;font-weight:600;color:#a29bfe;background:rgba(124,106,239,.12);border:1px solid rgba(124,106,239,.25);border-radius:8px;text-decoration:none;transition:all .2s}
.nav-cp-guide__link:hover{background:rgba(124,106,239,.2)}

/* ===== CP Expand Panel (탭하면 펼쳐지는 대시보드) ===== */
.cp-panel{max-height:0;overflow:hidden;transition:max-height .35s var(--ease-out-expo),opacity .25s ease,padding .35s ease;opacity:0;background:linear-gradient(180deg,rgba(124,106,239,.06) 0%,rgba(22,27,34,.95) 100%);border-bottom:1px solid rgba(124,106,239,.1)}
.cp-panel.open{max-height:500px;opacity:1;padding:14px var(--sp-6) 16px}
.cp-panel__inner{display:flex;align-items:center;gap:20px;max-width:1400px;margin:0 auto}
.cp-panel__main{display:flex;align-items:center;gap:14px;flex:1;min-width:0}
.cp-panel__donut{width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#7c6aef,#a29bfe);display:flex;align-items:center;justify-content:center;font-size:28px;flex-shrink:0;box-shadow:0 4px 20px rgba(124,106,239,.3);position:relative}
.cp-panel__donut::after{content:'';position:absolute;inset:3px;border-radius:50%;background:var(--bg-primary);z-index:0}
.cp-panel__donut span{position:relative;z-index:1}
.cp-panel__info{flex:1;min-width:0}
.cp-panel__balance{font-size:28px;font-weight:900;color:#f0f6fc;font-family:var(--font-display);line-height:1.1;display:flex;align-items:baseline;gap:6px}
.cp-panel__balance small{font-size:14px;font-weight:700;color:#a29bfe}
.cp-panel__won{font-size:12px;color:#7c6aef;margin-top:2px}
.cp-panel__meta{display:flex;align-items:center;gap:12px;margin-top:6px;flex-wrap:wrap}
.cp-panel__chip{font-size:11px;font-weight:600;padding:3px 10px;border-radius:var(--radius-full);display:inline-flex;align-items:center;gap:4px;line-height:1.3}
.cp-panel__chip--level{background:rgba(124,106,239,.1);color:#a29bfe;border:1px solid rgba(124,106,239,.2)}
.cp-panel__chip--streak{background:rgba(251,191,36,.08);color:#fbbf24;border:1px solid rgba(251,191,36,.15)}
.cp-panel__chip--today{background:rgba(45,212,168,.08);color:#2dd4a8;border:1px solid rgba(45,212,168,.15)}

.cp-panel__right{display:flex;flex-direction:column;gap:6px;flex-shrink:0}
.cp-panel__progress{width:140px}
.cp-panel__progress-label{font-size:10px;color:var(--text-muted);margin-bottom:4px;display:flex;justify-content:space-between}
.cp-panel__progress-bar{height:6px;background:rgba(124,106,239,.1);border-radius:3px;overflow:hidden}
.cp-panel__progress-fill{height:100%;background:linear-gradient(90deg,#7c6aef,#a29bfe);border-radius:3px;transition:width 1s ease}
.cp-panel__links{display:flex;gap:8px}
.cp-panel__link{font-size:11px;font-weight:600;color:var(--text-secondary);text-decoration:none;padding:5px 10px;border-radius:var(--radius-sm);background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);transition:all .2s;display:flex;align-items:center;gap:4px}
.cp-panel__link:hover{color:var(--text-primary);background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.12)}
.cp-panel__guide{margin-top:10px;max-width:1400px;margin-left:auto;margin-right:auto;padding:0 var(--sp-6)}
.cp-panel__guide-toggle{display:flex;align-items:center;justify-content:space-between;width:100%;background:none;border:none;color:var(--text-secondary);font-size:12px;font-weight:600;cursor:pointer;padding:6px 0;gap:6px}
.cp-panel__guide-toggle:hover{color:var(--text-primary)}
#cpGuideBody{padding:8px 0 2px}
.cp-guide__row{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:12px;color:var(--text-secondary)}
.cp-guide__val{font-weight:800;color:#a29bfe;font-family:var(--font-display)}

/* CP Panel 모바일 */
@media(max-width:768px){
  .cp-panel__inner{flex-direction:column;align-items:stretch;gap:12px}
  .cp-panel__right{flex-direction:row;align-items:center;gap:10px}
  .cp-panel__progress{flex:1;width:auto}
  .cp-panel__links{flex:0}
  .nav-cp__unit{display:none}
}
@media(max-width:480px){
  .cp-panel__balance{font-size:24px}
  .cp-panel__donut{width:44px;height:44px;font-size:22px}
}
.app-loader{position:fixed;inset:0;z-index:9999;background:var(--bg-primary);display:flex;align-items:center;justify-content:center;gap:12px;transition:opacity .3s ease}
.app-loader__spinner{width:28px;height:28px;border:3px solid rgba(255,255,255,.1);border-top-color:var(--accent,#8B5CF6);border-radius:50%;animation:app-spin .8s linear infinite}
@keyframes app-spin{to{transform:rotate(360deg)}}
.app-loader__text{font-size:14px;color:var(--text-muted,#6B7280);font-family:var(--font-display)}
.app-loader.fade-out{opacity:0;pointer-events:none}
</style>
</head>
<body>
<div class="app-loader" id="appLoader"><div class="app-loader__spinner"></div><div class="app-loader__text">불러오는 중...</div></div>
<div class="app-shell" style="visibility:hidden" id="appShell">
<!-- === Sidebar Panel (Push-aside) === -->
<aside class="sidebar" id="sidebar" role="navigation" aria-label="사이드 메뉴">
  <div class="sidebar__inner">
  <div class="sidebar__header">
    <span class="sidebar__title">질문방</span>
    <button class="sidebar__close" id="sidebarClose" aria-label="메뉴 닫기"><i class="fas fa-times"></i></button>
  </div>
  <!-- Sidebar CP Widget -->
  <div id="sideCpWidget" style="display:none;padding:14px 20px;margin:12px 16px 0;background:linear-gradient(135deg,rgba(124,106,239,.1),rgba(162,155,254,.04));border:1px solid rgba(124,106,239,.2);border-radius:12px;cursor:pointer" onclick="location.href='/cp'">
    <div style="display:flex;align-items:center;gap:10px">
      <div style="font-size:24px;line-height:1">🍩</div>
      <div style="flex:1">
        <div style="font-size:18px;font-weight:900;color:#a29bfe;font-family:var(--font-display)" id="sideCpVal">— 크로켓포인트</div>
      </div>
      <div style="font-size:11px;padding:3px 8px;background:rgba(124,106,239,.15);border-radius:20px;color:#a29bfe;font-weight:600" id="sideCpLevel">Lv.1</div>
    </div>
    <div style="margin-top:8px;height:4px;background:rgba(124,106,239,.1);border-radius:2px;overflow:hidden"><div id="sideCpBar" style="height:100%;background:linear-gradient(90deg,#7c6aef,#a29bfe);border-radius:2px;width:0%;transition:width 1s ease"></div></div>
  </div>
  <div class="sidebar__stats">
    <div class="sidebar__stat"><div class="sidebar__stat-num" id="sideStatTotal">—</div><div class="sidebar__stat-label">전체 질문</div></div>
    <div class="sidebar__stat"><div class="sidebar__stat-num" id="sideStatSolved" style="color:var(--accent-success)">0</div><div class="sidebar__stat-label">오늘 해결</div></div>
  </div>
  <div class="sidebar__divider"></div>
  <div class="sidebar__section">
    <div class="sidebar__section-title">카테고리</div>
    <button class="sidebar__item active" data-side-cat="all"><span class="sidebar__item-icon"><i class="fas fa-th"></i></span>전체 Q&A<span class="sidebar__item-count" id="sideCntAll"></span></button>
    <button class="sidebar__item" data-side-cat="normal"><span class="sidebar__item-icon"><i class="fas fa-book-open"></i></span>일반 질문<span class="sidebar__item-count" id="sideCntNormal"></span></button>
    <button class="sidebar__item" data-side-cat="killer"><span class="sidebar__item-icon" style="color:#F97316"><i class="fas fa-fire"></i></span>고난도 도전<span class="sidebar__item-count" id="sideCntKiller"></span></button>
    <button class="sidebar__item" data-side-cat="tutoring"><span class="sidebar__item-icon" style="color:#a78bfa"><i class="fas fa-chalkboard-teacher"></i></span>1:1 튜터링<span class="sidebar__item-count" id="sideCntTutor"></span></button>
  </div>
  <div class="sidebar__divider"></div>
  <div class="sidebar__section">
    <div class="sidebar__section-title">내 활동</div>
    <button class="sidebar__item" id="sideMyQ"><span class="sidebar__item-icon"><i class="fas fa-question-circle"></i></span>내가 한 질문</button>
    <button class="sidebar__item" id="sideMyA"><span class="sidebar__item-icon"><i class="fas fa-pen"></i></span>내가 한 답변</button>
    <a href="/my/dashboard" class="sidebar__item" id="sideMyDashLink" style="display:${isLoggedIn ? '' : 'none'}"><span class="sidebar__item-icon" style="color:#2dd4a8"><i class="fas fa-chart-line"></i></span>학습 대시보드</a>
    <a href="/my/bookmarks" class="sidebar__item" id="sideMyBookLink" style="display:${isLoggedIn ? '' : 'none'}"><span class="sidebar__item-icon" style="color:#fbbf24"><i class="fas fa-thumbtack"></i></span>찜한 문제<span class="sidebar__item-count" id="sideCntBookmarks"></span></a>
    <a href="/my/history" class="sidebar__item" id="sideMyHistLink" style="display:${isLoggedIn ? '' : 'none'}"><span class="sidebar__item-icon" style="color:#7c6aef"><i class="fas fa-history"></i></span>질문 히스토리</a>
  </div>
  <div class="sidebar__divider"></div>
  <div class="sidebar__section">
    <a href="/schedule" class="sidebar__item" id="sideSchLink" style="display:${isLoggedIn ? '' : 'none'}"><span class="sidebar__item-icon" style="color:#a78bfa"><i class="fas fa-calendar-alt"></i></span>스케줄</a>
    <a href="/coaching" class="sidebar__item" id="sideCoachLink" style="display:${isLoggedIn ? '' : 'none'}"><span class="sidebar__item-icon" style="color:#fbbf24"><i class="fas fa-chart-radar"></i></span>코칭</a>
    <a href="/ranking" class="sidebar__item"><span class="sidebar__item-icon" style="color:#ffd700"><i class="fas fa-trophy"></i></span>랭킹</a>
  </div>
  <button class="sidebar__cta" onclick="if(!requireAuth())return;location.href='/new'"><i class="fas fa-plus"></i> 질문하기</button>
  </div><!-- /sidebar__inner -->
</aside>

<!-- === Main Wrap (pushed by sidebar) === -->
<div class="main-wrap">
<!-- === Header === -->
<nav class="nav" id="nav">
  <button class="nav__menu-btn" id="sidebarToggle" aria-label="메뉴 열기/닫기"><i class="fas fa-bars"></i></button>
  <div class="nav__logo">질문방</div>
  <div class="nav__aux" id="navAux">
    <a href="/schedule" id="schLink" style="display:${isLoggedIn ? '' : 'none'}"><i class="fas fa-calendar-alt" style="color:#a78bfa"></i> 스케줄</a>
    <a href="/coaching" id="coachLink" style="display:${isLoggedIn ? '' : 'none'}"><i class="fas fa-chart-radar" style="color:#fbbf24"></i> 코칭</a>
    <a href="/ranking"><i class="fas fa-trophy" style="color:#ffd700"></i> 랭킹</a>
    <a href="#" id="teachersNavBadge" class="teachers-badge" style="display:${isLoggedIn ? 'inline-flex' : 'none'}">
      <span class="teachers-badge__icon"><i class="fas fa-graduation-cap"></i></span>
      <span class="teachers-badge__text"><strong>Teachers</strong><small>ClassIn</small></span>
    </a>
  </div>
  <div class="nav__right">
    <!-- CP Header Badge -->
    <div class="nav-cp-wrap" style="display:${isLoggedIn ? 'flex' : 'none'};align-items:center;position:relative">
      <button class="nav-cp" id="navCpBadge" type="button" aria-label="크로켓포인트" onclick="var p=document.getElementById('navCpGuide');p.style.display=p.style.display==='block'?'none':'block';event.stopPropagation()">
        <span class="nav-cp__icon">🍩</span>
        <span class="nav-cp__val" id="navCpVal">${ssrCpDisplay}</span>
        <span class="nav-cp__unit">P</span>
        <i class="fas fa-chevron-down nav-cp__chev"></i>
      </button>
      <div id="navCpGuide" class="nav-cp-guide" style="display:none">
        <div class="nav-cp-guide__title">💡 크로켓포인트 적립 안내</div>
        <div class="nav-cp-guide__row"><span>✏️ 답변 등록 <span class="nav-cp-guide__hint">(20자↑/이미지)</span></span><strong>+100</strong></div>
        <div class="nav-cp-guide__row"><span>✅ 답변 채택됨</span><strong>+1,000</strong></div>
        <div class="nav-cp-guide__row"><span>🤝 채택하기 (질문자)</span><strong>+100</strong></div>
        <div class="nav-cp-guide__row"><span>🎁 첫 답변 보너스 <span class="nav-cp-guide__hint">(1일1회)</span></span><strong>+100</strong></div>
        <div class="nav-cp-guide__row"><span>📝 정율 선생님 문제 정답</span><strong>+100~200</strong></div>
        <div class="nav-cp-guide__note">※ 자기 질문에 대한 답변은 적립 대상에서 제외됩니다.</div>
        <a href="/cp" class="nav-cp-guide__link">내 포인트 상세보기 →</a>
      </div>
    </div>
    <div class="nav__search-wrap">
      <i class="fas fa-search nav__search-icon" id="searchToggle"></i>
      <input id="searchInput" class="nav__search" type="text" placeholder="검색...">
    </div>
    <a href="/new" class="nav__btn" onclick="event.preventDefault();if(!requireAuth())return;location.href='/new'"><i class="fas fa-plus" style="margin-right:3px"></i>질문하기</a>
    <div id="authArea">${isLoggedIn ? `<a href="/mypage" class="nav__user-btn"><i class="fas fa-user-circle"></i> ${ssrNickname.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}</a>` : ''}</div>
  </div>
</nav>


<div class="app-layout">
<div class="main" role="main">
  <div id="todayScheduleBanner" style="display:none"></div>

  <!-- Filter Bar (Sticky) — subject chips + my Q/A + view toggle + sort -->
  <div class="filter-bar" id="filterBar" role="toolbar" aria-label="필터 바">
    <!-- Row 1: Subject Chips -->
    <div class="filter-row1">
      <div class="subj-bar" id="subjBar" role="tablist" aria-label="과목 필터">
        <button class="subj-chip active" data-subj="전체" role="tab" aria-selected="true">전체</button>
        <button class="subj-chip" data-subj="국어" role="tab" aria-selected="false">국어</button>
        <button class="subj-chip" data-subj="수학" role="tab" aria-selected="false">수학</button>
        <button class="subj-chip" data-subj="영어" role="tab" aria-selected="false">영어</button>
        <button class="subj-chip" data-subj="과학" role="tab" aria-selected="false">과학</button>
        <button class="subj-chip" data-subj="기타" role="tab" aria-selected="false">기타</button>
      </div>
    </div>
    <!-- Row 2: My Q/A + View Toggle + Sort -->
    <div class="filter-row2">
      <div class="my-bar" id="myBar" style="display:${isLoggedIn ? 'flex' : 'none'}">
        <button class="my-chip" data-my="내 질문" id="myQChip" aria-pressed="false"><i class="fas fa-user"></i> 내 질문</button>
        <button class="my-chip my-chip--ans" data-my="내 답변" id="myAChip" aria-pressed="false"><i class="fas fa-pen"></i> 내 답변</button>
      </div>
      <div class="subj-right">
        <div class="view-toggle" role="radiogroup" aria-label="뷰 모드">
          <button class="view-toggle__btn active" data-view="grid" aria-label="그리드 뷰" title="그리드 뷰"><i class="fas fa-th"></i></button>
          <button class="view-toggle__btn" data-view="list" aria-label="리스트 뷰" title="리스트 뷰"><i class="fas fa-list"></i></button>
        </div>
        <select id="sortSelect" aria-label="정렬 기준">
          <option value="latest">최신순</option>
          <option value="unanswered">미답변</option>
          <option value="points">포인트순</option>
        </select>
      </div>
    </div>
  </div><!-- /filter-bar -->

  <!-- Grid -->
  <div id="gallery" class="qgrid" role="feed" aria-label="질문 목록">
    <div id="initLoading" style="grid-column:1/-1;display:flex;align-items:center;justify-content:center;gap:10px;padding:60px 0;color:var(--text-secondary);font-size:14px">
      <i class="fas fa-spinner fa-spin" style="color:#7c6aef;font-size:18px"></i> 불러오는 중...
    </div>
  </div>

  <!-- Pagination -->
  <div id="pager" class="pager" aria-label="페이지 네비게이션"></div>

  <!-- Search Results -->
  <div id="searchResults" class="search-grid" style="display:none" role="feed" aria-label="검색 결과"></div>
</div><!-- /main -->
</div><!-- /app-layout -->

<a href="/new" class="fab" onclick="event.preventDefault();if(!requireAuth())return;location.href='/new'"><i class="fas fa-plus"></i></a>
</div><!-- /main-wrap -->
</div><!-- /app-shell -->

<script>
${sharedAuthJS()}

// === State ===
let currentUser=null;
let curCat='all'; // 'all' | 'normal' | 'killer' | 'tutoring'
let curSubj='전체';
let curSort='latest';
let curMyFilter=null; // null | '내 질문' | '내 답변'
const PAGE_SIZE=35;
let gridData=[];  // currently displayed items
const imageCache={};
let sto=null;
let isLoading=false;
let cachedAllData=[]; // Full dataset for current view (accumulated via infinite scroll)
let _nextCursor=null;  // {cursor, cursor_id} for next page
let _hasMore=true;     // whether more items exist
let _isLoadingMore=false; // loading lock
let _initDone=false; // 초기 로딩 완료 전 무한스크롤 억제
let _latestKnownId=0;   // for lightweight poll
let _categoryCounts={total:0,normal:0,killer:0,tutoring:0};
// Pre-loaded cache for instant "내 질문" / "내 답변" switching
let _myQCache=null;   // {myQuestions:[], answeredOnly:[]} — null = not loaded
let _myQLoading=false;
let _allCache=null;   // SSR 스냅샷: "전체" 탭 즉시 복원용

// === CP Header Badge & Panel ===
function toP(cp){return (cp||0)*100}
function fmtP(cp){return toP(cp).toLocaleString()+' 크로켓포인트'}
var _cpData = null;
var _cpPanelOpen = false;


document.addEventListener('click',function(e){
  var g=document.getElementById('navCpGuide');var btn=document.getElementById('navCpBadge');
  if(!g||!btn)return;
  if(g.style.display==='block'&&!g.contains(e.target)&&!btn.contains(e.target))g.style.display='none';
});

async function loadHeaderCp(){
  try{
    var r = await fetch('/api/cp', {headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'}});
    var d = await r.json();
    if(!r.ok) return;
    _cpData = d;
    // Header badge wrapper
    var wrap = document.querySelector('.nav-cp-wrap');
    if(wrap) wrap.style.display = 'flex';
    var valEl = document.getElementById('navCpVal');
    if(valEl) valEl.textContent = toP(d.cp_balance).toLocaleString();
    // Sidebar CP widget
    var earned = d.earned_cp || 0;
    var levels=[{lv:1,cp:0,title:'새싹',icon:'🌱'},{lv:2,cp:30,title:'학습자',icon:'📖'},{lv:3,cp:100,title:'조력자',icon:'🤝'},{lv:4,cp:250,title:'멘토',icon:'⭐'},{lv:5,cp:500,title:'마스터',icon:'👑'},{lv:6,cp:1000,title:'전설',icon:'🏆'}];
    var curLv = levels[0];
    for(var i=levels.length-1;i>=0;i--){if(earned>=levels[i].cp){curLv=levels[i];break}}
    var pct = 0;
    var nextLv = levels[curLv.lv] || null;
    if(nextLv) pct = Math.min(100, Math.floor((earned - curLv.cp) / (nextLv.cp - curLv.cp) * 100));
    else pct = 100;
    var sideWidget = document.getElementById('sideCpWidget');
    if(sideWidget) sideWidget.style.display = 'block';
    var sideCpVal = document.getElementById('sideCpVal');
    if(sideCpVal) sideCpVal.textContent = fmtP(d.cp_balance);
    var sideCpLevel = document.getElementById('sideCpLevel');
    if(sideCpLevel) sideCpLevel.textContent = curLv.icon + ' Lv.' + curLv.lv;
    var sideCpBar = document.getElementById('sideCpBar');
    if(sideCpBar) sideCpBar.style.width = pct + '%';
  }catch(e){}
}


function animateNavCpGain(amount){
  var badge = document.getElementById('navCpBadge');
  var valEl = document.getElementById('navCpVal');
  if(!badge || !valEl) return;
  var displayAmount = toP(amount);
  // Pop animation
  badge.classList.remove('nav-cp--gain');
  void badge.offsetWidth;
  badge.classList.add('nav-cp--gain');
  setTimeout(function(){ badge.classList.remove('nav-cp--gain'); }, 600);
  // Floating +N
  var plus = document.createElement('span');
  plus.className = 'nav-cp__plus';
  plus.textContent = '+' + displayAmount.toLocaleString();
  badge.appendChild(plus);
  setTimeout(function(){ if(plus.parentNode) plus.parentNode.removeChild(plus); }, 900);
  // Count up
  var cur = parseInt(String(valEl.textContent).replace(/,/g,'')) || 0;
  var start = null;
  function tick(ts){
    if(!start) start = ts;
    var p = Math.min((ts - start) / 600, 1);
    valEl.textContent = Math.round(cur + (displayAmount * (1 - Math.pow(1-p, 3)))).toLocaleString();
    if(p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// === Sidebar Toggle (push-aside) ===
(function(){
  var sidebar=document.getElementById('sidebar');
  var openBtn=document.getElementById('sidebarToggle');
  var closeBtn=document.getElementById('sidebarClose');
  function toggleSidebar(){sidebar.classList.toggle('open')}
  function closeSidebar(){sidebar.classList.remove('open')}
  if(openBtn)openBtn.addEventListener('click',toggleSidebar);
  if(closeBtn)closeBtn.addEventListener('click',closeSidebar);
  // Sidebar category items → category switching (cat-tabs removed from main area)
  document.querySelectorAll('[data-side-cat]').forEach(function(item){
    item.addEventListener('click',function(){
      var cat=item.getAttribute('data-side-cat');
      // Activate sidebar item
      document.querySelectorAll('[data-side-cat]').forEach(function(x){x.classList.remove('active')});
      item.classList.add('active');
      curCat=cat;curMyFilter=null;
      document.querySelectorAll('.my-chip').forEach(function(c){c.classList.remove('active')});
      // 카테고리가 'all'이면서 SSR 캐시가 있으면 즉시 복원
      if(cat==='all'&&_allCache&&_allCache.data.length>0){
        cachedAllData=_allCache.data.slice();
        gridData=_allCache.data.slice();
        _nextCursor=_allCache.cursor;
        _hasMore=_allCache.hasMore;
        _latestKnownId=_allCache.latestId;
        _categoryCounts=Object.assign({},_allCache.counts);
        updateCategoryCounts();
        var _el=document.getElementById('gallery');if(_el)_el.innerHTML='';
        renderGrid();
      } else { resetAndReload(); }
    });
  });
  // Sidebar "내 질문" / "내 답변"
  var sideMyQ=document.getElementById('sideMyQ');
  var sideMyA=document.getElementById('sideMyA');
  if(sideMyQ)sideMyQ.addEventListener('click',function(){
    var chip=document.getElementById('myQChip');
    if(chip)chip.click();
  });
  if(sideMyA)sideMyA.addEventListener('click',function(){
    var chip=document.getElementById('myAChip');
    if(chip)chip.click();
  });
  // Teachers 바로가기 뱃지
  var teachersBtn=document.getElementById('teachersNavBadge');
  if(teachersBtn)teachersBtn.addEventListener('click',function(e){
    e.preventDefault();
    if(!currentUser||!currentUser.external_id){showToast('로그인이 필요합니다.','warn');return}
    var url='https://teachers.jung-youl.com?user_id='+encodeURIComponent(currentUser.external_id);
    window.open(url,'_blank');
  });
})();

// === Card click delegation (handles card navigation + delete + like + bookmark + share) ===
(function(){
  var gallery=document.getElementById('gallery');
  if(!gallery)return;

  // --- Like button handler ---
  function handleLike(btn,qid){
    if(!requireAuth())return;
    var isLiked=btn.classList.contains('liked');
    var icon=btn.querySelector('i');
    var countEl=btn.querySelector('.count');
    // Optimistic UI update
    if(isLiked){
      btn.classList.remove('liked');
      btn.setAttribute('aria-pressed','false');
      if(icon){icon.className='far fa-heart'}
      if(countEl){var n=parseInt(countEl.textContent)||0;if(n>1)countEl.textContent=String(n-1);else countEl.remove()}
    }else{
      btn.classList.add('liked');
      btn.setAttribute('aria-pressed','true');
      if(icon){icon.className='fas fa-heart'}
      if(countEl){countEl.textContent=String((parseInt(countEl.textContent)||0)+1)}
      else{var sp=document.createElement('span');sp.className='count';sp.textContent='1';btn.appendChild(sp)}
    }
    // Server sync (fire and forget)
    fetch('/api/questions/'+qid+'/like',{method:'POST',headers:authHeaders()}).catch(function(){});
  }

  // --- Bookmark toggle handler ---
  function handleBookmark(btn,qid){
    if(!requireAuth())return;
    var isSaved=btn.classList.contains('saved');
    var icon=btn.querySelector('i');
    if(isSaved){
      btn.classList.remove('saved');
      btn.setAttribute('aria-pressed','false');
      if(icon)icon.className='far fa-bookmark';
    }else{
      btn.classList.add('saved');
      btn.setAttribute('aria-pressed','true');
      if(icon)icon.className='fas fa-bookmark';
    }
    fetch('/api/questions/'+qid+'/bookmark',{method:'POST',headers:authHeaders()}).catch(function(){});
  }

  // --- Share handler ---
  function handleShare(qid){
    var url=location.origin+'/question/'+qid;
    if(navigator.share){
      navigator.share({title:'질문방',url:url}).catch(function(){});
    }else{
      navigator.clipboard.writeText(url).then(function(){showToast('링크가 복사되었습니다','success')}).catch(function(){showToast('복사 실패','error')});
    }
  }

  // Close any open more menu when clicking outside
  document.addEventListener('click',function(e){
    if(!e.target.closest('.card__more')){
      document.querySelectorAll('.card__more.open').forEach(function(m){m.classList.remove('open')});
    }
  });

  gallery.addEventListener('click',function(e){
    // More menu toggle (···)
    var moreEl=e.target.closest('.card__more');
    if(moreEl&&!e.target.closest('.card__more-item')){
      e.preventDefault();e.stopPropagation();
      // Close other open menus
      document.querySelectorAll('.card__more.open').forEach(function(m){if(m!==moreEl)m.classList.remove('open')});
      moreEl.classList.toggle('open');
      return;
    }
    // Edit button (inside more menu)
    var editEl=e.target.closest('[data-edit-id]');
    if(editEl){
      e.preventDefault();e.stopPropagation();
      var qid=Number(editEl.getAttribute('data-edit-id'));
      var content=editEl.getAttribute('data-edit-content')||'';
      var subject=editEl.getAttribute('data-edit-subject')||'기타';
      // Close more menu
      var moreP=editEl.closest('.card__more');if(moreP)moreP.classList.remove('open');
      if(qid)openEditModal(qid,content,subject);
      return;
    }
    // Delete button (inside more menu)
    var delEl=e.target.closest('[data-del-id]');
    if(delEl){
      e.preventDefault();e.stopPropagation();
      var moreP2=delEl.closest('.card__more');if(moreP2)moreP2.classList.remove('open');
      var qid2=Number(delEl.getAttribute('data-del-id'));
      if(qid2)deleteQ(qid2);
      return;
    }
    // Like button
    var likeBtn=e.target.closest('[data-like-id]');
    if(likeBtn){
      e.preventDefault();e.stopPropagation();
      handleLike(likeBtn,Number(likeBtn.getAttribute('data-like-id')));
      return;
    }
    // Bookmark button
    var bmBtn=e.target.closest('[data-bookmark-id]');
    if(bmBtn){
      e.preventDefault();e.stopPropagation();
      handleBookmark(bmBtn,Number(bmBtn.getAttribute('data-bookmark-id')));
      return;
    }
    // Share button
    var shareBtn=e.target.closest('[data-share-id]');
    if(shareBtn){
      e.preventDefault();e.stopPropagation();
      handleShare(Number(shareBtn.getAttribute('data-share-id')));
      return;
    }
    // Otherwise navigate to card link
    var card=e.target.closest('.card[data-href]');
    if(card){
      var href=card.getAttribute('data-href');
      if(href)window.location.href=href;
    }
  });

  // === Double-tap to like (Instagram-style big heart) ===
  var lastTapTime=0;
  var lastTapTarget=null;
  gallery.addEventListener('touchend',function(e){
    // Ignore taps on action buttons
    if(e.target.closest('.card__action-btn')||e.target.closest('.card__del')||e.target.closest('.card__more'))return;
    var card=e.target.closest('.card[data-qid]');
    if(!card)return;
    var now=Date.now();
    if(lastTapTarget===card&&now-lastTapTime<350){
      // Double tap detected
      e.preventDefault();
      var qid=card.getAttribute('data-qid');
      // Trigger like
      var likeBtn=card.querySelector('[data-like-id]');
      if(likeBtn&&!likeBtn.classList.contains('liked')){
        handleLike(likeBtn,Number(qid));
      }
      // Show big heart animation
      var bigHeart=card.querySelector('.card__big-heart');
      if(bigHeart){
        bigHeart.classList.remove('pop');
        void bigHeart.offsetWidth; // force reflow
        bigHeart.classList.add('pop');
        setTimeout(function(){bigHeart.classList.remove('pop')},900);
      }
      lastTapTime=0;lastTapTarget=null;
    }else{
      lastTapTime=now;lastTapTarget=card;
    }
  },{passive:false});

  // Double-click for desktop
  gallery.addEventListener('dblclick',function(e){
    if(e.target.closest('.card__action-btn')||e.target.closest('.card__del')||e.target.closest('.card__more'))return;
    var card=e.target.closest('.card[data-qid]');
    if(!card)return;
    e.preventDefault();
    var qid=card.getAttribute('data-qid');
    var likeBtn=card.querySelector('[data-like-id]');
    if(likeBtn&&!likeBtn.classList.contains('liked')){
      handleLike(likeBtn,Number(qid));
    }
    var bigHeart=card.querySelector('.card__big-heart');
    if(bigHeart){
      bigHeart.classList.remove('pop');
      void bigHeart.offsetWidth;
      bigHeart.classList.add('pop');
      setTimeout(function(){bigHeart.classList.remove('pop')},900);
    }
  });
})();

// === View Toggle (Grid/List with localStorage persistence) ===
(function(){
  var viewMode=localStorage.getItem('qa_view_mode')||'grid';
  var gallery=document.getElementById('gallery');
  var btns=document.querySelectorAll('.view-toggle__btn');
  function applyViewMode(mode){
    viewMode=mode;
    localStorage.setItem('qa_view_mode',mode);
    if(gallery){
      if(mode==='list')gallery.classList.add('list-view');
      else gallery.classList.remove('list-view');
    }
    btns.forEach(function(b){
      if(b.getAttribute('data-view')===mode)b.classList.add('active');
      else b.classList.remove('active');
    });
  }
  // Apply saved preference on load
  applyViewMode(viewMode);
  // Button click handlers
  btns.forEach(function(b){
    b.addEventListener('click',function(){
      applyViewMode(b.getAttribute('data-view'));
    });
  });
})();

// === Staggered card fade-in animation ===
function applyCardFadeIn(){
  var cards=document.querySelectorAll('.card');
  cards.forEach(function(c,i){
    c.style.animationDelay=(i*0.04)+'s';
  });
}


function _revealApp(){
  var shell=document.getElementById('appShell');if(shell)shell.style.visibility='visible';
  var loader=document.getElementById('appLoader');if(loader){loader.classList.add('fade-out');setTimeout(function(){loader.remove()},300)}
}

// === Init ===
(async()=>{
  currentUser=await checkAuth();
  const el=document.getElementById('authArea');
  if(currentUser){
    el.innerHTML='<a href="/mypage" class="nav__user-btn"><i class="fas fa-user-circle"></i> '+currentUser.nickname+'</a>';
    document.getElementById('schLink').style.display='';
    document.getElementById('coachLink').style.display='';
    var tBadge=document.getElementById('teachersNavBadge');if(tBadge)tBadge.style.display='inline-flex';
    document.getElementById('myBar').style.display='flex';
    // Show sidebar admin links
    var sideSchLink=document.getElementById('sideSchLink');if(sideSchLink)sideSchLink.style.display='';
    var sideCoachLink=document.getElementById('sideCoachLink');if(sideCoachLink)sideCoachLink.style.display='';
    var sideMyDashLink=document.getElementById('sideMyDashLink');if(sideMyDashLink)sideMyDashLink.style.display='';
    var sideMyBookLink=document.getElementById('sideMyBookLink');if(sideMyBookLink)sideMyBookLink.style.display='';
    var sideMyHistLink=document.getElementById('sideMyHistLink');if(sideMyHistLink)sideMyHistLink.style.display='';
  }else{el.innerHTML=''}
  // SSR initial data (first 35 items only)
  // E4: XSS 방지 — script 종료 태그가 JSON 안에 있으면 HTML 파서가 스크립트를 조기 종료시킴
  const ssrQ=${JSON.stringify(questions).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')};
  const ssrCounts=${JSON.stringify(counts || {total:0,normal_count:0,killer_count:0,tutoring_count:0}).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')};
  // Initialize with SSR data
  cachedAllData=ssrQ;
  gridData=ssrQ;
  _hasMore=ssrQ.length>=PAGE_SIZE;
  if(ssrQ.length>0){
    var lastQ=ssrQ[ssrQ.length-1];
    _nextCursor={cursor:lastQ.created_at,cursor_id:lastQ.id};
    _latestKnownId=ssrQ[0].id;
  }
  _categoryCounts={total:ssrCounts.total||0,normal:ssrCounts.normal_count||0,killer:ssrCounts.killer_count||0,tutoring:ssrCounts.tutoring_count||0};
  // SSR 스냅샷 저장: "전체"로 복귀 시 즉시 렌더용
  _allCache={data:ssrQ.slice(),cursor:_nextCursor,hasMore:_hasMore,latestId:_latestKnownId,counts:Object.assign({},_categoryCounts)};
  updateCategoryCounts();
  setupInfiniteScroll();

  if(currentUser){
    loadTodayScheduleBanner();
    loadHeaderCp(); // CP 뱃지 로드
    preloadMyQuestions();
    // URL 파라미터 filter=my 지원 (플래너 iframe 연동)
    const _initParams=new URLSearchParams(location.search);
    if(_initParams.get('filter')==='my'){
      curMyFilter='내 질문';
      const _myChip=document.getElementById('myQChip');
      if(_myChip)_myChip.classList.add('active');
    }
    // 로그인 사용자: 스켈레톤 표시 상태에서 인증 데이터 로드 → 한 번에 렌더
    try{
      var url=buildQuestionsUrl(null,null);
      var res=await fetch(url,{headers:authHeaders()});
      var json=await res.json();
      var newItems=json.questions||[];
      if(newItems.length>0){
        cachedAllData=newItems;
        if(curMyFilter==='내 질문'&&currentUser)gridData=cachedAllData.filter(q=>q.user_id==currentUser.id);
        else if(curMyFilter==='내 답변')gridData=cachedAllData.filter(q=>q.i_answered);
        else gridData=cachedAllData;
        _hasMore=json.hasMore||false;
        _nextCursor=json.nextCursor||null;
        _latestKnownId=newItems[0].id;
        _allCache={data:cachedAllData.slice(),cursor:_nextCursor,hasMore:_hasMore,latestId:_latestKnownId,counts:Object.assign({},_categoryCounts)};
      }
    }catch(e){console.error('init fetch error',e)}
    renderGrid();
    _initDone=true;
    _revealApp();
  } else {
    // 비로그인 사용자: SSR 데이터로 렌더
    renderGrid();
    lazyLoadCardImages();
    _initDone=true;
    _revealApp();
  }
  // Load sidebar stats (stats-banner removed from main area)
  (async function(){
    try{
      var sTotal=document.getElementById('sideStatTotal');
      if(sTotal)sTotal.textContent=String(_categoryCounts.total||cachedAllData.length||'—');
      var res=await fetch('/api/stats/today-solved');
      var json=await res.json();
      var el3=document.getElementById('sideStatSolved');
      if(el3)el3.textContent=String(json.count||0);
    }catch(e){}
  })();
})();

function updateCategoryCounts(){
  // Cat-tabs and stats-banner removed from main area — update sidebar only
  var s=document.getElementById('sideCntAll');if(s)s.textContent=_categoryCounts.total?String(_categoryCounts.total):'';
  var sn=document.getElementById('sideCntNormal');if(sn)sn.textContent=_categoryCounts.normal?String(_categoryCounts.normal):'';
  var sk=document.getElementById('sideCntKiller');if(sk)sk.textContent=_categoryCounts.killer?String(_categoryCounts.killer):'';
  var st=document.getElementById('sideCntTutor');if(st)st.textContent=_categoryCounts.tutoring?String(_categoryCounts.tutoring):'';
  var ss=document.getElementById('sideStatTotal');if(ss&&_categoryCounts.total)ss.textContent=String(_categoryCounts.total);
}

// === Pre-load "내 질문" / "내 답변" cache for instant switching ===
async function preloadMyQuestions(){
  if(!currentUser||_myQLoading)return;
  _myQLoading=true;
  try{
    var res=await fetch('/api/my-questions',{headers:authHeaders()});
    if(res.ok){
      _myQCache=await res.json();
    }
  }catch(e){console.error('preloadMyQuestions error',e)}
  _myQLoading=false;
}
function invalidateMyCache(){_myQCache=null;}
function getMyFilteredData(filterType){
  if(!_myQCache||!currentUser)return null;
  var all=(_myQCache.myQuestions||[]).concat(_myQCache.answeredOnly||[]);
  // 중복 제거
  var seen=new Set();
  var unique=[];
  all.forEach(function(q){if(!seen.has(q.id)){seen.add(q.id);unique.push(q)}});
  if(filterType==='내 질문')return unique.filter(function(q){return q.user_id==currentUser.id});
  if(filterType==='내 답변')return unique.filter(function(q){return q.i_answered});
  return null;
}

// Build API URL with current filters + cursor
function buildQuestionsUrl(cursor,cursorId){
  var url='/api/questions?limit='+PAGE_SIZE;
  if(curCat&&curCat!=='all')url+='&category='+encodeURIComponent(curCat);
  if(curSubj&&curSubj!=='전체')url+='&subject='+encodeURIComponent(curSubj);
  if(curSort&&curSort!=='latest')url+='&sort='+encodeURIComponent(curSort);
  if(cursor)url+='&cursor='+encodeURIComponent(cursor);
  if(cursorId)url+='&cursor_id='+cursorId;
  return url;
}

// Load more items (infinite scroll - append)
async function loadMoreItems(){
  if(!_initDone||_isLoadingMore||!_hasMore)return;
  _isLoadingMore=true;
  showLoadingIndicator(true);
  try{
    var url=buildQuestionsUrl(_nextCursor?.cursor,_nextCursor?.cursor_id);
    var h=currentUser?authHeaders():{'Content-Type':'application/json'};
    var res=await fetch(url,{headers:h});
    var json=await res.json();
    var newItems=json.questions||[];
    _hasMore=json.hasMore||false;
    _nextCursor=json.nextCursor||null;
    // Client-side filter for myFilter (server doesn't know about it)
    if(curMyFilter==='내 질문'&&currentUser)newItems=newItems.filter(q=>q.user_id==currentUser.id);
    else if(curMyFilter==='내 답변')newItems=newItems.filter(q=>q.i_answered);
    // I9: 중복 아이템 방지 — 이미 로드된 ID는 건너뜀
    var existingIds=new Set(cachedAllData.map(function(q){return q.id}));
    newItems=newItems.filter(function(q){return !existingIds.has(q.id)});
    if(newItems.length>0){
      cachedAllData=cachedAllData.concat(newItems);
      gridData=gridData.concat(newItems);
      appendGrid(newItems);
    } else {
      // 새 아이템 없으면 스켈레톤 제거 (빈 결과 시 스켈레톤 잔류 방지)
      var _g=document.getElementById('gallery');
      if(_g)_g.querySelectorAll('.skeleton').forEach(function(s){s.remove()});
      if(_g&&_g.querySelectorAll('.card').length===0&&!_hasMore){
        _g.innerHTML='<div class="empty" style="grid-column:1/-1">등록된 질문이 없습니다</div>';
      }
    }
    // If filtered out all items but hasMore, try loading more
    if(newItems.length===0&&_hasMore){
      _isLoadingMore=false;
      showLoadingIndicator(false);
      loadMoreItems();
      return;
    }
  }catch(e){
    console.error('loadMoreItems error',e);
    var el=document.getElementById('gallery');
    if(el&&el.querySelectorAll('.card').length===0){
      el.innerHTML='<div class="error-state"><i class="fas fa-exclamation-circle" style="font-size:24px;margin-bottom:8px;display:block"></i>불러오기 실패<button class="error-state__btn" onclick="resetAndReload()"><i class="fas fa-redo" style="margin-right:4px"></i>다시 시도</button></div>';
    }
  }
  _isLoadingMore=false;
  showLoadingIndicator(false);
}

function skeletonCards(n){var h='';for(var i=0;i<n;i++)h+='<div class="skeleton"><div class="skeleton__bar skeleton__bar--long"></div><div class="skeleton__bar skeleton__bar--short"></div></div>';return h}
// Reset and reload (when filter/sort changes)
async function resetAndReload(){
  cachedAllData=[];
  gridData=[];
  _nextCursor=null;
  _hasMore=true;
  var el=document.getElementById('gallery');
  if(el)el.innerHTML=skeletonCards(6);
  await loadMoreItems();
  // Also refresh counts
  try{
    var cRes=await fetch('/api/questions/counts');
    var cJson=await cRes.json();
    _categoryCounts=cJson;
    updateCategoryCounts();
  }catch(e){}
}

// Refresh first page with auth (after login, keeps current items but updates statuses)
async function refreshFirstPage(){
  try{
    var url=buildQuestionsUrl(null,null);
    var res=await fetch(url,{headers:authHeaders()});
    var json=await res.json();
    var newItems=json.questions||[];
    if(newItems.length>0){
      // I9: 첨 페이지만 auth 데이터로 교체, 기존 스크롤 데이터는 유지
      var firstPageIds=new Set(newItems.map(function(q){return q.id}));
      var rest=cachedAllData.filter(function(q){return !firstPageIds.has(q.id)});
      cachedAllData=newItems.concat(rest);
      // Client-side filter for myFilter
      if(curMyFilter==='내 질문'&&currentUser)gridData=cachedAllData.filter(q=>q.user_id==currentUser.id);
      else if(curMyFilter==='내 답변')gridData=cachedAllData.filter(q=>q.i_answered);
      else gridData=cachedAllData;
      if(rest.length===0){
        _hasMore=json.hasMore||false;
        _nextCursor=json.nextCursor||null;
      }
      _latestKnownId=newItems[0].id;
      // _allCache 갱신: "전체"로 돌아갈 때 최신 데이터 사용
      if(!curMyFilter&&curCat==='all'&&curSubj==='전체'&&curSort==='latest'){
        _allCache={data:cachedAllData.slice(),cursor:_nextCursor,hasMore:_hasMore,latestId:_latestKnownId,counts:Object.assign({},_categoryCounts)};
      }
      renderGrid();
    }
  }catch(e){console.error('refreshFirstPage error',e)}
}

// Show/hide loading indicator at bottom
function showLoadingIndicator(show){
  var el=document.getElementById('loadMoreIndicator');
  if(!el){
    el=document.createElement('div');
    el.id='loadMoreIndicator';
    el.style.cssText='grid-column:1/-1;text-align:center;padding:20px;color:#888;font-size:13px;display:none';
    el.innerHTML='<i class="fas fa-spinner fa-spin" style="margin-right:6px"></i>더 불러오는 중...';
    var gallery=document.getElementById('gallery');
    if(gallery)gallery.parentNode.insertBefore(el,gallery.nextSibling);
  }
  el.style.display=show?'block':'none';
}

// Append new cards to existing grid (no full re-render)
function appendGrid(items){
  var el=document.getElementById('gallery');
  if(!el)return;
  // Remove skeleton loaders and "no items" message if present
  el.querySelectorAll('.skeleton').forEach(function(s){s.remove()});
  var empty=el.querySelector('.empty');
  if(empty)empty.remove();
  var existingCount=el.querySelectorAll('.card').length;
  el.insertAdjacentHTML('beforeend',items.map(cardHTML).join(''));
  // Apply staggered fade-in to new cards only
  var allCards=el.querySelectorAll('.card');
  for(var i=existingCount;i<allCards.length;i++){
    allCards[i].style.animationDelay=((i-existingCount)*0.04)+'s';
  }
  lazyLoadCardImages();
}

// === Card HTML ===
function cardHTML(q){
  var isMine=currentUser&&currentUser.id===q.user_id;
  var canDel=isMine&&(q.comment_count||0)===0&&q.status!=='채택 완료'&&q.status!=='매칭 확정'&&!q.has_pending_match&&!q.has_confirmed_match;
  var canEdit=canDel; // 수정 조건 = 삭제 조건 (답변 없고 채택 안 된 본인 질문)
  // Subject colors (needed early for placeholder)
  var subjColors={'수학':'#3B82F6','영어':'#10B981','국어':'#EC4899','과학':'#8B5CF6','기타':'#F97316'};
  var subj=q.subject||'기타';
  var subjColor=subjColors[subj]||'#6b7280';
  // Image
  var img=q.has_image
    ?(q.thumbnail_key?'<img class="card__img" src="/api/images/'+q.thumbnail_key+'" alt="문제 이미지" loading="lazy">'
      :q.thumbnail_data?'<img class="card__img" src="'+q.thumbnail_data+'" alt="문제 이미지" loading="lazy">'
      :imageCache[q.id]?'<img class="card__img" src="'+imageCache[q.id]+'" alt="문제 이미지" loading="lazy">'
      :'<img class="card__img" data-qid="'+q.id+'" alt="문제 이미지" loading="lazy" style="background:var(--bg-tertiary)">')
    :'<div class="card__ph" style="background:linear-gradient(135deg,'+subjColor+'15,'+subjColor+'30)"><i class="fas fa-file-alt" style="font-size:32px;color:'+subjColor+'55"></i></div>';
  // Multi-image count badge
  var multiImgCount=0;try{if(q.image_keys){var _ik=JSON.parse(q.image_keys);multiImgCount=Array.isArray(_ik)?_ik.length:0;}}catch(e){}
  var multiImgBadge=multiImgCount>1?'<div style="position:absolute;bottom:6px;right:6px;background:rgba(0,0,0,.65);color:#fff;font-size:10px;padding:2px 6px;border-radius:4px;pointer-events:none"><i class="fas fa-images"></i> '+multiImgCount+'</div>':'';
  // Badges on image
  var badge='';
  var rp=q.reward_points||0;
  var isAccepted=q.status==='채택 완료';
  if(isAccepted)badge+='<div class="card__badge card__badge--done"><i class="fas fa-lightbulb"></i> Aha!</div>';
  if(q.difficulty==='최상'){
    badge+='<div class="card__badge card__badge--killer"><i class="fas fa-fire"></i> 고난도'+(rp?' <span style="color:#ffd700;margin-left:2px">'+rp+'CP</span>':'')+'</div>';
  }else if(q.difficulty==='1:1심화설명'){
    badge+='<div class="card__badge card__badge--tutor"><i class="fas fa-chalkboard-teacher"></i> 튜터링'+(rp?' <span style="color:#ffd700;margin-left:2px">'+rp+'CP</span>':'')+'</div>';
  }
  // Answer count overlay on image
  var ccnt=q.comment_count||0;
  var ansOverlay=isAccepted
    ?'<div class="card__ans-overlay" style="right:auto;left:8px"><i class="fas fa-comment"></i> '+ccnt+'</div>'
    :'<div class="card__ans-overlay"><i class="fas fa-comment"></i> '+ccnt+'</div>';
  // Match notification badge
  var matchNotif='';
  if(q.difficulty==='1:1심화설명'){
    if(q.has_confirmed_match)matchNotif='<div class="card__match-badge card__match--confirmed"><i class="fas fa-check-circle"></i> 매칭</div>';
    else if(isMine&&q.has_pending_match)matchNotif='<div class="card__match-badge card__match--pending"><i class="fas fa-bell"></i> 신청!</div>';
    else if(q.my_match_status==='pending')matchNotif='<div class="card__match-badge card__match--my-pending"><i class="fas fa-hand-paper"></i> 신청</div>';
  }
  // 1:1 코칭 신청 배지
  var coachingBadge='';
  if(q.coaching_requested===3){
    coachingBadge='<div class="card__badge" style="position:absolute;top:8px;left:8px;z-index:3;background:linear-gradient(135deg,#7c6aef,#06b6d4);color:#fff;font-size:10px;font-weight:800;padding:4px 10px;border-radius:8px;box-shadow:0 2px 8px rgba(124,106,239,.4)"><i class="fas fa-graduation-cap"></i> 코칭 완료</div>';
  } else if(q.coaching_requested>=1){
    coachingBadge='<div class="card__badge" style="position:absolute;top:8px;left:8px;z-index:3;background:linear-gradient(135deg,#10b981,#06d6a0);color:#fff;font-size:10px;font-weight:800;padding:4px 10px;border-radius:8px;box-shadow:0 2px 8px rgba(16,185,129,.4);animation:coachingPulse 2s infinite"><i class="fas fa-chalkboard-teacher"></i> 코칭 신청중</div>';
  }
  // My answer badge
  var myBadge='';
  if(q.i_accepted)myBadge='<div class="card__my-badge" style="background:linear-gradient(135deg,#ffd700,#ffaa00);color:#111;font-weight:800"><i class="fas fa-star"></i> 채택됨</div>';
  else if(q.i_answered)myBadge='<div class="card__my-badge" style="background:rgba(108,92,231,.85);color:#fff"><i class="fas fa-pen"></i> 답변함</div>';
  // Subject color bar
  var subjBar='<div class="card__subject-bar" style="background:linear-gradient(0deg,'+subjColor+'dd,'+subjColor+'99)">';
  subjBar+='<span class="card__subj-name">'+subj+'</span>';
  if(q.ai_analyzed&&q.ai_tags){
    var tags=(q.ai_tags||'').split(/\\s+/).filter(function(t){return t.startsWith('#')}).slice(0,4);
    tags.forEach(function(t,i){subjBar+='<span class="card__subj-tag'+(i>=2?' extra':'')+'">'+t+'</span>';});
  }
  subjBar+='</div>';
  // Status badge
  var statusBadge='';
  if(isAccepted)statusBadge='<span class="card__status-badge card__status--solved"><i class="fas fa-check-circle"></i> 해결</span>';
  else if(ccnt===0)statusBadge='<span class="card__status-badge card__status--waiting"><i class="fas fa-clock"></i> 대기</span>';
  // Delete button
  // 더보기(···) 메뉴: 수정/삭제 옵션
  var moreMenu='';
  if(isMine&&(canEdit||canDel)){
    moreMenu='<div class="card__more" data-more-id="'+q.id+'" title="더보기" aria-label="더보기 메뉴"><i class="fas fa-ellipsis-h"></i>'+
      '<div class="card__more-menu">'+
        (canEdit?'<button class="card__more-item" data-edit-id="'+q.id+'" data-edit-content="'+esc(q.content||'')+'" data-edit-subject="'+(q.subject||'기타')+'"><i class="fas fa-pen"></i> 수정하기</button>':'')+
        (canDel?'<button class="card__more-item card__more-item--danger" data-del-id="'+q.id+'"><i class="fas fa-trash-alt"></i> 삭제하기</button>':'')+
      '</div>'+
    '</div>';
  }
  var delBtn=''; // 기존 삭제 버튼은 더보기 메뉴로 대체
  // Card class
  var cardClass='card'+(isAccepted?' card--accepted':'');
  var mineStyle=isMine&&!isAccepted?' style="outline:2px solid var(--accent-primary);outline-offset:-2px"':'';
  // Author header
  var authorGrade=q.author_grade?'<span class="card__grade-chip">'+q.author_grade+'</span>':'';
  var header='<div class="card__header">'+
    '<div class="card__avatar" aria-hidden="true"><i class="fas fa-user"></i></div>'+
    '<div class="card__author-info">'+
      '<div class="card__author-name">'+q.author_name+' '+authorGrade+'</div>'+
      '<div class="card__author-meta"><span>'+timeAgo(q.created_at)+'</span>'+
        (subj!=='기타'?'<span style="color:'+subjColor+'">'+subj+'</span>':'')+
        statusBadge+
      '</div>'+
    '</div>'+
    moreMenu+
  '</div>';
  // Meta info (visible in list view center column)
  var diffLabel={'상':'어려움','중':'보통','하':'쉬움','최상':'최고난도','1:1심화설명':'튜터링'};
  var metaHTML='<div class="card__meta">';
  metaHTML+='<span class="card__meta-item"><i class="fas fa-signal"></i> '+(diffLabel[q.difficulty]||'보통')+'</span>';
  if(subj!=='기타')metaHTML+='<span class="card__meta-item" style="color:'+subjColor+'"><i class="fas fa-book"></i> '+subj+'</span>';
  metaHTML+='</div>';
  // Tags (visible in list view)
  var tagsHTML='<div class="card__tags">';
  if(q.ai_analyzed&&q.ai_tags){var _tArr=(q.ai_tags||'').split(/\\s+/).filter(function(t){return t.startsWith('#')}).slice(0,4);_tArr.forEach(function(t){tagsHTML+='<span class="card__tag">'+t+'</span>';})}
  tagsHTML+='</div>';
  // Answer count link (visible in list view)
  var ansLink=ccnt>0?'<div class="card__ans-link"><i class="fas fa-arrow-right"></i> 답변 '+ccnt+'개 보기</div>':'';
  // Question text body
  var body='<div class="card__body"><div class="card__text">'+(q.content||'질문 내용 없음')+'</div>'+metaHTML+tagsHTML+ansLink+'</div>';
  // Image wrap (delBtn at card level for flexible positioning)
  var imgWrap='<div class="card__img-wrap" style="position:relative">'+img+badge+ansOverlay+matchNotif+myBadge+coachingBadge+multiImgBadge+subjBar+'</div>';
  // 선생님 도와주세요 히어로 스티커
  var teacherSticker='';
  if(q.requested_teacher){
    var tSubjMap={'희성':'수학','우제':'수학','우현':'수학','윤동':'수학','성희':'영어','제이든':'영어','성웅':'영어','지영':'국어','서욱':'국어','지후':'국어','동현':'과학','성현':'과학'};
    var tSubj=tSubjMap[q.requested_teacher]||'수학';
    var tEmoji={'수학':'⚡','영어':'🌊','국어':'🌸','과학':'🧬'};
    teacherSticker='<div class="card__teacher-sticker card__teacher-sticker--'+tSubj+'">'+
      '<div class="sticker__name"><span class="sticker__emoji">'+(tEmoji[tSubj]||'⭐')+'</span> '+q.requested_teacher+'쌤 <span class="sticker__emoji">'+(tEmoji[tSubj]||'⭐')+'</span></div>'+
      '<div class="sticker__msg">가르침 부탁해요~ 🙏</div>'+
    '</div>';
  }
  // Interaction bar (Instagram-style)
  var likeCount=q.like_count||0;
  var isLiked=q.i_liked?true:false;
  var isSaved=q.i_bookmarked?true:false;
  var actions='<div class="card__actions">'+
    '<button class="card__action-btn card__action-btn--like'+(isLiked?' liked':'')+'" data-like-id="'+q.id+'" aria-label="좋아요" aria-pressed="'+(isLiked?'true':'false')+'">'+
      '<i class="'+(isLiked?'fas':'far')+' fa-heart"></i><span class="card__action-label">좋아요</span>'+(likeCount?'<span class="count">'+likeCount+'</span>':'')+
    '</button>'+
    '<button class="card__action-btn" aria-label="댓글">'+
      '<i class="far fa-comment"></i><span class="card__action-label">댓글</span>'+(ccnt?'<span class="count">'+ccnt+'</span>':'')+
    '</button>'+
    /* 질문 단위 즐겨찾기는 MVP 범위 밖 — 연습 문제 단위 "찜한 문제"(/my/bookmarks)와 혼동 방지 위해 비노출 */
    '<button class="card__action-btn card__action-btn--share" data-share-id="'+q.id+'" aria-label="공유">'+
      '<i class="far fa-paper-plane"></i><span class="card__action-label">공유</span>'+
    '</button>'+
    '<div class="card__actions-right">'+
      (ccnt?'<span class="card__ans-count"><i class="fas fa-pen-nib"></i> 답변 '+ccnt+'</span>':'')+
    '</div>'+
  '</div>';
  // Comment preview
  var commentPreview='<div class="card__comments">';
  if(q.latest_comment_author&&q.latest_comment_text){
    commentPreview+='<div class="card__comment-item"><strong>'+q.latest_comment_author+'</strong>'+q.latest_comment_text+'</div>';
    if(ccnt>1)commentPreview+='<span class="card__comment-more">댓글 '+ccnt+'개 모두 보기</span>';
  }else if(ccnt>0){
    commentPreview+='<span class="card__comment-more">댓글 '+ccnt+'개 보기</span>';
  }else{
    commentPreview+='<div class="card__comment-empty">아직 답변이 없어요</div>';
  }
  commentPreview+='</div>';
  // Big heart overlay (for double-tap)
  var bigHeart='<div class="card__big-heart" aria-hidden="true"><i class="fas fa-heart"></i></div>';
  // Assemble: header → content(img+body+actions) → comments
  return '<article class="'+cardClass+'" data-href="/question/'+q.id+'" data-qid="'+q.id+'" data-subj="'+subj+'"'+mineStyle+' role="article" aria-label="'+q.author_name+'의 질문">'+
    header+
    '<div class="card__content">'+imgWrap+teacherSticker+body+actions+'</div>'+
    commentPreview+delBtn+bigHeart+
  '</article>';
}

// === Render Grid ===
function renderGrid(){
  const el=document.getElementById('gallery');
  if(!gridData.length){
    el.innerHTML='<div class="empty" style="grid-column:1/-1">등록된 질문이 없습니다</div>';
    return;
  }
  // Preserve view mode class
  var isListView=el.classList.contains('list-view');
  el.innerHTML=gridData.map(cardHTML).join('');
  if(isListView)el.classList.add('list-view');
  lazyLoadCardImages();
  applyCardFadeIn();
}

// === Infinite Scroll Setup ===
function setupInfiniteScroll(){
  // Use IntersectionObserver for efficient scroll detection
  var sentinel=document.createElement('div');
  sentinel.id='scrollSentinel';
  sentinel.style.cssText='height:1px;width:100%';
  var gallery=document.getElementById('gallery');
  if(gallery)gallery.parentNode.insertBefore(sentinel,gallery.nextSibling);
  
  if('IntersectionObserver' in window){
    var observer=new IntersectionObserver(function(entries){
      if(entries[0].isIntersecting&&_hasMore&&!_isLoadingMore){
        loadMoreItems();
      }
    },{rootMargin:'300px'}); // trigger 300px before reaching bottom
    observer.observe(sentinel);
  }else{
    // Fallback: scroll event
    window.addEventListener('scroll',function(){
      if(_isLoadingMore||!_hasMore)return;
      var scrollPos=window.innerHeight+window.scrollY;
      var docHeight=document.documentElement.scrollHeight;
      if(scrollPos>=docHeight-500)loadMoreItems();
    });
  }
}

// Pagination removed - using infinite scroll instead
function renderPager(){
  var el=document.getElementById('pager');
  if(el)el.innerHTML=_hasMore?'':'<div style="text-align:center;padding:16px;color:#555;font-size:13px">모든 질문을 불러왔습니다</div>';
}
window.goPage=function(){}; // deprecated - kept for compatibility

// === Lazy Load Images ===
function lazyLoadCardImages(){
  document.querySelectorAll('img[data-qid]').forEach(img=>{
    const qid=img.getAttribute('data-qid');
    if(!qid)return;
    if(imageCache[qid]){img.src=imageCache[qid];return}
    if(!img.src||img.src===location.href){
      fetch('/api/questions/'+qid+'/image').then(r=>r.json()).then(d=>{
        if(d.data){imageCache[qid]=d.data;img.src=d.data}
        else{img.alt='이미지 없음';img.style.background='var(--bg3)'}
      }).catch(()=>{img.alt='로드 실패';img.style.background='var(--bg3)'});
    }
  });
}

// === Category Tab Events (removed from main area — category switching via sidebar only) ===

// === Subject Filter Events (with aria-selected) ===
document.querySelectorAll('.subj-chip').forEach(c=>{
  c.addEventListener('click',()=>{
    document.querySelectorAll('.subj-chip').forEach(x=>{x.classList.remove('active');x.setAttribute('aria-selected','false')});
    c.classList.add('active');
    c.setAttribute('aria-selected','true');
    curSubj=c.dataset.subj;
    resetAndReload();
  });
});

// === Sort Events ===
document.getElementById('sortSelect').addEventListener('change',e=>{
  curSort=e.target.value;
  resetAndReload(); // Cursor-based reload with new sort
});

// === My Filter Events (with instant cache rendering + aria) ===
document.querySelectorAll('.my-chip').forEach(c=>{
  c.addEventListener('click',()=>{
    const wasActive=c.classList.contains('active');
    document.querySelectorAll('.my-chip').forEach(x=>{x.classList.remove('active');x.setAttribute('aria-pressed','false')});
    if(wasActive){
      curMyFilter=null;
      // "전체"로 복귀: 캐시에서 즉시 복원 (서버 재요청 없음)
      if(_allCache&&_allCache.data.length>0){
        cachedAllData=_allCache.data.slice();
        gridData=_allCache.data.slice();
        _nextCursor=_allCache.cursor;
        _hasMore=_allCache.hasMore;
        _latestKnownId=_allCache.latestId;
        _categoryCounts=Object.assign({},_allCache.counts);
        updateCategoryCounts();
        var _el=document.getElementById('gallery');if(_el)_el.innerHTML='';
        renderGrid();
      } else { resetAndReload(); }
    } else {
      c.classList.add('active');
      c.setAttribute('aria-pressed','true');
      curMyFilter=c.dataset.my;
      // 캐시가 있으면 즉시 렌더 (0ms)
      var cached=getMyFilteredData(curMyFilter);
      if(cached){
        cachedAllData=cached;
        gridData=cached;
        _hasMore=false;
        _nextCursor=null;
        var el=document.getElementById('gallery');
        if(el)el.innerHTML='';
        renderGrid();
      } else {
        // 캐시 없으면 기존 방식 (서버 요청)
        resetAndReload();
      }
    }
  });
});

// === Search ===
document.getElementById('searchToggle').addEventListener('click',()=>{
  const inp=document.getElementById('searchInput');
  inp.classList.toggle('open');
  if(inp.classList.contains('open'))inp.focus();
  else{inp.value='';exitSearch()}
});
document.getElementById('searchInput').addEventListener('input',e=>{
  clearTimeout(sto);const v=e.target.value.trim();
  if(!v){exitSearch();return}
  sto=setTimeout(()=>doSearch(v),300);
});
async function doSearch(q){
  document.getElementById('gallery').style.display='none';
  document.getElementById('pager').style.display='none';
  const el=document.getElementById('searchResults');el.style.display='grid';
  try{
    const r=await fetch('/api/questions?search='+encodeURIComponent(q));
    const json=await r.json();
    const items=json.questions||json||[];
    el.innerHTML=items.length?items.map(cardHTML).join(''):'<div class="empty" style="grid-column:1/-1">검색 결과가 없습니다</div>';
    lazyLoadCardImages();
  }catch(e){el.innerHTML='<div class="empty" style="grid-column:1/-1">검색 실패</div>'}
}
function exitSearch(){
  document.getElementById('searchResults').style.display='none';
  document.getElementById('gallery').style.display='';
  document.getElementById('pager').style.display='';
}
// Search results click delegation
(function(){
  var sr=document.getElementById('searchResults');
  if(!sr)return;
  sr.addEventListener('click',function(e){
    if(e.target.closest('.card__action-btn')||e.target.closest('.card__del')||e.target.closest('.card__more'))return;
    var card=e.target.closest('.card[data-href]');
    if(card){var href=card.getAttribute('data-href');if(href)window.location.href=href}
  });
})();

// === Refresh on tab visibility (no polling) ===
document.addEventListener('visibilitychange',()=>{if(!document.hidden){resetAndReload();if(currentUser)loadHeaderCp()}});

// === Edit Question Modal ===
function openEditModal(qid,currentContent,currentSubject){
  var ov=document.createElement('div');ov.className='edit-modal-overlay';
  ov.innerHTML='<div class="edit-modal">'+
    '<div class="edit-modal__header"><span class="edit-modal__title">질문 수정</span><button class="edit-modal__close"><i class="fas fa-times"></i></button></div>'+
    '<div class="edit-modal__body">'+
      '<label class="edit-modal__label">질문 내용</label>'+
      '<textarea class="edit-modal__textarea" maxlength="2000" placeholder="질문 내용을 입력하세요...">'+esc(currentContent)+'</textarea>'+
      '<div class="edit-modal__char-count"><span class="edit-modal__char-num">'+currentContent.length+'</span>/2000</div>'+
      '<div class="edit-modal__select-wrap">'+
        '<label class="edit-modal__label">과목</label>'+
        '<select class="edit-modal__select">'+
          '<option value="수학"'+(currentSubject==='수학'?' selected':'')+'>수학</option>'+
          '<option value="영어"'+(currentSubject==='영어'?' selected':'')+'>영어</option>'+
          '<option value="국어"'+(currentSubject==='국어'?' selected':'')+'>국어</option>'+
          '<option value="과학"'+(currentSubject==='과학'?' selected':'')+'>과학</option>'+
          '<option value="기타"'+(currentSubject==='기타'?' selected':'')+'>기타</option>'+
        '</select>'+
      '</div>'+
    '</div>'+
    '<div class="edit-modal__footer">'+
      '<button class="edit-modal__btn edit-modal__btn--cancel">취소</button>'+
      '<button class="edit-modal__btn edit-modal__btn--save">저장</button>'+
    '</div>'+
  '</div>';
  function closeModal(){ov.remove()}
  ov.addEventListener('click',function(e){if(e.target===ov)closeModal()});
  ov.querySelector('.edit-modal__close').addEventListener('click',closeModal);
  ov.querySelector('.edit-modal__btn--cancel').addEventListener('click',closeModal);
  var textarea=ov.querySelector('.edit-modal__textarea');
  var charNum=ov.querySelector('.edit-modal__char-num');
  var charWrap=ov.querySelector('.edit-modal__char-count');
  textarea.addEventListener('input',function(){
    var len=textarea.value.length;
    charNum.textContent=len;
    if(len>2000)charWrap.classList.add('over');else charWrap.classList.remove('over');
  });
  var saveBtn=ov.querySelector('.edit-modal__btn--save');
  saveBtn.addEventListener('click',async function(){
    var newContent=textarea.value.trim();
    var newSubject=ov.querySelector('.edit-modal__select').value;
    if(!newContent){showToast('질문 내용을 입력해주세요','error');return}
    if(newContent.length>2000){showToast('2000자 이내로 입력해주세요','error');return}
    saveBtn.disabled=true;saveBtn.textContent='저장 중...';
    try{
      var t=getToken();
      var hdrs=t?{'Authorization':'Bearer '+t,'Content-Type':'application/json'}:{'Content-Type':'application/json'};
      var body={};
      if(newContent!==currentContent)body.content=newContent;
      if(newSubject!==currentSubject)body.subject=newSubject;
      if(Object.keys(body).length===0){closeModal();return}
      var res=await fetch('/api/questions/'+qid,{method:'PATCH',headers:hdrs,body:JSON.stringify(body)});
      var d=await res.json();
      if(!res.ok){showToast(d.error||'수정 실패','error');saveBtn.disabled=false;saveBtn.textContent='저장';return}
      // 낙관적 업데이트: cachedAllData, gridData, DOM 카드 반영
      [cachedAllData,gridData].forEach(function(arr){
        var q=arr.find(function(item){return item.id===qid});
        if(q){
          if(body.content)q.content=body.content;
          if(body.subject)q.subject=body.subject;
        }
      });
      // DOM 카드 업데이트
      var cardEl=document.querySelector('.card[data-qid="'+qid+'"]');
      if(cardEl){
        var textEl=cardEl.querySelector('.card__text');
        if(textEl&&body.content)textEl.textContent=body.content;
      }
      showToast('질문이 수정되었습니다','success');
      closeModal();
    }catch(e){showToast('수정 요청 실패: '+(e.message||e),'error');saveBtn.disabled=false;saveBtn.textContent='저장'}
  });
  document.addEventListener('keydown',function handler(e){if(e.key==='Escape'){closeModal();document.removeEventListener('keydown',handler)}});
  document.body.appendChild(ov);
  textarea.focus();
}

// === Delete (optimistic UI) ===
var _deleteInProgress=false;
async function deleteQ(id){
  if(_deleteInProgress)return;
  showConfirmModal('이 질문을 삭제하시겠습니까?',async function(){
    _deleteInProgress=true;
    var cardEl=document.querySelector('.card[data-href="/question/'+id+'"]');
    if(cardEl){cardEl.style.transition='opacity .3s,transform .3s';cardEl.style.opacity='0';cardEl.style.transform='scale(.95)'}
    try{
      var t=getToken();
      var hdrs=t?{'Authorization':'Bearer '+t,'Content-Type':'application/json'}:{'Content-Type':'application/json'};
      var res=await fetch('/api/questions/'+id+'/delete',{method:'POST',headers:hdrs});
      var txt=await res.text();
      var d;
      try{d=JSON.parse(txt)}catch(pe){showToast('서버 응답 오류: '+txt.slice(0,100),'error');if(cardEl){cardEl.style.opacity='1';cardEl.style.transform=''}
      _deleteInProgress=false;return}
      if(!res.ok){showToast(d.error||'삭제 실패','error');if(cardEl){cardEl.style.opacity='1';cardEl.style.transform=''}
      _deleteInProgress=false;return}
      cachedAllData=cachedAllData.filter(function(q){return q.id!==id});
      gridData=gridData.filter(function(q){return q.id!==id});
      if(cardEl)cardEl.remove();
      try{var cRes=await fetch('/api/questions/counts');var cJson=await cRes.json();_categoryCounts=cJson;updateCategoryCounts()}catch(e){}
    }catch(e){showToast('삭제 요청 실패: '+(e.message||e),'error');if(cardEl){cardEl.style.opacity='1';cardEl.style.transform=''}}
    _deleteInProgress=false;
  },{danger:true});
}
window.deleteQ=deleteQ;

// === Today's Schedule Banner ===
let scheduleBannerTimer=null;
async function loadTodayScheduleBanner(){
  try{
    const res=await fetch('/api/schedule',{headers:authHeaders()});
    const data=await res.json();
    if(!res.ok||!data.schedules)return;
    const now=new Date();
    const schedules=data.schedules.filter(s=>s.status==='confirmed').map(s=>{
      const parts=s.slot_time.trim().split(' ');
      if(parts.length<3)return null;
      const dp=parts[1].split('/'),tp=parts[2].split(':');
      const yr=now.getFullYear();
      const d=new Date(yr,parseInt(dp[0])-1,parseInt(dp[1]),parseInt(tp[0]),parseInt(tp[1]||'0'));
      if(d.getTime()<now.getTime()-180*86400000)d.setFullYear(yr+1);
      return {...s,_date:d,_diff:d.getTime()-now.getTime()};
    }).filter(s=>s&&s._diff>-3600000).sort((a,b)=>a._diff-b._diff);
    const banner=document.getElementById('todayScheduleBanner');
    if(!schedules.length){banner.style.display='none';return}
    const next=schedules[0];
    const isQ=currentUser.id===next.questioner_id;
    const partner=isQ?next.tutor_name:next.questioner_name;
    const timeStr=next._date.getHours().toString().padStart(2,'0')+':'+next._date.getMinutes().toString().padStart(2,'0');
    function updateCountdown(){
      const diff=next._date.getTime()-Date.now();
      if(diff<=0){cdEl.textContent='지금 시작!';return}
      const h=Math.floor(diff/3600000),m=Math.floor((diff%3600000)/60000),sec=Math.floor((diff%60000)/1000);
      cdEl.textContent=(h>0?h+'시간 ':'')+m+'분 '+sec+'초 후';
    }
    banner.innerHTML='<div class="today-sch-banner" onclick="location.href=\\x27/schedule\\x27"><div class="today-sch-banner__icon"><i class="fas fa-bell"></i></div><div class="today-sch-banner__info"><div class="today-sch-banner__title">다가오는 1:1 튜터링</div><div class="today-sch-banner__sub">'+next.subject+' · '+partner+'님'+(schedules.length>1?' 외 '+(schedules.length-1)+'건':'')+'</div></div><div><div class="today-sch-banner__time">'+timeStr+'</div><div class="today-sch-banner__countdown" id="schCountdown"></div></div></div>';
    banner.style.display='block';
    const cdEl=document.getElementById('schCountdown');
    updateCountdown();
    if(scheduleBannerTimer)clearInterval(scheduleBannerTimer);
    scheduleBannerTimer=setInterval(updateCountdown,1000);
  }catch(e){}
}
</script>
</body>
</html>`
}

// ===== Auth Page (Login / Register) =====

function authPageHTML() {
  return `${htmlHead('로그인')}

.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-box{width:100%;max-width:380px;background:var(--bg2);border-radius:8px;padding:40px 32px;border:1px solid var(--border)}
.auth-logo{text-align:center;margin-bottom:28px}
.auth-logo span{font-size:28px;font-weight:800;color:var(--red)}
.auth-tabs{display:flex;gap:0;margin-bottom:24px;border-bottom:2px solid var(--border)}
.auth-tab{flex:1;text-align:center;padding:10px;font-size:14px;font-weight:600;color:var(--muted);background:none;border:none;cursor:pointer;transition:all .2s;border-bottom:2px solid transparent;margin-bottom:-2px}
.auth-tab.active{color:var(--white);border-bottom-color:var(--red)}
.auth-form{display:none}
.auth-form.active{display:block}
.auth-field{margin-bottom:14px}
.auth-field label{font-size:12px;font-weight:600;color:var(--muted);display:block;margin-bottom:6px}
.auth-field label em{color:var(--red);font-style:normal}
.auth-input{width:100%;padding:11px 14px;font-size:14px;border:1px solid var(--border);border-radius:4px;background:#1a1a1a;color:var(--white);outline:none;transition:border-color .15s}
.auth-input:focus{border-color:var(--muted)}
.auth-input::placeholder{color:var(--muted)}
select.auth-input{appearance:auto}
.auth-btn{width:100%;padding:12px;font-size:14px;font-weight:700;border:none;border-radius:4px;background:var(--red);color:var(--white);margin-top:8px;transition:opacity .15s}
.auth-btn:hover{opacity:.85}
.auth-btn:disabled{opacity:.4}
.auth-error{font-size:12px;color:#ff4444;text-align:center;margin-top:10px;min-height:16px}
.auth-back{display:block;text-align:center;margin-top:20px;font-size:13px;color:var(--muted);transition:color .15s}
.auth-back:hover{color:var(--white)}
</style>
</head>
<body>
<div class="auth-wrap">
  <div class="auth-box">
    <div class="auth-logo"><span>Q&A</span></div>
    <div class="auth-tabs">
      <button class="auth-tab active" data-tab="login">로그인</button>
      <button class="auth-tab" data-tab="register">회원가입</button>
    </div>

    <form class="auth-form active" id="loginForm" onsubmit="return false">
      <div class="auth-field">
        <label>아이디</label>
        <input class="auth-input" id="loginId" type="text" placeholder="아이디 입력" autocomplete="username">
      </div>
      <div class="auth-field">
        <label>비밀번호</label>
        <input class="auth-input" id="loginPw" type="password" placeholder="비밀번호 입력" autocomplete="current-password">
      </div>
      <button class="auth-btn" id="loginBtn" onclick="doLogin()">로그인</button>
      <div class="auth-error" id="loginError"></div>
    </form>

    <form class="auth-form" id="registerForm" onsubmit="return false">
      <div class="auth-field">
        <label>아이디 <em>*</em></label>
        <input class="auth-input" id="regId" type="text" placeholder="4자 이상" autocomplete="username">
      </div>
      <div class="auth-field">
        <label>비밀번호 <em>*</em></label>
        <input class="auth-input" id="regPw" type="password" placeholder="6자 이상" autocomplete="new-password">
      </div>
      <div class="auth-field">
        <label>닉네임 <em>*</em></label>
        <input class="auth-input" id="regNick" type="text" placeholder="다른 학생들에게 보여질 이름">
      </div>
      <div class="auth-field">
        <label>학년</label>
        <select class="auth-input" id="regGrade">
          <option value="">선택 (나중에 설정 가능)</option>
          <option value="중1">중1</option><option value="중2">중2</option><option value="중3">중3</option>
          <option value="고1">고1</option><option value="고2">고2</option><option value="고3">고3</option>
        </select>
      </div>
      <button class="auth-btn" id="regBtn" onclick="doRegister()">회원가입</button>
      <div class="auth-error" id="regError"></div>
    </form>

    <a href="/" class="auth-back"><i class="fas fa-arrow-left"></i> 메인으로 돌아가기</a>
  </div>
</div>

<script>
${sharedAuthJS()}

// If already logged in, redirect
(async()=>{const u=await checkAuth();if(u){const p=new URLSearchParams(location.search).get('redirect');location.href=p||'/'}})();

// Tab switching
const isReg=location.pathname==='/register';
if(isReg){document.querySelectorAll('.auth-tab').forEach(t=>t.classList.toggle('active',t.dataset.tab==='register'));document.querySelectorAll('.auth-form').forEach(f=>f.classList.toggle('active',f.id==='registerForm'))}

document.querySelectorAll('.auth-tab').forEach(tab=>{
  tab.addEventListener('click',()=>{
    document.querySelectorAll('.auth-tab').forEach(t=>t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.auth-form').forEach(f=>f.classList.toggle('active',f.id===(tab.dataset.tab==='login'?'loginForm':'registerForm')));
  });
});

async function doLogin(){
  const btn=document.getElementById('loginBtn');btn.disabled=true;
  document.getElementById('loginError').textContent='';
  try{
    const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('loginId').value.trim(),password:document.getElementById('loginPw').value})});
    const d=await r.json();
    if(!r.ok){document.getElementById('loginError').textContent=d.error;return}
    setToken(d.token);setUser(d.user);
    const p=new URLSearchParams(location.search).get('redirect');location.href=p||'/';
  }catch(e){document.getElementById('loginError').textContent='오류가 발생했습니다.'}
  finally{btn.disabled=false}
}

async function doRegister(){
  const btn=document.getElementById('regBtn');btn.disabled=true;
  document.getElementById('regError').textContent='';
  try{
    const r=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('regId').value.trim(),password:document.getElementById('regPw').value,nickname:document.getElementById('regNick').value.trim(),grade:document.getElementById('regGrade').value})});
    const d=await r.json();
    if(!r.ok){document.getElementById('regError').textContent=d.error;return}
    setToken(d.token);setUser(d.user);
    const p=new URLSearchParams(location.search).get('redirect');location.href=p||'/';
  }catch(e){document.getElementById('regError').textContent='오류가 발생했습니다.'}
  finally{btn.disabled=false}
}

// Enter key
document.getElementById('loginPw').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
document.getElementById('regGrade').addEventListener('keydown',e=>{if(e.key==='Enter')doRegister()});
</script>
</body>
</html>`
}

// ===== Coaching Page =====

function coachingPageHTML() {
  return `${htmlHead('질문 코칭')}
*{box-sizing:border-box}
body{background:var(--bg)}

.co-nav{position:fixed;top:0;left:0;right:0;z-index:200;height:56px;display:flex;align-items:center;padding:0 var(--sp-4);background:rgba(11,14,20,.9);border-bottom:1px solid var(--glass-border);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
.co-nav__back{color:var(--dim);font-size:14px;display:flex;align-items:center;gap:6px;padding:6px 10px;border-radius:10px;transition:all .2s}
.co-nav__back:hover{color:var(--white);background:rgba(255,255,255,.06)}
.co-nav__title{font-size:18px;font-weight:700;color:var(--white);margin-left:var(--sp-2);display:flex;align-items:center;gap:8px;font-family:var(--font-display)}
.co-nav__title i{color:#fbbf24}

.co-wrap{padding:68px 16px 40px;max-width:600px;margin:0 auto}

/* Tabs */
.co-tabs{display:flex;gap:0;margin-bottom:var(--sp-5);border-bottom:2px solid rgba(255,255,255,.04);position:sticky;top:56px;z-index:100;background:var(--bg);padding-top:4px}
.co-tab{flex:1;padding:14px 0;font-size:15px;font-weight:600;color:var(--dim);background:none;border:none;cursor:pointer;position:relative;transition:color .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.co-tab:hover{color:var(--white)}
.co-tab.active{color:var(--white)}
.co-tab.active::after{content:'';position:absolute;bottom:-2px;left:20%;right:20%;height:3px;background:linear-gradient(90deg,var(--gold),#F59E0B);border-radius:2px}

/* Profile Tab */
.co-header{text-align:center;margin-bottom:24px}
.co-header__name{font-size:20px;font-weight:800;color:var(--white);margin-bottom:4px}
.co-header__sub{font-size:13px;color:var(--dim)}
.co-level{display:inline-flex;align-items:center;gap:6px;padding:6px 16px;border-radius:20px;font-size:14px;font-weight:700;margin-top:10px}
.co-level--1{background:rgba(156,163,175,.15);color:#9ca3af;border:1px solid rgba(156,163,175,.2)}
.co-level--2{background:rgba(59,130,246,.1);color:#60a5fa;border:1px solid rgba(59,130,246,.2)}
.co-level--3{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.co-level--4{background:rgba(245,158,11,.1);color:#fbbf24;border:1px solid rgba(245,158,11,.2)}
.co-level--5{background:rgba(239,68,68,.1);color:#f87171;border:1px solid rgba(239,68,68,.2)}

/* Radar Chart */
.co-radar-wrap{position:relative;width:280px;height:280px;margin:0 auto 24px}

/* Bar Chart Section */
.co-section{margin-bottom:var(--sp-6);background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:16px;padding:var(--sp-4);backdrop-filter:blur(12px)}
.co-section__title{font-size:15px;font-weight:700;color:var(--white);margin-bottom:var(--sp-3);display:flex;align-items:center;gap:8px;font-family:var(--font-display)}
.co-section__title i{font-size:13px}

.co-bar-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.co-bar-label{width:70px;font-size:11px;font-weight:600;color:var(--dim);text-align:right;flex-shrink:0}
.co-bar-track{flex:1;height:20px;background:rgba(255,255,255,.04);border-radius:4px;overflow:hidden;position:relative}
.co-bar-fill{height:100%;border-radius:4px;transition:width .8s ease;display:flex;align-items:center;padding-left:6px}
.co-bar-val{font-size:10px;font-weight:700;color:rgba(255,255,255,.9);position:absolute;right:6px;top:50%;transform:translateY(-50%)}

/* Insight Cards */
.co-insight{display:flex;gap:8px;padding:12px;border-radius:10px;margin-bottom:8px;align-items:flex-start}
.co-insight--warn{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.15)}
.co-insight--good{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.15)}
.co-insight--info{background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.15)}
.co-insight__icon{font-size:16px;flex-shrink:0;margin-top:2px}
.co-insight__text{font-size:12px;color:var(--text);line-height:1.5}
.co-insight__text strong{color:var(--white)}

/* Weekly Trend */
.co-weekly{display:flex;gap:4px;align-items:flex-end;height:80px;padding:0 4px}
.co-week{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}
.co-week__bar{width:100%;border-radius:4px 4px 0 0;transition:height .6s ease;min-height:4px}
.co-week__label{font-size:10px;color:var(--muted)}
.co-week__score{font-size:10px;font-weight:700;color:var(--dim)}

/* Upgrade Tab */
.co-q-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:12px;transition:all .2s}
.co-q-card:hover{border-color:rgba(255,255,255,.15)}
.co-q-head{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.co-q-type{font-size:11px;font-weight:700;padding:3px 10px;border-radius:12px;white-space:nowrap}
.co-q-date{font-size:11px;color:var(--muted);margin-left:auto}
.co-q-text{font-size:13px;color:var(--text);line-height:1.5;margin-bottom:10px}
.co-q-subject{font-size:11px;color:var(--dim);display:flex;align-items:center;gap:4px}

.co-upgrade-btn{display:flex;align-items:center;gap:6px;padding:8px 14px;background:linear-gradient(135deg,rgba(245,158,11,.1),rgba(251,191,36,.08));border:1px solid rgba(245,158,11,.2);border-radius:8px;color:#fbbf24;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;margin-top:8px;width:100%}
.co-upgrade-btn:hover{background:linear-gradient(135deg,rgba(245,158,11,.18),rgba(251,191,36,.14));border-color:rgba(245,158,11,.35)}
.co-upgrade-btn i{font-size:11px}
.co-upgrade-btn.loading{pointer-events:none;opacity:.6}

.co-upgrade-result{margin-top:10px;display:none}
.co-upgrade-card{padding:12px;border-radius:10px;margin-bottom:8px;border:1px solid}
.co-upgrade-card__type{font-size:11px;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:4px}
.co-upgrade-card__q{font-size:13px;font-weight:600;color:var(--white);line-height:1.5;margin-bottom:6px;padding:8px;background:rgba(255,255,255,.04);border-radius:6px}
.co-upgrade-card__exp{font-size:11px;color:var(--dim);line-height:1.4}
.co-upgrade-card__tip{font-size:11px;color:#fbbf24;margin-top:6px;display:flex;align-items:flex-start;gap:4px}
.co-upgrade-card__tip i{margin-top:2px;flex-shrink:0}

/* Challenge Tab */
.co-progress-ring{position:relative;width:140px;height:140px;margin:0 auto 20px}
.co-progress-ring__text{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}
.co-progress-ring__num{font-size:28px;font-weight:800;color:var(--white);display:block}
.co-progress-ring__label{font-size:11px;color:var(--dim)}

.co-badge-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
.co-badge{padding:18px;border-radius:16px;text-align:center;transition:all .3s var(--spring)}
.co-badge--locked{background:rgba(255,255,255,.02);border:1px solid var(--glass-border);opacity:.5}
.co-badge--unlocked{background:var(--glass-bg);border:1px solid rgba(251,191,36,.15);box-shadow:0 0 20px rgba(251,191,36,.08);backdrop-filter:blur(12px)}
.co-badge--unlocked:hover{transform:translateY(-2px);box-shadow:0 8px 32px rgba(251,191,36,.12)}
.co-badge__icon{font-size:28px;margin-bottom:6px}
.co-badge__name{font-size:12px;font-weight:700;color:var(--white);margin-bottom:2px}
.co-badge__desc{font-size:10px;color:var(--muted);line-height:1.3}
.co-badge__check{font-size:10px;color:#34d399;margin-top:4px;font-weight:600}

.co-next-goal{margin-top:20px;padding:14px;background:linear-gradient(135deg,rgba(59,130,246,.06),rgba(99,102,241,.04));border:1px solid rgba(59,130,246,.15);border-radius:12px;text-align:center}
.co-next-goal__title{font-size:12px;font-weight:700;color:#60a5fa;margin-bottom:4px}
.co-next-goal__desc{font-size:12px;color:var(--dim);line-height:1.4}

/* No data */
.co-empty{text-align:center;padding:40px 20px;color:var(--muted)}
.co-empty i{font-size:40px;margin-bottom:12px;display:block;color:var(--border)}
.co-empty p{font-size:14px;margin-bottom:8px}
.co-empty a{color:#fbbf24;font-weight:600}

/* Loading */
.co-loading{text-align:center;padding:60px 0;color:var(--muted);font-size:13px}

@media(max-width:500px){
  .co-wrap{padding:62px 10px 30px}
  .co-radar-wrap{width:240px;height:240px}
  .co-badge-grid{grid-template-columns:repeat(2,1fr);gap:8px}
}
</style>
</head>
<body>
<nav class="co-nav">
  <a href="javascript:void(0)" class="co-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
  <div class="co-nav__title"><i class="fas fa-chart-line"></i> 질문 코칭</div>
</nav>

<div class="co-wrap">
  <div class="co-tabs">
    <button class="co-tab active" data-tab="profile" onclick="switchTab('profile')"><i class="fas fa-user-circle"></i> 프로필</button>
    <button class="co-tab" data-tab="upgrade" onclick="switchTab('upgrade')"><i class="fas fa-arrow-up"></i> 업그레이드</button>
    <button class="co-tab" data-tab="challenge" onclick="switchTab('challenge')"><i class="fas fa-trophy"></i> 챌린지</button>
  </div>

  <div id="profileTab"></div>
  <div id="upgradeTab" style="display:none"></div>
  <div id="challengeTab" style="display:none"></div>
  <div id="loadingArea" class="co-loading"><i class="fas fa-spinner fa-spin"></i> 데이터를 불러오는 중...</div>
</div>

<script>
${sharedAuthJS()}

const CATS = {
  'A-1':{label:'뭐지?',group:'See',color:'#9ca3af',icon:'🔍',short:'뭐지'},
  'A-2':{label:'어떻게?',group:'See',color:'#60a5fa',icon:'🔍',short:'어떻게'},
  'B-1':{label:'왜?',group:'Dig',color:'#34d399',icon:'💡',short:'왜'},
  'B-2':{label:'만약에?',group:'Dig',color:'#2dd4bf',icon:'🔀',short:'만약에'},
  'C-1':{label:'뭐가 더 나아?',group:'Expand',color:'#fbbf24',icon:'⚖️',short:'비교'},
  'C-2':{label:'그러면?',group:'Expand',color:'#f87171',icon:'🚀',short:'확장'},
  'R-1':{label:'어디서 틀렸지?',group:'Reflect',color:'#a78bfa',icon:'🔬',short:'오류찾기'},
  'R-2':{label:'왜 틀렸지?',group:'Reflect',color:'#c084fc',icon:'🔬',short:'원인분석'},
  'R-3':{label:'다음엔 어떻게?',group:'Reflect',color:'#e879f9',icon:'🛡️',short:'전략수정'}
};
const WEIGHTS={'A-1':1,'A-2':2,'B-1':5,'B-2':7,'C-1':8,'C-2':10,'R-1':4,'R-2':6,'R-3':8};
const LEVELS=[
  {min:0,name:'Lv.1 시작',label:'시작하는 질문자'},
  {min:15,name:'Lv.2 성장',label:'성장하는 질문자'},
  {min:30,name:'Lv.3 탐구',label:'탐구하는 질문자'},
  {min:50,name:'Lv.4 심화',label:'심화하는 질문자'},
  {min:75,name:'Lv.5 마스터',label:'질문 마스터'}
];

let coachData = null;

function getScore(counts) {
  const total = Object.values(counts).reduce((a,b)=>a+b,0);
  if(total===0)return 0;
  let w=0;Object.entries(counts).forEach(([k,v])=>{w+=(WEIGHTS[k]||0)*v});
  return Math.min(100,Math.round((w/(total*10))*100));
}
function getLevel(score) {
  let lv = LEVELS[0];
  for(const l of LEVELS){if(score>=l.min)lv=l}
  return lv;
}
function getLevelNum(score) {
  for(let i=LEVELS.length-1;i>=0;i--){if(score>=LEVELS[i].min)return i+1}return 1;
}

function switchTab(tab) {
  document.querySelectorAll('.co-tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));
  document.getElementById('profileTab').style.display=tab==='profile'?'':'none';
  document.getElementById('upgradeTab').style.display=tab==='upgrade'?'':'none';
  document.getElementById('challengeTab').style.display=tab==='challenge'?'':'none';
}

// ====== Radar Chart ======
function drawRadar(canvas, counts) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const size = canvas.parentElement.clientWidth;
  canvas.width = size * dpr; canvas.height = size * dpr;
  canvas.style.width = size+'px'; canvas.style.height = size+'px';
  ctx.scale(dpr, dpr);
  
  const cx = size/2, cy = size/2, R = size/2 - 40;
  const keys = Object.keys(CATS);
  const n = keys.length;
  const total = Object.values(counts).reduce((a,b)=>a+b,0);
  const maxVal = Math.max(...Object.values(counts), 1);

  // Background circles
  for(let r=1;r<=4;r++){
    ctx.beginPath();
    for(let i=0;i<=n;i++){
      const angle = (Math.PI*2/n)*i - Math.PI/2;
      const rr = R*(r/4);
      const x = cx + rr*Math.cos(angle);
      const y = cy + rr*Math.sin(angle);
      i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
    }
    ctx.closePath();
    ctx.strokeStyle='rgba(255,255,255,'+(r===4?0.1:0.05)+')';
    ctx.lineWidth=1;ctx.stroke();
  }

  // Axis lines
  for(let i=0;i<n;i++){
    const angle = (Math.PI*2/n)*i - Math.PI/2;
    ctx.beginPath();ctx.moveTo(cx,cy);
    ctx.lineTo(cx+R*Math.cos(angle),cy+R*Math.sin(angle));
    ctx.strokeStyle='rgba(255,255,255,.06)';ctx.stroke();
  }

  // Data shape
  ctx.beginPath();
  for(let i=0;i<=n;i++){
    const idx = i%n;
    const angle = (Math.PI*2/n)*idx - Math.PI/2;
    const val = (counts[keys[idx]]||0)/maxVal;
    const rr = Math.max(R*0.08, R*val);
    const x = cx + rr*Math.cos(angle);
    const y = cy + rr*Math.sin(angle);
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  }
  ctx.closePath();
  const grad = ctx.createRadialGradient(cx,cy,0,cx,cy,R);
  grad.addColorStop(0,'rgba(251,191,36,.25)');grad.addColorStop(1,'rgba(245,158,11,.08)');
  ctx.fillStyle=grad;ctx.fill();
  ctx.strokeStyle='rgba(251,191,36,.6)';ctx.lineWidth=2;ctx.stroke();

  // Data points
  for(let i=0;i<n;i++){
    const angle = (Math.PI*2/n)*i - Math.PI/2;
    const val = (counts[keys[i]]||0)/maxVal;
    const rr = Math.max(R*0.08, R*val);
    const x = cx + rr*Math.cos(angle);
    const y = cy + rr*Math.sin(angle);
    ctx.beginPath();ctx.arc(x,y,3,0,Math.PI*2);
    ctx.fillStyle=CATS[keys[i]].color;ctx.fill();
    ctx.strokeStyle='rgba(0,0,0,.3)';ctx.lineWidth=1;ctx.stroke();
  }

  // Labels
  ctx.font='600 11px Pretendard,-apple-system,sans-serif';
  ctx.textAlign='center';ctx.textBaseline='middle';
  for(let i=0;i<n;i++){
    const angle = (Math.PI*2/n)*i - Math.PI/2;
    const lr = R + 24;
    const lx = cx + lr*Math.cos(angle);
    const ly = cy + lr*Math.sin(angle);
    ctx.fillStyle=CATS[keys[i]].color;
    ctx.fillText(CATS[keys[i]].short+' '+(counts[keys[i]]||0),lx,ly);
  }
}

// ====== Render Profile Tab ======
function renderProfile(data) {
  const score = getScore(data.counts);
  const lv = getLevel(score);
  const lvNum = getLevelNum(score);
  const total = Object.values(data.counts).reduce((a,b)=>a+b,0);

  let html = '<div class="co-header">';
  const displayName = data.userName || (currentUser ? currentUser.nickname : '');
  const nameLabel = isViewingOther ? displayName + '님의 질문 분석' : '나의 질문 분석';
  html += '<div class="co-header__name">' + nameLabel + '</div>';
  html += '<div class="co-header__sub">총 '+data.totalQuestions+'개 질문 중 '+total+'개 분류됨</div>';
  html += '<div class="co-level co-level--'+lvNum+'"><i class="fas fa-star"></i> '+lv.name+' · '+lv.label+' ('+score+'점)</div>';
  html += '</div>';

  if(total === 0) {
    html += '<div class="co-empty"><i class="fas fa-chart-bar"></i><p>아직 분류된 질문이 없습니다</p><a href="/new">첫 질문을 해보세요! →</a></div>';
    document.getElementById('profileTab').innerHTML = html;
    return;
  }

  // Radar chart
  html += '<div class="co-radar-wrap"><canvas id="radarCanvas"></canvas></div>';

  // Bar chart
  html += '<div class="co-section"><div class="co-section__title"><i class="fas fa-chart-bar"></i> 유형별 분포</div>';
  const maxCnt = Math.max(...Object.values(data.counts),1);
  const groupLabels = {See:'보기(See)',Dig:'파기(Dig)',Expand:'넓히기(Expand)',Reflect:'성찰(Reflect)'};
  let prevGroup = '';
  Object.entries(CATS).forEach(([k,v])=>{
    if(v.group!==prevGroup){
      html += '<div style="font-size:10px;color:var(--muted);margin:8px 0 4px;font-weight:600">'+groupLabels[v.group]+'</div>';
      prevGroup = v.group;
    }
    const cnt = data.counts[k]||0;
    const pct = Math.round((cnt/maxCnt)*100);
    html += '<div class="co-bar-row"><div class="co-bar-label">'+v.icon+' '+v.label+'</div>';
    html += '<div class="co-bar-track"><div class="co-bar-fill" style="width:'+pct+'%;background:'+v.color+'"></div>';
    html += '<div class="co-bar-val">'+cnt+'개</div></div></div>';
  });
  html += '</div>';

  // Insights
  html += '<div class="co-section"><div class="co-section__title"><i class="fas fa-lightbulb"></i> 인사이트</div>';
  const insights = getInsights(data.counts, total);
  insights.forEach(ins=>{
    html += '<div class="co-insight co-insight--'+ins.type+'">';
    html += '<div class="co-insight__icon">'+ins.icon+'</div>';
    html += '<div class="co-insight__text">'+ins.text+'</div></div>';
  });
  html += '</div>';

  // Weekly trend
  if(data.weeklyScores && data.weeklyScores.length > 0) {
    html += '<div class="co-section"><div class="co-section__title"><i class="fas fa-chart-line"></i> 주간 성장 추이</div>';
    html += '<div class="co-weekly">';
    const maxScore = Math.max(...data.weeklyScores.map(w=>w.score),1);
    data.weeklyScores.forEach(w=>{
      const h = Math.max(4, (w.score/maxScore)*60);
      const color = w.score >= 50 ? '#fbbf24' : w.score >= 30 ? '#60a5fa' : 'var(--muted)';
      html += '<div class="co-week">';
      html += '<div class="co-week__score">'+w.score+'</div>';
      html += '<div class="co-week__bar" style="height:'+h+'px;background:'+color+'"></div>';
      html += '<div class="co-week__label">'+w.week+'</div></div>';
    });
    html += '</div></div>';
  }

  document.getElementById('profileTab').innerHTML = html;

  // Draw radar after DOM update
  setTimeout(()=>{
    const canvas = document.getElementById('radarCanvas');
    if(canvas) drawRadar(canvas, data.counts);
  }, 50);
}

function getInsights(counts, total) {
  const ins = [];
  const digRatio = ((counts['B-1']||0)+(counts['B-2']||0))/Math.max(total,1);
  const expandRatio = ((counts['C-1']||0)+(counts['C-2']||0))/Math.max(total,1);
  const seeRatio = ((counts['A-1']||0)+(counts['A-2']||0))/Math.max(total,1);
  const reflectRatio = ((counts['R-1']||0)+(counts['R-2']||0)+(counts['R-3']||0))/Math.max(total,1);

  if(seeRatio > 0.6) ins.push({type:'warn',icon:'⚠️',text:'<strong>보기(See)</strong> 질문 비율이 '+(seeRatio*100).toFixed(0)+'%로 높아요. "왜?", "만약에?"와 같은 파기·넓히기 질문을 시도해보세요!'});
  if(digRatio < 0.2 && total >= 3) ins.push({type:'warn',icon:'💡',text:'"<strong>왜?</strong>" 질문이 부족해요. B-1(왜?) 또는 B-2(만약에?) 질문을 늘려보세요.'});
  if(expandRatio > 0.3) ins.push({type:'good',icon:'🎯',text:'<strong>넓히기(Expand)</strong> 질문 비율이 '+(expandRatio*100).toFixed(0)+'%! 높은 수준의 사고력을 보여주고 있어요!'});
  if(reflectRatio > 0.2) ins.push({type:'good',icon:'🔬',text:'<strong>성찰(Reflect)</strong> 질문을 '+(Math.round(reflectRatio*total))+'개나 했어요! 메타인지 능력이 발달하고 있습니다.'});
  if((counts['C-2']||0) >= 1) ins.push({type:'good',icon:'🚀',text:'<strong>그러면?(C-2)</strong> 질문을 시도했어요! 최고 수준의 확장 질문 능력입니다.'});
  if(total >= 5 && expandRatio < 0.1) ins.push({type:'info',icon:'📊',text:'비교(C-1), 확장(C-2) 유형의 질문에도 도전해보세요. 수능 고난도 문제에 대한 감각이 생겨요.'});
  if(ins.length === 0) ins.push({type:'info',icon:'✨',text:'질문을 더 많이 하면 더 정확한 분석 결과를 볼 수 있어요!'});
  return ins;
}

// ====== Render Upgrade Tab ======
function renderUpgrade(data) {
  if(!data.recentQuestions || data.recentQuestions.length === 0) {
    document.getElementById('upgradeTab').innerHTML = '<div class="co-empty"><i class="fas fa-arrow-up"></i><p>분류된 질문이 없어 업그레이드를 제안할 수 없습니다</p><a href="/new">질문하러 가기 →</a></div>';
    return;
  }
  let html = '<div class="co-section"><div class="co-section__title"><i class="fas fa-magic"></i> AI 질문 업그레이드</div>';
  html += '<div style="font-size:12px;color:var(--dim);margin-bottom:12px">최근 질문을 더 높은 수준으로 업그레이드하는 방법을 AI가 제안합니다.</div></div>';

  data.recentQuestions.forEach((q,i)=>{
    const cat = CATS[q.cat] || {label:'미분류',color:'#666',icon:'❓'};
    const dateStr = q.date ? new Date(q.date+'Z').toLocaleDateString('ko-KR',{timeZone:'Asia/Seoul',month:'short',day:'numeric'}) : '';
    html += '<div class="co-q-card">';
    html += '<div class="co-q-head"><span class="co-q-type" style="background:'+cat.color+'22;color:'+cat.color+';border:1px solid '+cat.color+'33">'+cat.icon+' '+cat.label+'</span>';
    html += '<span class="co-q-date">'+dateStr+'</span></div>';
    html += '<div class="co-q-text">'+escHtml(q.text||'(내용 없음)')+'</div>';
    html += '<div class="co-q-subject"><i class="fas fa-tag"></i> '+(q.subject||'미분류')+'</div>';
    if(q.cat && q.cat !== 'C-2' && !isViewingOther) {
      html += '<button class="co-upgrade-btn" id="upgBtn'+i+'" onclick="requestUpgrade('+i+','+q.id+',\\''+escAttr(q.text||'')+'\\',\\''+q.cat+'\\',\\''+escAttr(q.subject||'수학')+'\\')"><i class="fas fa-wand-magic-sparkles"></i> 더 좋은 질문으로 업그레이드 제안받기</button>';
      html += '<div class="co-upgrade-result" id="upgResult'+i+'"></div>';
    } else if(q.cat === 'C-2') {
      html += '<div style="margin-top:8px;padding:8px 12px;border-radius:8px;background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.15);font-size:12px;color:#f87171;display:flex;align-items:center;gap:6px"><i class="fas fa-crown"></i> 이미 최고 수준의 질문입니다! 👏</div>';
    }
    html += '</div>';
  });

  document.getElementById('upgradeTab').innerHTML = html;
}

var escHtml=esc;
function escAttr(s){return String(s).replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'").replace(/"/g,'\\\\"').replace(/\\n/g,' ').slice(0,100)}

async function requestUpgrade(idx, qId, qText, qType, subject) {
  const btn = document.getElementById('upgBtn'+idx);
  const result = document.getElementById('upgResult'+idx);
  btn.classList.add('loading');
  btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> AI가 분석 중...';
  try {
    const res = await fetch('/api/coaching/upgrade', {
      method:'POST', headers:authHeaders(),
      body:JSON.stringify({questionId:qId, questionText:qText, questionType:qType, subject:subject})
    });
    const data = await res.json();
    if(!res.ok) throw new Error(data.error||'failed');
    let rhtml = '';
    (data.upgrades||[]).forEach(u=>{
      const tc = CATS[u.targetType]||{color:'#666',icon:'❓'};
      rhtml += '<div class="co-upgrade-card" style="background:'+tc.color+'08;border-color:'+tc.color+'22">';
      rhtml += '<div class="co-upgrade-card__type" style="color:'+tc.color+'">'+tc.icon+' '+u.targetTypeName+' ('+u.targetType+')</div>';
      rhtml += '<div class="co-upgrade-card__q">"'+escHtml(u.upgradedQuestion)+'"</div>';
      rhtml += '<div class="co-upgrade-card__exp">'+escHtml(u.explanation)+'</div>';
      if(u.tip) rhtml += '<div class="co-upgrade-card__tip"><i class="fas fa-lightbulb"></i> '+escHtml(u.tip)+'</div>';
      rhtml += '</div>';
    });
    result.innerHTML = rhtml;
    result.style.display='block';
    btn.style.display='none';
  } catch(e) {
    btn.classList.remove('loading');
    btn.innerHTML='<i class="fas fa-exclamation-circle"></i> 실패했습니다. 다시 시도';
  }
}

// ====== Render Challenge Tab ======
function renderChallenge(data) {
  const counts = data.counts;
  const total = Object.values(counts).reduce((a,b)=>a+b,0);
  const score = getScore(counts);

  const badges = [
    {id:'first',name:'첫 질문',desc:'첫 번째 질문을 했어요',icon:'🎉',check:data.totalQuestions>=1},
    {id:'why',name:'Why 탐험가',desc:'왜?(B-1) 질문 3개 이상',icon:'💡',check:(counts['B-1']||0)>=3},
    {id:'debug',name:'디버거',desc:'어디서 틀렸지?(R-1) 질문 2개 이상',icon:'🔬',check:(counts['R-1']||0)>=2},
    {id:'judge',name:'심판관',desc:'뭐가 더 나아?(C-1) 질문 2개 이상',icon:'⚖️',check:(counts['C-1']||0)>=2},
    {id:'creator',name:'창조자',desc:'그러면?(C-2) 질문 1개 이상',icon:'🚀',check:(counts['C-2']||0)>=1},
    {id:'balanced',name:'밸런서',desc:'5가지 이상 유형 질문',icon:'🎯',check:Object.values(counts).filter(v=>v>0).length>=5},
    {id:'deep',name:'깊은 사고',desc:'파기·넓히기 질문이 60% 이상',icon:'🧠',check:total>0&&((counts['B-1']||0)+(counts['B-2']||0)+(counts['C-1']||0)+(counts['C-2']||0))/total>=0.6},
    {id:'reflect',name:'성찰가',desc:'성찰 질문(R축) 2개 이상',icon:'🔬',check:((counts['R-1']||0)+(counts['R-2']||0)+(counts['R-3']||0))>=2},
    {id:'master',name:'질문 마스터',desc:'코칭 점수 75점 이상',icon:'👑',check:score>=75}
  ];

  const unlocked = badges.filter(b=>b.check).length;
  const pct = Math.round((unlocked/badges.length)*100);

  // Progress ring SVG
  let html = '<div class="co-progress-ring">';
  html += '<svg width="140" height="140" viewBox="0 0 140 140">';
  html += '<circle cx="70" cy="70" r="60" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="8"/>';
  const circumference = 2 * Math.PI * 60;
  const offset = circumference - (pct/100)*circumference;
  html += '<circle cx="70" cy="70" r="60" fill="none" stroke="#fbbf24" stroke-width="8" stroke-linecap="round" stroke-dasharray="'+circumference+'" stroke-dashoffset="'+offset+'" transform="rotate(-90 70 70)" style="transition:stroke-dashoffset 1s ease"/>';
  html += '</svg>';
  html += '<div class="co-progress-ring__text"><span class="co-progress-ring__num">'+unlocked+'/'+badges.length+'</span><span class="co-progress-ring__label">뱃지 달성</span></div>';
  html += '</div>';

  html += '<div class="co-badge-grid">';
  badges.forEach(b=>{
    html += '<div class="co-badge co-badge--'+(b.check?'unlocked':'locked')+'">';
    html += '<div class="co-badge__icon">'+b.icon+'</div>';
    html += '<div class="co-badge__name">'+b.name+'</div>';
    html += '<div class="co-badge__desc">'+b.desc+'</div>';
    if(b.check) html += '<div class="co-badge__check"><i class="fas fa-check-circle"></i> 달성!</div>';
    html += '</div>';
  });
  html += '</div>';

  // Next goal
  const next = badges.find(b=>!b.check);
  if(next) {
    html += '<div class="co-next-goal"><div class="co-next-goal__title"><i class="fas fa-flag"></i> 다음 목표</div>';
    html += '<div class="co-next-goal__desc">'+next.icon+' <strong>'+next.name+'</strong> — '+next.desc+'</div></div>';
  }

  document.getElementById('challengeTab').innerHTML = html;
}

// ====== Init ======
let currentUser = null;
let isViewingOther = false;
(async()=>{
  currentUser = await checkAuth();
  
  // Check if viewing a specific user's profile via URL /coaching/:userId
  const pathParts = location.pathname.split('/');
  const urlUserId = pathParts.length >= 3 && pathParts[1] === 'coaching' && pathParts[2] ? pathParts[2] : null;
  
  if (urlUserId) {
    // Viewing someone else's profile - no auth required
    isViewingOther = true;
    try {
      const res = await fetch('/api/coaching/stats?userId=' + urlUserId);
      if(!res.ok) throw new Error('Failed');
      coachData = await res.json();
      document.getElementById('loadingArea').style.display='none';
      renderProfile(coachData);
      renderUpgrade(coachData);
      renderChallenge(coachData);
    } catch(e) {
      document.getElementById('loadingArea').innerHTML = '<div class="co-empty"><i class="fas fa-exclamation-triangle"></i><p>데이터를 불러올 수 없습니다</p></div>';
    }
  } else if (currentUser) {
    // Viewing own profile
    try {
      const res = await fetch('/api/coaching/stats', {headers:authHeaders()});
      if(!res.ok) throw new Error('Failed');
      coachData = await res.json();
      document.getElementById('loadingArea').style.display='none';
      renderProfile(coachData);
      renderUpgrade(coachData);
      renderChallenge(coachData);
    } catch(e) {
      document.getElementById('loadingArea').innerHTML = '<div class="co-empty"><i class="fas fa-exclamation-triangle"></i><p>데이터를 불러올 수 없습니다</p></div>';
    }
  } else {
    document.getElementById('loadingArea').innerHTML = '<div class="co-empty"><i class="fas fa-lock"></i><p>로그인이 필요합니다</p><p style="font-size:12px">정율톡에서 접속해주세요</p></div>';
  }
})();
</script>
</body>
</html>`
}

// ===== My Page =====

function schedulePageHTML() {
  return `${htmlHead('내 스케줄')}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Pretendard',sans-serif;min-height:100vh}
.sch-nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(11,14,20,.9);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:1px solid var(--glass-border);display:flex;align-items:center;padding:0 var(--sp-4);height:52px}
.sch-nav a{color:var(--dim);font-size:14px;display:flex;align-items:center;gap:6px;text-decoration:none;position:relative;z-index:2;cursor:pointer;padding:8px 4px;transition:color .2s}
.sch-nav a:hover{color:var(--white)}
.sch-nav__title{position:absolute;left:0;right:0;text-align:center;font-size:16px;font-weight:700;color:var(--white);pointer-events:none;z-index:1;font-family:var(--font-display)}
.sch-nav__right{font-size:12px;color:var(--muted);margin-left:auto;position:relative;z-index:2}

.sch-wrap{padding:68px var(--sp-4) 100px;max-width:600px;margin:0 auto}
.sch-tabs{display:flex;gap:4px;margin-bottom:var(--sp-5);background:var(--bg2);border-radius:14px;padding:4px}
.sch-tab{flex:1;padding:12px;text-align:center;font-size:14px;font-weight:600;color:var(--muted);border-radius:10px;cursor:pointer;transition:all .2s var(--spring);border:none;background:none}
.sch-tab.active{background:var(--accent-gradient);color:#fff;box-shadow:0 4px 12px rgba(139,92,246,.3)}
.sch-tab .tab-count{font-size:11px;font-weight:400;margin-left:4px;opacity:.7}

.sch-section{margin-bottom:24px}
.sch-date{font-size:12px;font-weight:700;color:var(--muted);margin-bottom:10px;display:flex;align-items:center;gap:6px;padding-left:4px}
.sch-date i{color:var(--red)}

.sch-card{background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:16px;padding:18px;margin-bottom:12px;position:relative;overflow:hidden;transition:all .2s var(--spring);backdrop-filter:blur(12px)}
.sch-card:hover{border-color:rgba(139,92,246,.3);transform:translateY(-2px)}
.sch-card--today{border-left:3px solid var(--gold)}
.sch-card--past{opacity:.6}

.sch-card__top{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.sch-card__time{font-size:22px;font-weight:800;color:var(--white);min-width:60px;font-family:var(--font-display)}
.sch-card__subject{font-size:11px;font-weight:700;padding:3px 8px;border-radius:3px;background:rgba(108,92,231,.15);color:#a29bfe;border:1px solid rgba(108,92,231,.25)}
.sch-card__points{font-size:11px;font-weight:800;color:#ffd700;margin-left:auto}
.sch-card__dday{font-size:11px;font-weight:700;padding:3px 8px;border-radius:10px}
.sch-card__dday--today{background:rgba(255,215,0,.15);color:#ffd700;animation:ddayPulse 2s infinite}
.sch-card__dday--soon{background:rgba(255,69,0,.12);color:#ff4500}
.sch-card__dday--far{background:rgba(108,92,231,.12);color:#a29bfe}
.sch-card__dday--done{background:rgba(0,200,83,.12);color:#00c853}
@keyframes ddayPulse{0%,100%{opacity:1}50%{opacity:.6}}

.sch-card__title{font-size:13px;color:var(--white);margin-bottom:8px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.sch-card__partner{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);margin-bottom:10px}
.sch-card__partner i{color:#a29bfe}
.sch-card__role{font-size:10px;font-weight:700;padding:2px 6px;border-radius:3px}
.sch-card__role--q{background:rgba(255,65,54,.12);color:var(--red)}
.sch-card__role--t{background:rgba(108,92,231,.12);color:#a29bfe}

.sch-card__actions{display:flex;gap:8px;margin-top:12px}
.sch-btn{flex:1;padding:10px;border-radius:10px;font-size:13px;font-weight:700;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:6px;transition:all .2s var(--spring);min-height:44px}
.sch-btn--complete{background:linear-gradient(135deg,#10B981,#34D399);color:#fff;box-shadow:0 4px 12px rgba(16,185,129,.2)}
.sch-btn--complete:hover{opacity:.85}
.sch-btn--cancel{background:none;border:1px solid rgba(255,65,54,.3);color:var(--red)}
.sch-btn--cancel:hover{background:rgba(255,65,54,.08)}
.sch-btn--mutual{background:none;border:1px solid rgba(108,92,231,.3);color:#a29bfe;font-size:11px}
.sch-btn--mutual:hover{background:rgba(108,92,231,.08)}
.sch-btn--view{background:rgba(108,92,231,.12);color:#a29bfe;border:1px solid rgba(108,92,231,.25)}
.sch-btn--view:hover{background:rgba(108,92,231,.2)}
.sch-btn--accept-mutual{background:linear-gradient(135deg,#a29bfe,#6c5ce7);color:#fff}

/* Cancel Modal */
.cancel-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px;animation:fadeIn .2s}
.cancel-modal{background:var(--bg2);border:1px solid var(--border);border-radius:14px;max-width:420px;width:100%;max-height:90vh;overflow-y:auto;animation:slideUp .3s ease}
@keyframes slideUp{from{transform:translateY(30px);opacity:0}to{transform:translateY(0);opacity:1}}
.cancel-modal__header{padding:20px 20px 0;display:flex;align-items:center;gap:10px}
.cancel-modal__icon{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.cancel-modal__icon--warn{background:rgba(255,69,0,.12);color:#ff4500}
.cancel-modal__icon--ok{background:rgba(108,92,231,.12);color:#a29bfe}
.cancel-modal__title{font-size:16px;font-weight:700;color:var(--white)}
.cancel-modal__sub{font-size:12px;color:var(--muted);margin-top:2px}
.cancel-modal__body{padding:16px 20px}
.cancel-modal__penalty{background:rgba(255,69,0,.06);border:1px solid rgba(255,69,0,.15);border-radius:8px;padding:12px;margin-bottom:16px}
.cancel-modal__penalty-row{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);padding:3px 0}
.cancel-modal__penalty-val{font-weight:700;color:#ff4500}
.cancel-modal__penalty-none{color:#00c853}
.cancel-modal__reasons{display:flex;flex-direction:column;gap:6px;margin-bottom:16px}
.cancel-reason{display:flex;align-items:center;gap:10px;padding:12px;border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:all .15s;background:none}
.cancel-reason:hover{border-color:rgba(108,92,231,.3)}
.cancel-reason.selected{border-color:#a29bfe;background:rgba(108,92,231,.06)}
.cancel-reason input{accent-color:#a29bfe}
.cancel-reason__label{font-size:13px;color:var(--white)}
.cancel-detail{width:100%;padding:10px 12px;font-size:12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--white);resize:vertical;min-height:60px;margin-bottom:16px;outline:none}
.cancel-detail:focus{border-color:#a29bfe}
.cancel-modal__footer{padding:0 20px 20px;display:flex;gap:8px}
.cancel-modal__btn{flex:1;padding:12px;border-radius:8px;font-size:13px;font-weight:700;border:none;cursor:pointer;transition:all .15s}
.cancel-modal__btn--cancel{background:var(--bg);color:var(--dim);border:1px solid var(--border)}
.cancel-modal__btn--cancel:hover{background:var(--border)}
.cancel-modal__btn--confirm{background:linear-gradient(135deg,#ff4136,#ff6b6b);color:#fff}
.cancel-modal__btn--confirm:hover{opacity:.85}
.cancel-modal__btn--mutual{background:linear-gradient(135deg,#a29bfe,#6c5ce7);color:#fff}
.cancel-modal__btn--mutual:hover{opacity:.85}
.cancel-modal__btn:disabled{opacity:.4;cursor:not-allowed}

/* Penalty info banner */
.penalty-info{background:rgba(255,165,0,.06);border:1px solid rgba(255,165,0,.15);border-radius:8px;padding:12px;margin-bottom:16px;font-size:12px;color:var(--muted);display:flex;align-items:center;gap:8px}
.penalty-info i{color:#ffa500;font-size:14px}
.penalty-info__count{font-weight:700;color:#ff4500}
.mutual-pending{background:rgba(108,92,231,.08);border:1px solid rgba(108,92,231,.2);border-radius:8px;padding:10px 12px;margin-top:8px;font-size:12px;color:#a29bfe;display:flex;align-items:center;gap:8px}

.sch-empty{text-align:center;padding:60px 20px;color:var(--muted)}
.sch-empty i{font-size:40px;margin-bottom:12px;display:block;opacity:.3}
.sch-empty p{font-size:14px;margin-bottom:16px}
.sch-empty a{color:var(--red);font-weight:600;text-decoration:none}

.sch-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:var(--sp-2);margin-bottom:var(--sp-6)}
.sch-stat{background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:16px;padding:18px;text-align:center;backdrop-filter:blur(12px)}
.sch-stat__num{font-size:24px;font-weight:800;color:var(--white);font-family:var(--font-display)}
.sch-stat__label{font-size:12px;color:var(--muted);margin-top:4px}

.sch-alert{background:linear-gradient(135deg,rgba(255,215,0,.1),rgba(255,165,0,.05));border:1px solid rgba(255,215,0,.25);border-radius:10px;padding:14px 16px;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.sch-alert i{font-size:18px;color:#ffd700;animation:ring 1s ease infinite}
.sch-alert__text{font-size:13px;color:var(--white);font-weight:600}
.sch-alert__sub{font-size:11px;color:var(--muted);margin-top:2px}
.sch-alert__btn{margin-left:auto;padding:6px 14px;background:rgba(255,215,0,.15);border:1px solid rgba(255,215,0,.3);color:#ffd700;font-size:11px;font-weight:700;border-radius:6px;cursor:pointer;white-space:nowrap}
</style>
</head>
<body>

<nav class="sch-nav">
  <a href="/"><i class="fas fa-arrow-left"></i> 홈</a>
  <div class="sch-nav__title"><i class="fas fa-calendar-alt" style="margin-right:4px"></i> 내 스케줄</div>
  <div class="sch-nav__right" id="navUser"></div>
</nav>

<div class="sch-wrap">
  <div id="alertBanner"></div>

  <div class="sch-stats">
    <div class="sch-stat"><div class="sch-stat__num" id="statUpcoming">-</div><div class="sch-stat__label">예정된 수업</div></div>
    <div class="sch-stat"><div class="sch-stat__num" id="statCompleted">-</div><div class="sch-stat__label">완료된 수업</div></div>
    <div class="sch-stat"><div class="sch-stat__num" id="statPoints">-</div><div class="sch-stat__label">총 CP</div></div>
  </div>

  <div id="penaltyBanner"></div>

  <div class="sch-tabs">
    <button class="sch-tab active" data-tab="upcoming"><i class="fas fa-clock"></i> 예정<span class="tab-count" id="upcomingCount"></span></button>
    <button class="sch-tab" data-tab="completed"><i class="fas fa-check-circle"></i> 완료<span class="tab-count" id="completedCount"></span></button>
  </div>

  <div id="scheduleList"></div>
</div>

<script>
${sharedAuthJS()}
let currentUser=null;
let allSchedules=[];
let currentTab='upcoming';

(async()=>{
  currentUser=await checkAuth();
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  document.getElementById('navUser').textContent=currentUser.nickname;
  loadSchedule();
})();

async function loadSchedule(){
  try{
    const res=await fetch('/api/schedule',{headers:authHeaders()});
    const data=await res.json();
    if(!res.ok){showToast(data.error,'error');return}
    allSchedules=data.schedules||[];
    renderSchedule();
    checkMutualCancelStatus();
    loadPenaltyInfo();
  }catch(e){console.error(e)}
}

function parseSlotTime(slotTime){
  // Parse "수 02/11 18:00" or "수 2/11 18:00" format
  if(!slotTime)return null;
  const parts=slotTime.trim().split(' ');
  if(parts.length<3)return null;
  const dateParts=parts[1].split('/');
  if(dateParts.length<2)return null;
  const month=parseInt(dateParts[0])-1;
  const day=parseInt(dateParts[1]);
  const timeParts=parts[2].split(':');
  const hour=parseInt(timeParts[0]);
  const minute=parseInt(timeParts[1]||'0');
  const now=new Date();
  const year=now.getFullYear();
  const d=new Date(year,month,day,hour,minute);
  // If date is far in the past, assume next year
  if(d.getTime()<now.getTime()-180*86400000) d.setFullYear(year+1);
  return d;
}

function getDday(slotDate){
  if(!slotDate)return{text:'',cls:''};
  const now=new Date();
  const diff=slotDate.getTime()-now.getTime();
  const days=Math.floor(diff/86400000);
  const hours=Math.floor(diff/3600000);
  const mins=Math.floor(diff/60000);
  if(diff<0)return{text:'지남',cls:'done'};
  if(days===0&&hours<1)return{text:mins+'분 후',cls:'today'};
  if(days===0)return{text:'오늘 '+hours+'시간 후',cls:'today'};
  if(days===1)return{text:'내일',cls:'soon'};
  if(days<=7)return{text:'D-'+days,cls:'soon'};
  return{text:'D-'+days,cls:'far'};
}

function renderSchedule(){
  const now=new Date();
  const upcoming=[];
  const completed=[];
  let totalPoints=0;

  allSchedules.forEach(s=>{
    const slotDate=parseSlotTime(s.slot_time);
    s._date=slotDate;
    s._dday=getDday(slotDate);
    s._isQuestioner=currentUser.id===s.questioner_id;
    s._role=s._isQuestioner?'questioner':'tutor';
    if(s.status==='completed'){
      completed.push(s);
      if(s._role==='tutor')totalPoints+=s.reward_points||0;
    }else{
      upcoming.push(s);
    }
  });

  // Sort upcoming by date
  upcoming.sort((a,b)=>(a._date||0)-(b._date||0));
  completed.sort((a,b)=>(b._date||0)-(a._date||0));

  document.getElementById('statUpcoming').textContent=upcoming.length;
  document.getElementById('statCompleted').textContent=completed.length;
  document.getElementById('statPoints').textContent=totalPoints+'CP';
  document.getElementById('upcomingCount').textContent=upcoming.length?'('+upcoming.length+')':'';
  document.getElementById('completedCount').textContent=completed.length?'('+completed.length+')':'';

  // Alert banner for imminent session (1 hour or 10 min)
  const imminent=upcoming.find(s=>s._date&&(s._date.getTime()-now.getTime())<3600000&&(s._date.getTime()-now.getTime())>0);
  const tenMin=upcoming.find(s=>s._date&&(s._date.getTime()-now.getTime())<600000&&(s._date.getTime()-now.getTime())>0);
  const banner=document.getElementById('alertBanner');
  if(tenMin){
    const mins=Math.max(0,Math.floor((tenMin._date.getTime()-now.getTime())/60000));
    const secs=Math.max(0,Math.floor(((tenMin._date.getTime()-now.getTime())%60000)/1000));
    banner.innerHTML='<div class="sch-alert" style="border-color:rgba(255,69,0,.4);background:linear-gradient(135deg,rgba(255,69,0,.15),rgba(255,69,0,.05))"><i class="fas fa-exclamation-triangle" style="color:#ff4500;font-size:20px"></i><div><div class="sch-alert__text" style="color:#ff4500">⚡ '+mins+'분 '+secs+'초 후 수업 시작!</div><div class="sch-alert__sub">'+tenMin.subject+' · '+(tenMin._isQuestioner?tenMin.tutor_name:tenMin.questioner_name)+'님</div><div class="sch-alert__sub" style="margin-top:4px;color:#a29bfe"><i class="fas fa-comment-dots"></i> 정율톡에서 상대방과 미리 인사해보세요!</div></div><button class="sch-alert__btn" style="background:rgba(255,69,0,.15);border-color:rgba(255,69,0,.3);color:#ff4500" onclick="location.href=\\x27/question/'+tenMin.question_id+'\\x27">입장</button></div>';
  }else if(imminent){
    const mins=Math.max(0,Math.floor((imminent._date.getTime()-now.getTime())/60000));
    banner.innerHTML='<div class="sch-alert"><i class="fas fa-bell"></i><div><div class="sch-alert__text">🔔 '+mins+'분 후 1:1 튜터링이 시작됩니다!</div><div class="sch-alert__sub">'+imminent.subject+' · '+(imminent._isQuestioner?imminent.tutor_name:imminent.questioner_name)+'님</div><div class="sch-alert__sub" style="margin-top:4px;color:#a29bfe"><i class="fas fa-comment-dots"></i> 매칭 확정 시 정율톡 톡방이 자동으로 생성됩니다</div></div><button class="sch-alert__btn" onclick="location.href=\\x27/question/'+imminent.question_id+'\\x27">상세보기</button></div>';
  }else{banner.innerHTML=''}

  const list=currentTab==='upcoming'?upcoming:completed;
  renderList(list);
}

function renderList(list){
  const el=document.getElementById('scheduleList');
  if(!list.length){
    const isUp=currentTab==='upcoming';
    el.innerHTML='<div class="sch-empty"><i class="fas '+(isUp?'fa-calendar-plus':'fa-check-circle')+'"></i><p>'+(isUp?'예정된 수업이 없습니다':'완료된 수업이 없습니다')+'</p>'+(isUp?'<a href="/new">1:1 튜터링 질문하기 →</a>':'')+'</div>';
    return;
  }

  // Group by date
  let html='';
  let lastDate='';
  const now=new Date();
  const todayStr=now.getFullYear()+'-'+(now.getMonth()+1)+'-'+now.getDate();

  list.forEach(s=>{
    const d=s._date;
    const dateStr=d?d.getFullYear()+'-'+(d.getMonth()+1)+'-'+d.getDate():'';
    const isToday=dateStr===todayStr;
    const isPast=d&&d.getTime()<now.getTime();

    if(dateStr!==lastDate){
      const dayNames=['일','월','화','수','목','금','토'];
      const label=d?(isToday?'오늘':(d.getMonth()+1)+'/'+ d.getDate()+' ('+dayNames[d.getDay()]+')'):'날짜 미정';
      html+='<div class="sch-section"><div class="sch-date"><i class="fas '+(isToday?'fa-star':'fa-calendar-day')+'"></i> '+label+'</div>';
      lastDate=dateStr;
    }

    const timeStr=d?(d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0')):'--:--';
    const dday=s._dday;
    const partner=s._isQuestioner?{name:s.tutor_name,grade:s.tutor_grade,label:'답변자',cls:'t'}:{name:s.questioner_name,grade:s.questioner_grade,label:'질문자',cls:'q'};
    const roleTag=s._isQuestioner?'<span class="sch-card__role sch-card__role--q">질문자</span>':'<span class="sch-card__role sch-card__role--t">답변자</span>';

    html+='<div class="sch-card'+(isToday?' sch-card--today':'')+(isPast&&s.status!=='completed'?' sch-card--past':'')+'">';
    html+='<div class="sch-card__top">';
    html+='<div class="sch-card__time">'+timeStr+'</div>';
    html+='<div class="sch-card__subject"><i class="fas fa-chalkboard-teacher"></i> '+s.subject+'</div>';
    html+=roleTag;
    if(s.reward_points)html+='<div class="sch-card__points"><i class="fas fa-cookie-bite"></i> '+s.reward_points+'CP</div>';
    if(dday.text)html+='<div class="sch-card__dday sch-card__dday--'+dday.cls+'">'+dday.text+'</div>';
    html+='</div>';

    html+='<div class="sch-card__title">'+(s.title||s.content||'')+'</div>';
    html+='<div class="sch-card__partner"><i class="fas fa-user-circle"></i> '+partner.label+': <strong>'+partner.name+'</strong>'+(partner.grade?' ('+partner.grade+')':'')+'</div>';

    html+='<div class="sch-card__actions">';
    html+='<button class="sch-btn sch-btn--view" onclick="location.href=\\x27/question/'+s.question_id+'\\x27"><i class="fas fa-eye"></i> 질문보기</button>';
    if(s.status==='confirmed'){
      if(isPast){
        html+='<button class="sch-btn sch-btn--complete" onclick="completeSession('+s.id+')"><i class="fas fa-check"></i> 수업 완료</button>';
      }
      html+='<button class="sch-btn sch-btn--cancel" onclick="showCancelModal('+s.id+')"><i class="fas fa-times"></i> 취소</button>';
    }else if(s.status==='completed'){
      html+='<div class="sch-btn" style="background:rgba(0,200,83,.1);color:#00c853;cursor:default"><i class="fas fa-check-circle"></i> 수업 완료</div>';
    }
    html+='</div>';
    // Mutual cancel pending indicator
    html+='<div id="mutualStatus'+s.id+'"></div>';
    html+='</div>';
  });

  el.innerHTML=html;
}

// Cancel reasons
const CANCEL_REASONS=[
  {id:'schedule_conflict',label:'일정이 겹쳐서',icon:'fa-calendar-times'},
  {id:'emergency',label:'긴급한 개인 사정',icon:'fa-exclamation-circle'},
  {id:'health',label:'건강 문제',icon:'fa-heartbeat'},
  {id:'no_response',label:'상대방 연락 두절',icon:'fa-phone-slash'},
  {id:'wrong_match',label:'잘못된 매칭 (실수)',icon:'fa-undo'},
  {id:'other',label:'기타 사유',icon:'fa-ellipsis-h'}
];

function showCancelModal(matchId){
  const s=allSchedules.find(x=>x.id===matchId);
  if(!s)return;
  const d=parseSlotTime(s.slot_time);
  const now=new Date();
  const hoursLeft=d?(d.getTime()-now.getTime())/3600000:-1;
  // Check grace period (within 2h of confirmation)
  let isGrace=false;
  if(s.confirmed_at){
    const ct=new Date(s.confirmed_at+'Z').getTime();
    isGrace=(Date.now()-ct)<2*3600000&&hoursLeft>24;
  }
  const isMyQ=currentUser.id===s.questioner_id;
  let penaltyText='',penaltyCls='cancel-modal__penalty-none';
  if(isGrace){penaltyText='없음 (확정 후 2시간 이내 + 24시간 전)';}
  else if(isMyQ){
    // 질문자: CP 차감만
    if(hoursLeft>24){penaltyText='없음 (24시간 전)';}
    else if(hoursLeft>1){penaltyText='CP 50% 차감 ('+(s.reward_points?Math.floor(s.reward_points*0.5)+'CP':'')+'）';penaltyCls='cancel-modal__penalty-val';}
    else{penaltyText='CP 100% 차감 ('+(s.reward_points||0)+'CP)';penaltyCls='cancel-modal__penalty-val';}
  }else{
    // 답변자: 경고만
    if(hoursLeft>24){penaltyText='경고 1회';penaltyCls='cancel-modal__penalty-val';}
    else if(hoursLeft>1){penaltyText='경고 1회';penaltyCls='cancel-modal__penalty-val';}
    else{penaltyText='경고 2회';penaltyCls='cancel-modal__penalty-val';}
  }

  let timeLabel='';
  if(hoursLeft>24)timeLabel='수업 '+Math.floor(hoursLeft)+'시간 전';
  else if(hoursLeft>1)timeLabel='수업 '+Math.floor(hoursLeft)+'시간 전 (24시간 이내)';
  else if(hoursLeft>0)timeLabel='수업 '+Math.floor(hoursLeft*60)+'분 전 (1시간 이내!)';
  else timeLabel='수업 시간 경과';

  const overlay=document.createElement('div');
  overlay.className='cancel-overlay';
  overlay.id='cancelOverlay';
  overlay.innerHTML=\`
  <div class="cancel-modal">
    <div class="cancel-modal__header">
      <div class="cancel-modal__icon cancel-modal__icon--warn"><i class="fas fa-exclamation-triangle"></i></div>
      <div>
        <div class="cancel-modal__title">수업 취소</div>
        <div class="cancel-modal__sub">\${timeLabel}</div>
      </div>
    </div>
    <div class="cancel-modal__body">
      <div class="cancel-modal__penalty">
        <div class="cancel-modal__penalty-row"><span>일방 취소 시 패널티</span><span class="\${penaltyCls}">\${penaltyText}</span></div>
        <div class="cancel-modal__penalty-row"><span>상호 합의 취소</span><span class="cancel-modal__penalty-none">패널티 없음</span></div>
      </div>
      <div style="font-size:12px;font-weight:600;color:var(--dim);margin-bottom:8px">취소 사유 선택 <span style="color:var(--red)">*</span></div>
      <div class="cancel-modal__reasons" id="cancelReasons">
        \${CANCEL_REASONS.map(r=>'<label class="cancel-reason" data-reason="'+r.id+'"><input type="radio" name="cancelReason" value="'+r.id+'"><i class="fas '+r.icon+'" style="color:var(--muted);font-size:14px"></i><span class="cancel-reason__label">'+r.label+'</span></label>').join('')}
      </div>
      <textarea class="cancel-detail" id="cancelDetail" placeholder="상세 사유를 입력해주세요 (선택사항)" style="display:none"></textarea>
    </div>
    <div class="cancel-modal__footer">
      <button class="cancel-modal__btn cancel-modal__btn--cancel" onclick="closeCancelModal()">닫기</button>
      <button class="cancel-modal__btn cancel-modal__btn--mutual" id="mutualBtn" onclick="submitCancel(\${matchId},true)" disabled><i class="fas fa-handshake"></i> 상호합의 취소</button>
      <button class="cancel-modal__btn cancel-modal__btn--confirm" id="cancelBtn" onclick="submitCancel(\${matchId},false)" disabled><i class="fas fa-times"></i> 일방 취소</button>
    </div>
  </div>\`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click',(e)=>{if(e.target===overlay)closeCancelModal()});

  // Reason selection handlers
  document.querySelectorAll('#cancelReasons .cancel-reason').forEach(el=>{
    el.addEventListener('click',()=>{
      document.querySelectorAll('#cancelReasons .cancel-reason').forEach(x=>x.classList.remove('selected'));
      el.classList.add('selected');
      el.querySelector('input').checked=true;
      document.getElementById('mutualBtn').disabled=false;
      document.getElementById('cancelBtn').disabled=false;
      // Show detail textarea for 'other'
      document.getElementById('cancelDetail').style.display=el.dataset.reason==='other'?'block':'none';
    });
  });
}

function closeCancelModal(){
  const o=document.getElementById('cancelOverlay');
  if(o)o.remove();
}

async function submitCancel(matchId,isMutual){
  const reasonEl=document.querySelector('#cancelReasons input[name="cancelReason"]:checked');
  if(!reasonEl){showToast('취소 사유를 선택해주세요.','warn');return}
  const reason=reasonEl.value;
  const reasonLabel=CANCEL_REASONS.find(r=>r.id===reason)?.label||reason;
  const detail=document.getElementById('cancelDetail')?.value||'';

  if(!isMutual){
    const s=allSchedules.find(x=>x.id===matchId);
    const d=s?parseSlotTime(s.slot_time):null;
    const hoursLeft=d?(d.getTime()-Date.now())/3600000:-1;
    const amQ=s&&currentUser.id===s.questioner_id;
    let warn='';
    if(amQ){
      // 질문자: 포인트 차감만
      if(hoursLeft>1&&hoursLeft<=24)warn='\\n⚠️ CP 50% 차감 ('+(s.reward_points?Math.floor(s.reward_points*0.5)+'CP':'')+')';
      else if(hoursLeft<=1)warn='\\n🔴 CP 100% 차감 ('+(s.reward_points||0)+'CP)';
    }else{
      // 답변자: 경고만
      if(hoursLeft>24)warn='\\n⚠️ 경고 1회가 부여됩니다.';
      else if(hoursLeft>1)warn='\\n⚠️ 경고 1회가 부여됩니다.';
      else warn='\\n🔴 경고 2회가 부여됩니다.';
    }
    showConfirmModal('사유: '+reasonLabel+warn+'\\n\\n정말 일방적으로 취소하시겠습니까?',async function(){
      doCancel(matchId,reasonLabel,detail,false);
    },{danger:true});
    return;
  }

  doCancel(matchId,reasonLabel,detail,isMutual);
}

async function doCancel(matchId,reasonLabel,detail,isMutual){
  try{
    document.getElementById(isMutual?'mutualBtn':'cancelBtn').disabled=true;
    const res=await fetch('/api/schedule/'+matchId+'/cancel',{
      method:'POST',
      headers:{...authHeaders(),'Content-Type':'application/json'},
      body:JSON.stringify({reason:reasonLabel,reason_detail:detail,mutual:isMutual})
    });
    const data=await res.json();
    if(!res.ok){showToast(data.error,'error');document.getElementById(isMutual?'mutualBtn':'cancelBtn').disabled=false;return}
    closeCancelModal();
    showToast(data.message,'success');
    loadSchedule();
  }catch(e){showToast('취소에 실패했습니다.','error');document.getElementById(isMutual?'mutualBtn':'cancelBtn').disabled=false;}
}

// Load penalty/warning info
async function loadPenaltyInfo(){
  try{
    const res=await fetch('/api/user/penalty-info',{headers:authHeaders()});
    const data=await res.json();
    if(!res.ok)return;
    const el=document.getElementById('penaltyBanner');
    if(!el)return;
    if(data.suspended_until){
      // UTC → KST 변환하여 표시
      var _susp=new Date(data.suspended_until+'Z');
      var _suspKST=new Date(_susp.getTime()+9*3600000);
      var _suspStr=_suspKST.getFullYear()+'.'+((_suspKST.getMonth()+1)+'').padStart(2,'0')+'.'+(_suspKST.getDate()+'').padStart(2,'0')+' '+(_suspKST.getHours()+'').padStart(2,'0')+':'+(_suspKST.getMinutes()+'').padStart(2,'0');
      el.innerHTML='<div class="penalty-info" style="border-color:rgba(255,0,0,.3);background:rgba(255,0,0,.06)"><i class="fas fa-ban" style="color:#ff0000;font-size:16px"></i><div><strong style="color:#ff0000">1:1 튜터링 이용 정지</strong><br>정지 해제: '+_suspStr+'</div></div>';
    }else if(data.total_warnings>0){
      el.innerHTML='<div class="penalty-info"><i class="fas fa-exclamation-triangle"></i><div>누적 경고: <span class="penalty-info__count">'+data.total_warnings+'회</span> · 매칭 이행률: '+data.fulfill_rate+'% · 취소: '+data.cancelled_matches+'회'+(data.total_warnings>=2?' <span style="color:#ff4500;font-size:11px">('+((3-data.total_warnings)>0?(3-data.total_warnings):'0')+'회 더 시 3일 정지)</span>':'')+'</div></div>';
    }else{el.innerHTML=''}
  }catch(e){}
}

// Check mutual cancel requests for all upcoming schedules
async function checkMutualCancelStatus(){
  const upcoming=allSchedules.filter(s=>s.status==='confirmed');
  for(const s of upcoming){
    try{
      const res=await fetch('/api/schedule/'+s.id+'/cancel-status',{headers:authHeaders()});
      const data=await res.json();
      const el=document.getElementById('mutualStatus'+s.id);
      if(!el)continue;
      if(data.has_pending_request&&!data.requested_by_me){
        el.innerHTML='<div class="mutual-pending"><i class="fas fa-handshake"></i> 상대방이 상호합의 취소를 요청했습니다 <button class="sch-btn sch-btn--accept-mutual" style="margin-left:auto;padding:6px 12px;font-size:11px" onclick="acceptMutualCancel('+s.id+')">수락</button></div>';
      }else if(data.has_pending_request&&data.requested_by_me){
        el.innerHTML='<div class="mutual-pending"><i class="fas fa-clock"></i> 상호합의 취소 대기 중... 상대방의 승인을 기다리고 있습니다</div>';
      }else{el.innerHTML=''}
    }catch(e){}
  }
}

async function acceptMutualCancel(matchId){
  showConfirmModal('상호합의로 취소하시겠습니까? (패널티 없음)',async function(){
    try{
      const res=await fetch('/api/schedule/'+matchId+'/cancel',{
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body:JSON.stringify({reason:'상호합의 취소',mutual:true})
      });
      const data=await res.json();
      if(!res.ok){showToast(data.error,'error');return}
      showToast(data.message,'success');
      loadSchedule();
    }catch(e){showToast('처리에 실패했습니다.','error')}
  });
}

async function completeSession(matchId){
  showConfirmModal('수업이 완료되었나요?',async function(){
    try{
      const res=await fetch('/api/schedule/'+matchId+'/complete',{method:'POST',headers:{...authHeaders(),'Content-Type':'application/json'},body:JSON.stringify({})});
      const data=await res.json();
      if(!res.ok){showToast(data.error,'error');return}
      showToast(data.message,'success');
      loadSchedule();
    }catch(e){showToast('처리에 실패했습니다.','error')}
  });
}

// Tab switching
document.querySelectorAll('.sch-tab').forEach(t=>{
  t.addEventListener('click',()=>{
    document.querySelectorAll('.sch-tab').forEach(x=>x.classList.remove('active'));
    t.classList.add('active');
    currentTab=t.dataset.tab;
    renderSchedule();
  });
});

// Auto-refresh every 60 seconds + countdown every 10 seconds
setInterval(()=>{loadSchedule()},60000);
setInterval(()=>{renderSchedule()},10000);
</script>
</body>
</html>`;
}

function cpPageHTML() {
  return `${htmlHead('크로켓포인트')}
.detail-nav{height:56px;display:flex;align-items:center;padding:0 4%;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;background:rgba(20,20,20,.95);backdrop-filter:blur(6px)}
.detail-nav__back{font-size:14px;font-weight:500;color:var(--dim);background:none;border:none;padding:0;display:flex;align-items:center;gap:8px;transition:color .15s;text-decoration:none}
.detail-nav__back:hover{color:var(--white)}
.cp-page{max-width:520px;margin:0 auto;padding:30px 4% 80px}
.cp-hero{text-align:center;padding:24px 0 20px}
.cp-hero__icon{font-size:48px;margin-bottom:8px}
.cp-hero__balance{font-size:32px;font-weight:900;color:#a29bfe;font-family:var(--font-display)}
.cp-hero__label{font-size:12px;color:#8b949e;margin-top:2px}
.cp-hero__level{display:inline-flex;align-items:center;gap:4px;margin-top:10px;font-size:12px;font-weight:600;color:#a29bfe;background:rgba(124,106,239,.1);border:1px solid rgba(124,106,239,.2);border-radius:20px;padding:4px 12px}
.cp-stats{display:flex;gap:1px;margin:0 -4%;background:rgba(255,255,255,.04);border-top:1px solid rgba(255,255,255,.04);border-bottom:1px solid rgba(255,255,255,.04)}
.cp-stats__item{flex:1;text-align:center;padding:14px 0}
.cp-stats__val{font-size:16px;font-weight:800;color:var(--white);font-family:var(--font-display)}
.cp-stats__label{font-size:10px;color:#666;margin-top:2px}
.cp-progress{margin:20px 0;padding:0 2px}
.cp-progress__bar{height:8px;background:rgba(124,106,239,.1);border-radius:4px;overflow:hidden}
.cp-progress__fill{height:100%;background:linear-gradient(90deg,#7c6aef,#a29bfe);border-radius:4px;transition:width 1s ease}
.cp-progress__label{display:flex;justify-content:space-between;font-size:10px;color:#666;margin-top:4px}
.cp-section{margin-top:24px}
.cp-section__title{font-size:13px;font-weight:700;color:var(--white);margin-bottom:10px;display:flex;align-items:center;gap:6px}
.cp-guide{padding:0;margin:0;list-style:none}
.cp-guide__item{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;font-size:12px;color:#8b949e;border-bottom:1px solid rgba(255,255,255,.03)}
.cp-guide__item:last-child{border-bottom:none}
.cp-guide__val{font-weight:800;color:#a29bfe;font-family:var(--font-display)}
.cp-hist__box{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:4px 0;overflow:hidden}
.cp-hist__row{display:flex;align-items:center;gap:10px;padding:10px 14px;font-size:12px}
.cp-hist__dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.cp-hist__desc{flex:1;color:#bbb;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cp-hist__amount{font-weight:800;white-space:nowrap;font-family:var(--font-display);min-width:60px;text-align:right}
.cp-hist__date{font-size:10px;color:#555;white-space:nowrap;min-width:56px;text-align:right}
.cp-pager{display:flex;justify-content:center;align-items:center;gap:6px;margin-top:12px;flex-wrap:wrap}
.cp-pager__btn{font-size:11px;color:#a29bfe;background:rgba(124,106,239,.1);border:1px solid rgba(124,106,239,.2);border-radius:4px;padding:4px 10px;cursor:pointer}
.cp-pager__num{font-size:11px;color:#8b949e;background:none;border:1px solid rgba(255,255,255,.06);border-radius:4px;padding:4px 8px;cursor:pointer}
.cp-pager__cur{font-size:11px;font-weight:800;color:#a29bfe;padding:4px 8px}
.cp-guide-toggle{display:flex;align-items:center;justify-content:space-between;width:100%;background:none;border:none;color:#8b949e;font-size:12px;cursor:pointer;padding:0}
.cp-guide-toggle:hover{color:var(--white)}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
</div>

<div class="cp-page">
  <div class="cp-hero">
    <div class="cp-hero__icon">🍩</div>
    <div class="cp-hero__balance" id="cpBalance">0</div>
    <div class="cp-hero__label">크로켓포인트</div>
    <div class="cp-hero__level" id="cpLevel">🌱 Lv.1 새싹</div>
  </div>

  <div class="cp-stats">
    <div class="cp-stats__item"><div class="cp-stats__val" id="cpEarned">0</div><div class="cp-stats__label">누적 획득</div></div>
    <div class="cp-stats__item"><div class="cp-stats__val" id="cpBal">0</div><div class="cp-stats__label">사용 가능</div></div>
    <div class="cp-stats__item"><div class="cp-stats__val" id="cpStreak">0일</div><div class="cp-stats__label">연속 답변</div></div>
    <div class="cp-stats__item"><div class="cp-stats__val" id="cpToday">0</div><div class="cp-stats__label">오늘 획득</div></div>
  </div>

  <div class="cp-progress">
    <div class="cp-progress__bar"><div class="cp-progress__fill" id="cpBar" style="width:0%"></div></div>
    <div class="cp-progress__label"><span id="cpCurLv">Lv.1</span><span id="cpNextLv">다음 레벨까지 3,000</span></div>
  </div>

  <div class="cp-section">
    <div class="cp-section__title">📋 포인트 내역</div>
    <div id="cpHistArea"><div style="text-align:center;color:#666;font-size:12px;padding:20px 0">로딩 중...</div></div>
  </div>

  <div class="cp-section" style="margin-top:20px">
    <button class="cp-guide-toggle" onclick="var b=document.getElementById('cpGuideBody');b.style.display=b.style.display==='none'?'block':'none';this.querySelector('i').style.transform=b.style.display==='none'?'':'rotate(180deg)'">
      <span style="font-size:13px;font-weight:700;color:var(--white)">💡 적립 안내</span>
      <i class="fas fa-chevron-down" style="font-size:10px;transition:transform .2s"></i>
    </button>
    <ul class="cp-guide" id="cpGuideBody" style="display:none;margin-top:8px">
      <li class="cp-guide__item"><span>✏️ 답변 등록 <span style="color:#555;font-size:10px">(20자 이상 또는 이미지 첨부)</span></span><span class="cp-guide__val">+100</span></li>
      <li class="cp-guide__item"><span>✅ 답변 채택됨</span><span class="cp-guide__val">+1,000</span></li>
      <li class="cp-guide__item"><span>🤝 채택하기 (질문자)</span><span class="cp-guide__val">+100</span></li>
      <li class="cp-guide__item"><span>🎁 첫 답변 보너스 (1일1회)</span><span class="cp-guide__val">+100</span></li>
      <li class="cp-guide__item"><span>📝 정율 선생님 문제 정답</span><span class="cp-guide__val">+100~200</span></li>
    </ul>
    <div style="font-size:10px;color:#555;margin-top:6px;padding-left:4px">※ 자기 질문에 대한 답변은 적립 대상에서 제외됩니다.</div>
  </div>
</div>

<script>
${sharedAuthJS()}
function toP(cp){return (cp||0)*100}

var levels=[{level:1,cp:0,title:'새싹',icon:'🌱'},{level:2,cp:30,title:'학습자',icon:'📖'},{level:3,cp:100,title:'조력자',icon:'🤝'},{level:4,cp:250,title:'멘토',icon:'⭐'},{level:5,cp:500,title:'마스터',icon:'👑'},{level:6,cp:1000,title:'전설',icon:'🏆'}];
function fmtDate(d){if(!d)return '';var s=String(d);var m=s.match(/(\\d{4})-(\\d{2})-(\\d{2})\\s*(\\d{2}):(\\d{2})/);if(!m)return '';return parseInt(m[2])+'/'+parseInt(m[3])+' '+m[4]+':'+m[5]}

(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  try{
    const r=await fetch('/api/cp',{headers:{'Authorization':'Bearer '+getToken()}});
    const d=await r.json();
    if(!r.ok)return;
    const earned=d.earned_cp||0;
    const balance=d.cp_balance||0;
    document.getElementById('cpBalance').textContent=toP(balance).toLocaleString();
    document.getElementById('cpEarned').textContent=toP(earned).toLocaleString();
    document.getElementById('cpBal').textContent=toP(balance).toLocaleString();
    document.getElementById('cpStreak').textContent=(d.answer_streak||0)+'일';
    document.getElementById('cpToday').textContent=toP(d.today_earned).toLocaleString();
    // Level
    var curLv=levels[0],nextLv=levels[1];
    for(var i=levels.length-1;i>=0;i--){if(earned>=levels[i].cp){curLv=levels[i];nextLv=levels[i+1]||null;break}}
    document.getElementById('cpLevel').textContent=curLv.icon+' Lv.'+curLv.level+' '+curLv.title;
    document.getElementById('cpCurLv').textContent='Lv.'+curLv.level+' '+curLv.title;
    if(nextLv){
      var pct=Math.min(100,Math.floor((earned-curLv.cp)/(nextLv.cp-curLv.cp)*100));
      document.getElementById('cpBar').style.width=pct+'%';
      document.getElementById('cpNextLv').textContent=nextLv.title+'까지 '+toP(nextLv.cp-earned).toLocaleString();
    }else{
      document.getElementById('cpBar').style.width='100%';
      document.getElementById('cpNextLv').textContent='최고 레벨!';
    }
  }catch(e){}
  loadCpHist(1);
})();

async function loadCpHist(page){
  var area=document.getElementById('cpHistArea');
  if(!area)return;
  try{
    var r=await fetch('/api/cp/history?limit=10&page='+page,{headers:{'Authorization':'Bearer '+getToken()}});
    var d=await r.json();
    var logs=d.logs||[];
    var total=d.total||0;
    if(logs.length===0&&page===1){
      area.innerHTML='<div style="text-align:center;color:#666;font-size:12px;padding:24px 0">아직 내역이 없습니다.<br>답변을 등록하면 크로켓포인트를 받을 수 있어요!</div>';
      return;
    }
    var html='<div class="cp-hist__box">';
    logs.forEach(function(l){
      var isPlus=l.cp_amount>0;
      var dotColor=isPlus?'#2dd4a8':'#ff6b6b';
      html+='<div class="cp-hist__row">';
      html+='<span class="cp-hist__dot" style="background:'+dotColor+'"></span>';
      html+='<span class="cp-hist__desc">'+(l.description||l.cp_type)+'</span>';
      html+='<span class="cp-hist__amount" style="color:'+dotColor+'">'+(isPlus?'+':'')+toP(l.cp_amount).toLocaleString()+'</span>';
      html+='<span class="cp-hist__date">'+fmtDate(l.created_at)+'</span>';
      html+='</div>';
    });
    html+='</div>';
    // 페이지네이션
    var totalPages=Math.ceil(total/10);
    if(totalPages>1){
      html+='<div class="cp-pager">';
      if(page>1)html+='<button class="cp-pager__btn" onclick="loadCpHist('+(page-1)+')">← 이전</button>';
      for(var p=1;p<=totalPages;p++){
        if(p===page)html+='<span class="cp-pager__cur">'+p+'</span>';
        else if(p<=2||p>=totalPages-1||Math.abs(p-page)<=1)html+='<button class="cp-pager__num" onclick="loadCpHist('+p+')">'+p+'</button>';
        else if((p===3&&page>4)||(p===totalPages-2&&page<totalPages-3))html+='<span style="color:#666;font-size:11px">...</span>';
      }
      if(page<totalPages)html+='<button class="cp-pager__btn" onclick="loadCpHist('+(page+1)+')">다음 →</button>';
      html+='</div>';
    }
    area.innerHTML=html;
  }catch(e){area.innerHTML='<div style="color:#666;font-size:12px;text-align:center">불러오기 실패</div>';}
}
</script>
</body>
</html>`;
}

function rankingPageHTML() {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<title>랭킹</title>
${pwaHead()}
${katexHead()}
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#0B0E14;--bg2:#111827;--bg3:#1F2937;--bg4:#374151;--white:#F9FAFB;--dim:#9CA3AF;--muted:#6B7280;--border:rgba(255,255,255,0.08);--accent:#8B5CF6;--accent-gradient:linear-gradient(135deg,#8B5CF6,#06B6D4);--gold:#FBBF24;--glass-bg:rgba(255,255,255,0.06);--glass-border:rgba(255,255,255,0.1);--glass-blur:blur(20px) saturate(180%);--spring:cubic-bezier(0.34,1.56,0.64,1);--ease-out-expo:cubic-bezier(0.16,1,0.3,1);--font-display:'Outfit','Pretendard',-apple-system,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Outfit','Pretendard',-apple-system,sans-serif;background:var(--bg);color:var(--white);min-height:100vh;touch-action:manipulation;-webkit-tap-highlight-color:transparent;-webkit-font-smoothing:antialiased}
a{text-decoration:none;color:inherit}
button{min-height:44px;min-width:44px}

.rk-nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(11,14,20,.9);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:1px solid var(--glass-border);display:flex;align-items:center;padding:0 var(--sp-4,16px);height:52px;padding-top:env(safe-area-inset-top)}
.rk-nav__back{color:var(--dim);font-size:14px;font-weight:600;z-index:2;padding:8px 4px;transition:color .2s}
.rk-nav__back:hover{color:var(--white)}
.rk-nav__title{position:absolute;left:0;right:0;text-align:center;font-size:16px;font-weight:700;color:var(--white);pointer-events:none;font-family:var(--font-display)}

.rk-wrap{padding:68px 16px 32px;max-width:500px;margin:0 auto}

.rk-header{text-align:center;margin-bottom:28px}
.rk-header__icon{font-size:40px;margin-bottom:10px}
.rk-header__title{font-size:22px;font-weight:800;color:var(--white);font-family:var(--font-display)}
.rk-header__desc{font-size:13px;color:var(--muted);margin-top:6px}

.rk-tabs{display:flex;gap:4px;margin-bottom:24px;background:var(--bg2);border-radius:14px;padding:4px}
.rk-tab{flex:1;text-align:center;padding:12px 10px;font-size:14px;font-weight:600;color:var(--muted);background:none;border:none;border-radius:10px;cursor:pointer;transition:all .2s var(--spring);font-family:var(--font-display)}
.rk-tab.active{background:var(--accent-gradient);color:#fff;box-shadow:0 4px 12px rgba(139,92,246,.3)}
.rk-tab i{margin-right:4px}

/* Top 3 podium */
.rk-podium{display:flex;justify-content:center;align-items:flex-end;gap:10px;margin-bottom:28px;padding:0 8px}
.rk-podium__item{display:flex;flex-direction:column;align-items:center;border-radius:18px;padding:20px 10px 14px;position:relative;transition:all .3s var(--spring);backdrop-filter:blur(12px)}
.rk-podium__item:hover{transform:translateY(-3px)}
.rk-podium__item--1{background:linear-gradient(180deg,rgba(251,191,36,.1),rgba(251,191,36,.03));border:1px solid rgba(251,191,36,.2);flex:1.15;order:2}
.rk-podium__item--1 .rk-podium__count{color:var(--gold);font-family:var(--font-display)}
.rk-podium__item--2{background:linear-gradient(180deg,rgba(192,192,192,.08),rgba(192,192,192,.02));border:1px solid rgba(192,192,192,.15);flex:1;order:1}
.rk-podium__item--3{background:linear-gradient(180deg,rgba(205,127,50,.08),rgba(205,127,50,.02));border:1px solid rgba(205,127,50,.15);flex:1;order:3}
.rk-podium__medal{font-size:32px;margin-bottom:8px}
.rk-podium__name{font-size:14px;font-weight:700;color:var(--white);margin-bottom:2px;max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:center}
.rk-podium__grade{font-size:10px;color:var(--muted);margin-bottom:8px}
.rk-podium__count{font-size:20px;font-weight:800;margin-bottom:2px;font-family:var(--font-display)}
.rk-podium__item--2 .rk-podium__count{color:#c0c0c0}
.rk-podium__item--3 .rk-podium__count{color:#cd7f32}
.rk-podium__label{font-size:10px;color:var(--muted)}

/* List (4th+) */
.rk-list{display:flex;flex-direction:column;gap:8px}
.rk-row{display:flex;align-items:center;gap:14px;padding:14px 16px;background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:14px;transition:all .2s var(--spring);backdrop-filter:blur(12px)}
.rk-row:hover{background:rgba(255,255,255,.08);transform:translateX(4px)}
.rk-row__rank{width:28px;text-align:center;font-size:16px;font-weight:800;color:var(--dim);flex-shrink:0;font-family:var(--font-display)}
.rk-row__avatar{width:38px;height:38px;border-radius:50%;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:var(--dim);flex-shrink:0;border:1px solid var(--glass-border)}
.rk-row__info{flex:1;min-width:0}
.rk-row__name{font-size:14px;font-weight:700;color:var(--white);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rk-row__grade{font-size:11px;color:var(--muted)}
.rk-row__count{font-size:18px;font-weight:800;color:var(--gold);flex-shrink:0;font-family:var(--font-display)}
.rk-row__label{font-size:10px;color:var(--muted);text-align:right}

.rk-empty{text-align:center;padding:56px 16px;color:var(--muted);font-size:14px;font-family:var(--font-display)}
.rk-empty i{font-size:36px;margin-bottom:14px;display:block;opacity:.5}
</style>
</head>
<body>

<nav class="rk-nav">
  <a href="/" class="rk-nav__back"><i class="fas fa-arrow-left"></i> 홈</a>
  <div class="rk-nav__title"><i class="fas fa-trophy" style="color:#ffd700"></i> 랭킹</div>
</nav>

<div class="rk-wrap">
  <div class="rk-header">
    <div class="rk-header__icon">🏆</div>
    <div class="rk-header__title">랭킹</div>
    <div class="rk-header__desc">크로켓포인트를 가장 많이 획득한 유저를 확인하세요</div>
  </div>

  <div class="rk-tabs">
    <button class="rk-tab active" data-type="cp" onclick="switchTab('cp')"><i class="fas fa-cookie-bite"></i>크로켓포인트</button>
    <button class="rk-tab" data-type="accepted" onclick="switchTab('accepted')"><i class="fas fa-star"></i>채택</button>
    <button class="rk-tab" data-type="weekly" onclick="switchTab('weekly')"><i class="fas fa-calendar-week"></i>주간</button>
  </div>

  <div id="podium"></div>
  <div id="rankList"></div>
</div>

<script>
function toP(cp){return (cp||0)*100}
let curType='cp';
let rankCache={};

function switchTab(type){
  curType=type;
  document.querySelectorAll('.rk-tab').forEach(t=>t.classList.toggle('active',t.dataset.type===type));
  loadRanking(type);
}

async function loadRanking(type){
  // Use cache if available
  if(rankCache[type]){renderRanking(rankCache[type]);return}
  try{
    const res=await fetch('/api/ranking?type='+type);
    const data=await res.json();
    rankCache[type]=data.ranking||[];
    renderRanking(rankCache[type]);
  }catch(e){
    document.getElementById('podium').innerHTML='';
    document.getElementById('rankList').innerHTML='<div class="rk-empty"><i class="fas fa-exclamation-circle"></i>랭킹을 불러올 수 없습니다.</div>';
  }
}

function renderRanking(list){
  const podiumEl=document.getElementById('podium');
  const listEl=document.getElementById('rankList');
  const labelMap={cp:'크로켓포인트',accepted:'채택',weekly:'크로켓포인트(주간)'};
  const label=labelMap[curType]||'크로켓포인트';
  const isScore=curType==='cp'||curType==='weekly';

  if(!list.length){
    podiumEl.innerHTML='';
    listEl.innerHTML='<div class="rk-empty"><i class="fas fa-trophy"></i>아직 '+label+' 기록이 없습니다.<br>첫 번째 랭커가 되어보세요!</div>';
    return;
  }

  // Top 3 podium
  const medals=['🥇','🥈','🥉'];
  const top3=list.slice(0,3);
  let podiumHTML='<div class="rk-podium">';
  // Render in order: 2nd, 1st, 3rd for visual layout
  const order=[1,0,2];
  order.forEach(i=>{
    if(top3[i]){
      const r=top3[i];
      const initial=(r.nickname||'?')[0];
      podiumHTML+='<div class="rk-podium__item rk-podium__item--'+(i+1)+'">';
      podiumHTML+='<div class="rk-podium__medal">'+medals[i]+'</div>';
      podiumHTML+='<div class="rk-podium__name">'+esc(r.nickname||'익명')+'</div>';
      podiumHTML+='<div class="rk-podium__grade">'+(r.grade||'')+'</div>';
      podiumHTML+='<div class="rk-podium__count">'+(isScore?toP(r.score).toLocaleString():r.accept_count)+'</div>';
      podiumHTML+='<div class="rk-podium__label">'+label+'</div>';
      podiumHTML+='</div>';
    }
  });
  podiumHTML+='</div>';
  podiumEl.innerHTML=podiumHTML;

  // 4th and below
  const rest=list.slice(3);
  if(!rest.length){listEl.innerHTML='';return}
  let html='<div class="rk-list">';
  rest.forEach((r,idx)=>{
    const rank=idx+4;
    const initial=(r.nickname||'?')[0];
    html+='<div class="rk-row">';
    html+='<div class="rk-row__rank">'+rank+'</div>';
    html+='<div class="rk-row__avatar">'+esc(initial)+'</div>';
    html+='<div class="rk-row__info"><div class="rk-row__name">'+esc(r.nickname||'익명')+'</div><div class="rk-row__grade">'+(r.grade||'')+'</div></div>';
    html+='<div style="text-align:right"><div class="rk-row__count">'+(isScore?toP(r.score).toLocaleString():r.accept_count)+'</div><div class="rk-row__label">'+label+'</div></div>';
    html+='</div>';
  });
  html+='</div>';
  listEl.innerHTML=html;
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

// Initial load
loadRanking('cp');
</script>
</body>
</html>`;
}

function categoryPageHTML(categoryName: string) {
  // Map category names to API parameters
  const catMap: Record<string, {title: string, icon: string, color: string, apiParam: string, paramType: string}> = {
    '고난도': {title: '고난도 질문도전', icon: 'fa-fire', color: '#ff4500', apiParam: '최상', paramType: 'difficulty'},
    '1:1심화설명': {title: '1:1 튜터링 요청', icon: 'fa-chalkboard-teacher', color: '#6c5ce7', apiParam: '1:1심화설명', paramType: 'difficulty'},
    '영어': {title: '영어', icon: 'fa-language', color: '#3498db', apiParam: '영어', paramType: 'subject'},
    '수학': {title: '수학', icon: 'fa-calculator', color: '#e74c3c', apiParam: '수학', paramType: 'subject'},
    '국어': {title: '국어', icon: 'fa-book', color: '#2ecc71', apiParam: '국어', paramType: 'subject'},
    '과학': {title: '과학', icon: 'fa-flask', color: '#f39c12', apiParam: '과학', paramType: 'subject'},
    '기타': {title: '기타', icon: 'fa-ellipsis-h', color: '#95a5a6', apiParam: '기타', paramType: 'subject'},
  }
  const cat = catMap[categoryName] || {title: categoryName, icon: 'fa-folder', color: '#999', apiParam: categoryName, paramType: 'subject'}

  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>${cat.title} - Q&A</title>
${pwaHead()}
${katexHead()}
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
<style>
:root{--bg:#111;--bg2:#1a1a1a;--bg3:#222;--white:#f5f5f5;--dim:#999;--muted:#666;--border:#2a2a2a;--red:#ff4136}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--white);min-height:100vh}
a{text-decoration:none;color:inherit}

.ct-nav{position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(17,17,17,.95);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px;height:48px}
.ct-nav__back{color:var(--dim);font-size:13px;font-weight:600;z-index:2;padding:8px 4px}
.ct-nav__back:hover{color:var(--white)}
.ct-nav__title{position:absolute;left:0;right:0;text-align:center;font-size:15px;font-weight:700;color:var(--white);pointer-events:none}

.ct-wrap{padding:60px 12px 32px;max-width:600px;margin:0 auto}

.ct-header{display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:0 4px}
.ct-header__icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff;flex-shrink:0}
.ct-header__info h1{font-size:18px;font-weight:800;color:var(--white)}
.ct-header__count{font-size:12px;color:var(--muted);margin-top:2px}

.ct-sort{display:flex;gap:6px;margin-bottom:16px;overflow-x:auto;padding:0 4px;scrollbar-width:none}
.ct-sort::-webkit-scrollbar{display:none}
.ct-sort__btn{padding:6px 14px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid var(--border);background:var(--bg2);color:var(--dim);cursor:pointer;white-space:nowrap;transition:all .2s}
.ct-sort__btn.active{background:var(--white);color:var(--bg);border-color:var(--white)}

.ct-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;padding:0 4px}
@media(max-width:380px){.ct-grid{grid-template-columns:1fr}}

.ct-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;transition:transform .15s,border-color .15s;display:flex;flex-direction:column}
.ct-card:hover{border-color:var(--dim);transform:translateY(-2px)}
.ct-card__img{width:100%;aspect-ratio:4/3;object-fit:cover;background:var(--bg3)}
.ct-card__ph{width:100%;aspect-ratio:4/3;background:var(--bg3);display:flex;align-items:center;justify-content:center;padding:12px;font-size:11px;color:var(--muted);line-height:1.5;text-align:center;overflow:hidden}
.ct-card__body{padding:10px}
.ct-card__meta{display:flex;align-items:center;gap:6px;margin-bottom:4px}
.ct-card__author{font-size:11px;font-weight:600;color:var(--dim)}
.ct-card__grade{font-size:9px;color:var(--muted);background:var(--bg3);padding:1px 5px;border-radius:3px}
.ct-card__time{font-size:10px;color:var(--muted);margin-left:auto}
.ct-card__text{font-size:12px;color:var(--white);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:6px}
.ct-card__footer{display:flex;align-items:center;gap:8px;font-size:10px;color:var(--muted)}
.ct-card__badge{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;color:#fff}
.ct-card__badge--done{background:linear-gradient(135deg,#ffd700,#ffaa00);color:#111}
.ct-card__badge--killer{background:linear-gradient(135deg,#ff4500,#ff6b35)}
.ct-card__badge--tutor{background:linear-gradient(135deg,#6c5ce7,#a29bfe)}
.ct-card__pts{color:#ffd700;font-weight:700}

.ct-loading{text-align:center;padding:24px;color:var(--muted);font-size:12px}
.ct-empty{text-align:center;padding:48px 16px;color:var(--muted);font-size:13px}
.ct-end{text-align:center;padding:16px;color:var(--muted);font-size:11px}
</style>
</head>
<body>

<nav class="ct-nav">
  <a href="/" class="ct-nav__back"><i class="fas fa-arrow-left"></i> 홈</a>
  <div class="ct-nav__title"><i class="fas ${cat.icon}" style="color:${cat.color}"></i> ${cat.title}</div>
</nav>

<div class="ct-wrap">
  <div class="ct-header">
    <div class="ct-header__icon" style="background:${cat.color}"><i class="fas ${cat.icon}"></i></div>
    <div class="ct-header__info">
      <h1>${cat.title}</h1>
      <div class="ct-header__count" id="totalCount">불러오는 중...</div>
    </div>
  </div>

  <div class="ct-sort">
    <button class="ct-sort__btn active" data-sort="latest" onclick="changeSort('latest')">최신순</button>
    <button class="ct-sort__btn" data-sort="unanswered" onclick="changeSort('unanswered')">미답변 우선</button>
    <button class="ct-sort__btn" data-sort="answers_asc" onclick="changeSort('answers_asc')">답변 적은 순</button>
    <button class="ct-sort__btn" data-sort="points" onclick="changeSort('points')">포인트 높은 순</button>
  </div>

  <div class="ct-grid" id="grid"></div>
  <div id="loadMore"></div>
</div>

<script>
const CAT_PARAM_TYPE='${cat.paramType}';
const CAT_PARAM='${cat.apiParam}';
let curSort='latest',curPage=0,loading=false,noMore=false;
const PAGE_SIZE=20;
let imageCache={};

function changeSort(s){
  if(s===curSort)return;
  curSort=s;curPage=0;noMore=false;
  document.querySelectorAll('.ct-sort__btn').forEach(b=>b.classList.toggle('active',b.dataset.sort===s));
  document.getElementById('grid').innerHTML='';
  document.getElementById('loadMore').innerHTML='<div class="ct-loading"><i class="fas fa-spinner fa-spin"></i> 로딩 중...</div>';
  loadPage();
}

async function loadPage(){
  if(loading||noMore)return;
  loading=true;
  try{
    const paramKey=CAT_PARAM_TYPE==='difficulty'?'difficulty':'subject';
    const url='/api/questions?'+paramKey+'='+encodeURIComponent(CAT_PARAM)+'&sort='+curSort+'&page='+curPage+'&limit='+PAGE_SIZE;
    const res=await fetch(url);
    const data=await res.json();
    if(!Array.isArray(data)||data.length===0){
      noMore=true;
      if(curPage===0){
        document.getElementById('grid').innerHTML='<div class="ct-empty" style="grid-column:1/-1"><i class="fas fa-inbox" style="font-size:32px;margin-bottom:12px;display:block;opacity:.5"></i>아직 등록된 질문이 없습니다.</div>';
      }
      document.getElementById('loadMore').innerHTML=curPage>0?'<div class="ct-end">모든 질문을 불러왔습니다</div>':'';
      loading=false;return;
    }
    if(curPage===0){
      document.getElementById('totalCount').textContent=data.length>=PAGE_SIZE?PAGE_SIZE+'개 이상의 질문':'질문 '+data.length+'개';
    }
    const grid=document.getElementById('grid');
    data.forEach(q=>{
      const card=document.createElement('a');
      card.href='/question/'+q.id;
      card.className='ct-card';
      const imgPart=q.has_image
        ?(q.thumbnail_key?'<img class="ct-card__img" src="/api/images/'+q.thumbnail_key+'" alt="">'
          :q.thumbnail_data?'<img class="ct-card__img" src="'+q.thumbnail_data+'" alt="">'
          :'<img class="ct-card__img" data-qid="'+q.id+'" alt="">')
        :'<div class="ct-card__ph">'+(q.content||'').slice(0,80)+'</div>';
      let badgeHTML='';
      if(q.status==='채택 완료')badgeHTML='<span class="ct-card__badge ct-card__badge--done"><i class="fas fa-star"></i> 채택</span>';
      else if(q.difficulty==='최상')badgeHTML='<span class="ct-card__badge ct-card__badge--killer"><i class="fas fa-fire"></i> 고난도</span>';
      else if(q.difficulty==='1:1심화설명')badgeHTML='<span class="ct-card__badge ct-card__badge--tutor"><i class="fas fa-chalkboard-teacher"></i> 1:1튜터링</span>';
      const pts=q.reward_points?'<span class="ct-card__pts">'+q.reward_points+'P</span>':'';
      card.innerHTML=imgPart+
        '<div class="ct-card__body">'+
          '<div class="ct-card__meta"><span class="ct-card__author">'+esc(q.author_name||'익명')+'</span>'+(q.author_grade?'<span class="ct-card__grade">'+q.author_grade+'</span>':'')+'<span class="ct-card__time">'+timeAgo(q.created_at)+'</span></div>'+
          '<div class="ct-card__text">'+esc((q.content||'').slice(0,100))+'</div>'+
          '<div class="ct-card__footer">'+badgeHTML+'<span><i class="fas fa-comment"></i> '+(q.comment_count||0)+'</span><span><i class="fas fa-tag"></i> '+q.subject+'</span>'+pts+'</div>'+
        '</div>';
      grid.appendChild(card);
    });
    // Lazy-load images
    document.querySelectorAll('.ct-card__img[data-qid]').forEach(img=>{
      const qid=img.getAttribute('data-qid');
      if(!qid||img.src)return;
      if(imageCache[qid]){img.src=imageCache[qid];return}
      fetch('/api/questions/'+qid+'/image').then(r=>r.json()).then(d=>{
        if(d.data){imageCache[qid]=d.data;img.src=d.data}
      }).catch(()=>{});
    });
    if(data.length<PAGE_SIZE){noMore=true;document.getElementById('loadMore').innerHTML='<div class="ct-end">모든 질문을 불러왔습니다</div>'}
    else{document.getElementById('loadMore').innerHTML='';curPage++}
  }catch(e){
    document.getElementById('loadMore').innerHTML='<div style="text-align:center;padding:32px;color:var(--dim)"><i class="fas fa-exclamation-circle" style="font-size:20px;display:block;margin-bottom:8px"></i>불러오기 실패<br><button onclick="loading=false;loadPage()" style="margin-top:10px;padding:6px 16px;background:var(--bg2);color:var(--white);border:1px solid var(--border);border-radius:6px;cursor:pointer"><i class="fas fa-redo" style="margin-right:4px"></i>다시 시도</button></div>';
  }
  loading=false;
}

function timeAgo(d){
  if(!d)return'';
  const diff=Date.now()-new Date(d+'Z').getTime();
  const m=Math.floor(diff/60000);
  if(m<1)return'방금 전';if(m<60)return m+'분 전';
  const h=Math.floor(m/60);if(h<24)return h+'시간 전';
  return Math.floor(h/24)+'일 전';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

// Infinite scroll
let scrollTimer=null;
window.addEventListener('scroll',()=>{
  if(scrollTimer)return;
  scrollTimer=setTimeout(()=>{
    scrollTimer=null;
    if((window.innerHeight+window.scrollY)>=document.body.offsetHeight-400){loadPage()}
  },150);
});

// Initial load
loadPage();
</script>
</body>
</html>`;
}

function mypageHTML() {
  return `${htmlHead('마이페이지')}

.detail-nav{height:56px;display:flex;align-items:center;padding:0 4%;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;background:rgba(20,20,20,.95);backdrop-filter:blur(6px)}
.detail-nav__back{font-size:14px;font-weight:500;color:var(--dim);background:none;border:none;padding:0;display:flex;align-items:center;gap:8px;transition:color .15s}
.detail-nav__back:hover{color:var(--white)}

.mypage{max-width:480px;margin:0 auto;padding:40px 4% 80px}
.mypage__avatar{width:72px;height:72px;border-radius:50%;background:#2a2a3a;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:28px;margin:0 auto 20px}
.mypage__name{text-align:center;font-size:20px;font-weight:700;color:var(--white);margin-bottom:4px}
.mypage__sub{text-align:center;font-size:13px;color:var(--muted);margin-bottom:32px}

.mp-section{margin-bottom:20px}
.mp-label{font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px;display:block}
.mp-input{width:100%;padding:11px 14px;font-size:14px;border:1px solid var(--border);border-radius:4px;background:#1a1a1a;color:var(--white);outline:none;transition:border-color .15s}
.mp-input:focus{border-color:var(--muted)}
select.mp-input{appearance:auto}

.mp-btn{width:100%;padding:12px;font-size:14px;font-weight:700;border:none;border-radius:4px;transition:opacity .15s;margin-bottom:10px}
.mp-btn:hover{opacity:.85}
.mp-btn--save{background:var(--red);color:var(--white)}
.mp-btn--logout{background:none;border:1px solid var(--border);color:var(--muted)}
.mp-msg{text-align:center;font-size:12px;color:var(--green);min-height:18px;margin-top:8px}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
</div>

<div class="mypage">
  <div class="mypage__avatar"><i class="fas fa-user"></i></div>
  <div class="mypage__name" id="mpName">-</div>
  <div class="mypage__sub" id="mpSub">-</div>
  <a href="/cp" id="mpCpPanel" style="display:none;text-decoration:none;margin-bottom:20px;padding:14px 16px;background:linear-gradient(135deg,rgba(124,106,239,.08),rgba(124,106,239,.04));border:1px solid rgba(124,106,239,.25);border-radius:14px;flex-direction:row;align-items:center;gap:12px">
    <span style="font-size:24px">🍩</span>
    <span style="flex:1">
      <span style="font-size:16px;font-weight:900;color:#a29bfe" id="mpCpBalance">0</span>
      <span style="font-size:11px;color:#8b949e"> 크로켓포인트</span>
      <span style="display:block;font-size:11px;color:#666;margin-top:2px" id="mpCpLevel"></span>
    </span>
    <span style="font-size:11px;color:#a29bfe;font-weight:600">상세보기 →</span>
  </a>
  <div id="mpMatchStats" style="text-align:center;margin-bottom:24px"></div>

  <div class="mp-section">
    <label class="mp-label">닉네임</label>
    <input class="mp-input" id="mpNick" type="text" maxlength="12" placeholder="닉네임 입력">
  </div>
  <div class="mp-section">
    <label class="mp-label">학년</label>
    <select class="mp-input" id="mpGrade">
      <option value="">선택 안함</option>
      <option value="중1">중1</option><option value="중2">중2</option><option value="중3">중3</option>
      <option value="고1">고1</option><option value="고2">고2</option><option value="고3">고3</option>
    </select>
  </div>

  <button class="mp-btn mp-btn--save" onclick="saveProfile()">저장</button>
  <div class="mp-msg" id="mpMsg"></div>
</div>

<script>
${sharedAuthJS()}
function toP(cp){return (cp||0)*100}
function fmtP(cp){return toP(cp).toLocaleString()+' 크로켓포인트'}

(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  document.getElementById('mpName').textContent=u.nickname;
  document.getElementById('mpSub').textContent=u.grade||'학년 미설정';
  document.getElementById('mpNick').value=u.nickname;
  document.getElementById('mpGrade').value=u.grade||'';
  // Load CP summary
  try{
    const cr=await fetch('/api/cp',{headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'}});
    const cd=await cr.json();
    if(cr.ok){
      const panel=document.getElementById('mpCpPanel');
      panel.style.display='flex';
      document.getElementById('mpCpBalance').textContent=toP(cd.cp_balance).toLocaleString();
      const levels=[{level:1,cp:0,title:'새싹',icon:'🌱'},{level:2,cp:30,title:'학습자',icon:'📖'},{level:3,cp:100,title:'조력자',icon:'🤝'},{level:4,cp:250,title:'멘토',icon:'⭐'},{level:5,cp:500,title:'마스터',icon:'👑'},{level:6,cp:1000,title:'전설',icon:'🏆'}];
      let curLv=levels[0];
      for(let i=levels.length-1;i>=0;i--){if((cd.earned_cp||0)>=levels[i].cp){curLv=levels[i];break}}
      document.getElementById('mpCpLevel').textContent=curLv.icon+' Lv.'+curLv.level+' '+curLv.title;
    }
  }catch(e){}
  // Load match stats
  try{
    const pr=await fetch('/api/user/penalty-info',{headers:authHeaders()});
    const pd=await pr.json();
    if(pr.ok){
      const el=document.getElementById('mpMatchStats');
      const hasMatches=(pd.completed_matches||0)+(pd.cancelled_matches||0)>0;
      const rate=hasMatches?(pd.fulfill_rate||100):null;
      const rateText=rate!==null?rate+'%':'-';
      const barColor=rate===null?'var(--muted)':rate>=90?'#00c853':rate>=70?'#ffa500':'#ff4136';
      var _pdSusp='';if(pd.suspended_until){var _s2=new Date(pd.suspended_until+'Z');var _s2k=new Date(_s2.getTime()+9*3600000);_pdSusp=_s2k.getFullYear()+'.'+((_s2k.getMonth()+1)+'').padStart(2,'0')+'.'+(_s2k.getDate()+'').padStart(2,'0')+' '+(_s2k.getHours()+'').padStart(2,'0')+':'+(_s2k.getMinutes()+'').padStart(2,'0');}
      el.innerHTML='<div style="display:flex;gap:16px;justify-content:center;align-items:center;font-size:12px;color:var(--muted);flex-wrap:wrap"><div>매칭 이행률 <strong style="color:'+barColor+';font-size:16px">'+rateText+'</strong></div><div>완료 <strong style="color:var(--white)">'+(pd.completed_matches||0)+'</strong>회</div><div>취소 <strong style="color:'+(pd.cancelled_matches>0?'#ff4136':'var(--white)')+'">'+(pd.cancelled_matches||0)+'</strong>회</div><div>경고 <strong style="color:'+(pd.total_warnings>0?'#ff4136':'var(--white)')+'">'+(pd.total_warnings||0)+'</strong>회</div></div>'+(_pdSusp?'<div style="margin-top:8px;font-size:11px;color:#ff0000;font-weight:600"><i class="fas fa-ban"></i> 이용 정지 중 ('+_pdSusp+'까지)</div>':'');
    }
  }catch(e){}
})();

async function saveProfile(){
  const nickname=document.getElementById('mpNick').value.trim();
  const grade=document.getElementById('mpGrade').value;
  if(!nickname||nickname.length<1){showToast('닉네임을 입력해주세요.','warn');return}
  if(nickname.length>12){showToast('닉네임은 12자 이내로 입력해주세요.','warn');return}
  try{
    const r=await fetch('/api/auth/profile',{method:'PATCH',headers:authHeaders(),body:JSON.stringify({nickname,grade})});
    if(r.ok){
      const u=getUser();if(u){u.nickname=nickname;u.grade=grade;setUser(u)}
      document.getElementById('mpName').textContent=nickname;
      document.getElementById('mpSub').textContent=grade||'학년 미설정';
      document.getElementById('mpMsg').textContent='저장되었습니다!';
      setTimeout(()=>document.getElementById('mpMsg').textContent='',2000);
    }else{
      const d=await r.json().catch(()=>({}));
      showToast(d.error||'저장에 실패했습니다.','error');
    }
  }catch(e){showToast('오류가 발생했습니다.','error')}
}

async function doLogout(){
  try{await fetch('/api/auth/logout',{method:'POST',headers:authHeaders()})}catch(e){}
  clearToken();location.href='/';
}
</script>
</body>
</html>`
}

// ===== My Learning Pages (Dashboard / Bookmarks / History) =====
// Phase 3: 실데이터 연결 — /api/platform/* BFF 호출

function myPageShellCSS() {
  return `
.detail-nav{height:56px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;background:rgba(13,17,23,.95);backdrop-filter:blur(12px)}
.detail-nav__back{font-size:14px;font-weight:500;color:var(--dim);background:none;border:none;padding:0;display:flex;align-items:center;gap:8px}
.detail-nav__back:hover{color:var(--text)}
.detail-nav__title{font-size:15px;font-weight:700;color:var(--text);font-family:var(--font-display)}
.my-wrap{max-width:1200px;margin:0 auto;padding:20px 16px 80px}
.my-subj-tabs{display:flex;gap:8px;overflow-x:auto;margin-bottom:20px;padding-bottom:8px;scrollbar-width:none}
.my-subj-tabs::-webkit-scrollbar{display:none}
.my-subj-chip{flex-shrink:0;padding:8px 16px;font-size:13px;font-weight:600;color:var(--dim);background:var(--bg2);border:1px solid var(--border);border-radius:20px;cursor:pointer;transition:all .15s;white-space:nowrap;min-height:36px}
.my-subj-chip:hover{color:var(--text);border-color:rgba(255,255,255,.15)}
.my-subj-chip.active{background:var(--accent-primary);border-color:var(--accent-primary);color:#fff}
.my-empty{text-align:center;padding:60px 20px;color:var(--dim)}
.my-empty__icon{font-size:48px;margin-bottom:16px;opacity:.5}
.my-empty__title{font-size:16px;font-weight:700;color:var(--text);margin-bottom:8px}
.my-empty__desc{font-size:13px;color:var(--dim);line-height:1.6;margin-bottom:20px}
.my-empty__cta{display:inline-block;padding:10px 20px;background:var(--accent-gradient);color:#fff;border-radius:10px;font-size:13px;font-weight:600;text-decoration:none}
.my-section-title{font-size:14px;font-weight:700;color:var(--dim);margin:24px 0 12px;text-transform:uppercase;letter-spacing:.5px;font-family:var(--font-display)}
.my-skel{background:var(--bg2);border-radius:12px;padding:40px 20px;text-align:center;color:var(--dim);font-size:13px;border:1px dashed var(--border)}
.my-skel i{font-size:24px;margin-bottom:12px;display:block;opacity:.5}
.my-err{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);border-radius:12px;padding:16px;color:#fca5a5;font-size:13px;margin-bottom:16px}
.my-err button{margin-left:10px;padding:4px 12px;background:rgba(239,68,68,.2);color:#fca5a5;border:none;border-radius:6px;font-size:12px;cursor:pointer;min-height:28px;min-width:auto}
`
}

// 공용 JS 헬퍼: 포맷, 색상, 렌더
function myPageHelpersJS() {
  return `
function fmtMs(ms){
  if(!ms||ms<0)return '0m';
  var s=Math.floor(ms/1000);
  var h=Math.floor(s/3600);
  var m=Math.floor((s%3600)/60);
  if(h>0)return h+'h '+m+'m';
  if(m>0)return m+'m';
  return s+'s';
}
function fmtPct(r){if(r==null)return '—';return Math.round(r*100)+'%'}
function rateColor(r){if(r==null)return 'var(--dim)';if(r>=0.8)return '#2dd4a8';if(r>=0.5)return '#fbbf24';return '#ff6b6b'}
function subjHex(s){var m={'국어':'#ef6351','수학':'#7c6aef','영어':'#00d2d3','과학':'#2dd4a8','기타':'#8b949e'};return m[s]||'#8b949e'}
function fmtDate(d){if(!d)return '';var s=String(d).replace('T',' ');var m=s.match(/(\\d{4})-(\\d{2})-(\\d{2})/);if(!m)return s;var now=new Date();var then=new Date(d+(d.includes('Z')?'':'Z'));var ms=now-then;var days=Math.floor(ms/86400000);if(days===0)return '오늘';if(days===1)return '어제';if(days<7)return days+'일 전';return parseInt(m[2])+'월 '+parseInt(m[3])+'일'}
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function apiHeaders(){var t=localStorage.getItem('qa_token');return t?{'Authorization':'Bearer '+t,'Content-Type':'application/json'}:{'Content-Type':'application/json'}}
async function apiGet(url){
  var r=await fetch(url,{headers:apiHeaders()});
  if(!r.ok){var e=new Error('HTTP '+r.status);e.status=r.status;try{e.body=await r.json()}catch(x){}throw e}
  return await r.json()
}
async function apiPost(url,body){
  var r=await fetch(url,{method:'POST',headers:apiHeaders(),body:JSON.stringify(body||{})});
  if(!r.ok){var e=new Error('HTTP '+r.status);e.status=r.status;try{e.body=await r.json()}catch(x){}throw e}
  return await r.json()
}
function renderErr(boxId,err,retryFn){
  var el=document.getElementById(boxId);
  if(!el)return;
  var msg=(err&&err.body&&err.body.error)||err.message||'요청 실패';
  el.innerHTML='<div class="my-err"><i class="fas fa-exclamation-triangle"></i> '+esc(msg)+'<button onclick="('+retryFn.name+')()">다시 시도</button></div>'
}
function emptyState(icon,title,desc,ctaHref,ctaText){
  return '<div class="my-empty"><div class="my-empty__icon">'+icon+'</div><div class="my-empty__title">'+esc(title)+'</div><div class="my-empty__desc">'+esc(desc)+'</div>'+(ctaHref?'<a class="my-empty__cta" href="'+ctaHref+'">'+esc(ctaText||'바로가기')+'</a>':'')+'</div>'
}
`
}

function mySubjTabsHTML() {
  return `<div class="my-subj-tabs" id="mySubjTabs">
    <button class="my-subj-chip active" data-subj="전체">전체</button>
    <button class="my-subj-chip" data-subj="국어">국어</button>
    <button class="my-subj-chip" data-subj="수학">수학</button>
    <button class="my-subj-chip" data-subj="영어">영어</button>
    <button class="my-subj-chip" data-subj="과학">과학</button>
    <button class="my-subj-chip" data-subj="기타">기타</button>
  </div>`
}

function mySubjTabsJS() {
  return `
document.querySelectorAll('#mySubjTabs .my-subj-chip').forEach(function(btn){
  btn.addEventListener('click',function(){
    document.querySelectorAll('#mySubjTabs .my-subj-chip').forEach(function(b){b.classList.remove('active')});
    btn.classList.add('active');
    var subj=btn.getAttribute('data-subj');
    if(typeof onSubjChange==='function')onSubjChange(subj);
  });
});
`
}

// === 연습 문제 풀이 결과 모달 (bookmarks, history detail 공유) ===
// openItemFromDetail(detail, si, ii) 로 호출. 페이지별 카드 동기화는 window.onPracticeBookmarkToggle 훅 사용.
function practiceModalCSS() {
  return `.pract-modal{display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.75);backdrop-filter:blur(4px)}
.pract-modal.show{display:flex;flex-direction:column}
.pract-modal__shell{display:flex;flex-direction:column;width:100%;height:100%;max-width:1400px;margin:0 auto;background:var(--bg);position:relative}
.pract-modal__header{flex-shrink:0;display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);background:var(--bg2)}
.pract-modal__title{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:700;color:var(--text);font-family:var(--font-display)}
.pract-modal__title i{color:#7c6aef}
.pract-modal__close{width:40px;height:40px;background:transparent;border:none;border-radius:8px;color:var(--dim);font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s}
.pract-modal__close:hover{background:var(--bg3);color:var(--text)}
.pract-modal__body{flex:1;display:grid;grid-template-columns:1fr 1fr;gap:0;min-height:0;overflow:hidden}
.pract-pane{padding:24px;overflow-y:auto;min-height:0}
.pract-pane--left{border-right:1px solid var(--border)}
.pract-pane::-webkit-scrollbar{width:8px}
.pract-pane::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:4px}
.pract-tags{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
.pract-tag{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:14px;font-size:11px;font-weight:700;font-family:var(--font-display)}
.pract-tag--diff{background:rgba(124,106,239,.15);color:#a78bfa;border:1px solid rgba(124,106,239,.3)}
.pract-tag--correct{background:rgba(45,212,168,.15);color:#2dd4a8;border:1px solid rgba(45,212,168,.3)}
.pract-tag--wrong{background:rgba(255,107,107,.15);color:#ff6b6b;border:1px solid rgba(255,107,107,.3)}
.pract-tag--meta{background:var(--bg3);color:var(--dim);border:1px solid var(--border)}
.pract-q-card{background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.18);border-radius:12px;padding:18px;margin-bottom:14px}
.pract-q-card:last-child{margin-bottom:0}
.pract-q-card--passage{background:rgba(167,139,250,.04);border-color:rgba(167,139,250,.2)}
.pract-q-card--passage .pract-q-card__label{background:rgba(167,139,250,.15);color:#a78bfa}
.pract-q-card__label{display:inline-block;padding:2px 10px;background:rgba(59,130,246,.15);color:#60a5fa;border-radius:8px;font-size:11px;font-weight:700;margin-bottom:12px}
.pract-q-card__body{font-size:15px;color:var(--text);line-height:1.8;white-space:pre-wrap;word-break:keep-all}
.pract-choices{display:flex;flex-direction:column;gap:10px;margin-bottom:24px}
.pract-choice{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--bg2);border:2px solid var(--border);border-radius:10px;font-size:16px;color:var(--text);line-height:1.6;transition:all .15s}
.pract-choice__icon{flex-shrink:0;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;background:var(--bg3);color:var(--dim)}
.pract-choice__text{flex:1;min-width:0}
.pract-choice--mine{border-color:rgba(255,107,107,.5);background:rgba(255,107,107,.05)}
.pract-choice--mine .pract-choice__icon{background:#ff6b6b;color:#fff}
.pract-choice--correct{border-color:rgba(45,212,168,.6);background:rgba(45,212,168,.08)}
.pract-choice--correct .pract-choice__icon{background:#2dd4a8;color:#fff}
.pract-choice--mine.pract-choice--correct{border-color:rgba(45,212,168,.6);background:rgba(45,212,168,.08)}
.pract-choice--mine.pract-choice--correct .pract-choice__icon{background:#2dd4a8;color:#fff}
.pract-expl{padding:18px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;font-size:14px;color:var(--text);line-height:1.8;white-space:pre-wrap;word-break:keep-all}
.pract-expl__label{display:block;font-weight:700;color:#60a5fa;font-size:13px;margin-bottom:10px;font-family:var(--font-display)}
.pract-expl__answer{display:inline-block;padding:3px 12px;background:rgba(45,212,168,.12);color:#2dd4a8;border-radius:8px;font-weight:700;margin-bottom:12px;font-size:13px}
.pract-modal__footer{flex-shrink:0;display:flex;gap:10px;padding:14px 24px;border-top:1px solid var(--border);background:var(--bg2);justify-content:space-between;align-items:center}
.pract-modal__btn{padding:10px 18px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:var(--bg3);color:var(--text);min-height:42px;display:inline-flex;align-items:center;gap:6px}
.pract-modal__btn:hover{background:var(--bg4)}
.pract-modal__btn--bm{background:rgba(251,191,36,.12);border-color:rgba(251,191,36,.3);color:#fbbf24}
.pract-modal__btn--bm.on{background:#fbbf24;border-color:#fbbf24;color:#1a1a1a}
.pract-section-title{font-size:12px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;font-family:var(--font-display)}
@media(max-width:768px){
  .pract-modal__body{grid-template-columns:1fr;grid-template-rows:auto auto;overflow-y:auto}
  .pract-pane{overflow-y:visible}
  .pract-pane--left{border-right:none;border-bottom:1px solid var(--border)}
  .pract-modal__header{padding:12px 16px}
  .pract-pane{padding:16px}
  .pract-modal__footer{padding:12px 16px}
  .pract-modal__btn{padding:8px 14px;font-size:13px}
}`
}

function practiceModalHTML() {
  return `<div class="pract-modal" id="practModal">
  <div class="pract-modal__shell" id="practModalBox"></div>
</div>`
}

function practiceModalJS() {
  return `
var PRACT_LEVEL_LABELS={'B-1':'2등급 보장','B-2':'높은 2등급 보장','C-1':'1등급 근접','C-2':'1등급 도전'};
var CURRENT_PRACT_DETAIL=null;
function practRenderMathIn(el){
  if(!el||typeof renderMathInElement!=='function')return;
  try{
    renderMathInElement(el,{
      delimiters:[
        {left:'$$',right:'$$',display:true},
        {left:'$',right:'$',display:false},
        {left:'\\\\(',right:'\\\\)',display:false},
        {left:'\\\\[',right:'\\\\]',display:true}
      ],
      throwOnError:false
    });
  }catch(e){console.warn('math render failed',e)}
}
// preview 텍스트를 지정 길이로 자르되, LaTeX $...$ 쌍이 열린 채 끊기지 않게 함.
// (KaTeX auto-render가 열린 $를 처리 못해 카드에 raw $ 보이는 문제 방지)
function practSmartTruncate(raw,limit){
  raw=String(raw||'').trim();
  if(raw.length<=limit)return raw;
  var slice=raw.slice(0,limit);
  // 현재 잘린 부분의 $ 카운트가 홀수면 $ 페어가 열려있는 상태 → 마지막 $ 앞에서 자름
  var count=(slice.match(/\\$/g)||[]).length;
  if(count%2!==0){
    var lastDollar=slice.lastIndexOf('$');
    if(lastDollar>=0)slice=slice.slice(0,lastDollar);
  }
  return slice.replace(/\\s+$/,'')+'…';
}
function closePractModal(){document.getElementById('practModal').classList.remove('show');document.body.style.overflow='';CURRENT_PRACT_DETAIL=null}
function findSiIiByItemId(detail,itemId){
  if(!detail)return null;
  var found=null;
  (detail.practice_sessions||[]).forEach(function(ps,si){
    (ps.items||[]).forEach(function(it,ii){
      if(String(it.item_id)===String(itemId))found={si:si,ii:ii};
    });
  });
  return found;
}
function openItemFromDetail(detail,si,ii){
  CURRENT_PRACT_DETAIL=detail;
  var ps=(detail.practice_sessions||[])[si];if(!ps)return;
  var it=(ps.items||[])[ii];if(!it)return;
  var box=document.getElementById('practModalBox');
  function choiceText(ch){if(ch==null)return '';if(typeof ch==='string')return ch;return esc(ch.text||'')}
  function choiceLabel(ch,idx){if(ch&&typeof ch==='object'&&ch.label)return ch.label;return String(idx+1)}
  function isMatch(label,ans){if(ans==null)return false;return String(label).trim()===String(ans).trim()||String(ans).trim()===String(parseInt(label)||'')}
  var header='<div class="pract-modal__header">'+
    '<div class="pract-modal__title"><i class="fas fa-clipboard-check"></i> 문제 풀이 결과</div>'+
    '<button class="pract-modal__close" onclick="closePractModal()" aria-label="닫기"><i class="fas fa-times"></i></button>'+
    '</div>';
  var tags='<div class="pract-tags">';
  var _lvlLabel=PRACT_LEVEL_LABELS[it.difficulty];
  if(_lvlLabel)tags+='<span class="pract-tag pract-tag--diff">'+esc(_lvlLabel)+'</span>';
  var _tagClass=it.is_correct===true?'pract-tag--correct':it.is_correct===false?'pract-tag--wrong':'pract-tag--meta';
  var _tagText=it.is_correct===true?'✓ 정답':it.is_correct===false?'✗ 오답':'미풀이';
  tags+='<span class="pract-tag '+_tagClass+'">'+_tagText+'</span>';
  tags+='<span class="pract-tag pract-tag--meta">문제 '+((it.index!=null?it.index:ii)+1)+'</span>';
  tags+='</div>';
  var hasPassage=it.passage_text&&String(it.passage_text).trim();
  var leftHTML='<div class="pract-pane pract-pane--left">'+tags;
  if(hasPassage){
    leftHTML+='<div class="pract-q-card pract-q-card--passage"><span class="pract-q-card__label">지문</span>'+
      '<div class="pract-q-card__body">'+esc(it.passage_text)+'</div></div>';
  }else{
    leftHTML+='<div class="pract-q-card"><span class="pract-q-card__label">문제</span>'+
      '<div class="pract-q-card__body">'+esc(it.question_text||'문제 내용이 없어요')+'</div></div>';
  }
  leftHTML+='</div>';
  var rightHTML='<div class="pract-pane pract-pane--right">';
  if(hasPassage){
    rightHTML+='<div class="pract-q-card" style="margin-bottom:16px"><span class="pract-q-card__label">문제</span>'+
      '<div class="pract-q-card__body">'+esc(it.question_text||'문제 내용이 없어요')+'</div></div>';
  }
  if(Array.isArray(it.choices)&&it.choices.length){
    rightHTML+='<div class="pract-section-title">선택지</div><div class="pract-choices">';
    it.choices.forEach(function(ch,idx){
      var lbl=choiceLabel(ch,idx);
      var txt=choiceText(ch);
      var isMine=isMatch(lbl,it.my_answer);
      var isCorrect=isMatch(lbl,it.correct_answer);
      var klass='pract-choice';
      var iconHTML='<span class="pract-choice__icon">'+esc(lbl)+'</span>';
      if(isCorrect){klass+=' pract-choice--correct';iconHTML='<span class="pract-choice__icon"><i class="fas fa-check"></i></span>'}
      else if(isMine){klass+=' pract-choice--mine';iconHTML='<span class="pract-choice__icon"><i class="fas fa-times"></i></span>'}
      if(isMine&&isCorrect)klass+=' pract-choice--mine';
      rightHTML+='<div class="'+klass+'">'+iconHTML+'<span class="pract-choice__text">'+txt+'</span></div>';
    });
    rightHTML+='</div>';
  }
  if(it.explanation){
    rightHTML+='<div class="pract-expl"><span class="pract-expl__label">해설</span>';
    rightHTML+=esc(it.explanation)+'</div>';
  }
  rightHTML+='</div>';
  var footer='<div class="pract-modal__footer">'+
    '<button class="pract-modal__btn" onclick="closePractModal()"><i class="fas fa-arrow-left"></i> 돌아가기</button>'+
    '<button class="pract-modal__btn pract-modal__btn--bm'+(it.is_bookmarked?' on':'')+'" id="modalBmBtn" onclick="togglePractItemBm('+si+','+ii+',this)"><i class="fas fa-thumbtack"></i> '+(it.is_bookmarked?'찜 해제':'찜하기')+'</button>'+
    '</div>';
  box.innerHTML=header+'<div class="pract-modal__body">'+leftHTML+rightHTML+'</div>'+footer;
  document.getElementById('practModal').classList.add('show');
  document.body.style.overflow='hidden';
  practRenderMathIn(box);
}
async function togglePractItemBm(si,ii,btn){
  var detail=CURRENT_PRACT_DETAIL;if(!detail)return;
  var ps=detail.practice_sessions[si];if(!ps)return;
  var it=ps.items[ii];if(!it)return;
  btn.disabled=true;
  try{
    var r=await apiPost('/api/platform/bookmark',{item_id:it.item_id,practice_id:ps.practice_id});
    it.is_bookmarked=!!r.is_bookmarked;
    btn.classList.toggle('on',it.is_bookmarked);
    btn.innerHTML='<i class="fas fa-thumbtack"></i> '+(it.is_bookmarked?'찜 해제':'찜하기');
    if(typeof window.onPracticeBookmarkToggle==='function'){
      window.onPracticeBookmarkToggle(it.item_id,it.is_bookmarked,r&&r.total_bookmarks);
    }
  }catch(err){alert('찜 변경 실패: '+((err.body&&err.body.error)||err.message))}
  btn.disabled=false;
}
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){
    var m=document.getElementById('practModal');
    if(m&&m.classList.contains('show'))closePractModal();
  }
});
`
}

function myDashboardHTML() {
  return `${htmlHead('학습 대시보드')}
${myPageShellCSS()}
/* === [1] Player Card === */
.dash-player{display:flex;align-items:center;gap:16px;padding:16px;background:var(--bg2);border:1px solid var(--border);border-radius:14px;margin-bottom:20px}
.dash-player__ring{width:64px;height:64px;flex-shrink:0;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;background:conic-gradient(var(--accent-primary) calc(var(--prog,0) * 3.6deg),var(--bg3) 0);position:relative}
.dash-player__ring::after{content:'';position:absolute;inset:5px;border-radius:50%;background:var(--bg2)}
.dash-player__ring span{position:relative;z-index:1}
.dash-player__info{flex:1;min-width:0}
.dash-player__level{font-size:16px;font-weight:800;color:var(--text);font-family:var(--font-display)}
.dash-player__streak{font-size:13px;color:#fbbf24;font-weight:600;margin-top:2px}
.dash-player__today{font-size:12px;color:var(--dim);margin-top:2px}
.dash-player__bar-wrap{flex-shrink:0;width:140px;text-align:right}
.dash-player__bar{height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-bottom:4px}
.dash-player__bar-fill{height:100%;background:var(--accent-gradient);border-radius:3px;transition:width .5s var(--spring)}
.dash-player__next{font-size:11px;color:var(--dim)}
@keyframes streakPulse{0%,100%{opacity:1}50%{opacity:.6}}
.dash-player__streak--hot{animation:streakPulse 1.5s ease infinite}
/* === [2] KPI Cards === */
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
@media(max-width:640px){.kpi-grid{grid-template-columns:repeat(2,1fr)}}
.kpi-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;min-height:88px}
.kpi-card__label{font-size:12px;color:var(--dim);font-weight:600;margin-bottom:6px}
.kpi-card__value{font-size:24px;font-weight:800;color:var(--text);font-family:var(--font-display)}
.kpi-card__sub{font-size:11px;color:var(--dim);margin-top:4px}
.kpi-card__trend{font-size:11px;font-weight:700;margin-top:4px}
.kpi-card__trend--up{color:#2dd4a8}
.kpi-card__trend--down{color:#ff6b6b}
.kpi-card__trend--flat{color:var(--dim)}
/* === [3] Heatmap === */
.dash-heatmap{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;margin-bottom:20px}
.dash-heatmap__head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dash-heatmap__title{font-size:13px;font-weight:700;color:var(--dim);font-family:var(--font-display)}
.dash-heatmap__streak-badge{font-size:11px;color:#fbbf24;font-weight:600}
.dash-heatmap__body{display:flex;gap:8px;align-items:flex-start}
.dash-heatmap__labels{display:flex;flex-direction:column;gap:3px;font-size:9px;color:var(--muted);padding-top:0}
.dash-heatmap__labels span{height:12px;display:flex;align-items:center}
.dash-heatmap__grid{display:grid;grid-template-rows:repeat(7,12px);grid-auto-flow:column;grid-auto-columns:12px;gap:3px}
.dash-heatmap__cell{width:12px;height:12px;border-radius:2px;background:var(--bg3);transition:background .2s}
.dash-heatmap__cell:hover{outline:1px solid var(--dim);outline-offset:1px}
.dash-heatmap__legend{display:flex;align-items:center;gap:4px;margin-top:10px;font-size:10px;color:var(--muted);justify-content:flex-end}
.dash-heatmap__swatch{width:12px;height:12px;border-radius:2px;background:#2dd4a8}
/* === [4] Recommend === */
.dash-recommend{display:flex;align-items:center;gap:14px;padding:16px;background:linear-gradient(90deg,rgba(124,106,239,.06),transparent);border:1px solid rgba(124,106,239,.2);border-left:3px solid var(--accent-primary);border-radius:14px;margin-bottom:20px}
.dash-recommend__icon{font-size:28px;flex-shrink:0}
.dash-recommend__body{flex:1;min-width:0}
.dash-recommend__title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:4px}
.dash-recommend__desc{font-size:12px;color:var(--dim);line-height:1.5}
/* recommend CTA removed — 정보 전달 카드로 변경 */
/* === [5] Recent === */
.recent-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.recent-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:12px;cursor:pointer;transition:all .15s;min-height:100px;display:flex;flex-direction:column;gap:6px}
.recent-card:hover{border-color:var(--accent-primary);transform:translateY(-1px)}
.recent-card__score{font-size:18px;font-weight:800;font-family:var(--font-display)}
.recent-card__subj{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff;align-self:flex-start}
.recent-card__time{font-size:11px;color:var(--dim)}
/* === [6] Subject === */
.subj-breakdown{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.subj-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px}
.subj-card__head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.subj-card__name{font-size:14px;font-weight:700;color:var(--text)}
.subj-card__rate{font-size:16px;font-weight:800;font-family:var(--font-display)}
.subj-card__bar{height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-bottom:8px}
.subj-card__fill{height:100%;border-radius:3px;transition:width .5s var(--spring)}
.subj-card__meta{font-size:11px;color:var(--dim)}
/* === [7] Radar === */
.dash-radar{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:16px;margin-bottom:20px;display:flex;gap:20px;align-items:center}
.dash-radar__chart{width:160px;height:160px;flex-shrink:0}
.dash-radar__chart svg{width:100%;height:100%}
.dash-radar__side{flex:1;min-width:0}
.dash-radar__label{font-size:13px;font-weight:700;color:var(--dim);margin-bottom:10px;font-family:var(--font-display)}
.dash-radar__bars{display:flex;gap:4px;align-items:flex-end;height:60px;margin-bottom:8px}
.dash-radar__bar{flex:1;background:var(--bg3);border-radius:3px 3px 0 0;min-height:4px;transition:height .3s var(--spring);position:relative}
.dash-radar__bar-label{position:absolute;bottom:-16px;left:50%;transform:translateX(-50%);font-size:9px;color:var(--muted);white-space:nowrap}
.dash-radar__link{font-size:12px;color:var(--accent-primary);font-weight:600;text-decoration:none}
/* === [8] Weakness === */
.weak-chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}
.weak-chip{padding:6px 12px;background:rgba(255,107,107,.1);border:1px solid rgba(255,107,107,.3);border-radius:16px;font-size:12px;color:#fca5a5;display:flex;align-items:center;gap:6px;transition:all .15s}
.weak-chip:hover{background:rgba(255,107,107,.2);transform:translateY(-1px)}
.weak-chip__pct{font-weight:700}
.weak-chip__bar{width:32px;height:3px;background:var(--bg3);border-radius:2px;overflow:hidden}
.weak-chip__bar-fill{height:100%;background:#ff6b6b;border-radius:2px}
.weak-chip__count{color:var(--dim);font-size:11px}
.weak-more{background:none;border:none;color:var(--accent-primary);font-size:12px;font-weight:600;cursor:pointer;padding:6px 12px}
/* === Responsive === */
@media(max-width:640px){
  .dash-player{flex-direction:column;text-align:center}
  .dash-player__bar-wrap{width:100%}
  .dash-recommend{flex-direction:column;text-align:center}
  .dash-recommend__cta{width:100%;text-align:center;display:block}
  .dash-radar{flex-direction:column;align-items:stretch}
  .dash-radar__chart{width:120px;height:120px;margin:0 auto}
}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
  <span class="detail-nav__title"><i class="fas fa-chart-line" style="color:#2dd4a8;margin-right:6px"></i>학습 대시보드</span>
  <span style="width:60px"></span>
</div>
<div class="my-wrap">
  ${mySubjTabsHTML()}
  <div id="errTop"></div>
  <!-- [1] Player Card -->
  <div class="dash-player" id="playerCard" style="display:none">
    <div class="dash-player__ring" id="playerRing" style="--prog:0"><span id="playerIcon">🌱</span></div>
    <div class="dash-player__info">
      <div class="dash-player__level" id="playerLevel">—</div>
      <div class="dash-player__streak" id="playerStreak"></div>
      <div class="dash-player__today" id="playerToday"></div>
    </div>
    <div class="dash-player__bar-wrap">
      <div class="dash-player__bar"><div class="dash-player__bar-fill" id="playerBarFill" style="width:0%"></div></div>
      <div class="dash-player__next" id="playerNext"></div>
    </div>
  </div>
  <!-- [2] KPI Cards -->
  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-card__label">푼 문제</div><div class="kpi-card__value" id="kpiTotal">—</div><div class="kpi-card__sub" id="kpiTotalSub"></div><div class="kpi-card__trend" id="kpiTotalTrend"></div></div>
    <div class="kpi-card"><div class="kpi-card__label">정답률</div><div class="kpi-card__value" id="kpiRate">—</div><div class="kpi-card__sub" id="kpiRateSub"></div><div class="kpi-card__trend" id="kpiRateTrend"></div></div>
    <div class="kpi-card"><div class="kpi-card__label">학습 시간</div><div class="kpi-card__value" id="kpiTime">—</div><div class="kpi-card__trend" id="kpiTimeTrend"></div></div>
    <div class="kpi-card"><div class="kpi-card__label">찜한 문제</div><div class="kpi-card__value" id="kpiBookmark">—</div></div>
  </div>
  <!-- [3] Heatmap -->
  <div class="dash-heatmap" id="heatmapBox" style="display:none">
    <div class="dash-heatmap__head">
      <span class="dash-heatmap__title">12주 활동</span>
      <span class="dash-heatmap__streak-badge" id="heatmapStreak"></span>
    </div>
    <div class="dash-heatmap__body">
      <div class="dash-heatmap__labels"><span>월</span><span></span><span>수</span><span></span><span>금</span><span></span><span>일</span></div>
      <div class="dash-heatmap__grid" id="heatmapGrid"></div>
    </div>
    <div class="dash-heatmap__legend">
      <span>적음</span>
      <span class="dash-heatmap__swatch" style="opacity:.15"></span>
      <span class="dash-heatmap__swatch" style="opacity:.35"></span>
      <span class="dash-heatmap__swatch" style="opacity:.6"></span>
      <span class="dash-heatmap__swatch" style="opacity:1"></span>
      <span>많음</span>
    </div>
  </div>
  <!-- [4] Recommend -->
  <div id="recommendBox"></div>
  <!-- [5] Recent -->
  <div class="my-section-title">최근 연습</div>
  <div id="recentBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
  <!-- [6] Subject -->
  <div class="my-section-title">과목별 성취도</div>
  <div id="subjBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
  <!-- [7] Radar -->
  <div id="radarBox" style="display:none"></div>
  <!-- [8] Weakness -->
  <div class="my-section-title">자주 틀리는 개념</div>
  <div id="weakBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
</div>
<script>
${sharedAuthJS()}
${myPageHelpersJS()}
var currentSubj='전체';
var LEVEL_ICONS=['🌱','📖','🤝','⭐','👑','🏆'];
var LEVEL_TITLES=['새싹','학습자','조력자','멘토','마스터','전설'];

// === [1] Player Card ===
function renderPlayer(cp){
  if(!cp)return;
  var card=document.getElementById('playerCard');
  card.style.display='flex';
  var lv=(cp.level||1)-1;
  document.getElementById('playerIcon').textContent=LEVEL_ICONS[lv]||'🌱';
  document.getElementById('playerRing').style.setProperty('--prog',String(cp.progress_percent||0));
  document.getElementById('playerLevel').textContent='Lv.'+(cp.level||1)+' '+(cp.level_title||LEVEL_TITLES[lv]||'새싹');
  var streak=cp.answer_streak||0;
  var streakEl=document.getElementById('playerStreak');
  if(streak>0){streakEl.textContent='🔥 '+streak+'일 연속 답변';if(streak>=7)streakEl.classList.add('dash-player__streak--hot')}
  else{streakEl.textContent='연속 답변 기록 없음';streakEl.style.color='var(--dim)'}
  var todayEl=document.getElementById('playerToday');
  todayEl.textContent='오늘 +'+((cp.today_earned||0)*100).toLocaleString()+' 크로켓포인트 · 답변 '+(cp.today_answers||0)+'개';
  document.getElementById('playerBarFill').style.width=(cp.progress_percent||0)+'%';
  var nextEl=document.getElementById('playerNext');
  if(cp.next_level_cp){var remaining=((cp.next_level_cp-(cp.earned_cp||0))*100);nextEl.textContent=LEVEL_TITLES[lv+1]+'까지 '+remaining.toLocaleString()+' 크로켓포인트'}
  else{nextEl.textContent='최고 레벨 달성!';nextEl.style.color='#ffd700'}
}

// === [2] KPI with trends ===
function computeTrends(rp){
  if(!rp||!rp.length)return{count:null,rate:null};
  var now=Date.now();
  var week1=[],week2=[];
  rp.forEach(function(p){if(!p.started_at||!p.is_complete)return;var t=new Date(p.started_at+(p.started_at.includes('Z')?'':'Z')).getTime();var days=(now-t)/86400000;if(days<=7)week1.push(p);else if(days<=14)week2.push(p)});
  var c1=week1.length,c2=week2.length;
  var r1=c1?week1.reduce(function(s,p){return s+(p.total?p.correct/p.total:0)},0)/c1:null;
  var r2=c2?week2.reduce(function(s,p){return s+(p.total?p.correct/p.total:0)},0)/c2:null;
  return{count:c2>0?c1-c2:null,rate:(r1!=null&&r2!=null)?Math.round((r1-r2)*100):null}
}
function renderTrend(id,val,suffix){
  var el=document.getElementById(id);if(!el)return;
  if(val==null||val===0){el.textContent='';return}
  if(val>0){el.className='kpi-card__trend kpi-card__trend--up';el.textContent='▲ +'+val+(suffix||'')}
  else{el.className='kpi-card__trend kpi-card__trend--down';el.textContent='▼ '+val+(suffix||'')}
}

// === [3] Heatmap ===
function renderHeatmap(data,streak){
  if(!data||!data.days)return;
  var box=document.getElementById('heatmapBox');
  box.style.display='block';
  var grid=document.getElementById('heatmapGrid');
  if(streak>0)document.getElementById('heatmapStreak').textContent='🔥 '+streak+'일 연속';
  var byDay={};(data.days||[]).forEach(function(d){byDay[d.day]=d.actions||0});
  // Build 84 days (12 weeks) ending today, starting from Monday
  var today=new Date();var cells=[];
  // Find the Monday 12 weeks ago
  var start=new Date(today);start.setDate(start.getDate()-83);
  var dow=start.getDay();var mondayOffset=dow===0?-6:1-dow;start.setDate(start.getDate()+mondayOffset);
  var totalDays=Math.ceil((today-start)/86400000)+1;
  var html='';
  for(var i=0;i<totalDays&&i<91;i++){
    var d=new Date(start);d.setDate(d.getDate()+i);
    var key=d.toISOString().slice(0,10);
    var cnt=byDay[key]||0;
    var opacity=cnt===0?0:cnt<=2?0.25:cnt<=5?0.5:0.85;
    var bg=cnt===0?'var(--bg3)':'rgba(45,212,168,'+opacity+')';
    html+='<div class="dash-heatmap__cell" style="background:'+bg+'" title="'+key+': '+cnt+'회"></div>';
  }
  grid.innerHTML=html;
}

// === [4] Recommend ===
function renderRecommend(dash,cp,coach){
  var box=document.getElementById('recommendBox');
  var sb=(dash.subject_breakdown||[]).filter(function(s){return currentSubj==='전체'||s.subject===currentSubj});
  var wt=dash.weakness_tags||[];
  var icon='',title='',desc='';
  // Priority 1: Low accuracy subject — 약점 상세 표시
  var lowSubj=sb.filter(function(s){return s.total>=3&&s.accuracy_rate<0.5}).sort(function(a,b){return a.accuracy_rate-b.accuracy_rate})[0];
  if(lowSubj){
    icon='📉';
    var subjPct=Math.round((lowSubj.accuracy_rate||0)*100);
    title=lowSubj.subject+' 정답률 '+subjPct+'% — 약점이에요';
    // 해당 과목 관련 약점 태그 상위 3개
    var weakTags=wt.filter(function(t){return t.accuracy_rate<0.5}).sort(function(a,b){return (a.accuracy_rate||0)-(b.accuracy_rate||0)}).slice(0,3);
    if(weakTags.length){
      desc='취약 개념: '+weakTags.map(function(t){return '<span style="color:'+rateColor(t.accuracy_rate)+';font-weight:700">'+esc(t.tag)+' '+Math.round((t.accuracy_rate||0)*100)+'%</span>'}).join(' · ');
    }else{
      desc=lowSubj.total+'문제 중 '+Math.round(lowSubj.total*lowSubj.accuracy_rate)+'개만 맞췄어요. 연습이 필요합니다.';
    }
  }
  // Priority 2: Specific subject selected but no data
  else if(currentSubj!=='전체'&&!sb.length){
    icon='📚';title=currentSubj+' 연습을 시작해보세요';desc='질문방에서 '+currentSubj+' 질문을 하면 AI 튜터가 연습 문제를 만들어줘요'
  }
  // Priority 3: Streak broken (전체 탭에서만)
  else if(currentSubj==='전체'&&cp&&cp.answer_streak===0){
    icon='🔥';title='연속 답변을 시작하세요!';desc='매일 답변하면 보너스 크로켓포인트를 받아요. 3일 연속 시 200P!'
  }
  // Priority 4: Untouched subject (전체 탭에서만)
  else if(currentSubj==='전체'){
    var allSubjs=['국어','수학','영어','과학'];
    var touched=(dash.subject_breakdown||[]).map(function(s){return s.subject});
    var miss=allSubjs.filter(function(s){return touched.indexOf(s)===-1})[0];
    if(miss){icon='📚';title='아직 '+miss+'를 안 풀었어요';desc='다양한 과목을 풀어보면 실력이 골고루 올라가요'}
    else{icon='✨';title='잘 하고 있어요!';desc='모든 과목을 골고루 풀고 있습니다. 이 페이스를 유지하세요!'}
  }
  // Fallback
  else{icon='✨';title='잘 하고 있어요!';desc=currentSubj+' 실력을 키워가고 있습니다!'}
  box.innerHTML='<div class="dash-recommend"><div class="dash-recommend__icon">'+icon+'</div><div class="dash-recommend__body"><div class="dash-recommend__title">'+esc(title)+'</div><div class="dash-recommend__desc">'+desc+'</div></div></div>';
}

// === [7] Radar ===
function renderRadar(coach){
  if(!coach||!coach.counts)return;
  var c=coach.counts||{};
  var groups=[
    {name:'보기',val:(c['A-1']||0)+(c['A-2']||0)},
    {name:'파기',val:(c['B-1']||0)+(c['B-2']||0)},
    {name:'넓히기',val:(c['C-1']||0)+(c['C-2']||0)},
    {name:'성찰',val:(c['R-1']||0)+(c['R-2']||0)+(c['R-3']||0)}
  ];
  var maxVal=Math.max.apply(null,groups.map(function(g){return g.val}))||1;
  if(maxVal===0)return;
  var box=document.getElementById('radarBox');box.style.display='block';
  var cx=100,cy=100,r=70;
  // 4 axes: top, right, bottom, left
  var axes=[[0,-1],[1,0],[0,1],[-1,0]];
  // Guide rings at 25,50,75,100%
  var guides='';
  [0.25,0.5,0.75,1].forEach(function(pct){
    var pts=axes.map(function(a){return (cx+a[0]*r*pct)+','+(cy+a[1]*r*pct)}).join(' ');
    guides+='<polygon points="'+pts+'" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="1"/>';
  });
  // Axis lines
  var axLines='';axes.forEach(function(a){axLines+='<line x1="'+cx+'" y1="'+cy+'" x2="'+(cx+a[0]*r)+'" y2="'+(cy+a[1]*r)+'" stroke="rgba(255,255,255,.08)" stroke-width="1"/>'});
  // Data polygon
  var dataPts=groups.map(function(g,i){var pct=g.val/maxVal;return (cx+axes[i][0]*r*pct)+','+(cy+axes[i][1]*r*pct)}).join(' ');
  var dataPoly='<polygon points="'+dataPts+'" fill="rgba(124,106,239,.2)" stroke="#7c6aef" stroke-width="2"/>';
  // Labels
  var labels='';
  var labelPos=[[cx,-4],[cx+r+4,cy+4],[cx,cy+r+14],[cx-r-4,cy+4]];
  var anchors=['middle','start','middle','end'];
  groups.forEach(function(g,i){
    labels+='<text x="'+labelPos[i][0]+'" y="'+labelPos[i][1]+'" fill="var(--dim)" font-size="11" font-weight="600" text-anchor="'+anchors[i]+'" font-family="var(--font-body)">'+g.name+' '+g.val+'</text>';
  });
  var svg='<svg viewBox="-10 -10 220 220">'+guides+axLines+dataPoly+labels+'</svg>';
  // Weekly trend bars
  var ws=coach.weeklyScores||[];
  var maxScore=Math.max.apply(null,ws.map(function(w){return w.score||0}))||1;
  var barsHtml='<div class="dash-radar__bars">';
  ws.slice(-5).forEach(function(w,i){
    var h=Math.max(4,Math.round((w.score||0)/maxScore*60));
    var col=(w.score||0)>50?'#7c6aef':'var(--bg4)';
    barsHtml+='<div class="dash-radar__bar" style="height:'+h+'px;background:'+col+'"><span class="dash-radar__bar-label">'+(i+1)+'주</span></div>';
  });
  barsHtml+='</div>';
  box.innerHTML='<div class="dash-radar"><div class="dash-radar__chart">'+svg+'</div><div class="dash-radar__side"><div class="dash-radar__label">질문 유형 분포</div>'+barsHtml+'<div style="margin-top:20px"><a class="dash-radar__link" href="/coaching"><i class="fas fa-chart-radar"></i> 코칭 상세보기 →</a></div></div></div>';
}

// === [8] Weakness enhanced ===
function renderWeakness(wt){
  if(!wt||!wt.length){document.getElementById('weakBox').innerHTML=emptyState('💡','약점 분석 중','3문제 이상 푼 개념이 쌓이면 분석이 시작됩니다.');return}
  var sorted=wt.slice().sort(function(a,b){return (a.accuracy_rate||0)-(b.accuracy_rate||0)});
  var show5=sorted.slice(0,5);
  var rest=sorted.slice(5);
  var html='<div class="weak-chips" id="weakChips">';
  function chipHTML(t){
    var pct=Math.round((t.accuracy_rate||0)*100);
    return '<span class="weak-chip"><span class="weak-chip__pct" style="color:'+rateColor(t.accuracy_rate)+'">'+pct+'%</span> '+esc(t.tag)+'<span class="weak-chip__bar"><span class="weak-chip__bar-fill" style="width:'+pct+'%"></span></span><span class="weak-chip__count">'+t.wrong_count+'회</span></span>';
  }
  show5.forEach(function(t){html+=chipHTML(t)});
  html+='</div>';
  if(rest.length){
    html+='<div id="weakRest" style="display:none"><div class="weak-chips">';
    rest.forEach(function(t){html+=chipHTML(t)});
    html+='</div></div>';
    html+='<button class="weak-more" id="weakMoreBtn" onclick="document.getElementById(&quot;weakRest&quot;).style.display=&quot;block&quot;;this.style.display=&quot;none&quot;">+'+(rest.length)+'개 더보기</button>';
  }
  document.getElementById('weakBox').innerHTML=html;
}

// === Main load ===
var _cpData=null;
async function loadGlobal(){
  // 사용자 전역 데이터 (과목 탭과 무관) — 최초 1회만
  var results=await Promise.allSettled([
    apiGet('/api/cp'),
    apiGet('/api/coaching/stats'),
    apiGet('/api/dashboard/activity-heatmap')
  ]);
  _cpData=results[0].status==='fulfilled'?results[0].value:null;
  var coachData=results[1].status==='fulfilled'?results[1].value:null;
  var heatData=results[2].status==='fulfilled'?results[2].value:null;
  renderPlayer(_cpData);
  renderHeatmap(heatData,_cpData?_cpData.answer_streak:0);
  renderRadar(coachData);
  return{cpData:_cpData,coachData:coachData};
}
async function loadDashboard(globalCtx){
  document.getElementById('recentBox').innerHTML='<div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div>';
  document.getElementById('subjBox').innerHTML='<div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div>';
  document.getElementById('weakBox').innerHTML='<div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div>';
  var qs=currentSubj==='전체'?'':('?subject='+encodeURIComponent(currentSubj));
  try{
    var d=await apiGet('/api/platform/dashboard'+qs);
    // KPI
    document.getElementById('kpiTotal').textContent=(d.total_items||0)+'개';
    var rate=d.accuracy_rate;
    var rateEl=document.getElementById('kpiRate');
    rateEl.textContent=fmtPct(rate);rateEl.style.color=rateColor(rate);
    document.getElementById('kpiRateSub').textContent=(d.correct_count||0)+' / '+(d.total_items||0);
    document.getElementById('kpiTime').textContent=fmtMs(d.total_time_ms);
    document.getElementById('kpiBookmark').textContent=(d.bookmark_count||0)+'개';
    // Trends
    var trends=computeTrends(d.recent_practices||[]);
    renderTrend('kpiTotalTrend',trends.count,'개');
    renderTrend('kpiRateTrend',trends.rate,'%p');
    // Recommend
    renderRecommend(d,_cpData||{},globalCtx&&globalCtx.coachData||{});
    // Recent
    var rp=(d.recent_practices||[]).filter(function(p){return p.is_complete&&(currentSubj==='전체'||p.subject===currentSubj)});
    if(!rp.length){document.getElementById('recentBox').innerHTML=emptyState('📝','아직 푼 문제가 없어요','질문방에서 AI 튜터와 얘기해보세요.','/','질문방 가기')}
    else{
      var html='<div class="recent-grid">';
      rp.forEach(function(p){
        var col=subjHex(p.subject);
        var score=p.correct+'/'+p.total+' 정답';
        var scoreCol=rateColor(p.total?p.correct/p.total:0);
        html+='<div class="recent-card" onclick="location.href=\\'/my/history/'+p.question_id+'\\'">';
        html+='<span class="recent-card__subj" style="background:'+col+'">'+esc(p.subject||'기타')+'</span>';
        html+='<div class="recent-card__score" style="color:'+scoreCol+'">'+score+'</div>';
        html+='<div class="recent-card__time">'+fmtDate(p.started_at)+'</div>';
        html+='</div>';
      });
      html+='</div>';
      document.getElementById('recentBox').innerHTML=html;
    }
    // Subject breakdown
    var sb=(d.subject_breakdown||[]).filter(function(s){return currentSubj==='전체'||s.subject===currentSubj});
    if(!sb.length){document.getElementById('subjBox').innerHTML=emptyState('📊','과목별 데이터 없음','연습 문제를 풀면 과목별 성취도가 표시됩니다.')}
    else{
      var shtml='<div class="subj-breakdown">';
      sb.forEach(function(s){
        var col=subjHex(s.subject);
        var pct=Math.round((s.accuracy_rate||0)*100);
        shtml+='<div class="subj-card">';
        shtml+='<div class="subj-card__head"><span class="subj-card__name" style="color:'+col+'">'+esc(s.subject)+'</span><span class="subj-card__rate" style="color:'+rateColor(s.accuracy_rate)+'">'+pct+'%</span></div>';
        shtml+='<div class="subj-card__bar"><div class="subj-card__fill" style="width:'+pct+'%;background:'+col+'"></div></div>';
        shtml+='<div class="subj-card__meta">'+s.total+'문제 · '+fmtMs(s.time_ms)+'</div>';
        shtml+='</div>';
      });
      shtml+='</div>';
      document.getElementById('subjBox').innerHTML=shtml;
    }
    // Weakness
    renderWeakness(d.weakness_tags||[]);
    document.getElementById('errTop').innerHTML='';
  }catch(err){
    console.error('dashboard load failed',err);
    renderErr('recentBox',err,function(){loadDashboard(globalCtx)});
    document.getElementById('subjBox').innerHTML='';
    document.getElementById('weakBox').innerHTML='';
  }
}
var _globalCtx=null;
function onSubjChange(subj){currentSubj=subj;loadDashboard(_globalCtx)}
(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  _globalCtx=await loadGlobal();
  loadDashboard(_globalCtx);
})();
${mySubjTabsJS()}
</script>
</body>
</html>`
}

function myBookmarksHTML() {
  return `${htmlHead('찜한 문제')}
${myPageShellCSS()}
.bm-toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;font-size:13px;color:var(--dim)}
.bm-group{margin-bottom:28px}
.bm-group__head{display:flex;align-items:center;gap:10px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.bm-group__subj{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
.bm-group__title{font-size:14px;font-weight:700;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bm-group__title a{text-decoration:none}
.bm-group__title a:hover{text-decoration:underline}
.bm-group__date{font-size:11px;color:var(--dim)}
.bm-items{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
@media(max-width:560px){.bm-items{grid-template-columns:1fr}}
.bm-item{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px 16px 12px;display:flex;flex-direction:column;gap:10px;cursor:pointer;transition:all .18s;min-height:160px;position:relative}
.bm-item:hover{border-color:var(--accent-primary);transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,0,0,.25)}
.bm-item.removing{opacity:.3;pointer-events:none;transform:scale(.95)}
.bm-item__top{display:flex;justify-content:space-between;align-items:center;gap:8px;padding-right:32px}
.bm-item__idx{font-size:11px;color:var(--dim);font-weight:600}
.bm-item__chip{display:inline-flex;align-items:center;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;font-family:var(--font-display)}
.bm-item__chip--correct{background:rgba(45,212,168,.15);color:#2dd4a8}
.bm-item__chip--wrong{background:rgba(255,107,107,.15);color:#ff6b6b}
.bm-item__chip--pending{background:var(--bg3);color:var(--dim)}
.bm-item__preview{flex:1;font-size:13px;color:var(--text);line-height:1.55;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;word-break:keep-all}
.bm-item__preview--skel{color:var(--dim);font-style:italic;opacity:.6}
.bm-item__meta{display:flex;justify-content:space-between;align-items:center;padding-top:8px;border-top:1px solid var(--border);font-size:11px}
.bm-item__diff{color:#a78bfa;font-weight:600}
.bm-item__date{color:var(--dim)}
.bm-item__unbm{position:absolute;top:10px;right:10px;width:28px;height:28px;min-height:28px;min-width:28px;background:rgba(251,191,36,.12);border:none;border-radius:8px;color:#fbbf24;font-size:12px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .12s;z-index:1}
.bm-item__unbm:hover{background:rgba(251,191,36,.28);transform:scale(1.08)}
${practiceModalCSS()}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
  <span class="detail-nav__title"><i class="fas fa-thumbtack" style="color:#fbbf24;margin-right:6px"></i>찜한 문제</span>
  <span style="width:60px"></span>
</div>
<div class="my-wrap">
  ${mySubjTabsHTML()}
  <div class="bm-toolbar">
    <span id="bmTotal">총 — 개</span>
    <span><i class="fas fa-layer-group"></i> 질문별 그룹핑</span>
  </div>
  <div id="bmBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
</div>
${practiceModalHTML()}
<script>
${sharedAuthJS()}
${myPageHelpersJS()}
${practiceModalJS()}
var currentSubj='전체';
var BM_LEVELS={'B-1':'2등급 보장','B-2':'높은 2등급 보장','C-1':'1등급 근접','C-2':'1등급 도전'};
// question_id -> detail(practice_sessions 포함) 캐시. 카드 preview 채우기 + 클릭 시 해당 item으로 이동에 사용.
var BM_DETAIL_CACHE={};
async function loadBookmarks(){
  document.getElementById('bmBox').innerHTML='<div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div>';
  var qs='?group_by=question'+(currentSubj==='전체'?'':'&subject='+encodeURIComponent(currentSubj));
  try{
    var d=await apiGet('/api/platform/bookmarks'+qs);
    var groups=d.groups||[];
    var total=d.total||groups.reduce(function(s,g){return s+(g.items||[]).length},0);
    document.getElementById('bmTotal').textContent='총 '+total+'개';
    if(!total){document.getElementById('bmBox').innerHTML=emptyState('📌','찜한 문제가 없어요','마음에 드는 연습 문제에 📌를 눌러보세요.','/','질문방 가기');return}
    // 1차 렌더: 카드 뼈대 (preview는 placeholder)
    var html='';
    groups.forEach(function(g){
      var col=subjHex(g.subject);
      html+='<div class="bm-group">';
      html+='<div class="bm-group__head">';
      html+='<span class="bm-group__subj" style="background:'+col+'">'+esc(g.subject||'기타')+'</span>';
      html+='<span class="bm-group__title"><a href="/my/history/'+g.question_id+'" style="color:inherit">'+esc(g.title||'#'+g.question_id)+'</a></span>';
      html+='<span class="bm-group__date">'+fmtDate(g.created_at)+'</span>';
      html+='</div>';
      html+='<div class="bm-items">';
      var bmGroupDate=fmtDate(g.created_at);
      (g.items||[]).forEach(function(it){
        var statusChip=it.is_correct===true?'bm-item__chip--correct':it.is_correct===false?'bm-item__chip--wrong':'bm-item__chip--pending';
        var statusTxt=it.is_correct===true?'✓ 정답':it.is_correct===false?'✗ 오답':'— 미풀이';
        html+='<div class="bm-item" data-qid="'+g.question_id+'" data-item-id="'+it.item_id+'" data-practice-id="'+esc(it.practice_id||'')+'" onclick="openBookmarkItem(this)">';
        html+='<button class="bm-item__unbm" title="찜 해제" onclick="event.stopPropagation();toggleBm(this)"><i class="fas fa-thumbtack"></i></button>';
        html+='<div class="bm-item__top">';
        html+='<span class="bm-item__idx">문제 '+((it.index!=null?it.index:0)+1)+'</span>';
        html+='<span class="bm-item__chip '+statusChip+'">'+statusTxt+'</span>';
        html+='</div>';
        html+='<div class="bm-item__preview bm-item__preview--skel" data-preview-slot="1">문제 내용 불러오는 중…</div>';
        var _bmLvl=BM_LEVELS[it.difficulty];
        html+='<div class="bm-item__meta">';
        html+='<span class="bm-item__diff">'+(_bmLvl?esc(_bmLvl):'')+'</span>';
        html+='<span class="bm-item__date">'+bmGroupDate+'</span>';
        html+='</div>';
        html+='</div>';
      });
      html+='</div></div>';
    });
    document.getElementById('bmBox').innerHTML=html;
    // 2차: 각 question_id별 detail 병렬 fetch → item_id 매칭 → preview 주입
    var uniqQids={};groups.forEach(function(g){uniqQids[g.question_id]=1});
    var qidList=Object.keys(uniqQids);
    qidList.forEach(function(qid){
      if(BM_DETAIL_CACHE[qid]){hydrateBookmarkPreviews(qid);return}
      apiGet('/api/platform/question-history/'+qid).then(function(detail){
        BM_DETAIL_CACHE[qid]=detail;
        hydrateBookmarkPreviews(qid);
      }).catch(function(e){
        console.warn('detail fetch failed qid=',qid,e);
        // preview 실패 시 placeholder 제거 (카드는 기존 정보로 충분히 동작)
        document.querySelectorAll('.bm-item[data-qid="'+qid+'"] .bm-item__preview').forEach(function(el){el.remove()});
      });
    });
  }catch(err){console.error('bookmarks failed',err);renderErr('bmBox',err,loadBookmarks)}
}
// detail이 도착하면 해당 qid의 카드들에 preview 텍스트 주입 + KaTeX 렌더
function hydrateBookmarkPreviews(qid){
  var detail=BM_DETAIL_CACHE[qid];if(!detail)return;
  var itemMap={};
  (detail.practice_sessions||[]).forEach(function(ps){
    (ps.items||[]).forEach(function(it){itemMap[it.item_id]=it});
  });
  document.querySelectorAll('.bm-item[data-qid="'+qid+'"]').forEach(function(card){
    var itemId=card.getAttribute('data-item-id');
    var it=itemMap[itemId];
    var slot=card.querySelector('.bm-item__preview');
    if(!slot)return;
    if(!it||(!it.question_text&&!it.passage_text)){slot.textContent='문제 내용 없음';return}
    var raw=it.passage_text||it.question_text||'';
    slot.textContent=practSmartTruncate(raw,120);
    slot.classList.remove('bm-item__preview--skel');
    practRenderMathIn(slot);
  });
}
// 카드 클릭 → 같은 페이지에서 공유 모달 바로 open. detail이 아직 캐시 안 됐으면 fetch 후 open.
async function openBookmarkItem(card){
  var qid=card.getAttribute('data-qid');
  var itemId=card.getAttribute('data-item-id');
  if(!qid||!itemId)return;
  var detail=BM_DETAIL_CACHE[qid];
  if(!detail){
    try{detail=await apiGet('/api/platform/question-history/'+qid);BM_DETAIL_CACHE[qid]=detail;hydrateBookmarkPreviews(qid)}
    catch(err){console.error('detail fetch failed',err);alert('문제 내용을 불러올 수 없어요.');return}
  }
  var loc=findSiIiByItemId(detail,itemId);
  if(!loc){alert('이 문제는 최신 데이터에서 찾을 수 없어요.');return}
  openItemFromDetail(detail,loc.si,loc.ii);
}
// 모달에서 찜 해제 시 북마크 페이지 카드 즉시 제거 + 카운트 갱신
window.onPracticeBookmarkToggle=function(itemId,isBookmarked,totalBookmarks){
  if(isBookmarked)return; // 찜 유지 상태면 카드 유지
  var cards=document.querySelectorAll('.bm-item[data-item-id="'+itemId+'"]');
  cards.forEach(function(card){
    card.classList.add('removing');
    setTimeout(function(){
      card.remove();
      if(totalBookmarks!=null)updateBmCount(totalBookmarks);
    },300);
  });
  // 모달 닫기 (찜 해제 후)
  setTimeout(function(){if(typeof closePractModal==='function')closePractModal();},320);
};
async function toggleBm(btn){
  var card=btn.closest('.bm-item');
  if(!card)return;
  var itemId=parseInt(card.getAttribute('data-item-id'));
  var practiceId=card.getAttribute('data-practice-id')||null;
  card.classList.add('removing');
  try{
    var r=await apiPost('/api/platform/bookmark',{item_id:itemId,practice_id:practiceId});
    if(r&&r.is_bookmarked===false){
      card.style.transition='all .3s';card.style.opacity='0';card.style.transform='scale(.9)';
      setTimeout(function(){card.remove();updateBmCount(r.total_bookmarks)},300);
    }else{card.classList.remove('removing')}
  }catch(err){card.classList.remove('removing');alert('찜 해제 실패: '+((err.body&&err.body.error)||err.message))}
}
function updateBmCount(n){
  document.getElementById('bmTotal').textContent='총 '+(n||0)+'개';
  if(n===0)document.getElementById('bmBox').innerHTML=emptyState('📌','찜한 문제가 없어요','마음에 드는 연습 문제에 📌를 눌러보세요.','/','질문방 가기');
}
function onSubjChange(subj){currentSubj=subj;loadBookmarks()}
(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  loadBookmarks();
})();
${mySubjTabsJS()}
</script>
</body>
</html>`
}

function myHistoryHTML() {
  return `${htmlHead('질문 히스토리')}
${myPageShellCSS()}
.hist-list{display:flex;flex-direction:column;gap:10px}
.hist-row{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:12px;display:flex;align-items:center;gap:12px;cursor:pointer;transition:all .15s;min-height:80px}
.hist-row:hover{border-color:var(--accent-primary);transform:translateY(-1px)}
.hist-row__thumb{width:64px;height:64px;flex-shrink:0;border-radius:8px;overflow:hidden;background:var(--bg3);display:flex;align-items:center;justify-content:center}
.hist-row__thumb img{width:100%;height:100%;object-fit:cover}
.hist-row__body{flex:1;min-width:0}
.hist-row__title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hist-row__meta{font-size:12px;color:var(--dim);display:flex;gap:10px;flex-wrap:wrap}
.hist-row__subj{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
.hist-row__date{font-size:11px;color:var(--dim);flex-shrink:0}
.hist-more{width:100%;padding:12px;margin-top:12px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;color:var(--dim);font-size:13px;cursor:pointer}
.hist-more:hover{background:var(--bg3);color:var(--text)}
.hist-more:disabled{opacity:.5;cursor:default}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
  <span class="detail-nav__title"><i class="fas fa-history" style="color:#7c6aef;margin-right:6px"></i>질문 히스토리</span>
  <span style="width:60px"></span>
</div>
<div class="my-wrap">
  ${mySubjTabsHTML()}
  <div id="histBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
  <button class="hist-more" id="histMore" style="display:none" onclick="loadMore()">더 보기</button>
</div>
<script>
${sharedAuthJS()}
${myPageHelpersJS()}
var currentSubj='전체';
var nextCursor=null;
var accumulated=[];
function renderRows(items,replace){
  if(replace)accumulated=[];
  accumulated=accumulated.concat(items||[]);
  if(!accumulated.length){document.getElementById('histBox').innerHTML=emptyState('📝','아직 기록이 없어요','연습 문제를 푼 질문이 여기 모입니다.','/','질문방 가기');return}
  var html='<div class="hist-list">';
  accumulated.forEach(function(it){
    var col=subjHex(it.subject);
    var rate=it.total?(it.correct/it.total):null;
    var rateTxt=it.total?(it.correct+'/'+it.total+' 정답'):'기록 없음';
    var rateCol=rate!=null?rateColor(rate):'var(--dim)';
    var thumb=it.thumbnail_url?'<img src="'+esc(it.thumbnail_url)+'" alt="">':'<i class="fas fa-file-alt" style="color:'+col+';font-size:24px"></i>';
    html+='<div class="hist-row" onclick="location.href=\\'/my/history/'+it.question_id+'\\'">';
    html+='<div class="hist-row__thumb">'+thumb+'</div>';
    html+='<div class="hist-row__body">';
    html+='<div class="hist-row__title">'+esc(it.title||'#'+it.question_id)+'</div>';
    html+='<div class="hist-row__meta">';
    html+='<span class="hist-row__subj" style="background:'+col+'">'+esc(it.subject||'기타')+'</span>';
    html+='<span>🧠 '+(it.practice_count||0)+'세트</span>';
    html+='<span style="color:'+rateCol+';font-weight:700">'+rateTxt+'</span>';
    html+='</div></div>';
    html+='<div class="hist-row__date">'+fmtDate(it.created_at)+'</div>';
    html+='</div>';
  });
  html+='</div>';
  document.getElementById('histBox').innerHTML=html;
}
async function loadHistory(append){
  if(!append){
    document.getElementById('histBox').innerHTML='<div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div>';
    nextCursor=null;accumulated=[];
  }
  var qs='?limit=20'+(currentSubj==='전체'?'':'&subject='+encodeURIComponent(currentSubj))+(append&&nextCursor?'&cursor='+encodeURIComponent(nextCursor):'');
  try{
    var d=await apiGet('/api/platform/question-history'+qs);
    renderRows((d.items||[]).filter(function(it){return Number.isFinite(Number(it.question_id))&&it.question_id>0}),!append);
    nextCursor=d.next_cursor||null;
    var btn=document.getElementById('histMore');
    btn.style.display=nextCursor?'block':'none';
    btn.disabled=false;
    btn.innerHTML='더 보기';
  }catch(err){console.error('history failed',err);renderErr('histBox',err,loadHistory)}
}
function loadMore(){
  var btn=document.getElementById('histMore');
  btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 불러오는 중...';
  loadHistory(true);
}
function onSubjChange(subj){currentSubj=subj;loadHistory(false)}
(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  loadHistory(false);
})();
${mySubjTabsJS()}
</script>
</body>
</html>`
}

function myHistoryDetailHTML(questionId: string) {
  const qidSafe = String(questionId || '').replace(/[^0-9]/g, '')
  return `${htmlHead('질문 히스토리 상세')}
${myPageShellCSS()}
.hist-detail-card{background:var(--bg2);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:20px;display:flex;gap:16px;align-items:flex-start}
.hist-detail-card__thumb{width:96px;height:96px;flex-shrink:0;border-radius:10px;overflow:hidden;background:var(--bg3);display:flex;align-items:center;justify-content:center}
.hist-detail-card__thumb img{width:100%;height:100%;object-fit:cover}
.hist-detail-card__body{flex:1;min-width:0}
.hist-detail-card__subj{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;color:#fff;margin-bottom:8px}
.hist-detail-card__title{font-size:17px;font-weight:700;color:var(--text);margin-bottom:6px}
.hist-detail-card__meta{font-size:12px;color:var(--dim);margin-bottom:12px}
.hist-origin-link{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;font-size:13px;color:var(--accent-primary);text-decoration:none;font-weight:600}
.hist-origin-link:hover{background:var(--bg4)}
.pract-session{margin-bottom:20px}
.pract-session__head{font-size:13px;color:var(--dim);margin-bottom:10px;display:flex;justify-content:space-between}
.pract-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
@media(max-width:560px){.pract-grid{grid-template-columns:1fr}}
.pract-item{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px 16px 12px;display:flex;flex-direction:column;gap:10px;cursor:pointer;transition:all .18s;min-height:160px;position:relative}
.pract-item:hover{border-color:var(--accent-primary);transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,0,0,.25)}
.pract-item__top{display:flex;justify-content:space-between;align-items:center;gap:8px;padding-right:26px}
.pract-item__idx{font-size:11px;color:var(--dim);font-weight:600}
.pract-item__chip{display:inline-flex;align-items:center;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;font-family:var(--font-display)}
.pract-item__chip--correct{background:rgba(45,212,168,.15);color:#2dd4a8}
.pract-item__chip--wrong{background:rgba(255,107,107,.15);color:#ff6b6b}
.pract-item__chip--pending{background:var(--bg3);color:var(--dim)}
.pract-item__preview{flex:1;font-size:13px;color:var(--text);line-height:1.55;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;word-break:keep-all}
.pract-item__preview--skel{color:var(--dim);font-style:italic;opacity:.6}
.pract-item__meta{display:flex;justify-content:space-between;align-items:center;padding-top:8px;border-top:1px solid var(--border);font-size:11px}
.pract-item__diff{color:#a78bfa;font-weight:600}
.pract-item__time{color:var(--dim)}
.pract-item__bm{position:absolute;top:10px;right:10px;width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:#fbbf24;font-size:12px}
${practiceModalCSS()}
/* (legacy, still used by modal layout) */
.pract-modal__body-legacy-noop{display:none}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
  <span class="detail-nav__title">질문 상세</span>
  <span style="width:60px"></span>
</div>
<div class="my-wrap">
  <div id="histOriginBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
  <div class="my-section-title">생성된 연습 문제</div>
  <div id="histPractBox"><div class="my-skel"><i class="fas fa-spinner fa-spin"></i> 불러오는 중...</div></div>
</div>

${practiceModalHTML()}

<script>
${sharedAuthJS()}
${myPageHelpersJS()}
var questionId=${qidSafe || 0};
var DETAIL=null;
async function loadDetail(){
  try{
    var d=await apiGet('/api/platform/question-history/'+questionId);
    DETAIL=d;
    var col=subjHex(d.subject);
    var thumb=d.thumbnail_url?'<img src="'+esc(d.thumbnail_url)+'" alt="">':'<i class="fas fa-file-alt" style="color:'+col+';font-size:32px"></i>';
    var html='<div class="hist-detail-card">';
    html+='<div class="hist-detail-card__thumb">'+thumb+'</div>';
    html+='<div class="hist-detail-card__body">';
    html+='<span class="hist-detail-card__subj" style="background:'+col+'">'+esc(d.subject||'기타')+'</span>';
    html+='<div class="hist-detail-card__title">'+esc(d.title||'#'+questionId)+'</div>';
    html+='<div class="hist-detail-card__meta">'+fmtDate(d.created_at)+'</div>';
    html+='<a href="/question/'+questionId+'" class="hist-origin-link"><i class="fas fa-external-link-alt"></i> 원 질문방으로 이동</a>';
    html+='</div></div>';
    document.getElementById('histOriginBox').innerHTML=html;
    // Practice sessions
    var sess=(d.practice_sessions||[]).filter(function(ps){var items=ps.items||[];return items.some(function(it){return it.my_answer!=null})});
    if(!sess.length){document.getElementById('histPractBox').innerHTML=emptyState('🧠','연습 문제 없음','이 질문에는 아직 생성된 연습 문제가 없어요.');return}
    var phtml='';
    var MODE_LABELS={'normal':'실력UP','quick':'빠른해결'};
    sess.forEach(function(ps,si){
      var items=ps.items||[];
      var correct=items.filter(function(x){return x.is_correct}).length;
      var modeLabel=MODE_LABELS[ps.mode]||(ps.mode||'세트 '+(si+1));
      var dateStr=ps.started_at?fmtDate(ps.started_at):'';
      phtml+='<div class="pract-session">';
      phtml+='<div class="pract-session__head"><span>'+esc(modeLabel)+(dateStr?' <span style="font-weight:400;color:var(--dim);font-size:12px;margin-left:6px">'+dateStr+'</span>':'')+'</span><span style="color:'+rateColor(items.length?correct/items.length:0)+';font-weight:700">'+correct+'/'+items.length+' 정답</span></div>';
      phtml+='<div class="pract-grid">';
      items.forEach(function(it){
        var statusChip=it.is_correct===true?'pract-item__chip--correct':it.is_correct===false?'pract-item__chip--wrong':'pract-item__chip--pending';
        var statusTxt=it.is_correct===true?'✓ 정답':it.is_correct===false?'✗ 오답':'— 미풀이';
        var preview=practSmartTruncate(it.passage_text||it.question_text||'',120);
        phtml+='<div class="pract-item" data-si="'+si+'" data-ii="'+items.indexOf(it)+'" data-item-id="'+(it.item_id||'')+'" onclick="openItem(this)">';
        if(it.is_bookmarked)phtml+='<div class="pract-item__bm" title="찜함"><i class="fas fa-thumbtack"></i></div>';
        phtml+='<div class="pract-item__top">';
        phtml+='<span class="pract-item__idx">문제 '+((it.index!=null?it.index:items.indexOf(it))+1)+'</span>';
        phtml+='<span class="pract-item__chip '+statusChip+'">'+statusTxt+'</span>';
        phtml+='</div>';
        if(preview){
          phtml+='<div class="pract-item__preview">'+esc(preview)+'</div>';
        }else{
          phtml+='<div class="pract-item__preview pract-item__preview--skel">문제 내용 없음</div>';
        }
        var _cardLvl=LEVEL_LABELS[it.difficulty];
        phtml+='<div class="pract-item__meta">';
        phtml+='<span class="pract-item__diff">'+(_cardLvl?esc(_cardLvl):'')+'</span>';
        phtml+='<span class="pract-item__time"></span>';
        phtml+='</div>';
        phtml+='</div>';
      });
      phtml+='</div></div>';
    });
    document.getElementById('histPractBox').innerHTML=phtml;
    // 카드 preview 내 LaTeX 렌더 ($f(x)$, $$...$$ 등)
    practRenderMathIn(document.getElementById('histPractBox'));
    // 북마크 페이지에서 #item-<item_id> hash로 진입 시 해당 item 모달 자동 open
    maybeAutoOpenFromHash();
  }catch(err){console.error('detail failed',err);renderErr('histOriginBox',err,loadDetail);document.getElementById('histPractBox').innerHTML=''}
}
${practiceModalJS()}
var LEVEL_LABELS=PRACT_LEVEL_LABELS;
// history page의 pract-item 카드 클릭 핸들러 — 공유 모달 오픈
function openItem(el){
  var si=parseInt(el.getAttribute('data-si'));
  var ii=parseInt(el.getAttribute('data-ii'));
  if(!DETAIL)return;
  openItemFromDetail(DETAIL,si,ii);
}
// bookmark hash 진입 시 자동 open (/my/history/:qid#item-<id> 이전 링크 호환)
function maybeAutoOpenFromHash(){
  var h=String(location.hash||'');
  var m=h.match(/^#item-(\\d+)$/);
  if(!m||!DETAIL)return;
  var found=findSiIiByItemId(DETAIL,m[1]);
  if(!found)return;
  var card=document.querySelector('.pract-item[data-si="'+found.si+'"][data-ii="'+found.ii+'"]');
  if(card)try{card.scrollIntoView({behavior:'smooth',block:'center'})}catch(e){}
  openItemFromDetail(DETAIL,found.si,found.ii);
}
// 모달에서 찜 토글 시 카드 뱃지 동기화
window.onPracticeBookmarkToggle=function(itemId,isBookmarked){
  var card=document.querySelector('.pract-item[data-item-id="'+itemId+'"]');
  if(!card)return;
  var bmEl=card.querySelector('.pract-item__bm');
  if(isBookmarked&&!bmEl){card.insertAdjacentHTML('beforeend','<div class="pract-item__bm" title="찜함"><i class="fas fa-thumbtack"></i></div>')}
  else if(!isBookmarked&&bmEl){bmEl.remove()}
};
(async()=>{
  const u=await checkAuth();
  if(!u){location.href='/';return}
  loadDetail();
})();
</script>
</body>
</html>`
}

// ===== Question Detail Page =====

function questionDetailHTML(question: any = null, answers: any[] = [], ssrHasMore: boolean = false) {
  return `${htmlHead('질문 상세')}

/* ===== ORZO-STYLE SPLIT LAYOUT ===== */
.detail-nav{height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 var(--sp-4);padding-top:env(safe-area-inset-top);border-bottom:1px solid var(--glass-border);position:fixed;top:0;left:0;right:0;z-index:100;background:rgba(11,14,20,.9);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
.detail-nav__back{font-size:15px;font-weight:500;color:var(--dim);background:none;border:none;padding:0;display:flex;align-items:center;gap:8px;transition:color .2s}
.detail-nav__back:hover{color:var(--white)}

/* ===== CP BADGE & TOAST ===== */
.cp-badge{display:flex;align-items:center;gap:8px;padding:4px 14px 4px 8px;background:linear-gradient(135deg,rgba(124,106,239,.12),rgba(162,155,254,.06));border:1px solid rgba(124,106,239,.3);border-radius:20px;cursor:pointer;transition:all .2s;position:relative}
.cp-badge:hover{background:linear-gradient(135deg,rgba(124,106,239,.2),rgba(162,155,254,.1));transform:scale(1.03)}
.cp-badge__icon{font-size:18px;animation:cpPulse 2s infinite}
.cp-badge__info{display:flex;flex-direction:column;gap:0}
.cp-badge__total{font-size:14px;font-weight:800;color:#a29bfe;line-height:1.2}
.cp-badge__question{font-size:10px;color:#7c6aef;line-height:1.2;opacity:.8}
.cp-badge.cp-badge--gain{animation:cpBounce .6s ease}
@keyframes cpPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.15)}}
@keyframes cpBounce{0%{transform:scale(1)}30%{transform:scale(1.2)}60%{transform:scale(.95)}100%{transform:scale(1)}}

.cp-toast{position:fixed;top:60px;left:50%;transform:translateX(-50%);z-index:9999;pointer-events:none}
.cp-toast__item{display:flex;align-items:center;gap:8px;padding:10px 20px;background:linear-gradient(135deg,#7c6aef,#6c5ce7);color:#fff;border-radius:14px;font-size:15px;font-weight:800;box-shadow:0 8px 32px rgba(124,106,239,.4);animation:cpToastIn .5s ease forwards,cpToastOut .4s ease 2.2s forwards;margin-bottom:8px}
.cp-toast__item .cp-toast__icon{font-size:20px}
.cp-toast__item .cp-toast__text{display:flex;flex-direction:column;gap:1px}
.cp-toast__item .cp-toast__amount{font-size:16px;font-weight:900}
.cp-toast__item .cp-toast__desc{font-size:11px;opacity:.85;font-weight:600}
@keyframes cpToastIn{0%{opacity:0;transform:translateY(-20px) scale(.8)}60%{transform:translateY(5px) scale(1.05)}100%{opacity:1;transform:translateY(0) scale(1)}}
@keyframes cpToastOut{0%{opacity:1;transform:translateY(0)}100%{opacity:0;transform:translateY(-30px) scale(.8)}}
.detail-nav__center{font-size:15px;font-weight:700;color:var(--white);position:absolute;left:50%;transform:translateX(-50%)}
.detail-nav__user{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px}
.detail-nav__left{display:flex;align-items:center;gap:12px}
.detail-nav__home{font-size:16px;color:var(--dim);transition:all .2s;display:flex;align-items:center;justify-content:center;width:36px;height:36px;border-radius:12px;background:var(--glass-bg);border:1px solid var(--glass-border);cursor:pointer;backdrop-filter:blur(8px)}
.detail-nav__home:hover{color:var(--white);background:rgba(255,255,255,.1)}

/* Split panel container — Orzo 2-column layout */
.split-container{display:flex;position:fixed;top:52px;left:0;right:0;bottom:110px;overflow:hidden}
.split-left{
  width:50%;min-width:300px;
  overflow-y:auto;overflow-x:hidden;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;
  padding:0;
  display:flex;flex-direction:column;
  background:var(--bg);
}
.split-right{
  flex:1;min-width:0;
  overflow-y:auto;overflow-x:hidden;-webkit-overflow-scrolling:touch;overscroll-behavior:contain;
  padding:var(--sp-5) var(--sp-6) var(--sp-10);
  background:rgba(17,24,39,.5);
}

/* Left panel: question content */
.q-panel-inner{padding:var(--sp-5) var(--sp-5) 80px}
.q-head{display:flex;align-items:center;gap:12px;margin-bottom:var(--sp-4)}
.q-avatar{width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#1F2937,#374151);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:16px;flex-shrink:0;border:2px solid var(--glass-border)}
.q-meta{flex:1;min-width:0}
.q-name{font-size:14px;font-weight:700;color:var(--white);display:flex;align-items:center;gap:6px}
.q-name .grade-tag{font-size:10px;font-weight:600;color:var(--dim);background:var(--bg3);padding:2px 7px;border-radius:3px}
.q-sub{font-size:11px;color:var(--muted);margin-top:2px}
.q-status{flex-shrink:0;font-size:11px;font-weight:700;padding:5px 14px;border-radius:8px;border:1px solid var(--glass-border);color:var(--dim);letter-spacing:.3px}
.q-status.done{border-color:var(--green);color:var(--green);background:rgba(16,185,129,.08)}
.q-status.waiting{border-color:var(--gold);color:var(--gold);background:rgba(251,191,36,.08)}

.q-content{font-size:15px;color:var(--text);line-height:1.8;white-space:pre-wrap;margin-bottom:var(--sp-4);word-break:break-word}
.q-image-wrap{margin-bottom:16px;border-radius:8px;overflow:hidden;background:#1a1a1a;border:1px solid #2a2a2a;position:relative}
.q-image-gallery{margin-bottom:16px;position:relative;border-radius:8px;overflow:hidden;background:#1a1a1a;border:1px solid #2a2a2a}
.q-gallery-track{display:flex;overflow-x:auto;scroll-snap-type:x mandatory;-webkit-overflow-scrolling:touch;scrollbar-width:none}
.q-gallery-track::-webkit-scrollbar{display:none}
.q-gallery-item{position:relative;min-width:100%;scroll-snap-align:start;flex-shrink:0;display:flex;align-items:center;justify-content:center;background:#1a1a1a}
.q-gallery-item .q-image{width:100%;height:auto;max-height:70vh;object-fit:contain}
.q-gallery-label{position:absolute;bottom:8px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,.65);color:#fff;font-size:11px;padding:3px 10px;border-radius:10px;pointer-events:none}
.q-gallery-arrows{position:absolute;top:50%;left:0;right:0;display:flex;justify-content:space-between;pointer-events:none;transform:translateY(-50%);padding:0 6px;z-index:4}
.q-gallery-arrow{pointer-events:auto;width:36px;height:36px;border-radius:50%;background:rgba(0,0,0,.55);border:1px solid rgba(255,255,255,.15);color:#fff;font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);transition:all .2s;opacity:.8}
.q-gallery-arrow:hover{opacity:1;background:rgba(0,0,0,.8)}
.q-gallery-arrow:disabled{opacity:0;pointer-events:none}
.q-image{width:100%;display:block;cursor:pointer;transition:opacity .15s}
.q-img-btns{position:absolute;top:8px;right:8px;z-index:5;display:flex;gap:6px}
.q-img-btn{display:flex;align-items:center;gap:5px;padding:7px 12px;font-size:11px;font-weight:600;color:#fff;background:rgba(0,0,0,.65);border:1px solid rgba(255,255,255,.15);border-radius:8px;cursor:pointer;backdrop-filter:blur(8px);transition:all .2s;opacity:.85}
.q-img-btn:hover{opacity:1;background:rgba(0,0,0,.85);border-color:rgba(255,255,255,.3)}
.q-img-btn.copied{background:rgba(70,211,105,.85);border-color:rgba(70,211,105,.5);color:#fff}
.q-img-btn.downloaded{background:rgba(59,130,246,.85);border-color:rgba(59,130,246,.5);color:#fff}
.q-img-btn i{font-size:12px}
.q-image:hover{opacity:.92}
@media(max-width:768px){.q-gallery-arrow{width:30px;height:30px;font-size:12px}.q-gallery-item .q-image{max-height:60vh}}
.q-footer{display:flex;gap:14px;padding-top:14px;border-top:1px solid var(--border);font-size:12px;color:var(--muted);align-items:center}
.q-footer .tag{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;background:var(--bg3);border-radius:3px;font-weight:500}

/* AI Analysis Meta Info Section */
.ai-meta{margin-top:var(--sp-4);padding:var(--sp-5);background:var(--glass-bg);border:1px solid rgba(139,92,246,.12);border-radius:16px;backdrop-filter:blur(12px)}
.ai-meta__header{display:flex;align-items:center;gap:12px;margin-bottom:var(--sp-4);font-size:20px;font-weight:700;color:#A78BFA;font-family:var(--font-display)}
.ai-meta__header i{font-size:22px}
.ai-meta__row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;align-items:center}
.ai-meta__row:last-child{margin-bottom:0}
.ai-meta__label{font-size:18px;font-weight:600;color:var(--muted);min-width:70px;flex-shrink:0}
.ai-meta__stars{display:flex;align-items:center;gap:2px}
.ai-meta__star{font-size:24px;color:#ffd700}
.ai-meta__star.empty{color:#444}
.ai-meta__tags{display:flex;flex-wrap:wrap;gap:5px}
.ai-meta__tag{display:inline-flex;align-items:center;font-size:14px;font-weight:600;color:#A78BFA;background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.15);padding:6px 16px;border-radius:24px;transition:all .2s var(--spring);cursor:default}
.ai-meta__tag:hover{background:rgba(139,92,246,.15);transform:translateY(-1px)}
.ai-meta__info{font-size:20px;color:var(--dim);display:flex;align-items:center;gap:6px}
.ai-meta__info i{font-size:16px;color:var(--muted)}
.ai-meta__desc{font-size:20px;color:var(--dim);line-height:1.7;padding:12px 14px;background:rgba(0,0,0,.15);border-radius:8px;margin-top:6px}
.ai-meta__badge{display:inline-flex;align-items:center;gap:6px;font-size:18px;font-weight:600;padding:6px 14px;border-radius:14px}
.ai-meta__badge--level{background:rgba(255,215,0,.1);color:#ffd700;border:1px solid rgba(255,215,0,.2)}
.ai-meta__badge--time{background:rgba(70,211,105,.1);color:#46d369;border:1px solid rgba(70,211,105,.2)}
.ai-meta__badge--topic{background:rgba(229,9,20,.08);color:#ff6b6b;border:1px solid rgba(229,9,20,.15)}
.ai-meta__analyzing{display:flex;align-items:center;gap:10px;font-size:20px;color:var(--muted);padding:10px 0}
.ai-meta__analyzing i{animation:spin 1s linear infinite}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}

/* AI Section 2 & 3: Question Analysis + Coaching */
.ai-section{margin-top:var(--sp-3);padding:var(--sp-5);border-radius:16px;backdrop-filter:blur(12px)}
.ai-section--question{background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.1)}
.ai-section--coaching{background:rgba(16,185,129,.04);border:1px solid rgba(16,185,129,.1)}
.ai-section__header{display:flex;align-items:center;gap:10px;margin-bottom:16px;font-size:22px;font-weight:700}
.ai-section--question .ai-section__header{color:#60a5fa}
.ai-section--coaching .ai-section__header{color:#34d399}
.ai-section__header i{font-size:22px}
.ai-section__body{font-size:20px;color:var(--text);line-height:1.8;word-break:keep-all}
.ai-section__coaching-text{padding:14px 18px;background:rgba(16,185,129,.05);border-radius:8px;border-left:4px solid rgba(52,211,153,.4);font-style:normal;color:var(--dim)}
.q-level-bar{margin-bottom:14px}
.q-level-label{font-size:15px;color:var(--muted);font-weight:600;margin-bottom:8px}
.q-level-track{display:flex;align-items:center;gap:2px;overflow-x:auto;padding:4px 0}
.q-level-step{display:flex;flex-direction:column;align-items:center;padding:4px 6px;border-radius:8px;border:2px solid transparent;min-width:36px;transition:all .2s}
.q-level-step--active{border-width:2px;font-weight:700}
.q-level-step--past .q-level-emoji,.q-level-step--past .q-level-code{opacity:1}
.q-level-step--future .q-level-emoji{opacity:.3}
.q-level-step--future .q-level-code{opacity:.3}
.q-level-emoji{font-size:18px;line-height:1}
.q-level-code{font-size:12px;color:var(--dim);margin-top:1px}
.q-level-step--active .q-level-code{color:var(--text);font-weight:700}
.q-level-name{font-size:12px;color:var(--text);font-weight:700;white-space:nowrap;margin-top:1px}
.q-level-arrow{font-size:12px;color:var(--muted);opacity:.4;flex-shrink:0}
.q-level-arrow--past{opacity:.8}
.gi-select-btn:hover{background:rgba(255,255,255,.08)!important;border-color:rgba(165,180,252,.4)!important;transform:translateY(-1px)}
.next-q-wrap{margin-top:14px;padding:0}
.next-q-title{font-size:15px;font-weight:700;color:#fbbf24;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.next-q-card{background:rgba(255,255,255,.04);border-radius:10px;padding:12px 14px;margin-bottom:8px}
.next-q-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;margin-bottom:6px}
.next-q-text{font-size:15px;font-weight:600;color:var(--text);line-height:1.5;margin-bottom:4px}
.next-q-why{font-size:12px;color:var(--muted);line-height:1.4}

/* Growth Coaching Interactive UI */
.gc-wrap{margin-top:12px}
.gc-step{display:none;animation:gcFadeIn .3s ease}
.gc-step.active{display:block}
@keyframes gcFadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.gc-card{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-bottom:10px}
.gc-card__title{font-size:17px;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:6px}
.gc-card__body{font-size:16px;color:var(--text);line-height:1.7}
.gc-card__q{font-size:17px;font-weight:700;color:#fbbf24;margin-top:8px}
.gc-btns{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.gc-btn{padding:12px 20px;font-size:15px;font-weight:700;border:none;border-radius:10px;cursor:pointer;transition:all .15s;flex:1;min-width:100px;text-align:center}
.gc-btn--yes{background:rgba(52,211,153,.15);color:#34d399;border:1px solid rgba(52,211,153,.3)}
.gc-btn--yes:hover{background:rgba(52,211,153,.25)}
.gc-btn--no{background:rgba(248,113,113,.15);color:#f87171;border:1px solid rgba(248,113,113,.3)}
.gc-btn--no:hover{background:rgba(248,113,113,.25)}
.gc-btn--choice{background:rgba(96,165,250,.1);color:#60a5fa;border:1px solid rgba(96,165,250,.2);flex:none;min-width:auto;padding:12px 16px;font-size:15px}
.gc-btn--choice:hover{background:rgba(96,165,250,.2)}
.gc-btn--next{background:rgba(251,191,36,.15);color:#fbbf24;border:1px solid rgba(251,191,36,.3)}
.gc-btn--next:hover{background:rgba(251,191,36,.25)}
.gc-hint{padding:14px 16px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.15);border-radius:8px;margin-top:10px;font-size:15px;color:#fbbf24;line-height:1.6}
.gc-bridge{padding:14px;background:rgba(167,139,250,.06);border:1px solid rgba(167,139,250,.15);border-radius:10px;margin-top:10px}
.gc-bridge__step{font-size:15px;color:var(--text);line-height:1.8;padding-left:4px}
.gc-bridge__conn{font-size:16px;font-weight:700;color:#a78bfa;margin-top:8px}
.gc-progress{display:flex;gap:4px;margin-bottom:12px}
.gc-progress__dot{width:100%;height:3px;border-radius:2px;background:var(--border);transition:background .3s}
.gc-progress__dot.done{background:#34d399}
.gc-progress__dot.active{background:#fbbf24}

/* Coaching Review Timeline */
.gc-review-timeline{margin-top:10px;padding:0}
.gc-review-step{display:flex;align-items:flex-start;gap:10px;padding:8px 0;position:relative}
.gc-review-step:not(:last-child):after{content:'';position:absolute;left:13px;top:30px;bottom:0;width:2px;background:rgba(255,255,255,.1)}
.gc-review-dot{width:26px;height:26px;min-width:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;z-index:1}
.gc-review-dot--select{background:linear-gradient(135deg,#fbbf24,#f59e0b);color:#1a1a2e}
.gc-review-dot--wa{background:linear-gradient(135deg,#f472b6,#ec4899);color:#fff}
.gc-review-dot--hint{background:linear-gradient(135deg,#a78bfa,#8b5cf6);color:#fff}
.gc-review-dot--choice{background:linear-gradient(135deg,#60a5fa,#3b82f6);color:#fff}
.gc-review-dot--bridge{background:linear-gradient(135deg,#34d399,#10b981);color:#fff}
.gc-review-content{flex:1;min-width:0}
.gc-review-label{font-size:12px;color:var(--muted);font-weight:600;margin-bottom:2px}
.gc-review-choice{font-size:14px;color:var(--text);line-height:1.5}
.gc-review-time{font-size:10px;color:var(--muted);margin-top:2px}

/* Drag divider for split panel */
.split-divider{width:6px;cursor:col-resize;background:var(--glass-border);position:relative;flex-shrink:0;transition:background .2s;z-index:10}
.split-divider:hover,.split-divider.active{background:rgba(139,92,246,.4)}
.split-divider::after{content:'';position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:2px;height:36px;background:rgba(255,255,255,.2);border-radius:1px}
.split-divider:hover::after{background:rgba(139,92,246,.6)}

/* Right panel: answers */
.ans-header{font-size:17px;font-weight:800;color:var(--white);padding:0 0 16px;display:flex;align-items:center;gap:8px}
.ans-header .cnt{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:22px;background:var(--accent-gradient);color:#fff;font-size:11px;font-weight:700;border-radius:11px;padding:0 7px}

/* Answer card — Orzo tutor answer style */
.ans-card{background:rgba(28,35,51,0.92);border:1px solid rgba(255,255,255,0.12);border-radius:16px;margin-bottom:var(--sp-4);overflow:hidden;transition:all .2s var(--spring);backdrop-filter:blur(12px);box-shadow:0 2px 12px rgba(0,0,0,0.25)}
.ans-card:hover{border-color:rgba(255,255,255,.2);transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,0,0,0.35)}
.ans-card.accepted{border-color:rgba(16,185,129,.3);background:rgba(16,185,129,.04);box-shadow:0 0 24px rgba(16,185,129,.1)}

.ans-card-head{display:flex;align-items:center;gap:12px;padding:16px 20px;border-bottom:1px solid rgba(255,255,255,0.08)}
.ans-card .ans-avatar{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#2a4a3a,#3a5a4a);display:flex;align-items:center;justify-content:center;color:#88cc99;font-size:14px;flex-shrink:0;box-shadow:0 2px 8px rgba(45,212,168,0.15)}
.ans-card .ans-meta{flex:1;min-width:0}
.ans-card .ans-name{font-size:14px;font-weight:700;color:var(--white);display:flex;align-items:center;gap:6px}
.ans-card .ans-grade{font-size:11px;color:var(--dim);font-weight:600;background:var(--bg3);padding:2px 8px;border-radius:4px}
.ans-card .ans-time{font-size:12px;color:var(--dim);margin-top:2px}
.ans-badge{flex-shrink:0;font-size:10px;font-weight:700;color:var(--green);border:1px solid var(--green);padding:3px 10px;border-radius:4px;display:flex;align-items:center;gap:4px;background:rgba(70,211,105,.08)}

.ans-card-body{padding:18px 20px}
.ans-section{margin-bottom:14px}
.ans-section:last-child{margin-bottom:0}
.ans-section-title{font-size:12px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.ans-section-title i{font-size:10px;color:var(--dim)}
.ans-content{font-size:15px;line-height:1.8;color:var(--white);white-space:pre-wrap;word-break:break-word;font-weight:400;letter-spacing:.01em}
.ans-img-wrap{border-radius:8px;overflow:hidden;background:#1a1a1a;margin-top:8px;border:1px solid #2a2a2a}
.ans-img{width:100%;display:block;cursor:pointer;transition:opacity .15s}
.ans-img:hover{opacity:.92}

/* Answer interaction bar */
.ans-actions{display:flex;align-items:center;gap:12px;padding:12px 20px;border-top:1px solid rgba(255,255,255,0.08)}
.ans-act-btn{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--dim);background:none;border:none;cursor:pointer;padding:5px 10px;border-radius:6px;transition:all .15s}
.ans-act-btn:hover{background:var(--bg3);color:var(--dim)}
.ans-del-btn:hover{color:#e55;background:rgba(238,85,85,.1)}
.ans-act-btn.active-reply{color:var(--green);background:rgba(70,211,105,.1)}
.ans-accept-btn{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--green);background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);cursor:pointer;padding:6px 14px;border-radius:10px;font-weight:600;transition:all .2s var(--spring);margin-left:auto}
.ans-accept-btn:hover{background:rgba(16,185,129,.15);border-color:rgba(16,185,129,.4);transform:scale(1.03)}

/* Acceptance review section on accepted answer card */
.accept-review{margin:0 16px 14px;padding:14px;background:rgba(70,211,105,.04);border:1px solid rgba(70,211,105,.15);border-radius:10px}
.accept-review-title{font-size:12px;font-weight:700;color:var(--green);margin-bottom:10px;display:flex;align-items:center;gap:6px}
.accept-review-tags{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.accept-review-tag{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--dim);background:var(--bg3);padding:4px 10px;border-radius:20px}
.accept-review-text{font-size:14px;color:rgba(240,246,252,0.85);line-height:1.65;white-space:pre-wrap;margin-top:8px;padding-top:8px;border-top:1px solid var(--border)}

/* Accept modal */
.accept-modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.7);z-index:10010;display:flex;align-items:center;justify-content:center;padding:20px;backdrop-filter:blur(4px)}
.accept-modal{background:var(--bg2);border:1px solid var(--border);border-radius:16px;max-width:420px;width:100%;max-height:90vh;overflow-y:auto;padding:0;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.accept-modal-header{padding:20px 24px 16px;border-bottom:1px solid var(--border);text-align:center}
.accept-modal-header h3{font-size:17px;font-weight:700;color:var(--white);margin-bottom:4px}
.accept-modal-header p{font-size:12px;color:var(--muted)}
.accept-modal-body{padding:20px 24px}
.accept-tag-list{display:flex;flex-direction:column;gap:6px;margin-bottom:20px}
.accept-tag-item{display:flex;align-items:center;gap:12px;padding:12px 14px;border-radius:10px;border:1px solid var(--border);cursor:pointer;transition:all .15s;background:var(--bg3)}
.accept-tag-item:hover{border-color:#555;background:rgba(255,255,255,.05)}
.accept-tag-item.selected{border-color:var(--green);background:rgba(70,211,105,.08)}
.accept-tag-item .tag-emoji{font-size:22px;flex-shrink:0;width:32px;text-align:center}
.accept-tag-item .tag-text{font-size:13px;color:var(--dim);flex:1}
.accept-tag-item .tag-check{width:20px;height:20px;border-radius:50%;border:2px solid #555;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:11px;color:transparent;transition:all .15s}
.accept-tag-item.selected .tag-check{border-color:var(--green);background:var(--green);color:#fff}
.accept-review-input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--dim);font-size:13px;padding:12px;resize:none;min-height:70px;font-family:inherit;transition:border-color .15s}
.accept-review-input:focus{outline:none;border-color:var(--green)}
.accept-review-input::placeholder{color:#555}
.accept-modal-footer{padding:14px 24px 20px;display:flex;gap:10px}
.accept-modal-footer button{flex:1;padding:12px;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:all .15s;border:none}
.accept-cancel-btn{background:var(--bg3);color:var(--dim)}
.accept-cancel-btn:hover{background:#444}
.accept-confirm-btn{background:var(--green);color:#fff}
.accept-confirm-btn:hover{background:#3bc35e}
.accept-confirm-btn:disabled{opacity:.4;cursor:not-allowed}

/* Reply (대댓글) styles */
.reply-section{padding:0 16px 12px}
.reply-toggle{font-size:11px;color:var(--muted);background:none;border:none;cursor:pointer;padding:4px 0;display:flex;align-items:center;gap:4px;transition:color .15s}
.reply-toggle:hover{color:var(--dim)}
.reply-list{margin-top:8px}
.reply-item{display:flex;gap:8px;padding:8px 0;border-top:1px solid rgba(255,255,255,.04)}
.reply-item:first-child{border-top:none}
.reply-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#2a2a4a,#3a3a5a);display:flex;align-items:center;justify-content:center;color:#9999cc;font-size:10px;flex-shrink:0;margin-top:2px}
.reply-body{flex:1;min-width:0}
.reply-head{display:flex;align-items:center;gap:6px;margin-bottom:2px}
.reply-name{font-size:12px;font-weight:700;color:var(--white)}
.reply-grade{font-size:9px;color:var(--muted);background:var(--bg3);padding:1px 5px;border-radius:2px}
.reply-time{font-size:10px;color:var(--muted);margin-left:auto}
.reply-del{font-size:10px;color:#ff6b6b;background:none;border:none;cursor:pointer;padding:0 4px;opacity:.6;transition:opacity .15s}
.reply-del:hover{opacity:1}
.reply-text{font-size:13px;color:rgba(240,246,252,0.85);line-height:1.65;word-break:break-word}
.reply-input-row{display:flex;gap:6px;margin-top:8px;align-items:center}
.reply-input{flex:1;min-width:0;padding:7px 12px;font-size:12px;border:1px solid var(--border);border-radius:16px;background:#1e1e1e;color:var(--white);outline:none;transition:border-color .15s}
.reply-input:focus{border-color:var(--muted)}
.reply-input::placeholder{color:var(--muted)}
.reply-send{width:28px;height:28px;border-radius:50%;background:var(--green);border:none;color:#111;display:flex;align-items:center;justify-content:center;font-size:11px;cursor:pointer;flex-shrink:0;transition:opacity .15s}
.reply-send:hover{opacity:.85}
.reply-send:disabled{opacity:.3}
.reply-count{font-size:10px;color:var(--muted);margin-left:2px}

/* Bottom bar — KakaoTalk-style chat input */
.bottom-bar{position:fixed;bottom:0;left:0;right:0;min-height:56px;background:rgba(11,14,20,.95);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-top:1px solid var(--glass-border);display:flex;align-items:flex-end;gap:var(--sp-2);padding:10px var(--sp-3);z-index:100;padding-bottom:calc(10px + env(safe-area-inset-bottom))}
.bottom-bar .bb-draw-btn{flex-shrink:0;display:flex;align-items:center;gap:6px;padding:10px 16px;font-size:13px;font-weight:600;color:var(--dim);background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:16px;transition:all .2s var(--spring);white-space:nowrap;margin-bottom:1px}
.bottom-bar .bb-draw-btn:hover{border-color:rgba(255,255,255,.2);color:var(--white)}
.bottom-bar .bb-draw-btn.active{background:var(--green);color:#fff;border-color:var(--green)}
/* Chat input wrapper — contains input + image btn inside like KakaoTalk */
.bb-input-wrap{flex:1;min-width:0;display:flex;align-items:flex-end;border:1px solid var(--glass-border);border-radius:22px;background:rgba(255,255,255,.04);padding:2px 4px 2px 16px;transition:all .2s;gap:4px;backdrop-filter:blur(8px)}
.bb-input-wrap:focus-within{border-color:var(--accent);box-shadow:var(--focus-ring)}
.bb-input-wrap .bb-input{flex:1;min-width:0;padding:7px 0;font-size:13px;border:none;background:transparent;color:var(--white);outline:none}
.bb-input-wrap .bb-input::placeholder{color:var(--muted)}
/* Image button inside the input wrap */
.bb-input-wrap .bb-img-btn{flex-shrink:0;width:32px;height:32px;border-radius:50%;background:none;border:none;color:var(--muted);display:flex;align-items:center;justify-content:center;font-size:14px;cursor:pointer;transition:color .15s;margin-bottom:1px}
.bb-input-wrap .bb-img-btn:hover{color:var(--dim)}
.bb-input-wrap .bb-img-btn.has-img{color:var(--green)}

/* Mic button inside input wrap */
.bb-mic-btn{flex-shrink:0;width:32px;height:32px;border-radius:50%;background:none;border:none;color:var(--muted);display:flex;align-items:center;justify-content:center;font-size:14px;cursor:pointer;transition:all .15s;margin-bottom:1px}
.bb-mic-btn:hover{color:var(--dim)}
.bb-mic-btn.recording{color:#ff4444;animation:pulse-mic 1s ease-in-out infinite}
.bb-mic-btn.has-voice{color:#ff6b6b}
@keyframes pulse-mic{0%,100%{transform:scale(1)}50%{transform:scale(1.2)}}

/* ========== ClassIn-Style Voice Recording — Bottom Bar ========== */
/* Recording bar: fixed at bottom, red strip */
.voice-rec-bar{position:fixed;bottom:0;left:0;right:0;z-index:200;display:none;flex-direction:column;animation:slideUpBar .25s ease-out}
@keyframes slideUpBar{from{transform:translateY(100%)}to{transform:translateY(0)}}
/* Main red strip */
.voice-rec-strip{background:linear-gradient(90deg,#e53935,#ff5252);display:flex;align-items:center;padding:10px 16px;gap:12px;min-height:48px}
.voice-rec-strip__icon{width:28px;height:28px;border-radius:50%;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;flex-shrink:0;animation:pulse-mic 1.2s ease-in-out infinite}
.voice-rec-strip__timer{font-size:16px;font-weight:700;color:#fff;font-family:'SF Mono',Menlo,monospace;letter-spacing:1px;min-width:48px}
.voice-rec-strip__wave{flex:1;height:28px;min-width:0}
.voice-rec-strip__wave canvas{width:100%;height:100%;border-radius:4px}
.voice-rec-strip__btn{width:32px;height:32px;border-radius:50%;border:none;display:flex;align-items:center;justify-content:center;font-size:13px;cursor:pointer;flex-shrink:0;transition:all .12s}
.voice-rec-strip__btn:hover{transform:scale(1.1)}
.voice-rec-strip__btn--pause{background:rgba(255,255,255,.25);color:#fff}
.voice-rec-strip__btn--resume{background:rgba(255,255,255,.25);color:#fff}
.voice-rec-strip__btn--stop{background:#fff;color:#e53935;font-size:14px}
.voice-rec-strip__btn--cancel{background:rgba(255,255,255,.15);color:rgba(255,255,255,.7);font-size:11px}
/* Paused state */
.voice-rec-bar.paused .voice-rec-strip{background:linear-gradient(90deg,#f59e0b,#fbbf24)}
.voice-rec-bar.paused .voice-rec-strip__icon{animation:none}

/* Preview bar (after recording) */
.voice-preview-bar{background:rgba(20,20,30,.97);backdrop-filter:blur(8px);border-top:1px solid rgba(255,255,255,.08);display:none;align-items:center;padding:10px 16px;gap:10px}
.voice-prev-play{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#6c5ce7,#a29bfe);border:none;color:#fff;font-size:13px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .12s}
.voice-prev-play:hover{transform:scale(1.05)}
.voice-prev-play.playing{background:linear-gradient(135deg,#fbbf24,#f59e0b)}
.voice-prev-info{flex:1;min-width:0}
.voice-prev-progress{width:100%;height:3px;background:rgba(255,255,255,.1);border-radius:2px;cursor:pointer;margin-bottom:4px}
.voice-prev-progress__fill{height:100%;background:linear-gradient(90deg,#6c5ce7,#a29bfe);border-radius:2px;width:0%;transition:width .1s linear}
.voice-prev-times{display:flex;justify-content:space-between;font-size:10px;color:rgba(255,255,255,.35);font-family:monospace}
.voice-prev-btn{padding:7px 16px;border-radius:20px;border:none;font-size:12px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:4px;transition:all .12s;flex-shrink:0}
.voice-prev-btn--redo{background:rgba(255,255,255,.08);color:rgba(255,255,255,.6)}
.voice-prev-btn--redo:hover{background:rgba(255,255,255,.15);color:#fff}
.voice-prev-btn--confirm{background:linear-gradient(135deg,#00b894,#00cec9);color:#fff}
.voice-prev-btn--confirm:hover{opacity:.9}
.voice-prev-close{width:32px;height:32px;border-radius:50%;border:none;background:rgba(255,255,255,.08);color:rgba(255,255,255,.5);font-size:14px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .12s;margin-left:2px}
.voice-prev-close:hover{background:rgba(255,68,68,.2);color:#ff4444;transform:scale(1.1)}
.voice-prev-btn--confirm:disabled{opacity:.4;cursor:not-allowed}

/* === Voice preview in answer input area (Step 5) === */
.voice-preview{display:flex;align-items:center;gap:10px;padding:10px 14px;background:linear-gradient(135deg,rgba(108,92,231,.08),rgba(162,155,254,.05));border:1px solid rgba(108,92,231,.2);border-radius:12px;margin:8px 16px 0}
.voice-preview__icon{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#6c5ce7,#a29bfe);display:flex;align-items:center;justify-content:center;color:#fff;font-size:14px;flex-shrink:0}
.voice-preview__info{flex:1;min-width:0}
.voice-preview__label{font-size:12px;font-weight:600;color:#a29bfe;margin-bottom:2px}
.voice-preview__duration{font-size:11px;color:rgba(255,255,255,.4);font-family:monospace}
.voice-preview__play{width:28px;height:28px;border-radius:50%;background:rgba(108,92,231,.15);border:1px solid rgba(108,92,231,.3);color:#a29bfe;font-size:11px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .15s}
.voice-preview__play:hover{background:rgba(108,92,231,.25)}
.voice-preview__remove{width:24px;height:24px;border-radius:50%;background:rgba(255,70,70,.15);color:#ff6b6b;border:1px solid rgba(255,70,70,.2);font-size:10px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .15s}
.voice-preview__remove:hover{background:rgba(255,70,70,.3)}

/* === Voice player in answer cards === */
.ans-voice{margin-top:10px;padding:12px 14px;background:linear-gradient(135deg,rgba(108,92,231,.06),rgba(162,155,254,.03));border:1px solid rgba(108,92,231,.12);border-radius:12px}
.ans-voice__header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.ans-voice__icon{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#6c5ce7,#a29bfe);display:flex;align-items:center;justify-content:center;color:#fff;font-size:12px;flex-shrink:0}
.ans-voice__label{font-size:13px;font-weight:600;color:#a29bfe}
.ans-voice__duration{font-size:11px;color:rgba(255,255,255,.4);font-family:monospace;margin-left:auto}
.ans-voice-player{display:flex;align-items:center;gap:10px}
.ans-voice-play{width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#6c5ce7,#a29bfe);border:none;color:#fff;font-size:14px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .15s}
.ans-voice-play:hover{transform:scale(1.05);box-shadow:0 2px 10px rgba(108,92,231,.3)}
.ans-voice-play.playing{background:linear-gradient(135deg,#fbbf24,#f59e0b)}
.ans-voice-progress{flex:1;height:4px;background:rgba(255,255,255,.08);border-radius:2px;cursor:pointer;position:relative}
.ans-voice-progress__fill{height:100%;background:linear-gradient(90deg,#6c5ce7,#a29bfe);border-radius:2px;width:0%;transition:width .1s linear}
.ans-voice-times{display:flex;justify-content:space-between;font-size:10px;color:rgba(255,255,255,.35);font-family:monospace;margin-top:4px}
/* Inline image preview inside input area */
.bb-img-preview{position:relative;margin:4px 0 4px 0;max-width:120px}
.bb-img-preview img{width:100%;border-radius:8px;display:block}
.bb-img-preview .bb-img-remove{position:absolute;top:-6px;right:-6px;width:20px;height:20px;border-radius:50%;background:rgba(255,70,70,.9);color:#fff;border:none;font-size:9px;display:flex;align-items:center;justify-content:center;cursor:pointer}
/* Send button */
.bottom-bar .bb-send{flex-shrink:0;width:40px;height:40px;border-radius:50%;background:var(--accent-gradient);border:none;color:#fff;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .2s var(--spring);margin-bottom:1px;box-shadow:0 4px 12px rgba(139,92,246,.3)}
.bottom-bar .bb-send:hover{transform:scale(1.05);box-shadow:0 6px 16px rgba(139,92,246,.4)}
.bottom-bar .bb-send:active{transform:scale(0.9)}
.bottom-bar .bb-send:disabled{opacity:.3}

/* Empty state & misc */
.ans-empty{text-align:center;padding:48px 20px;color:var(--muted)}
.ans-empty i{font-size:32px;margin-bottom:12px;display:block;color:#444}
.ans-empty p{font-size:13px;line-height:1.6}

.ans-login-prompt{text-align:center;padding:32px 0}
.ans-login-btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;font-size:14px;font-weight:600;color:#fff;background:var(--accent-gradient);border:none;border-radius:14px;transition:all .2s var(--spring);box-shadow:0 4px 12px rgba(139,92,246,.3)}
.ans-login-btn:hover{transform:translateY(-2px);box-shadow:0 6px 16px rgba(139,92,246,.4)}

/* Previews in right panel */
.preview-section{margin:16px 0;padding:12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px}
.preview-section img{max-width:100%;border-radius:6px}
.preview-section .preview-label{font-size:11px;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:4px}
.preview-remove-btn{font-size:11px;color:#ff6b6b;background:none;border:none;cursor:pointer;margin-left:auto}

/* Responsive: stack vertically on narrow screens */
@media(max-width:700px){
  .split-container{flex-direction:column}
  .split-left{width:100%!important;max-width:none;min-width:auto;border-right:none;border-bottom:1px solid var(--glass-border);max-height:40vh}
  .split-divider{display:none}
  .split-right{flex:1;min-height:0}
}

/* ====== ORZO-STYLE FULLSCREEN DRAWING MODE ====== */
/* === Drawing Overlay: Glass-morphism Dark Theme === */
.draw-overlay{position:fixed;inset:0;z-index:10000;background:#1a1a2e;display:flex;flex-direction:column;overflow:hidden}
.draw-overlay{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent}
.draw-overlay *{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
/* Top toolbar: glass-morphism dark bar */
.draw-topbar{display:flex;align-items:center;gap:0;padding:0;background:rgba(15,15,30,.85);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border-bottom:1px solid rgba(255,255,255,.08);flex-shrink:0;z-index:10;height:52px;min-height:52px}
.draw-topbar .dt-group{display:flex;align-items:center;gap:2px;padding:0 6px;height:100%}
.draw-topbar .dt-sep{width:1px;height:28px;background:rgba(255,255,255,.1);margin:0;flex-shrink:0}
.draw-topbar .dt-btn{width:40px;height:40px;border-radius:10px;background:none;border:none;color:rgba(255,255,255,.55);font-size:16px;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .2s cubic-bezier(.34,1.56,.64,1)}
.draw-topbar .dt-btn:hover{background:rgba(255,255,255,.1);color:rgba(255,255,255,.85)}
.draw-topbar .dt-btn:active{background:rgba(255,255,255,.15);transform:scale(.93)}
.draw-topbar .dt-btn.active{background:rgba(139,92,246,.35);color:#fff;box-shadow:0 0 12px rgba(139,92,246,.25),inset 0 0 0 1px rgba(139,92,246,.4)}
.draw-topbar .dt-btn.active[data-tool="eraser"]{background:rgba(255,107,107,.3);color:#ff6b6b;box-shadow:0 0 12px rgba(255,107,107,.2),inset 0 0 0 1px rgba(255,107,107,.35)}
.draw-topbar .dt-btn:disabled{opacity:.25;cursor:default}
/* Color circles */
.draw-topbar .dt-color{width:28px;height:28px;border-radius:50%;cursor:pointer;border:3px solid transparent;flex-shrink:0;transition:all .2s cubic-bezier(.34,1.56,.64,1);box-shadow:0 2px 6px rgba(0,0,0,.3)}
.draw-topbar .dt-color.active{border-color:rgba(255,255,255,.9);transform:scale(1.2);box-shadow:0 0 0 2px rgba(139,92,246,.4),0 2px 8px rgba(0,0,0,.4)}
.draw-topbar .dt-color-plus{width:28px;height:28px;border-radius:50%;cursor:pointer;border:2px dashed rgba(255,255,255,.25);background:none;display:flex;align-items:center;justify-content:center;font-size:12px;color:rgba(255,255,255,.4);flex-shrink:0}
/* (Slider removed — replaced by 3 fixed width buttons) */
.draw-topbar .dt-label{font-size:11px;color:rgba(255,255,255,.5);min-width:22px;text-align:center;flex-shrink:0;font-weight:600}
.draw-topbar .spacer{flex:1;min-width:4px}
/* Action buttons */
.draw-done-btn{padding:8px 20px;border-radius:10px;background:var(--accent-gradient,linear-gradient(135deg,#8B5CF6,#06B6D4));color:#fff;border:none;font-size:14px;font-weight:700;cursor:pointer;white-space:nowrap;transition:all .2s cubic-bezier(.34,1.56,.64,1);box-shadow:0 4px 16px rgba(139,92,246,.35)}
.draw-done-btn:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(139,92,246,.45)}
.draw-close-btn{padding:8px 14px;border-radius:10px;background:rgba(255,255,255,.08);color:rgba(255,255,255,.7);border:1px solid rgba(255,255,255,.1);font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .15s}
.draw-close-btn:hover{background:rgba(255,255,255,.14);color:#fff}

/* Canvas area — CRITICAL: block all iOS text selection & callout menus */
.draw-canvas-area{flex:1;overflow:auto;-webkit-overflow-scrolling:touch;background:#2a2a3e;position:relative;
  -webkit-user-select:none;user-select:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent}
.draw-canvas-inner{position:relative;-webkit-user-select:none;user-select:none;will-change:transform}
.draw-canvas-inner canvas{display:block;touch-action:none;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
#bgCanvas{position:relative;z-index:0;pointer-events:none}
#drawCanvas{position:absolute;top:0;left:0;z-index:1}
#tempCanvas{position:absolute;top:0;left:0;z-index:2;pointer-events:none}

/* Zoom bar: glass pill */
.draw-zoom-bar{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:10001;display:flex;gap:2px;background:rgba(15,15,30,.8);backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);padding:4px 6px;border-radius:24px;border:1px solid rgba(255,255,255,.08)}
.draw-zoom-bar button{width:34px;height:34px;border-radius:50%;background:transparent;border:none;color:rgba(255,255,255,.7);font-size:14px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .15s}
.draw-zoom-bar button:hover{background:rgba(255,255,255,.12);color:#fff}
.draw-zoom-bar span{font-size:12px;color:rgba(255,255,255,.6);display:flex;align-items:center;min-width:44px;justify-content:center;font-weight:600;font-family:'Outfit','Pretendard',sans-serif}

/* Tool-specific active styles */
.draw-topbar .dt-btn.active[data-tool="scissors"]{background:rgba(22,163,74,.3);color:#4ade80;box-shadow:0 0 12px rgba(22,163,74,.2),inset 0 0 0 1px rgba(22,163,74,.35)}
.draw-topbar .dt-btn.active[data-tool="select"]{background:rgba(37,99,235,.3);color:#60a5fa;box-shadow:0 0 12px rgba(37,99,235,.2),inset 0 0 0 1px rgba(37,99,235,.35)}
.draw-topbar .dt-btn.active[data-tool="text"]{background:rgba(245,158,11,.3);color:#fbbf24;box-shadow:0 0 12px rgba(245,158,11,.2),inset 0 0 0 1px rgba(245,158,11,.35)}
.select-delete-btn{position:absolute;z-index:10001;background:#e50914;color:#fff;border:none;border-radius:50%;width:28px;height:28px;font-size:13px;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 2px 8px rgba(0,0,0,.3);transform:translate(-50%,-120%)}
.text-input-box{position:relative;z-index:10002;display:block;width:100%;min-width:80px;min-height:32px;padding:6px 10px;border:1.5px dashed rgba(180,180,180,.7);border-radius:2px;background:transparent;color:#222;font-size:18px;font-family:'Pretendard',-apple-system,sans-serif;outline:none;resize:none;overflow:hidden;line-height:1.4;white-space:pre-wrap;word-break:break-word;box-sizing:border-box}
.text-input-box::placeholder{color:rgba(150,150,150,.6)}
.text-input-box:focus{border-color:rgba(150,150,150,.9)}
.text-toolbar{position:relative;z-index:10003;display:flex;align-items:center;gap:2px;background:rgba(15,15,30,.9);padding:6px 10px;border-radius:22px;backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);box-shadow:0 4px 20px rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.08);margin-top:8px;width:fit-content}
.text-toolbar button,.text-toolbar select{background:transparent;border:none;color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background .15s}
.text-toolbar button{width:32px;height:32px;border-radius:50%;font-size:14px}
.text-toolbar button:hover{background:rgba(255,255,255,.12)}
.text-toolbar button.active{background:rgba(139,92,246,.3)}
.text-toolbar .tt-close{width:28px;height:28px;border-radius:50%;background:rgba(255,255,255,.08);font-size:12px}
.text-toolbar .tt-divider{width:1px;height:20px;background:rgba(255,255,255,.1);margin:0 4px}
.text-toolbar .tt-size-select{appearance:none;background:transparent;color:#fff;font-size:14px;font-weight:600;padding:4px 8px;border:none;outline:none;cursor:pointer;min-width:36px;text-align:center}
.text-toolbar .tt-size-select option{background:#1a1a2e;color:#fff}

/* Floating object context menu */
.float-ctx-menu{position:absolute;z-index:10003;display:flex;gap:2px;background:rgba(15,15,30,.85);padding:4px 6px;border-radius:16px;backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%);border:1px solid rgba(255,255,255,.08)}
.float-ctx-menu button{width:32px;height:32px;border-radius:50%;background:transparent;border:none;color:rgba(255,255,255,.8);font-size:13px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .15s}
.float-ctx-menu button:hover{background:rgba(255,255,255,.15)}

/* Width selector buttons (3 fixed sizes) */
.dt-width-group{gap:3px!important}
.dt-width-btn{width:36px;height:36px;border-radius:10px;background:none;border:1px solid transparent;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:all .2s cubic-bezier(.34,1.56,.64,1)}
.dt-width-btn:hover{background:rgba(255,255,255,.1)}
.dt-width-btn.active{background:rgba(139,92,246,.3);border-color:rgba(139,92,246,.5);box-shadow:0 0 10px rgba(139,92,246,.2)}
.dt-width-dot{border-radius:50%;background:rgba(255,255,255,.85);flex-shrink:0;transition:transform .15s}
.dt-width-btn.active .dt-width-dot{background:#fff;box-shadow:0 0 6px rgba(255,255,255,.4)}
/* Eraser cursor (stroke-based) */
.eraser-cursor{position:absolute;pointer-events:none;border:2px solid rgba(255,107,107,.5);border-radius:50%;z-index:10003;box-shadow:0 0 8px rgba(255,107,107,.15)}

.preview-wrap{position:relative;margin:12px 0}
.preview-wrap img{max-width:100%;border-radius:6px}
.preview-remove{position:absolute;top:8px;right:8px;width:28px;height:28px;border-radius:50%;background:rgba(0,0,0,.7);color:var(--white);border:none;font-size:11px;display:flex;align-items:center;justify-content:center}

.img-modal{position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;padding:20px;animation:cmFadeIn .2s ease;backdrop-filter:blur(8px)}
.img-modal img{max-width:100%;max-height:90vh;border-radius:12px;box-shadow:0 24px 80px rgba(0,0,0,.5)}
.img-modal__spinner{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%)}
.img-modal__close{position:absolute;top:20px;right:20px;background:var(--glass-bg);border:1px solid var(--glass-border);color:#fff;width:44px;height:44px;border-radius:50%;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s var(--spring);z-index:1;backdrop-filter:blur(8px)}
.img-modal__close:hover{background:rgba(255,255,255,.2);transform:scale(1.1)}

.loading{text-align:center;padding:40px 0;color:var(--muted);font-size:13px}
.empty{text-align:center;padding:40px 0;color:var(--muted);font-size:14px}

@media(max-width:768px){
  .draw-topbar{height:48px;min-height:48px;flex-wrap:nowrap}
  .draw-topbar .dt-tools-scroll{display:flex;align-items:center;gap:0;overflow-x:auto;flex:1;min-width:0;-webkit-overflow-scrolling:touch;scrollbar-width:none}
  .draw-topbar .dt-tools-scroll::-webkit-scrollbar{display:none}
  .draw-topbar .dt-actions{display:flex;align-items:center;gap:6px;padding:0 8px;flex-shrink:0;border-left:1px solid rgba(255,255,255,.1)}
  .draw-topbar .dt-btn{width:36px;height:36px;font-size:14px;border-radius:8px}
  .draw-topbar .dt-color{width:24px;height:24px}
  .draw-topbar .dt-group{gap:1px;padding:0 4px}
  .dt-width-btn{width:32px;height:32px}
}
@media(min-width:768px){
  .draw-topbar .dt-tools-scroll{display:flex;align-items:center;gap:0;flex:1;min-width:0}
  .draw-topbar .dt-actions{display:flex;align-items:center;gap:6px;padding:0 8px;flex-shrink:0}
  .draw-topbar .dt-btn{width:44px;height:44px;font-size:17px}
  .draw-topbar .dt-color{width:30px;height:30px}
  .draw-topbar{height:56px;min-height:56px}
  .dt-width-btn{width:40px;height:40px}
}
</style>
</head>
<body>
<!-- Fixed top nav -->
<div class="detail-nav">
  <div class="detail-nav__left">
    <a onclick="history.back()" class="detail-nav__back" style="cursor:pointer"><i class="fas fa-arrow-left"></i></a>
    <a href="/" class="detail-nav__home" title="홈으로"><i class="fas fa-home"></i></a>
  </div>
  <div class="detail-nav__user" id="navUser"></div>
</div>
<!-- CP Toast -->
<div id="cpToast" class="cp-toast"></div>

<!-- Orzo-style split layout: Left=Question, Right=Answers -->
<div class="split-container" id="splitContainer">
  <div class="split-left" id="splitLeft">
    <div class="q-panel-inner" id="questionSection"><div class="loading">불러오는 중...</div></div>
  </div>
  <div class="split-divider" id="splitDivider"></div>
  <div class="split-right" id="splitRight">
    <div class="ans-header">답변 <span class="cnt" id="answerCount">0</span></div>
    <!-- 1:1 코칭 신청 버튼 (질문자 본인 + 대기중 상태일 때만 표시) -->
    <div id="coachingRequestArea" style="display:none;margin-bottom:16px">
      <div style="background:linear-gradient(135deg,rgba(124,106,239,.1),rgba(6,182,212,.08));border:1px solid rgba(124,106,239,.25);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:14px">
        <div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);display:flex;align-items:center;justify-content:center;flex-shrink:0">
          <i class="fas fa-chalkboard-teacher" style="color:#fff;font-size:18px"></i>
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:2px">1:1 코칭 받기</div>
          <div style="font-size:12px;color:rgba(255,255,255,.5);line-height:1.4">ClassIn Teachers의 강사에게 실시간 1:1 코칭을 요청할 수 있어요</div>
        </div>
        <button id="coachingRequestBtn" onclick="showCoachingModal()" style="flex-shrink:0;padding:10px 20px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 4px 16px rgba(124,106,239,.3);transition:all .2s">
          <i class="fas fa-hand-paper"></i> 신청하기
        </button>
      </div>
    </div>
    <!-- 코칭 시간 선택 모달 -->
    <div id="coachingModal" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center">
      <div style="background:#1e1e2e;border-radius:20px;padding:28px;max-width:340px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.5)">
        <h3 style="font-size:18px;font-weight:700;color:#e2e8f0;margin:0 0 8px"><i class="fas fa-chalkboard-teacher" style="color:#7c6aef;margin-right:8px"></i>1:1 코칭 시간 선택</h3>
        <p style="font-size:13px;color:rgba(255,255,255,.5);margin:0 0 20px">원하는 코칭 시간을 선택해주세요</p>
        <div style="display:flex;gap:12px;margin-bottom:20px">
          <button onclick="selectCoachingDuration(15)" style="flex:1;padding:16px 12px;border-radius:14px;border:2px solid rgba(124,106,239,.3);background:rgba(124,106,239,.08);color:#e2e8f0;cursor:pointer;transition:all .2s">
            <div style="font-size:24px;font-weight:800;color:#7c6aef">15<span style="font-size:14px">분</span></div>
            <div style="font-size:11px;color:rgba(255,255,255,.4);margin-top:4px">빠른 질문 해결</div>
          </button>
          <button onclick="selectCoachingDuration(30)" style="flex:1;padding:16px 12px;border-radius:14px;border:2px solid rgba(6,182,212,.3);background:rgba(6,182,212,.08);color:#e2e8f0;cursor:pointer;transition:all .2s">
            <div style="font-size:24px;font-weight:800;color:#06b6d4">30<span style="font-size:14px">분</span></div>
            <div style="font-size:11px;color:rgba(255,255,255,.4);margin-top:4px">깊이 있는 코칭</div>
          </button>
        </div>
        <button onclick="closeCoachingModal()" style="width:100%;padding:10px;border-radius:10px;border:none;background:rgba(255,255,255,.08);color:rgba(255,255,255,.5);font-size:13px;cursor:pointer">취소</button>
      </div>
    </div>
    <!-- 1:1 코칭 하기 카드 (타인 질문일 때만 표시) -->
    <div id="teachersCoachingCard" style="display:none;margin-bottom:16px;padding:16px;background:linear-gradient(135deg,rgba(99,102,241,.08),rgba(139,92,246,.05));border:1px solid rgba(99,102,241,.2);border-radius:12px;">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:40px;height:40px;border-radius:10px;background:linear-gradient(135deg,#6366f1,#8b5cf6);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
          <i class="fas fa-chalkboard-teacher" style="color:#fff;font-size:18px;"></i>
        </div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:14px;font-weight:700;color:#fff;">1:1 코칭 하기</div>
          <div style="font-size:12px;color:var(--muted);margin-top:2px;">ClassIn Teachers에서 1:1 코칭을 할 수 있어요</div>
        </div>
        <button id="teachersEnterBtn" style="padding:8px 16px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap;box-shadow:0 2px 8px rgba(99,102,241,.3);">
          <i class="fas fa-sign-in-alt" style="margin-right:4px;"></i>티쳐스 입장
        </button>
      </div>
    </div>
    <div id="answersContainer"></div>

    <!-- Drawing preview (shown after drawing mode, before submit) -->
    <div id="drawingPreview" class="preview-section" style="display:none">
      <div class="preview-label"><i class="fas fa-pen-fancy"></i> 필기 답변 미리보기 <button class="preview-remove-btn" id="clearDrawingPreview"><i class="fas fa-times"></i> 삭제</button></div>
      <canvas id="drawPreviewCanvas" style="max-width:100%;border-radius:6px;background:#fff"></canvas>
    </div>
    <!-- Image preview (shown after attaching image, before submit) -->
    <div id="answerImagePreview" class="preview-section" style="display:none">
      <div class="preview-label"><i class="fas fa-image"></i> 첨부 이미지 <button class="preview-remove-btn" id="clearImgPreview"><i class="fas fa-times"></i> 삭제</button></div>
      <img id="ansImgPreview" style="max-width:100%;border-radius:6px">
    </div>
    <div id="answerFormArea"></div>
  </div>
</div>

<!-- AI Tutor Button -->
<style>@keyframes aiHgFlip{0%,45%{transform:rotate(0deg)}50%,95%{transform:rotate(180deg)}100%{transform:rotate(360deg)}}#aiTutorHourglass{display:inline-block;animation:aiHgFlip 2s ease-in-out infinite}</style>
<div class="ai-tutor-bar" id="aiTutorBar" style="position:fixed;bottom:66px;left:0;right:0;display:none;justify-content:flex-start;padding:8px 12px;background:rgba(11,14,20,.95);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-top:1px solid var(--glass-border);z-index:99;">
  <button class="ai-tutor-btn" id="aiTutorBtn" style="background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff;border:none;border-radius:20px;padding:8px 16px;font-size:14px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:6px;box-shadow:0 2px 8px rgba(108,92,231,0.3);">
    <i class="fas fa-robot"></i> 정율 선생님 &gt;
  </button>
  <span id="aiTutorStatus" style="display:none;margin-left:10px;font-size:13px;color:#a29bfe;align-self:center;"><span id="aiTutorHourglass">⏳</span> 튜터 로딩 중... (최대 5분)</span>
</div>

<!-- Fixed bottom bar — KakaoTalk-style -->
<div class="bottom-bar" id="bottomBar">
  <button class="bb-draw-btn" id="toggleDrawing"><i class="fas fa-pen-fancy"></i> 필기</button>
  <div class="bb-input-wrap" id="bbInputWrap">
    <input class="bb-input" id="answerContent" placeholder="답변을 입력하세요..." autocomplete="off">
    <label class="bb-img-btn" id="bbImgBtn" title="이미지 첨부"><i class="fas fa-image"></i><input id="answerImage" type="file" accept="image/*" style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none"></label>
    <button class="bb-mic-btn" id="bbMicBtn" title="음성 녹음"><i class="fas fa-microphone"></i></button>
  </div>
  <button class="bb-send" id="submitAnswer" title="답변 등록"><i class="fas fa-paper-plane"></i></button>
</div>

<!-- Voice recording bottom bar (ClassIn-style) -->
<div class="voice-rec-bar" id="voiceRecBar">
  <!-- Recording strip (red bar) -->
  <div class="voice-rec-strip" id="voiceRecStrip">
    <div class="voice-rec-strip__icon"><i class="fas fa-microphone"></i></div>
    <div class="voice-rec-strip__timer" id="voiceTimer">00:00</div>
    <div class="voice-rec-strip__wave"><canvas id="voiceWaveCanvas" width="300" height="28"></canvas></div>
    <button class="voice-rec-strip__btn voice-rec-strip__btn--pause" id="voicePauseBtn" title="일시정지"><i class="fas fa-pause"></i></button>
    <button class="voice-rec-strip__btn voice-rec-strip__btn--stop" id="voiceStopBtn" title="완료"><i class="fas fa-stop"></i></button>
    <button class="voice-rec-strip__btn voice-rec-strip__btn--cancel" id="voiceCancelBtn" title="취소"><i class="fas fa-times"></i></button>
  </div>
  <!-- Preview bar (after recording) -->
  <div class="voice-preview-bar" id="voicePreviewBar">
    <button class="voice-prev-play" id="voicePreviewPlay"><i class="fas fa-play"></i></button>
    <div class="voice-prev-info">
      <div class="voice-prev-progress" id="voicePreviewProgress"><div class="voice-prev-progress__fill" id="voicePreviewFill"></div></div>
      <div class="voice-prev-times"><span id="voicePreviewCurrent">00:00</span><span id="voicePreviewTotal">00:00</span></div>
    </div>
    <button class="voice-prev-btn voice-prev-btn--redo" id="voiceRerecordBtn"><i class="fas fa-redo"></i> 재녹음</button>
    <button class="voice-prev-btn voice-prev-btn--confirm" id="voiceConfirmBtn"><i class="fas fa-check"></i> 첨부</button>
    <button class="voice-prev-close" id="voicePreviewCloseBtn" title="녹음 취소"><i class="fas fa-times"></i></button>
  </div>
</div>
<audio id="voiceAudio" style="display:none"></audio>

<script>
${sharedAuthJS()}

const qId=location.pathname.split('/').pop();
let drawOn=false,curTool='pen',curColor='#111111',curWidth=3,drawing=false,drawHistory=[],curStroke=null,ansImgData=null;
let questionImageData=null;

// === Voice recording state ===
let voiceBlob=null, voiceKey=null, mediaRecorder=null, audioChunks=[], voiceTimerInterval=null, voiceSeconds=0;
let audioCtx=null, analyser=null, micStream=null;
let bgCanvas,bgCtx,canvas,ctx,tempCanvas,tempCtx,bgImg=null;
let currentUser=null;
let zoomLevel=1,canvasBaseW=0,canvasBaseH=0,canvasSetupWrapW=0;
let drawOverlay=null;
let lastLineWidth=0;
let drawRAF=null; // rAF ID for batched highlighter rendering
// DPR will be set dynamically in setupCanvas() at runtime.
// This ensures we read devicePixelRatio AFTER the page is fully rendered.
let canvasDpr=2; // default, overridden in setupCanvas
// Shape drawing state
let shapeStart=null; // {x,y} start point for shapes
let pinching=false; // global: pinch-zoom state (used by setZoom to defer re-rasterize)

// ===== FLOATING OBJECTS (Scissors capture) =====
let floatingObjects=[]; // Array of {img:HTMLImageElement, x, y, w, h, id}
let selectedFloat=null; // Currently selected floating object
let floatDragMode=null; // null | 'move' | 'resize-tl' | 'resize-tr' | 'resize-bl' | 'resize-br' | ... 
let floatDragStart=null; // {x, y, origX, origY, origW, origH}
let scissorsStart=null; // Start point of scissors selection
let floatCtxMenu=null; // Context menu DOM element
let cachedQData=${(JSON.stringify(question)||'null').replace(/</g,'\\u003c').replace(/>/g,'\\u003e')};
const ssrAnswers=${JSON.stringify(answers).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')};
const ssrHasMore=${ssrHasMore ? 'true' : 'false'};

// === KaTeX Math Rendering ===
function renderMath(el){
  if(!el) return;
  if(typeof renderMathInElement==='function'){
    try{
      renderMathInElement(el,{
        delimiters:[
          {left:'$$',right:'$$',display:true},
          {left:'$',right:'$',display:false},
          {left:'\\\\(',right:'\\\\)',display:false},
          {left:'\\\\[',right:'\\\\]',display:true}
        ],
        throwOnError:false,
        trust:true
      });
    }catch(e){}
  }
}
function renderAllMath(){
  document.querySelectorAll('.ai-section,.ai-meta,.q-content,#answerList,#challengeSection,#giInteractionArea,.coaching-text').forEach(function(el){renderMath(el)});
}
// Auto-render when KaTeX loads
document.addEventListener('DOMContentLoaded',function(){setTimeout(renderAllMath,500)});

// === Split panel drag resize ===
(function(){
  const divider=document.getElementById('splitDivider');
  const left=document.getElementById('splitLeft');
  const container=document.getElementById('splitContainer');
  if(!divider||!left||!container) return;
  let isDragging=false;
  function onStart(e){
    isDragging=true;
    divider.classList.add('active');
    document.body.style.cursor='col-resize';
    document.body.style.userSelect='none';
    e.preventDefault();
  }
  function onMove(e){
    if(!isDragging) return;
    const clientX=e.touches?e.touches[0].clientX:e.clientX;
    const rect=container.getBoundingClientRect();
    let pct=((clientX-rect.left)/rect.width)*100;
    if(pct<20) pct=20;
    if(pct>80) pct=80;
    left.style.width=pct+'%';
  }
  function onEnd(){
    if(!isDragging) return;
    isDragging=false;
    divider.classList.remove('active');
    document.body.style.cursor='';
    document.body.style.userSelect='';
  }
  divider.addEventListener('mousedown',onStart);
  divider.addEventListener('touchstart',onStart,{passive:false});
  document.addEventListener('mousemove',onMove);
  document.addEventListener('touchmove',onMove,{passive:false});
  document.addEventListener('mouseup',onEnd);
  document.addEventListener('touchend',onEnd);
})();

// SSR: render question and answers IMMEDIATELY from embedded data (zero fetch)
try{if(cachedQData) renderQ(cachedQData)}catch(e){console.error('renderQ error:',e)}
var _ansPage=0;var _allAns=ssrAnswers.slice();
try{renderA(_allAns, cachedQData)}catch(e){console.error('renderA error:',e)}
if(ssrHasMore){
  var moreBtn=document.createElement('button');
  moreBtn.id='loadMoreAnswers';moreBtn.className='load-more-btn';
  moreBtn.style.cssText='display:block;margin:16px auto;padding:10px 24px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:13px';
  moreBtn.innerHTML='<i class="fas fa-chevron-down" style="margin-right:6px"></i>답변 더보기';
  moreBtn.onclick=function(){_ansPage++;loadA(false)};
  document.getElementById('answersContainer').parentNode.appendChild(moreBtn);
}

// Then async: check auth and re-render with accept buttons if needed
(async()=>{
  currentUser=await checkAuth();
  const navUser=document.getElementById('navUser');
  if(currentUser){
    navUser.innerHTML='<i class="fas fa-user-circle"></i> '+currentUser.nickname;
    renderAnswerForm(true);
    // Re-render answers with accept buttons now that auth is known
    renderA(_allAns, cachedQData);
    // Re-render tutoring panel now that currentUser is known (fixes owner detection)
    if(cachedQData&&cachedQData.difficulty==='1:1심화설명') loadTutoring(cachedQData);
    // Load XP data
    loadCpData();
    // Check tier2 status and conditionally show/hide button
    // ⚠️ 일시 중단: 유료화 이후 재활성화 예정
    // checkTier2Access();
    // Show/hide challenge buttons based on ownership
    showChallengeButtons();
    // Show AI Tutor button only for question owner
    // Show Teachers coaching card for OTHER users' questions (not mine)
    if(cachedQData&&currentUser.id!==cachedQData.user_id){
      document.getElementById('teachersCoachingCard').style.display='block';
    }
    if(cachedQData&&currentUser.id===cachedQData.user_id){
      document.getElementById('aiTutorBar').style.display='flex';
      document.querySelector('.split-container').style.bottom='120px';
      if(!(cachedQData.ai_analyzed===1 && (cachedQData.solution_stat===1 || cachedQData.solution_stat===-1 || cachedQData.solution_stat===2))){
        const btn=document.getElementById('aiTutorBtn');
        const st=document.getElementById('aiTutorStatus');
        btn.disabled=true;
        btn.style.opacity='0.45';
        btn.style.cursor='default';
        st.style.display='inline';
        const enableBtn=()=>{btn.disabled=false;btn.style.opacity='1';btn.style.cursor='pointer';st.style.display='none';};
        // Pro 해설 즉시 트리거 (DB에 subject, image_key 등은 이미 저장됨)
        fetch('/api/questions/'+qId+'/generate-solution',{method:'POST',headers:{'Content-Type':'application/json'}}).catch(()=>{});
        const poll=setInterval(async()=>{
          try{
            const r=await fetch('/api/questions/'+qId);
            if(r.ok){
              const q=await r.json();
              if(q.ai_analyzed===-1){clearInterval(poll);clearTimeout(fallbackTimer);clearTimeout(longWaitTimer);st.innerHTML='<span style="color:#ef4444">AI 분석 실패 — 재시도해주세요</span>';}
              else if(q.ai_analyzed===1 && q.solution_stat===1){enableBtn();clearInterval(poll);clearTimeout(fallbackTimer);clearTimeout(longWaitTimer);}
              else if(q.ai_analyzed===1 && (q.solution_stat===-1)){enableBtn();clearInterval(poll);clearTimeout(fallbackTimer);clearTimeout(longWaitTimer);}
            }
          }catch(e){}
        },10000);
        // 3분 경과: 고난이도 문제 안내 문구로 전환 (학생 이탈 방지)
        const longWaitTimer=setTimeout(()=>{st.innerHTML='<span id="aiTutorHourglass">⏳</span> 고난이도 문제라 해설 정리에 조금 더 걸려요 (최대 5분)';},3*60*1000);
        // 5분 타임아웃: 분석 성공이면 solution 상관없이 활성화, 분석 실패면 에러
        const fallbackTimer=setTimeout(async()=>{clearInterval(poll);clearTimeout(longWaitTimer);try{const r=await fetch('/api/questions/'+qId);if(r.ok){const q=await r.json();if(q.ai_analyzed===1){enableBtn();return;}}}catch(e){}st.innerHTML='<span style="color:#ef4444">AI 분석 시간 초과 — 새로고침 후 재시도해주세요</span>';},5*60*1000);
      }
    }
    // 1:1 코칭 신청 버튼 — 본인 질문이면 항상 표시 (답변 유무 무관)
    if(cachedQData&&currentUser.id===cachedQData.user_id){
      document.getElementById('coachingRequestArea').style.display='block';
      // SSR에서 이미 coaching_requested가 있으면 즉시 반영
      if(cachedQData.coaching_requested===3){
        renderCoachingCompleted();
      } else if(cachedQData.coaching_requested>=1){
        renderCoachingRequested();
      }
      // Teachers API에서 실시간 상태 동기화
      fetch('/api/questions/'+qId+'/coaching-status',{headers:authHeaders()})
        .then(r=>r.json())
        .then(d=>{
          if(d.coaching_requested===3){
            renderCoachingCompleted(d.coaching_url);
          } else if(d.coaching_requested>=1){
            renderCoachingRequested(d.request_id,d.coaching_url);
          } else if(d.coaching_requested===0 && cachedQData.coaching_requested>=1){
            // Teachers에서 취소/만료됨 → 신청 버튼으로 복원
            renderCoachingDefault();
          }
        }).catch(()=>{});
    }
  }else{
    navUser.innerHTML='';
    renderAnswerForm(false);
  }
  // Lazy load question image
  if(cachedQData&&cachedQData.has_image){
    // For multi-image questions, images are already rendered via buildImageGalleryHTML (src set at render time)
    if(cachedQData.image_key){
      questionImageData='/api/images/'+cachedQData.image_key;
      // Single-image legacy: ensure qImage src is set
      const img=document.getElementById('qImage');
      if(img&&!img.src)img.src='/api/images/'+cachedQData.image_key;
    } else if(cachedQData.image_keys){
      try{const _ik=JSON.parse(cachedQData.image_keys);if(Array.isArray(_ik)&&_ik[0])questionImageData='/api/images/'+_ik[0].key;}catch(e){}
    } else {
    fetch('/api/questions/'+qId+'/image').then(r=>r.json()).then(d=>{
      if(d.data){
        const img=document.getElementById('qImage');
        if(img)img.src=d.data;
        questionImageData=d.data;
      } else {
        const wrap=document.querySelector('.q-image-wrap');
        if(wrap)wrap.style.display='none';
      }
    }).catch(()=>{
      const wrap=document.querySelector('.q-image-wrap');
      if(wrap)wrap.style.display='none';
    });
    } // end else (non-R2 fallback)
  }
})();

// Auto-poll answers every 20s
let ansPollTimer=null;
let lastAnsKey='';
function ansKey(list){return(list||[]).map(a=>a.id+':'+a.is_accepted).join(',')}
lastAnsKey=ansKey(ssrAnswers);
async function ansPollOnce(){
  try{
    const h=currentUser?authHeaders():{'Content-Type':'application/json'};
    const res=await fetch('/api/questions/'+qId+'/answers',{headers:h});
    const d=await res.json();
    const list=d.answers||d;
    if(!Array.isArray(list)){console.log('[ansPoll] list not array, skipping');return;}
    const nk=ansKey(list);
    console.log('[ansPoll] fetched',list.length,'answers, keyChanged:',nk!==lastAnsKey);
    if(nk!==lastAnsKey){lastAnsKey=nk;_allAns=list;renderA(_allAns,cachedQData);}
  }catch(e){console.error('[ansPoll] error:',e)}
}
function startAnsPoll(){if(!ansPollTimer)ansPollTimer=setInterval(ansPollOnce,5000);}
function stopAnsPoll(){if(ansPollTimer){clearInterval(ansPollTimer);ansPollTimer=null;}}
document.addEventListener('visibilitychange',()=>{
  if(document.hidden)stopAnsPoll();
  else{ansPollOnce();startAnsPoll();}
});
startAnsPoll();

function renderAnswerForm(loggedIn){
  const bottomBar=document.getElementById('bottomBar');
  if(!loggedIn){
    // Hide bottom bar, show login prompt in right panel
    bottomBar.style.display='none';
    document.getElementById('answerFormArea').innerHTML='<div class="ans-login-prompt"><p style="color:var(--muted);font-size:13px;margin-bottom:12px">답변을 작성하려면 로그인이 필요합니다</p><a href="/login?redirect=/question/'+qId+'" class="ans-login-btn"><i class="fas fa-sign-in-alt"></i> 로그인하기</a></div>';
    // Extend split-container to bottom
    document.querySelector('.split-container').style.bottom='0';
    return;
  }
  // Wire up bottom bar events
  initDrawingTools();
}

// === 1:1 코칭 시간 선택 모달 ===
async function showCoachingModal(){
  // 먼저 Teachers 계정 연결 상태 확인
  try{
    const linkRes=await fetch('/api/account-link/status',{headers:authHeaders()});
    const linkData=await linkRes.json();
    if(!linkData.linked){
      // 계정 미연결 → 연결 안내 모달
      showAccountLinkModal();
      return;
    }
  }catch(e){}
  const modal=document.getElementById('coachingModal');
  if(modal) modal.style.display='flex';
}
function closeCoachingModal(){
  const modal=document.getElementById('coachingModal');
  if(modal) modal.style.display='none';
}
function selectCoachingDuration(mins){
  closeCoachingModal();
  requestCoaching(mins);
}
// Teachers 계정 연결 모달
function showAccountLinkModal(){
  let m=document.getElementById('accountLinkModal');
  if(!m){
    m=document.createElement('div');
    m.id='accountLinkModal';
    m.style.cssText='position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';
    m.innerHTML=
      '<div style="background:#1e1e2e;border-radius:20px;padding:28px;max-width:380px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.5)">'+
        '<h3 style="font-size:18px;font-weight:700;color:#e2e8f0;margin:0 0 8px"><i class="fas fa-link" style="color:#7c6aef;margin-right:8px"></i>ClassIn Teachers 계정 연결</h3>'+
        '<p style="font-size:13px;color:rgba(255,255,255,.5);margin:0 0 16px;line-height:1.5">1:1 코칭을 받으려면 ClassIn Teachers 계정이 필요합니다.<br>계정이 없으면 먼저 회원가입해주세요.</p>'+
        '<div style="margin-bottom:12px">'+
          '<input id="linkEmail" type="email" placeholder="Teachers 이메일" style="width:100%;padding:10px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);color:#e2e8f0;font-size:14px;margin-bottom:8px;box-sizing:border-box">'+
          '<input id="linkPassword" type="password" placeholder="비밀번호" style="width:100%;padding:10px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.06);color:#e2e8f0;font-size:14px;box-sizing:border-box">'+
        '</div>'+
        '<div id="linkError" style="display:none;color:#ef4444;font-size:12px;margin-bottom:8px"></div>'+
        '<button onclick="submitAccountLink()" id="linkSubmitBtn" style="width:100%;padding:12px;border-radius:12px;border:none;background:linear-gradient(135deg,#7c6aef,#06b6d4);color:#fff;font-size:14px;font-weight:700;cursor:pointer;margin-bottom:8px">계정 연결하기</button>'+
        '<div style="text-align:center;margin-bottom:8px"><a href="https://teachers.jung-youl.com/" target="_blank" style="font-size:12px;color:#7c6aef;text-decoration:underline">아직 계정이 없으신가요? 회원가입 →</a></div>'+
        '<button onclick="closeAccountLinkModal()" style="width:100%;padding:10px;border-radius:10px;border:none;background:rgba(255,255,255,.08);color:rgba(255,255,255,.5);font-size:13px;cursor:pointer">취소</button>'+
      '</div>';
    document.body.appendChild(m);
  }else{
    m.style.display='flex';
  }
}
function closeAccountLinkModal(){
  const m=document.getElementById('accountLinkModal');
  if(m) m.style.display='none';
}
async function submitAccountLink(){
  const email=document.getElementById('linkEmail').value.trim();
  const password=document.getElementById('linkPassword').value;
  const errEl=document.getElementById('linkError');
  const btn=document.getElementById('linkSubmitBtn');
  if(!email||!password){errEl.textContent='이메일과 비밀번호를 입력해주세요.';errEl.style.display='block';return;}
  btn.disabled=true;btn.textContent='연결 중...';errEl.style.display='none';
  try{
    const res=await fetch('/api/account-link/verify',{
      method:'POST',headers:authHeaders(),
      body:JSON.stringify({email,password})
    });
    const data=await res.json();
    if(!res.ok||!data.success){throw new Error(data.error||'연결 실패');}
    closeAccountLinkModal();
    // 연결 성공 → 시간 선택 모달 표시
    const modal=document.getElementById('coachingModal');
    if(modal) modal.style.display='flex';
  }catch(e){
    errEl.textContent=e.message||'계정 연결에 실패했습니다.';errEl.style.display='block';
  }finally{
    btn.disabled=false;btn.textContent='계정 연결하기';
  }
}
window.showCoachingModal=showCoachingModal;
window.closeCoachingModal=closeCoachingModal;
window.selectCoachingDuration=selectCoachingDuration;
window.showAccountLinkModal=showAccountLinkModal;
window.closeAccountLinkModal=closeAccountLinkModal;
window.submitAccountLink=submitAccountLink;

// === 코칭 상태별 UI 렌더링 ===
function renderCoachingRequested(requestId,coachingUrl){
  document.getElementById('coachingRequestArea').innerHTML=
    '<div style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:12px">'+
      '<div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#10b981,#06d6a0);display:flex;align-items:center;justify-content:center;flex-shrink:0">'+
        '<i class="fas fa-check" style="color:#fff;font-size:18px"></i>'+
      '</div>'+
      '<div style="flex:1">'+
        '<div style="font-size:14px;font-weight:700;color:#10b981">코칭 신청 완료!</div>'+
        '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-top:2px">ClassIn Teachers에서 강사가 매칭되면 알려드릴게요</div>'+
        '<div style="display:flex;gap:8px;margin-top:8px">'+
          (coachingUrl?'<a href="'+coachingUrl+'" target="_blank" style="font-size:12px;color:#7c6aef;background:none;border:none;cursor:pointer;text-decoration:underline"><i class="fas fa-external-link-alt"></i> 코칭 페이지로 이동 →</a>':'')+
          '<button onclick="cancelCoaching()" id="cancelCoachingBtn" style="font-size:12px;color:#ef4444;background:none;border:none;cursor:pointer;text-decoration:underline">취소하기</button>'+
        '</div>'+
      '</div>'+
    '</div>';
}
function renderCoachingCompleted(coachingUrl){
  document.getElementById('coachingRequestArea').innerHTML=
    '<div style="background:rgba(124,106,239,.08);border:1px solid rgba(124,106,239,.25);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:12px">'+
      '<div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);display:flex;align-items:center;justify-content:center;flex-shrink:0">'+
        '<i class="fas fa-graduation-cap" style="color:#fff;font-size:18px"></i>'+
      '</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:14px;font-weight:700;color:#a78bfa">코칭 완료</div>'+
        '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-top:2px">1:1 코칭이 완료되었습니다. 수고하셨어요!</div>'+
        (coachingUrl?'<div style="margin-top:8px"><a href="'+coachingUrl+'" target="_blank" style="font-size:12px;color:#7c6aef;text-decoration:underline"><i class="fas fa-external-link-alt"></i> 코칭 기록 보기 →</a></div>':'')+
      '</div>'+
    '</div>';
}
window.renderCoachingCompleted=renderCoachingCompleted;
function renderCoachingDefault(){
  document.getElementById('coachingRequestArea').innerHTML=
    '<div style="background:linear-gradient(135deg,rgba(124,106,239,.1),rgba(6,182,212,.08));border:1px solid rgba(124,106,239,.25);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:14px">'+
      '<div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);display:flex;align-items:center;justify-content:center;flex-shrink:0">'+
        '<i class="fas fa-chalkboard-teacher" style="color:#fff;font-size:18px"></i>'+
      '</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:2px">1:1 코칭 받기</div>'+
        '<div style="font-size:12px;color:rgba(255,255,255,.5);line-height:1.4">ClassIn Teachers의 강사에게 실시간 1:1 코칭을 요청할 수 있어요</div>'+
      '</div>'+
      '<button id="coachingRequestBtn" onclick="showCoachingModal()" style="flex-shrink:0;padding:10px 20px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 4px 16px rgba(124,106,239,.3);transition:all .2s">'+
        '<i class="fas fa-hand-paper"></i> 신청하기'+
      '</button>'+
    '</div>';
}

// === 코칭 취소 ===
async function cancelCoaching(){
  if(!confirm('코칭 신청을 취소하시겠습니까?'))return;
  const btn=document.getElementById('cancelCoachingBtn');
  if(btn){btn.disabled=true;btn.textContent='취소 중...';}
  try{
    const res=await fetch('/api/questions/'+qId+'/coaching-cancel',{
      method:'POST',headers:authHeaders()
    });
    const data=await res.json();
    if(!res.ok)throw new Error(data.error||'취소 실패');
    // 원래 신청 버튼으로 복원
    document.getElementById('coachingRequestArea').innerHTML=
      '<div style="background:linear-gradient(135deg,rgba(124,106,239,.1),rgba(6,182,212,.08));border:1px solid rgba(124,106,239,.25);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:14px">'+
        '<div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);display:flex;align-items:center;justify-content:center;flex-shrink:0">'+
          '<i class="fas fa-chalkboard-teacher" style="color:#fff;font-size:18px"></i>'+
        '</div>'+
        '<div style="flex:1;min-width:0">'+
          '<div style="font-size:14px;font-weight:700;color:#e2e8f0;margin-bottom:2px">1:1 코칭 받기</div>'+
          '<div style="font-size:12px;color:rgba(255,255,255,.5);line-height:1.4">코칭이 취소되었습니다. 다시 신청할 수 있어요.</div>'+
        '</div>'+
        '<button id="coachingRequestBtn" onclick="showCoachingModal()" style="flex-shrink:0;padding:10px 20px;border-radius:12px;background:linear-gradient(135deg,#7c6aef,#06b6d4);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap;box-shadow:0 4px 16px rgba(124,106,239,.3);transition:all .2s">'+
          '<i class="fas fa-hand-paper"></i> 다시 신청'+
        '</button>'+
      '</div>';
  }catch(e){
    alert(e.message||'취소에 실패했습니다.');
    if(btn){btn.disabled=false;btn.textContent='취소하기';}
  }
}
window.cancelCoaching=cancelCoaching;

// === 1:1 코칭 신청 ===
async function requestCoaching(duration){
  const btn=document.getElementById('coachingRequestBtn');
  if(!btn||btn.disabled)return;
  btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 신청 중...';
  try{
    const res=await fetch('/api/questions/'+qId+'/coaching-request',{
      method:'POST',
      headers:authHeaders(),
      body:JSON.stringify({duration:duration||15})
    });
    const data=await res.json();
    if(!res.ok){
      if(data.need_link){showAccountLinkModal();btn.disabled=false;btn.innerHTML='<i class="fas fa-hand-paper"></i> 신청하기';return;}
      throw new Error(data.error||'코칭 신청 실패');
    }
    // Teachers 코칭 페이지로 새 탭 열기
    if(data.coaching_url) window.open(data.coaching_url,'_blank');
    // 성공: 버튼을 완료 상태로 변경 + 취소 버튼 포함
    document.getElementById('coachingRequestArea').innerHTML=
      '<div style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:14px;padding:16px 20px;display:flex;align-items:center;gap:12px">'+
        '<div style="width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#10b981,#06d6a0);display:flex;align-items:center;justify-content:center;flex-shrink:0">'+
          '<i class="fas fa-check" style="color:#fff;font-size:18px"></i>'+
        '</div>'+
        '<div style="flex:1">'+
          '<div style="font-size:14px;font-weight:700;color:#10b981">코칭 신청 완료!</div>'+
          '<div style="font-size:12px;color:rgba(255,255,255,.5);margin-top:2px">ClassIn Teachers에서 강사가 매칭되면 알려드릴게요</div>'+
          '<div style="display:flex;gap:8px;margin-top:8px">'+
            (data.coaching_url?'<a href="'+data.coaching_url+'" target="_blank" style="font-size:12px;color:#7c6aef;text-decoration:underline">코칭 페이지로 이동 →</a>':'')+
            '<button onclick="cancelCoaching()" id="cancelCoachingBtn" style="font-size:12px;color:#ef4444;background:none;border:none;cursor:pointer;text-decoration:underline">취소하기</button>'+
          '</div>'+
        '</div>'+
      '</div>';
  }catch(e){
    btn.disabled=false;btn.innerHTML='<i class="fas fa-hand-paper"></i> 신청하기';
    alert(e.message||'코칭 신청에 실패했습니다.');
  }
}
window.requestCoaching=requestCoaching;

function removeAnsImg(){
  ansImgData=null;
  // Remove inline preview from input wrap
  const existing=document.getElementById('bbInlineImgPreview');
  if(existing)existing.remove();
  const imgBtn=document.getElementById('bbImgBtn');
  if(imgBtn)imgBtn.classList.remove('has-img');
  // Also hide old preview area
  document.getElementById('answerImagePreview').style.display='none';
}

function removeDrawingPreview(){
  drawHistory=[];drawOn=false;
  document.getElementById('drawingPreview').style.display='none';
  document.getElementById('toggleDrawing').classList.remove('active');
}

function showInlineImgPreview(){
  // Show small preview inside the input wrap (KakaoTalk style)
  const wrap=document.getElementById('bbInputWrap');
  if(!wrap)return;
  let prev=document.getElementById('bbInlineImgPreview');
  if(!prev){
    prev=document.createElement('div');
    prev.id='bbInlineImgPreview';
    prev.className='bb-img-preview';
    wrap.insertBefore(prev,wrap.firstChild);
  }
  prev.innerHTML='<img src="'+ansImgData+'"><button class="bb-img-remove" onclick="removeAnsImg()"><i class="fas fa-times"></i></button>';
  const imgBtn=document.getElementById('bbImgBtn');
  if(imgBtn)imgBtn.classList.add('has-img');
}
window.removeAnsImg=removeAnsImg;

function initDrawingTools(){
  // Toggle drawing — opens fullscreen mode
  document.getElementById('toggleDrawing').addEventListener('click',()=>openDrawingMode());

  // Preview removal buttons
  document.getElementById('clearDrawingPreview').addEventListener('click',removeDrawingPreview);
  document.getElementById('clearImgPreview').addEventListener('click',removeAnsImg);

  // Image attach via bottom bar (inside input wrap)
  document.getElementById('answerImage').addEventListener('change',e=>{
    const f=e.target.files[0];if(!f)return;
    const url=URL.createObjectURL(f);
    const img=new Image();
    img.onload=()=>{
      URL.revokeObjectURL(url);
      try{
        let w=img.width,h=img.height;const max=1200;
        if(w>max||h>max){const s=max/Math.max(w,h);w=Math.round(w*s);h=Math.round(h*s)}
        const cv=document.createElement('canvas');cv.width=w;cv.height=h;
        cv.getContext('2d').drawImage(img,0,0,w,h);
        ansImgData=cv.toDataURL('image/jpeg',0.82);
        showInlineImgPreview();
      }catch(e){showToast('이미지 처리에 실패했습니다.','error')}
    };
    img.onerror=()=>{URL.revokeObjectURL(url);showToast('이미지를 불러올 수 없습니다.','error')};
    img.src=url;
  });

  // Submit answer via bottom bar send button
  document.getElementById('submitAnswer').addEventListener('click',submitAnswer);
  // Enter key in input sends
  document.getElementById('answerContent').addEventListener('keydown',e=>{
    if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();submitAnswer()}
  });

  // AI Tutor button click handler
  document.getElementById('aiTutorBtn').addEventListener('click',()=>{
    if(!currentUser||!currentUser.external_id){showToast('로그인이 필요합니다.','warn');return}
    showTutorModePopup(function(mode){
      const url='https://www.jungyoul.com/chat-tutor/?user_id='+encodeURIComponent(currentUser.external_id)+'&question_id='+encodeURIComponent(qId)+'&mode='+encodeURIComponent(mode);
      window.open(url,'_blank');
    });
  });

  // Teachers coaching button click handler (for other users' questions)
  document.getElementById('teachersEnterBtn').addEventListener('click',()=>{
    if(!currentUser||!currentUser.external_id){showToast('로그인이 필요합니다.','warn');return}
    const url='https://teachers.jung-youl.com?user_id='+encodeURIComponent(currentUser.external_id);
    window.open(url,'_blank');
  });

  // === Voice recording setup (ClassIn bottom-bar style) ===
  document.getElementById('bbMicBtn').addEventListener('click',()=>startRecording());
  document.getElementById('voicePauseBtn').addEventListener('click',togglePauseRecording);
  document.getElementById('voiceStopBtn').addEventListener('click',stopRecording);
  document.getElementById('voiceCancelBtn').addEventListener('click',cancelRecording);
  document.getElementById('voiceRerecordBtn').addEventListener('click',rerecordVoice);
  document.getElementById('voiceConfirmBtn').addEventListener('click',confirmVoice);
  document.getElementById('voicePreviewCloseBtn').addEventListener('click',cancelFromPreview);
  document.getElementById('voicePreviewPlay').addEventListener('click',togglePreviewPlay);
  document.getElementById('voicePreviewProgress').addEventListener('click',seekPreview);
}

function openDrawingMode(){
  drawOn=true;
  document.getElementById('toggleDrawing').classList.add('active');
  if(drawOverlay){drawOverlay.remove()}
  drawOverlay=document.createElement('div');
  drawOverlay.className='draw-overlay';
  // Orzo-style toolbar: Left=undo/redo | Center=tools+colors+width | Right=cancel/done
  drawOverlay.innerHTML=\`
    <div class="draw-topbar">
      <div class="dt-tools-scroll">
        <div class="dt-group">
          <button class="dt-btn" id="undoBtn" title="되돌리기"><i class="fas fa-undo"></i></button>
          <button class="dt-btn" id="redoBtn" title="다시 실행"><i class="fas fa-redo"></i></button>
        </div>
        <div class="dt-sep"></div>
        <div class="dt-group">
          <button class="dt-btn active" data-tool="pen" title="펜"><i class="fas fa-pen"></i></button>
          <button class="dt-btn" data-tool="highlighter" title="형광펜"><i class="fas fa-highlighter"></i></button>
          <button class="dt-btn" data-tool="eraser" title="지우개"><i class="fas fa-eraser"></i></button>
        </div>
        <div class="dt-sep"></div>
        <div class="dt-group">
          <div class="dt-color active" style="background:#111111" data-color="#111111"></div>
          <div class="dt-color" style="background:#e50914" data-color="#e50914"></div>
          <div class="dt-color" style="background:#2563eb" data-color="#2563eb"></div>
          <div class="dt-color" style="background:#16a34a" data-color="#16a34a"></div>
          <div class="dt-color" style="background:#9333ea" data-color="#9333ea"></div>
        </div>
        <div class="dt-sep"></div>
        <div class="dt-group">
          <button class="dt-btn" data-tool="text" title="텍스트"><i class="fas fa-font"></i></button>
          <button class="dt-btn" data-tool="line" title="직선"><i class="fas fa-minus"></i></button>
          <button class="dt-btn" data-tool="rect" title="사각형"><i class="far fa-square"></i></button>
          <button class="dt-btn" data-tool="circle" title="원"><i class="far fa-circle"></i></button>
          <button class="dt-btn" data-tool="select" title="선택/이동"><i class="fas fa-mouse-pointer"></i></button>
          <button class="dt-btn" data-tool="scissors" title="캡처/이동"><i class="fas fa-cut"></i></button>
        </div>
        <div class="dt-sep"></div>
        <div class="dt-group dt-width-group">
          <button class="dt-width-btn\${curWidth===1.5?' active':''}" data-width="1.5" title="가늘게"><span class="dt-width-dot" style="width:4px;height:4px"></span></button>
          <button class="dt-width-btn\${curWidth===3?' active':''}" data-width="3" title="보통"><span class="dt-width-dot" style="width:8px;height:8px"></span></button>
          <button class="dt-width-btn\${curWidth===5?' active':''}" data-width="5" title="굵게"><span class="dt-width-dot" style="width:13px;height:13px"></span></button>
        </div>
        <div class="dt-group">
          <button class="dt-btn" id="clearBtn" title="전체 지우기" style="color:#ff6b6b"><i class="fas fa-trash-alt"></i></button>
        </div>
      </div>
      <div class="dt-actions">
        <button class="draw-close-btn" id="drawCancelBtn">취소</button>
        <button class="draw-done-btn" id="drawDoneBtn"><i class="fas fa-check" style="margin-right:4px"></i>완료</button>
      </div>
    </div>
    <div class="draw-canvas-area" id="canvasWrap">
      <div class="draw-canvas-inner" id="canvasInner">
        <canvas id="bgCanvas"></canvas>
        <canvas id="drawCanvas"></canvas>
        <canvas id="tempCanvas"></canvas>
      </div>
    </div>
    <div class="draw-zoom-bar">
      <button id="zoomOutBtn"><i class="fas fa-minus"></i></button>
      <span id="zoomLabel">100%</span>
      <button id="zoomInBtn"><i class="fas fa-plus"></i></button>
      <button id="zoomFitBtn" title="맞추기"><i class="fas fa-expand"></i></button>
    </div>
  \`;
  document.body.appendChild(drawOverlay);
  document.body.style.overflow='hidden';

  bgCanvas=document.getElementById('bgCanvas');
  canvas=document.getElementById('drawCanvas');
  tempCanvas=document.getElementById('tempCanvas');
  bgCtx=bgCanvas.getContext('2d',{alpha:false}); // opaque bg layer
  ctx=canvas.getContext('2d',{alpha:true}); // transparent stroke layer — destination-out works
  tempCtx=tempCanvas.getContext('2d',{alpha:true});
  [bgCtx,ctx,tempCtx].forEach(c=>{c.imageSmoothingEnabled=true;c.imageSmoothingQuality='high'});

  if(questionImageData&&!bgImg){
    const img=new Image();
    img.onload=()=>{bgImg=img;setupCanvas()};
    img.src=questionImageData;
  }else{
    setupCanvas();
  }
  wireToolbar();
  updateStrokeDot();
}

function setupCanvas(){
  const wrap=document.getElementById('canvasWrap');
  if(!wrap)return;
  const wrapR=wrap.getBoundingClientRect();
  const wrapW=wrapR.width;
  canvasSetupWrapW=wrapW; // Store original wrapW so drawBackground() stays consistent
  const PAD_LEFT=100,PAD_RIGHT=200,PAD_TOP=40,PAD_BOTTOM=800;

  let imgDrawW=0,imgDrawH=0;
  if(bgImg&&bgImg.naturalWidth){
    imgDrawW=Math.min(wrapW*0.9,bgImg.naturalWidth);
    imgDrawH=imgDrawW*(bgImg.naturalHeight/bgImg.naturalWidth);
  }

  const contentW=Math.max(imgDrawW,wrapW*0.7);
  const totalW=PAD_LEFT+contentW+PAD_RIGHT;
  const totalH=PAD_TOP+Math.max(800,imgDrawH)+PAD_BOTTOM;
  canvasBaseW=totalW;canvasBaseH=totalH;

  // CRITICAL: Read DPR at RUNTIME, not at script parse time.
  // On some iOS Safari versions, devicePixelRatio may not be ready at parse time.
  // Force minimum 2 for Retina displays.
  canvasDpr=Math.max(window.devicePixelRatio||2, 2);
  console.log('[DRAW] DPR='+window.devicePixelRatio+' canvasDpr='+canvasDpr+' totalW='+totalW+' totalH='+totalH);

  // 3 canvases: bgCanvas (background) + drawCanvas (strokes) + tempCanvas (in-progress)
  [bgCanvas,canvas,tempCanvas].forEach(c=>{
    c.width=totalW*canvasDpr;
    c.height=totalH*canvasDpr;
    c.style.width=totalW+'px';
    c.style.height=totalH+'px';
  });
  const inner=document.getElementById('canvasInner');
  inner.style.width=totalW+'px';inner.style.height=totalH+'px';

  // Scale contexts by render scale so we draw in CSS-pixel coordinates
  [bgCtx,ctx,tempCtx].forEach(c=>{
    c.setTransform(canvasDpr,0,0,canvasDpr,0,0);
    c.imageSmoothingEnabled=true;
    c.imageSmoothingQuality='high';
  });

  // Draw background on bgCanvas (never erased!)
  bgCtx.fillStyle='#ffffff';
  bgCtx.fillRect(0,0,totalW,totalH);

  if(bgImg&&bgImg.naturalWidth){
    const imgX=PAD_LEFT,imgY=PAD_TOP;
    bgCtx.drawImage(bgImg,imgX,imgY,imgDrawW,imgDrawH);
    bgCtx.strokeStyle='#ddd';bgCtx.lineWidth=0.5;bgCtx.setLineDash([]);
    bgCtx.strokeRect(imgX,imgY,imgDrawW,imgDrawH);
    const lineY=imgY+imgDrawH+30;
    bgCtx.strokeStyle='#ccc';bgCtx.lineWidth=1;
    bgCtx.setLineDash([6,4]);
    bgCtx.beginPath();bgCtx.moveTo(PAD_LEFT,lineY);bgCtx.lineTo(PAD_LEFT+contentW,lineY);bgCtx.stroke();
    bgCtx.setLineDash([]);
    bgCtx.fillStyle='#aaa';bgCtx.font='13px -apple-system,BlinkMacSystemFont,Pretendard,sans-serif';
    bgCtx.textAlign='center';
    bgCtx.fillText('\\u2193 \\ud480\\uc774 \\uc791\\uc131 \\uc601\\uc5ed',PAD_LEFT+contentW/2,lineY+20);
    bgCtx.textAlign='start';
  }

  redrawStrokes();
  setZoom(1);
  setTimeout(()=>{wrap.scrollLeft=Math.max(0,PAD_LEFT-80);wrap.scrollTop=0},50);

  // === VERIFICATION: Check DPR is actually applied ===
  const actualRatio=canvas.width/parseFloat(canvas.style.width);
  if(actualRatio<1.5){
    console.error('[DRAW] WARNING: DPR not applied! canvas.width='+canvas.width+' css='+canvas.style.width+' ratio='+actualRatio);
  }

  // Debug info in console only (no on-screen overlay)
  const memMB=(canvas.width*canvas.height*4*2/1024/1024).toFixed(0);
  console.log('[DRAW] DPR:'+canvasDpr+' canvas:'+canvas.width+'x'+canvas.height+' ratio:'+actualRatio.toFixed(2)+' mem:~'+memMB+'MB');
}

function updateStrokeDot(){
  // Width buttons are self-descriptive; no dynamic dot update needed
}

// --- RENDER A FULL STROKE as one continuous Bezier path ---
// This is THE key to ClassIn-quality: one path = one anti-aliased render
function renderFullStroke(c,stroke){
  const pts=stroke.points;
  if(!pts||pts.length<1)return;

  c.save();
  c.strokeStyle=stroke.color;
  c.globalAlpha=stroke.alpha||1;
  c.globalCompositeOperation=stroke.composite||'source-over';
  c.lineCap='round';
  c.lineJoin='round';
  c.lineWidth=stroke.width;

  if(pts.length===1){
    c.fillStyle=stroke.color;
    c.beginPath();
    c.arc(pts[0].x,pts[0].y,stroke.width/2,0,Math.PI*2);
    c.fill();
  }else if(pts.length===2){
    c.beginPath();
    c.moveTo(pts[0].x,pts[0].y);
    c.lineTo(pts[1].x,pts[1].y);
    c.stroke();
  }else{
    // Smooth Bezier through midpoints — SINGLE continuous path
    c.beginPath();
    c.moveTo(pts[0].x,pts[0].y);
    c.lineTo((pts[0].x+pts[1].x)/2,(pts[0].y+pts[1].y)/2);
    for(let i=1;i<pts.length-1;i++){
      const mx=(pts[i].x+pts[i+1].x)/2;
      const my=(pts[i].y+pts[i+1].y)/2;
      c.quadraticCurveTo(pts[i].x,pts[i].y,mx,my);
    }
    c.lineTo(pts[pts.length-1].x,pts[pts.length-1].y);
    c.stroke();
  }
  c.restore();
}

// === STROKE HIT-TEST (for stroke-based eraser) ===
function strokeNearPoint(s,px,py,radius){
  if(s.type==='shape'){
    if(s.tool==='line'){
      return distToLineSeg(px,py,s.start.x,s.start.y,s.end.x,s.end.y)<radius;
    }
    var sx=Math.min(s.start.x,s.end.x),sy=Math.min(s.start.y,s.end.y);
    var sw=Math.abs(s.end.x-s.start.x),sh=Math.abs(s.end.y-s.start.y);
    return px>=sx-radius&&px<=sx+sw+radius&&py>=sy-radius&&py<=sy+sh+radius;
  }
  if(s.type==='text'){
    var tw=(s.text||'').length*(s.fontSize||18)*0.6;
    var th=(s.text||'').split('\\n').length*(s.fontSize||18)*1.4;
    return px>=s.x-radius&&px<=s.x+Math.max(tw,60)+radius&&py>=s.y-radius&&py<=s.y+th+radius;
  }
  if(s.type==='float'){
    return px>=s.x-radius&&px<=s.x+s.w+radius&&py>=s.y-radius&&py<=s.y+s.h+radius;
  }
  if(s.points&&s.points.length){
    // Sample every few points for performance
    var step=Math.max(1,Math.floor(s.points.length/200));
    for(var i=0;i<s.points.length;i+=step){
      if(Math.hypot(s.points[i].x-px,s.points[i].y-py)<radius)return true;
    }
    // Always check last point
    var last=s.points[s.points.length-1];
    if(Math.hypot(last.x-px,last.y-py)<radius)return true;
  }
  return false;
}

function distToLineSeg(px,py,x1,y1,x2,y2){
  var dx=x2-x1,dy=y2-y1;
  var lenSq=dx*dx+dy*dy;
  if(lenSq===0)return Math.hypot(px-x1,py-y1);
  var t=((px-x1)*dx+(py-y1)*dy)/lenSq;
  t=Math.max(0,Math.min(1,t));
  return Math.hypot(px-(x1+t*dx),py-(y1+t*dy));
}

// --- RENDER A SHAPE ---
function renderShape(c,s){
  c.save();
  c.strokeStyle=s.color;
  c.lineWidth=s.width;
  c.lineCap='round';
  c.lineJoin='round';
  c.globalAlpha=1;
  c.globalCompositeOperation='source-over';
  c.beginPath();
  if(s.tool==='line'){
    c.moveTo(s.start.x,s.start.y);c.lineTo(s.end.x,s.end.y);
  }else if(s.tool==='rect'){
    c.rect(Math.min(s.start.x,s.end.x),Math.min(s.start.y,s.end.y),Math.abs(s.end.x-s.start.x),Math.abs(s.end.y-s.start.y));
  }else if(s.tool==='circle'){
    const cx=(s.start.x+s.end.x)/2,cy=(s.start.y+s.end.y)/2;
    const rx=Math.abs(s.end.x-s.start.x)/2,ry=Math.abs(s.end.y-s.start.y)/2;
    c.ellipse(cx,cy,Math.max(rx,1),Math.max(ry,1),0,0,Math.PI*2);
  }
  c.stroke();
  c.restore();
}

function renderText(c,s){
  if(!s.text)return;
  c.save();
  c.font=(s.bold?'bold ':'')+s.fontSize+'px Pretendard,-apple-system,sans-serif';
  c.fillStyle=s.color||'#111';
  c.globalAlpha=1;
  c.globalCompositeOperation='source-over';
  c.textBaseline='top';
  const lines=s.text.split('\\n');
  const lh=s.fontSize*1.4;
  for(let i=0;i<lines.length;i++){
    c.fillText(lines[i],s.x,s.y+i*lh);
  }
  c.restore();
}

function wireToolbar(){
  const overlay=drawOverlay;if(!overlay)return;
  let redoStack=[];

  // Width buttons (3 fixed sizes)
  overlay.querySelectorAll('.dt-width-btn').forEach(b=>b.addEventListener('click',()=>{
    overlay.querySelectorAll('.dt-width-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    curWidth=parseFloat(b.dataset.width);
  }));

  // Tool buttons
  overlay.querySelectorAll('.dt-btn[data-tool]').forEach(b=>b.addEventListener('click',()=>{
    overlay.querySelectorAll('.dt-btn[data-tool]').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    const prevTool=curTool;
    curTool=b.dataset.tool;
    updateStrokeDot();
    // When switching tools, ALWAYS reset drawing state to prevent ghost strokes
    drawing=false;curStroke=null;shapeStart=null;drawPointerId=-1;
    scissorsStart=null;floatDragMode=null;floatDragStart=null;
    // Clear select tool state
    if(prevTool==='select'&&curTool!=='select'){clearSelection();}
    // Clear text input
    if(prevTool==='text'&&curTool!=='text'){commitTextInput();}
    // When switching away from scissors, auto-commit floating objects to drawCanvas
    // This permanently bakes them into the main canvas so they never disappear
    if(prevTool==='scissors'&&curTool!=='scissors'){
      commitAllFloats();
      selectedFloat=null;
      removeFloatContextMenu();
    }
    clearTemp();
  }));

  // Color buttons
  overlay.querySelectorAll('.dt-color').forEach(d=>d.addEventListener('click',()=>{
    overlay.querySelectorAll('.dt-color').forEach(x=>x.classList.remove('active'));
    d.classList.add('active');curColor=d.dataset.color;
    if(curTool==='eraser'){curTool='pen';overlay.querySelectorAll('.dt-btn[data-tool]').forEach(x=>x.classList.remove('active'));overlay.querySelector('[data-tool=pen]').classList.add('active')}
    updateStrokeDot();
  }));

  // History
  overlay.querySelector('#clearBtn').addEventListener('click',()=>{
    if(!drawHistory.length)return;
    showConfirmModal('전체 지우시겠습니까?',function(){drawHistory=[];redoStack=[];redrawStrokes()},{danger:true});
  });
  overlay.querySelector('#undoBtn').addEventListener('click',()=>{if(drawHistory.length){redoStack.push(drawHistory.pop());redrawStrokes()}});
  overlay.querySelector('#redoBtn').addEventListener('click',()=>{if(redoStack.length){drawHistory.push(redoStack.pop());redrawStrokes()}});

  // Keyboard shortcuts: Cmd+Z (undo), Cmd+Shift+Z (redo)
  function drawKeyHandler(e){
    if((e.metaKey||e.ctrlKey)&&e.key==='z'){
      e.preventDefault();e.stopPropagation();
      if(e.shiftKey){
        // Redo
        if(redoStack.length){drawHistory.push(redoStack.pop());redrawStrokes()}
      }else{
        // Undo
        if(drawHistory.length){redoStack.push(drawHistory.pop());redrawStrokes()}
      }
    }
  }
  document.addEventListener('keydown',drawKeyHandler);
  // Store cleanup ref so we can remove on close
  overlay._drawKeyHandler=drawKeyHandler;

  // Zoom
  overlay.querySelector('#zoomInBtn').addEventListener('click',()=>setZoom(Math.min(zoomLevel+0.25,4)));
  overlay.querySelector('#zoomOutBtn').addEventListener('click',()=>setZoom(Math.max(zoomLevel-0.25,0.5)));
  overlay.querySelector('#zoomFitBtn').addEventListener('click',()=>{
    const wrap=document.getElementById('canvasWrap');
    if(!wrap||!canvasBaseW)return;
    const fitZoom=Math.min(wrap.clientWidth/canvasBaseW,wrap.clientHeight/canvasBaseH,1);
    setZoom(Math.max(0.5,fitZoom));
  });

  // Done / Cancel
  overlay.querySelector('#drawDoneBtn').addEventListener('click',()=>closeDrawingMode(true));
  overlay.querySelector('#drawCancelBtn').addEventListener('click',()=>{
    if(drawHistory.length>0){showConfirmModal('필기를 취소하시겠습니까?',function(){closeDrawingMode(false)},{danger:true});return}
    closeDrawingMode(false);
  });

  // ====== INCREMENTAL DRAWING ENGINE ======
  // Key insight: NEVER clear+redraw entire stroke on each frame.
  // Instead, draw only the NEW segment on tempCanvas each pointermove.
  // This eliminates frame drops and ensures zero visual gaps.
  let hasPenInput=false;
  pinching=false; // reset (global var)
  let pinchStartDist=0,pinchStartZoom=1;
  let panStartX=0,panStartY=0,panScrollX=0,panScrollY=0;
  let touchCount=0;
  let drawPointerId=-1;
  const SHAPE_TOOLS=['line','rect','circle'];
  function isShapeTool(){return SHAPE_TOOLS.includes(curTool)}
  function isSelect(){return curTool==='select'}

  // ===== SELECT TOOL: hit-test, move, delete =====
  let selectedIdx=-1; // index in drawHistory
  let selectDragStart=null; // {x,y,origStroke}
  let selectDeleteBtn=null;

  function getBounds(s){
    if(s.type==='shape'){
      if(s.tool==='line') return{x:Math.min(s.start.x,s.end.x)-s.width,y:Math.min(s.start.y,s.end.y)-s.width,w:Math.abs(s.end.x-s.start.x)+s.width*2,h:Math.abs(s.end.y-s.start.y)+s.width*2};
      if(s.tool==='rect'||s.tool==='circle') return{x:Math.min(s.start.x,s.end.x)-s.width,y:Math.min(s.start.y,s.end.y)-s.width,w:Math.abs(s.end.x-s.start.x)+s.width*2,h:Math.abs(s.end.y-s.start.y)+s.width*2};
    }else if(s.type==='text'){
      const lines=(s.text||'').split('\\n');
      const lh=s.fontSize*1.4;
      const maxW=Math.max(...lines.map(l=>l.length*s.fontSize*0.6),60);
      return{x:s.x-4,y:s.y-4,w:maxW+8,h:lines.length*lh+8};
    }else if(s.type==='float'){
      return{x:s.x,y:s.y,w:s.w,h:s.h};
    }else if(s.points&&s.points.length){
      let mx=Infinity,my=Infinity,Mx=-Infinity,My=-Infinity;
      for(const p of s.points){if(p.x<mx)mx=p.x;if(p.y<my)my=p.y;if(p.x>Mx)Mx=p.x;if(p.y>My)My=p.y;}
      const pad=s.width||6;
      return{x:mx-pad,y:my-pad,w:Mx-mx+pad*2,h:My-my+pad*2};
    }
    return null;
  }

  function hitTest(px,py){
    // Test from top (most recent) to bottom
    for(let i=drawHistory.length-1;i>=0;i--){
      const s=drawHistory[i];
      if(s.tool==='eraser'||s.composite==='destination-out')continue;
      const b=getBounds(s);
      if(b&&px>=b.x&&px<=b.x+b.w&&py>=b.y&&py<=b.y+b.h) return i;
    }
    return -1;
  }

  function drawSelectionBox(){
    if(selectedIdx<0||selectedIdx>=drawHistory.length)return;
    const s=drawHistory[selectedIdx];
    const b=getBounds(s);
    if(!b)return;
    tempCtx.save();
    tempCtx.strokeStyle='#2563eb';
    tempCtx.lineWidth=2/zoomLevel;
    tempCtx.setLineDash([6/zoomLevel,4/zoomLevel]);
    tempCtx.globalAlpha=1;
    tempCtx.globalCompositeOperation='source-over';
    tempCtx.strokeRect(b.x,b.y,b.w,b.h);
    tempCtx.setLineDash([]);
    tempCtx.restore();
  }

  function showDeleteBtn(){
    removeDeleteBtn();
    if(selectedIdx<0||selectedIdx>=drawHistory.length)return;
    const s=drawHistory[selectedIdx];
    const b=getBounds(s);
    if(!b)return;
    const btn=document.createElement('button');
    btn.className='select-delete-btn';
    btn.innerHTML='<i class="fas fa-trash"></i>';
    // Position: top-center of bounding box in screen coords
    const canvasArea=drawOverlay.querySelector('.draw-canvas-area');
    const rect=canvas.getBoundingClientRect();
    const sx=(b.x+b.w/2)*zoomLevel*(rect.width/(canvas.width/canvasDpr));
    const sy=b.y*zoomLevel*(rect.height/(canvas.height/canvasDpr));
    btn.style.left=(sx+rect.left-canvasArea.getBoundingClientRect().left+canvasArea.scrollLeft)+'px';
    btn.style.top=(sy+rect.top-canvasArea.getBoundingClientRect().top+canvasArea.scrollTop-10)+'px';
    btn.addEventListener('click',e=>{
      e.stopPropagation();
      drawHistory.splice(selectedIdx,1);
      selectedIdx=-1;
      removeDeleteBtn();
      redrawStrokes();clearTemp();
    });
    selectDeleteBtn=btn;
    canvasArea.appendChild(btn);
  }

  function removeDeleteBtn(){
    if(selectDeleteBtn&&selectDeleteBtn.parentElement)selectDeleteBtn.remove();
    selectDeleteBtn=null;
  }

  function clearSelection(){selectedIdx=-1;removeDeleteBtn();clearTemp();}

  // ===== TEXT INPUT (ClassIn-style) =====
  let activeTextInput=null;
  let textFontSize=18;
  let textBold=false;
  function removeTextInput(){
    if(activeTextInput){
      if(activeTextInput.wrap&&activeTextInput.wrap.parentElement)activeTextInput.wrap.remove();
      if(activeTextInput.toolbar&&activeTextInput.toolbar.parentElement)activeTextInput.toolbar.remove();
      activeTextInput=null;
    }
  }
  function commitTextInput(){
    if(!activeTextInput)return;
    const text=activeTextInput.ta.value.trim();
    if(text){
      const s={type:'text',text,x:activeTextInput.cx,y:activeTextInput.cy,fontSize:textFontSize,color:curColor,bold:textBold};
      drawHistory.push(s);
      redrawStrokes();
    }
    removeTextInput();
  }
  function showTextInput(cx,cy){
    // If there's already an active text input, commit it first
    if(activeTextInput) commitTextInput();

    const canvasArea=drawOverlay.querySelector('.draw-canvas-area');
    const cRect=canvas.getBoundingClientRect();
    const aRect=canvasArea.getBoundingClientRect();
    const scaleX=cRect.width/(canvas.width/canvasDpr);
    const scaleY=cRect.height/(canvas.height/canvasDpr);
    const screenX=cx*zoomLevel*scaleX+cRect.left-aRect.left+canvasArea.scrollLeft;
    const screenY=cy*zoomLevel*scaleY+cRect.top-aRect.top+canvasArea.scrollTop;

    // Text input wrapper
    const wrap=document.createElement('div');
    wrap.style.cssText='position:absolute;left:'+screenX+'px;top:'+screenY+'px;z-index:10002';

    const ta=document.createElement('textarea');
    ta.className='text-input-box';
    ta.placeholder='입력...';
    ta.style.fontSize=textFontSize+'px';
    ta.style.fontWeight=textBold?'bold':'normal';
    ta.style.color=curColor;
    ta.rows=1;
    ta.addEventListener('input',()=>{ta.style.height='auto';ta.style.height=ta.scrollHeight+'px';});

    wrap.appendChild(ta);
    canvasArea.appendChild(wrap);

    // Floating toolbar (ClassIn style) - positioned below text input
    const toolbar=document.createElement('div');
    toolbar.className='text-toolbar';
    toolbar.innerHTML=
      '<button class="tt-close" title="닫기"><i class="fas fa-times"></i></button>'+
      '<select class="tt-size-select" title="글자 크기">'+
        [12,14,16,18,20,24,28,32,40,48,60].map(s=>'<option value="'+s+'"'+(s===textFontSize?' selected':'')+'>'+s+'</option>').join('')+
      '</select>'+
      '<button title="글자 색상"><i class="fas fa-font" style="text-decoration:underline;text-decoration-color:'+curColor+'"></i></button>'+
      '<span class="tt-divider"></span>'+
      '<button class="tt-bold'+(textBold?' active':'')+'" title="굵게"><b>B</b></button>'+
      '<span class="tt-divider"></span>'+
      '<button class="tt-delete" title="삭제"><i class="fas fa-trash"></i></button>';
    wrap.appendChild(toolbar);

    // Wire toolbar events
    toolbar.querySelector('.tt-close').addEventListener('click',e=>{e.stopPropagation();commitTextInput();});
    toolbar.querySelector('.tt-size-select').addEventListener('change',e=>{
      e.stopPropagation();
      textFontSize=parseInt(e.target.value);
      ta.style.fontSize=textFontSize+'px';
      ta.style.height='auto';ta.style.height=ta.scrollHeight+'px';
      ta.focus();
    });
    toolbar.querySelector('.tt-bold').addEventListener('click',e=>{
      e.stopPropagation();
      textBold=!textBold;
      e.currentTarget.classList.toggle('active',textBold);
      ta.style.fontWeight=textBold?'bold':'normal';
      ta.focus();
    });
    toolbar.querySelector('.tt-delete').addEventListener('click',e=>{e.stopPropagation();removeTextInput();});
    // Color button: use current drawing color
    toolbar.querySelectorAll('button')[2].addEventListener('click',e=>{
      e.stopPropagation();
      // Cycle through a few colors
      const colors=['#111','#e50914','#2563eb','#16a34a','#f59e0b','#8b5cf6','#fff'];
      const idx=colors.indexOf(curColor);
      const next=colors[(idx+1)%colors.length];
      curColor=next;
      ta.style.color=curColor;
      e.currentTarget.querySelector('i').style.textDecorationColor=curColor;
      ta.focus();
    });

    ta.focus();

    ta.addEventListener('keydown',e=>{
      if(e.key==='Escape'){e.preventDefault();removeTextInput();}
      e.stopPropagation();
    });

    activeTextInput={wrap,toolbar,ta,cx,cy};
  }

  function moveStroke(s,dx,dy){
    if(s.type==='shape'){
      s.start.x+=dx;s.start.y+=dy;s.end.x+=dx;s.end.y+=dy;
    }else if(s.type==='text'){
      s.x+=dx;s.y+=dy;
    }else if(s.type==='float'){
      s.x+=dx;s.y+=dy;
    }else if(s.points){
      for(const p of s.points){p.x+=dx;p.y+=dy;}
    }
  }
  function isScissors(){return curTool==='scissors'}

  // ===== FLOATING OBJECT RENDERING =====
  const HANDLE_SIZE=10;
  const HANDLE_POSITIONS=['tl','tr','bl','br','t','b','l','r'];

  function getHandleRects(fo){
    const hs=HANDLE_SIZE/zoomLevel;
    return{
      tl:{x:fo.x-hs/2,y:fo.y-hs/2,w:hs,h:hs},
      tr:{x:fo.x+fo.w-hs/2,y:fo.y-hs/2,w:hs,h:hs},
      bl:{x:fo.x-hs/2,y:fo.y+fo.h-hs/2,w:hs,h:hs},
      br:{x:fo.x+fo.w-hs/2,y:fo.y+fo.h-hs/2,w:hs,h:hs},
      t:{x:fo.x+fo.w/2-hs/2,y:fo.y-hs/2,w:hs,h:hs},
      b:{x:fo.x+fo.w/2-hs/2,y:fo.y+fo.h-hs/2,w:hs,h:hs},
      l:{x:fo.x-hs/2,y:fo.y+fo.h/2-hs/2,w:hs,h:hs},
      r:{x:fo.x+fo.w-hs/2,y:fo.y+fo.h/2-hs/2,w:hs,h:hs},
    };
  }

  function drawFloatingObjects(){
    // Draw all floating objects on tempCanvas
    // Use raw clear (not clearTemp which re-draws floats) to avoid recursion
    tempCtx.setTransform(1,0,0,1,0,0);
    tempCtx.clearRect(0,0,tempCanvas.width,tempCanvas.height);
    tempCtx.setTransform(canvasDpr,0,0,canvasDpr,0,0);
    tempCtx.imageSmoothingEnabled=true;
    tempCtx.imageSmoothingQuality='high';
    // CRITICAL: Reset composite state — previous eraser may have left destination-out
    tempCtx.globalAlpha=1;
    tempCtx.globalCompositeOperation='source-over';
    for(const fo of floatingObjects){
      tempCtx.save();
      tempCtx.globalAlpha=1;
      tempCtx.globalCompositeOperation='source-over';
      tempCtx.drawImage(fo.img,fo.x,fo.y,fo.w,fo.h);
      tempCtx.restore();
      if(selectedFloat&&selectedFloat.id===fo.id){
        // Draw selection border
        tempCtx.save();
        tempCtx.strokeStyle='#16a34a';
        tempCtx.lineWidth=2/zoomLevel;
        tempCtx.setLineDash([6/zoomLevel,4/zoomLevel]);
        tempCtx.strokeRect(fo.x,fo.y,fo.w,fo.h);
        tempCtx.setLineDash([]);
        // Draw handles
        const handles=getHandleRects(fo);
        for(const key of HANDLE_POSITIONS){
          const h=handles[key];
          tempCtx.fillStyle='#fff';
          tempCtx.strokeStyle='#16a34a';
          tempCtx.lineWidth=1.5/zoomLevel;
          tempCtx.beginPath();
          tempCtx.arc(h.x+h.w/2,h.y+h.h/2,h.w/2,0,Math.PI*2);
          tempCtx.fill();
          tempCtx.stroke();
        }
        tempCtx.restore();
      }
    }
  }

  function hitTestHandle(p,fo){
    const handles=getHandleRects(fo);
    const hitPad=8/zoomLevel;
    for(const key of HANDLE_POSITIONS){
      const h=handles[key];
      if(p.x>=h.x-hitPad&&p.x<=h.x+h.w+hitPad&&p.y>=h.y-hitPad&&p.y<=h.y+h.h+hitPad){
        return'resize-'+key;
      }
    }
    return null;
  }

  function hitTestFloat(p){
    // Check in reverse order (top-most first)
    for(let i=floatingObjects.length-1;i>=0;i--){
      const fo=floatingObjects[i];
      if(p.x>=fo.x&&p.x<=fo.x+fo.w&&p.y>=fo.y&&p.y<=fo.y+fo.h){
        return fo;
      }
    }
    return null;
  }

  function showFloatContextMenu(fo){
    removeFloatContextMenu();
    const inner=document.getElementById('canvasInner');
    if(!inner)return;
    const menu=document.createElement('div');
    menu.className='float-ctx-menu';
    menu.id='floatCtxMenu';
    // Position above the object (in CSS pixels relative to canvasInner)
    // canvasInner CSS size = canvasBaseW * zoomLevel
    // fo.x/y are in logical canvas coords (canvasBase space)
    const menuX=fo.x*zoomLevel;
    const menuY=Math.max(0,fo.y*zoomLevel-44);
    menu.style.left=menuX+'px';
    menu.style.top=menuY+'px';
    menu.style.zIndex='100';
    menu.innerHTML=\`
      <button id="floatDuplicate" title="복제"><i class="fas fa-copy"></i></button>
      <button id="floatCommit" title="확정 (캔버스에 붙이기)"><i class="fas fa-check"></i></button>
      <button id="floatDelete" title="삭제"><i class="fas fa-trash"></i></button>
    \`;
    inner.appendChild(menu);
    floatCtxMenu=menu;

    menu.querySelector('#floatDuplicate').addEventListener('click',()=>{
      const newFo={img:fo.img,x:fo.x+20/zoomLevel,y:fo.y+20/zoomLevel,w:fo.w,h:fo.h,id:Date.now()};
      floatingObjects.push(newFo);
      selectedFloat=newFo;
      drawFloatingObjects();
      showFloatContextMenu(newFo);
    });
    menu.querySelector('#floatCommit').addEventListener('click',()=>{
      // Draw floating object onto main canvas permanently
      ctx.save();
      ctx.globalAlpha=1;
      ctx.globalCompositeOperation='source-over';
      ctx.drawImage(fo.img,fo.x,fo.y,fo.w,fo.h);
      ctx.restore();
      drawHistory.push({type:'float',img:fo.img,x:fo.x,y:fo.y,w:fo.w,h:fo.h});
      floatingObjects=floatingObjects.filter(f=>f.id!==fo.id);
      selectedFloat=null;
      removeFloatContextMenu();
      drawFloatingObjects();
    });
    menu.querySelector('#floatDelete').addEventListener('click',()=>{
      floatingObjects=floatingObjects.filter(f=>f.id!==fo.id);
      selectedFloat=null;
      removeFloatContextMenu();
      drawFloatingObjects();
    });
  }

  function removeFloatContextMenu(){
    if(floatCtxMenu){floatCtxMenu.remove();floatCtxMenu=null}
    const existing=document.getElementById('floatCtxMenu');
    if(existing)existing.remove();
  }

  // "Unstick" a committed float from drawHistory back to a floating object
  function unstickFloat(histIdx){
    const entry=drawHistory[histIdx];
    if(!entry||entry.type!=='float')return;
    // Remove from history
    drawHistory.splice(histIdx,1);
    // Re-render canvas without this float
    redrawStrokes();
    // Create a new floating object from the saved image
    const fo={img:entry.img,x:entry.x,y:entry.y,w:entry.w,h:entry.h,id:Date.now()};
    floatingObjects.push(fo);
    selectedFloat=fo;
    drawFloatingObjects();
    showFloatContextMenu(fo);
  }

  // Hit-test committed floats in drawHistory (reverse order = topmost first)
  function hitTestCommittedFloat(p){
    for(let i=drawHistory.length-1;i>=0;i--){
      const s=drawHistory[i];
      if(s.type==='float'&&p.x>=s.x&&p.x<=s.x+s.w&&p.y>=s.y&&p.y<=s.y+s.h){
        return i;
      }
    }
    return -1;
  }

  // Auto-commit ALL floating objects to drawCanvas permanently
  function commitAllFloats(){
    if(floatingObjects.length===0)return;
    ctx.save();
    ctx.globalAlpha=1;
    ctx.globalCompositeOperation='source-over';
    for(const fo of floatingObjects){
      ctx.drawImage(fo.img,fo.x,fo.y,fo.w,fo.h);
      drawHistory.push({type:'float',img:fo.img,x:fo.x,y:fo.y,w:fo.w,h:fo.h});
    }
    ctx.restore();
    floatingObjects=[];
    selectedFloat=null;
  }

  function captureRegion(x,y,w,h){
    // Capture region from drawCanvas as image
    if(w<5||h<5)return; // Too small
    // Source coordinates in physical pixels
    const sx=Math.round(x*canvasDpr), sy=Math.round(y*canvasDpr);
    const sw=Math.round(w*canvasDpr), sh=Math.round(h*canvasDpr);
    // Clamp to canvas bounds
    const cw=canvas.width, ch=canvas.height;
    const clampSx=Math.max(0,Math.min(sx,cw));
    const clampSy=Math.max(0,Math.min(sy,ch));
    const clampSw=Math.min(sw,cw-clampSx);
    const clampSh=Math.min(sh,ch-clampSy);
    if(clampSw<2||clampSh<2)return;
    // Create capture canvas at high resolution
    const capCanvas=document.createElement('canvas');
    capCanvas.width=clampSw;
    capCanvas.height=clampSh;
    const capCtx=capCanvas.getContext('2d');
    capCtx.imageSmoothingEnabled=true;
    capCtx.imageSmoothingQuality='high';
    // Merge bgCanvas + drawCanvas for capture (bg is separate layer)
    capCtx.drawImage(bgCanvas, clampSx, clampSy, clampSw, clampSh, 0, 0, clampSw, clampSh);
    capCtx.drawImage(canvas, clampSx, clampSy, clampSw, clampSh, 0, 0, clampSw, clampSh);
    const dataURL=capCanvas.toDataURL('image/png');
    const img=new Image();
    img.onload=()=>{
      // Store the natural (physical) size of the captured image for quality rendering
      const fo={img,x:x+10/zoomLevel,y:y+10/zoomLevel,w,h,id:Date.now(),
                naturalW:clampSw,naturalH:clampSh};
      floatingObjects.push(fo);
      selectedFloat=fo;
      drawFloatingObjects();
      showFloatContextMenu(fo);
    };
    img.src=dataURL;
  }

  // Coordinate mapping: screen-pixel → canvas logical-pixel
  function pos(e){
    const r=canvas.getBoundingClientRect();
    return{
      x:(e.clientX-r.left)/r.width*canvasBaseW,
      y:(e.clientY-r.top)/r.height*canvasBaseH
    };
  }

  // --- Draw a single smooth segment between 3 consecutive points ---
  // Uses quadratic Bezier through midpoints for smooth connection.
  // Fixed width throughout the stroke for consistent note-taking.
  function drawSegment(c, p0, p1, p2, stroke){
    c.save();
    c.strokeStyle=stroke.color;
    c.globalAlpha=stroke.alpha||1;
    c.globalCompositeOperation=stroke.composite||'source-over';
    c.lineCap='round';
    c.lineJoin='round';
    c.lineWidth=stroke.width;
    c.beginPath();
    if(!p2){
      // Only 2 points: straight line
      c.moveTo(p0.x,p0.y);
      c.lineTo(p1.x,p1.y);
    }else{
      // 3 points: smooth Bezier from midpoint(p0,p1) → through p1 → midpoint(p1,p2)
      const mx0=(p0.x+p1.x)/2, my0=(p0.y+p1.y)/2;
      const mx1=(p1.x+p2.x)/2, my1=(p1.y+p2.y)/2;
      c.moveTo(mx0,my0);
      c.quadraticCurveTo(p1.x,p1.y,mx1,my1);
    }
    c.stroke();
    c.restore();
  }

  // --- SHAPE PREVIEW on tempCanvas ---
  function drawShapePreview(start,end,tool,color,width){
    tempCtx.setTransform(1,0,0,1,0,0);
    tempCtx.clearRect(0,0,tempCanvas.width,tempCanvas.height);
    tempCtx.setTransform(canvasDpr,0,0,canvasDpr,0,0);
    tempCtx.imageSmoothingEnabled=true;
    tempCtx.imageSmoothingQuality='high';
    tempCtx.globalAlpha=1;
    tempCtx.globalCompositeOperation='source-over';
    // Re-draw floating objects if any exist (they live on tempCanvas)
    for(const fo of floatingObjects){
      tempCtx.save();
      tempCtx.globalAlpha=1;
      tempCtx.globalCompositeOperation='source-over';
      tempCtx.drawImage(fo.img,fo.x,fo.y,fo.w,fo.h);
      tempCtx.restore();
    }
    renderShape(tempCtx,{start,end,tool,color,width});
  }

  // --- COMMIT SHAPE to main canvas + history ---
  function commitShape(start,end,tool,color,width){
    const s={type:'shape',tool,start:{...start},end:{...end},color,width};
    renderShape(ctx,s);
    drawHistory.push(s);
  }

  function clearTemp(){
    // Simply delegate to drawFloatingObjects which handles all clearing and re-drawing.
    // If no floating objects, just clear the canvas raw.
    if(floatingObjects.length>0){
      drawFloatingObjects(); // This already clears tempCanvas + redraws all floats
    }else{
      tempCtx.setTransform(1,0,0,1,0,0);
      tempCtx.clearRect(0,0,tempCanvas.width,tempCanvas.height);
      tempCtx.setTransform(canvasDpr,0,0,canvasDpr,0,0);
      tempCtx.imageSmoothingEnabled=true;
      tempCtx.imageSmoothingQuality='high';
      tempCtx.globalAlpha=1;
      tempCtx.globalCompositeOperation='source-over';
    }
  }

  // ===== PINCH-ZOOM + PAN =====
  const wrap=document.getElementById('canvasWrap');
  function tDist(a,b){return Math.hypot(a.clientX-b.clientX,a.clientY-b.clientY)}
  function tMid(a,b){return{x:(a.clientX+b.clientX)/2,y:(a.clientY+b.clientY)/2}}

  wrap.addEventListener('touchstart',e=>{
    touchCount=e.touches.length;
    if(touchCount>=2){
      e.preventDefault();e.stopPropagation();
      pinching=true;
      if(drawing){drawing=false;curStroke=null;shapeStart=null;drawPointerId=-1;clearTemp();redrawStrokes()}
      pinchStartDist=tDist(e.touches[0],e.touches[1]);
      pinchStartZoom=zoomLevel;
      const m=tMid(e.touches[0],e.touches[1]);
      panStartX=m.x;panStartY=m.y;
      panScrollX=wrap.scrollLeft;panScrollY=wrap.scrollTop;
    }
  },{passive:false,capture:true});

  wrap.addEventListener('touchmove',e=>{
    touchCount=e.touches.length;
    if(touchCount>=2&&pinching){
      e.preventDefault();e.stopPropagation();
      const d=tDist(e.touches[0],e.touches[1]);
      setZoom(Math.max(0.5,Math.min(4,pinchStartZoom*(d/pinchStartDist))));
      const m=tMid(e.touches[0],e.touches[1]);
      wrap.scrollLeft=panScrollX-(m.x-panStartX);
      wrap.scrollTop=panScrollY-(m.y-panStartY);
    }
  },{passive:false,capture:true});

  wrap.addEventListener('touchend',e=>{
    touchCount=e.touches.length;
    if(touchCount<2&&pinching){
      pinching=false;
      // Pinch ended: now re-rasterize at final zoom level for sharp strokes
      setZoom(zoomLevel);
    }
  },{passive:false});
  wrap.addEventListener('touchcancel',()=>{
    const wasPinching=pinching;
    touchCount=0;pinching=false;
    if(wasPinching)setZoom(zoomLevel);
  },{passive:false});

  // ===== POINTER EVENTS: INCREMENTAL DRAWING =====
  // Architecture:
  //   drawCanvas(z:1) = background + ALL committed strokes (final quality)
  //   tempCanvas(z:2) = in-progress stroke (incremental segments)
  //
  // INCREMENTAL strategy:
  //   pointermove → draw ONLY the new segment on tempCanvas (no clear!)
  //   pointerup   → render full Bezier path on drawCanvas, clear tempCanvas
  //
  // This gives: zero lag, zero gaps, zero frame drops.
  // The final stroke on drawCanvas uses full Bezier for perfect anti-aliasing.

  const drawTarget=canvas;

  drawTarget.addEventListener('pointerdown',e=>{
    if(e.pointerType==='pen')hasPenInput=true;
    // Palm rejection: reject large touch contacts (palm/wrist)
    if(e.pointerType==='touch'){
      if(hasPenInput||pinching||touchCount>=2){e.preventDefault();return}
      // Reject palm: only when pen is detected (no reason to reject large touches on touch-only devices)
      if(hasPenInput&&(e.width>30||e.height>30)){e.preventDefault();return}
    }
    if(drawing||pinching){e.preventDefault();return}
    e.preventDefault();e.stopPropagation();
    drawTarget.setPointerCapture(e.pointerId);
    drawPointerId=e.pointerId;
    const p=pos(e);

    // ===== SCISSORS TOOL =====
    if(isScissors()){
      // First check: are we clicking on a floating object handle?
      if(selectedFloat){
        const handleHit=hitTestHandle(p,selectedFloat);
        if(handleHit){
          drawing=true;
          floatDragMode=handleHit;
          floatDragStart={x:p.x,y:p.y,origX:selectedFloat.x,origY:selectedFloat.y,origW:selectedFloat.w,origH:selectedFloat.h};
          removeFloatContextMenu();
          return;
        }
      }
      // Check: are we clicking on a floating object body?
      const hitFo=hitTestFloat(p);
      if(hitFo){
        selectedFloat=hitFo;
        drawing=true;
        floatDragMode='move';
        floatDragStart={x:p.x,y:p.y,origX:hitFo.x,origY:hitFo.y,origW:hitFo.w,origH:hitFo.h};
        removeFloatContextMenu();
        drawFloatingObjects();
        return;
      }
      // Check if clicking outside all floats → deselect
      if(selectedFloat){
        selectedFloat=null;
        removeFloatContextMenu();
        drawFloatingObjects();
      }
      // Check if clicking on a COMMITTED float in drawHistory → unstick it
      const committedIdx=hitTestCommittedFloat(p);
      if(committedIdx>=0){
        unstickFloat(committedIdx);
        drawing=false;drawPointerId=-1;
        return;
      }
      // Start new scissors selection
      drawing=true;
      scissorsStart=p;
      return;
    }

    // ===== TEXT TOOL =====
    if(curTool==='text'){
      showTextInput(p.x,p.y);
      return;
    }

    // ===== SELECT TOOL =====
    if(isSelect()){
      const hit=hitTest(p.x,p.y);
      if(hit>=0){
        selectedIdx=hit;
        selectDragStart={x:p.x,y:p.y,moved:false};
        drawing=true;
        // Show selection box + delete btn
        clearTemp();drawSelectionBox();showDeleteBtn();
      }else{
        clearSelection();
      }
      return;
    }

    // ===== NORMAL DRAWING =====
    drawing=true;redoStack=[];

    if(isShapeTool()){
      shapeStart=p;
    }else if(curTool==='eraser'){
      // Stroke-based eraser: no curStroke, just erase on contact
      curStroke=null;
      const eraserR=Math.max(curWidth*2,12);
      // Erase any stroke at the initial touch point
      let erased=false;
      for(let i=drawHistory.length-1;i>=0;i--){
        if(drawHistory[i].tool==='eraser')continue;
        if(strokeNearPoint(drawHistory[i],p.x,p.y,eraserR)){
          drawHistory.splice(i,1);erased=true;
        }
      }
      if(erased)redrawStrokes();
      // Show eraser cursor
      clearTemp();
      tempCtx.save();
      tempCtx.strokeStyle='rgba(255,107,107,0.5)';
      tempCtx.lineWidth=1.5;
      tempCtx.setLineDash([4,3]);
      tempCtx.beginPath();
      tempCtx.arc(p.x,p.y,eraserR,0,Math.PI*2);
      tempCtx.stroke();
      tempCtx.setLineDash([]);
      tempCtx.restore();
    }else if(curTool==='highlighter'){
      const hw=curWidth*3;
      curStroke={points:[p],color:curColor,width:hw,alpha:0.3,tool:'highlighter'};
    }else{
      // Pen tool: fixed width, smooth Bezier rendering
      curStroke={points:[p],color:curColor,width:curWidth,alpha:1,tool:'pen'};
    }

    // Immediate feedback: draw first dot (not for eraser)
    if(curStroke){
      clearTemp();
      tempCtx.save();
      tempCtx.fillStyle=curStroke.color;
      tempCtx.globalAlpha=curStroke.alpha||1;
      tempCtx.globalCompositeOperation=curStroke.composite||'source-over';
      tempCtx.beginPath();
      tempCtx.arc(p.x,p.y,curStroke.width/2,0,Math.PI*2);
      tempCtx.fill();
      tempCtx.restore();
    }
  },{passive:false});

  drawTarget.addEventListener('pointermove',e=>{
    if(!drawing||e.pointerId!==drawPointerId)return;
    // Palm rejection: ignore touch with large contact area or when pen detected
    if(e.pointerType==='touch'&&(hasPenInput||pinching||touchCount>=2))return;
    e.preventDefault();

    const p=pos(e);

    // ===== SELECT: drag to move =====
    if(isSelect()&&selectedIdx>=0&&selectDragStart){
      const dx=p.x-selectDragStart.x;
      const dy=p.y-selectDragStart.y;
      if(Math.abs(dx)>2||Math.abs(dy)>2) selectDragStart.moved=true;
      if(selectDragStart.moved){
        moveStroke(drawHistory[selectedIdx],dx,dy);
        selectDragStart.x=p.x;selectDragStart.y=p.y;
        redrawStrokes();clearTemp();drawSelectionBox();
        removeDeleteBtn(); // Hide while dragging
      }
      return;
    }

    // ===== SCISSORS: float drag/resize =====
    if(isScissors()&&floatDragMode&&selectedFloat&&floatDragStart){
      const dx=p.x-floatDragStart.x;
      const dy=p.y-floatDragStart.y;
      if(floatDragMode==='move'){
        selectedFloat.x=floatDragStart.origX+dx;
        selectedFloat.y=floatDragStart.origY+dy;
      }else{
        // Resize based on handle
        const mode=floatDragMode.replace('resize-','');
        let nx=floatDragStart.origX,ny=floatDragStart.origY,nw=floatDragStart.origW,nh=floatDragStart.origH;
        const aspect=floatDragStart.origW/floatDragStart.origH;
        const isCorner=['tl','tr','bl','br'].includes(mode);
        if(isCorner){
          // Corner handles: maintain aspect ratio
          // Use the larger delta to determine scale
          const absDx=Math.abs(dx),absDy=Math.abs(dy);
          let delta=absDx>absDy?dx:dy*aspect;
          if(mode==='br'){nw=floatDragStart.origW+delta;nh=nw/aspect}
          else if(mode==='bl'){nw=floatDragStart.origW-delta;nh=nw/aspect;nx=floatDragStart.origX+(floatDragStart.origW-nw)}
          else if(mode==='tr'){nw=floatDragStart.origW+delta;nh=nw/aspect;ny=floatDragStart.origY+(floatDragStart.origH-nh)}
          else if(mode==='tl'){nw=floatDragStart.origW-delta;nh=nw/aspect;nx=floatDragStart.origX+(floatDragStart.origW-nw);ny=floatDragStart.origY+(floatDragStart.origH-nh)}
        }else{
          // Edge handles: free resize
          if(mode==='r'){nw+=dx}
          else if(mode==='l'){nx+=dx;nw-=dx}
          else if(mode==='b'){nh+=dy}
          else if(mode==='t'){ny+=dy;nh-=dy}
        }
        // Minimum size
        if(nw<20){nw=20;if(isCorner)nh=nw/aspect}
        if(nh<20){nh=20;if(isCorner)nw=nh*aspect}
        selectedFloat.x=nx;selectedFloat.y=ny;selectedFloat.w=nw;selectedFloat.h=nh;
      }
      drawFloatingObjects();
      return;
    }

    // ===== SCISSORS: selection rectangle =====
    if(isScissors()&&scissorsStart){
      drawFloatingObjects(); // Redraw existing floats first
      // Draw selection rectangle with green dashed line
      const sx=Math.min(scissorsStart.x,p.x),sy=Math.min(scissorsStart.y,p.y);
      const sw=Math.abs(p.x-scissorsStart.x),sh=Math.abs(p.y-scissorsStart.y);
      tempCtx.strokeStyle='#16a34a';
      tempCtx.lineWidth=2/zoomLevel;
      tempCtx.setLineDash([6/zoomLevel,4/zoomLevel]);
      tempCtx.strokeRect(sx,sy,sw,sh);
      tempCtx.setLineDash([]);
      // Dim the outside area slightly
      tempCtx.fillStyle='rgba(0,0,0,0.1)';
      tempCtx.fillRect(0,0,canvasBaseW,sy); // top
      tempCtx.fillRect(0,sy,sx,sh); // left
      tempCtx.fillRect(sx+sw,sy,canvasBaseW-sx-sw,sh); // right
      tempCtx.fillRect(0,sy+sh,canvasBaseW,canvasBaseH-sy-sh); // bottom
      return;
    }

    if(isShapeTool()&&shapeStart){
      drawShapePreview(shapeStart,p,curTool,curColor,curWidth);
      return;
    }

    // ===== STROKE-BASED ERASER =====
    if(curTool==='eraser'){
      const eraserR=Math.max(curWidth*2,12);
      // Collect coalesced events for smooth erasing
      let evts;
      try{evts=e.getCoalescedEvents();if(!evts||!evts.length)evts=[e]}catch(_){evts=[e]}
      let erased=false;
      for(const ev of evts){
        const pt=pos(ev);
        for(let i=drawHistory.length-1;i>=0;i--){
          if(drawHistory[i].tool==='eraser')continue;
          if(strokeNearPoint(drawHistory[i],pt.x,pt.y,eraserR)){
            drawHistory.splice(i,1);erased=true;
          }
        }
      }
      if(erased)redrawStrokes();
      // Show eraser cursor
      const lastPt=pos(e);
      clearTemp();
      tempCtx.save();
      tempCtx.strokeStyle='rgba(255,107,107,0.5)';
      tempCtx.lineWidth=1.5;
      tempCtx.setLineDash([4,3]);
      tempCtx.beginPath();
      tempCtx.arc(lastPt.x,lastPt.y,eraserR,0,Math.PI*2);
      tempCtx.stroke();
      tempCtx.setLineDash([]);
      tempCtx.restore();
      return;
    }

    if(!curStroke)return;
    const isHighlighter=curStroke.tool==='highlighter';

    // Collect coalesced events for high-fidelity input
    let evts;
    try{evts=e.getCoalescedEvents();if(!evts||!evts.length)evts=[e]}catch(_){evts=[e]}

    for(const ev of evts){
      const pt=pos(ev);
      const pts=curStroke.points;
      const prev=pts[pts.length-1];
      const dist=Math.hypot(pt.x-prev.x,pt.y-prev.y);
      if(dist<0.5)continue; // Sub-pixel filter
      pts.push(pt);

      // PEN: draw each segment immediately (incremental rendering)
      if(!isHighlighter){
        const n=pts.length;
        if(n===2){
          drawSegment(tempCtx, pts[0], pts[1], null, curStroke);
        }else if(n>=3){
          drawSegment(tempCtx, pts[n-3], pts[n-2], pts[n-1], curStroke);
        }
      }
    }

    // HIGHLIGHTER: use rAF to batch full-stroke redraws (avoids alpha overlap)
    if(isHighlighter){
      if(!drawRAF){
        drawRAF=requestAnimationFrame(()=>{
          drawRAF=null;
          if(!curStroke)return;
          clearTemp();
          renderFullStroke(tempCtx, curStroke);
        });
      }
    }
  },{passive:false});

  function endDraw(e){
    if(e.pointerId!==drawPointerId)return;
    if(e.pointerType==='touch'&&hasPenInput)return;

    // ===== SCISSORS: end drag/resize or selection =====
    if(isScissors()){
      if(floatDragMode&&selectedFloat){
        floatDragMode=null;floatDragStart=null;
        drawFloatingObjects();
        showFloatContextMenu(selectedFloat);
        drawing=false;drawPointerId=-1;
        return;
      }
      if(scissorsStart){
        const p=pos(e);
        const sx=Math.min(scissorsStart.x,p.x),sy=Math.min(scissorsStart.y,p.y);
        const sw=Math.abs(p.x-scissorsStart.x),sh=Math.abs(p.y-scissorsStart.y);
        scissorsStart=null;
        drawing=false;drawPointerId=-1;
        if(sw>10&&sh>10){
          captureRegion(sx,sy,sw,sh);
        }else{
          drawFloatingObjects();
        }
        return;
      }
      drawing=false;drawPointerId=-1;
      return;
    }

    // ===== SELECT: end drag =====
    if(isSelect()){
      if(selectedIdx>=0&&selectDragStart&&selectDragStart.moved){
        showDeleteBtn(); // Re-show after drag
      }
      selectDragStart=null;
      drawing=false;drawPointerId=-1;
      return;
    }

    // ===== STROKE-BASED ERASER: just clear cursor and stop =====
    if(curTool==='eraser'){
      if(drawRAF){cancelAnimationFrame(drawRAF);drawRAF=null}
      clearTemp();
      drawing=false;drawPointerId=-1;
      return;
    }

    if(isShapeTool()&&shapeStart){
      const p=pos(e);
      const dx=Math.abs(p.x-shapeStart.x),dy=Math.abs(p.y-shapeStart.y);
      if(dx>3||dy>3){commitShape(shapeStart,p,curTool,curColor,curWidth)}
      clearTemp();
      shapeStart=null;
    }else if(curStroke&&curStroke.points.length>0){
      drawHistory.push(curStroke);
      // COMMIT: render the full Bezier/pressure path on drawCanvas for perfect quality
      // This replaces the incremental segments with one smooth path
      renderFullStroke(ctx,curStroke);
      if(drawRAF){cancelAnimationFrame(drawRAF);drawRAF=null}
      clearTemp();
    }else{
      clearTemp();
    }
    drawing=false;curStroke=null;drawPointerId=-1;
  }
  drawTarget.addEventListener('pointerup',endDraw);
  drawTarget.addEventListener('pointercancel',endDraw);

  // Block ALL default touch behaviors
  drawTarget.addEventListener('touchstart',e=>{e.preventDefault()},{passive:false});
  drawTarget.addEventListener('touchmove',e=>{e.preventDefault()},{passive:false});
  drawTarget.addEventListener('touchend',e=>{e.preventDefault()},{passive:false});
  drawTarget.addEventListener('contextmenu',e=>e.preventDefault());
  drawTarget.addEventListener('selectstart',e=>e.preventDefault());
}

function closeDrawingMode(save){
  // Auto-commit any remaining floating objects
  if(save&&floatingObjects.length>0&&canvas&&ctx){
    ctx.save();
    ctx.globalAlpha=1;
    ctx.globalCompositeOperation='source-over';
    for(const fo of floatingObjects){
      ctx.drawImage(fo.img,fo.x,fo.y,fo.w,fo.h);
      drawHistory.push({type:'float',img:fo.img,x:fo.x,y:fo.y,w:fo.w,h:fo.h});
    }
    ctx.restore();
  }
  floatingObjects=[];selectedFloat=null;floatDragMode=null;scissorsStart=null;
  if(floatCtxMenu){floatCtxMenu.remove();floatCtxMenu=null}
  const existingCtxMenu=document.getElementById('floatCtxMenu');
  if(existingCtxMenu)existingCtxMenu.remove();

  if(!save){
    // Cancel: don't save, just close
  }else{
    // Show preview in the form
    if(drawHistory.length>0){
      const preview=document.getElementById('drawingPreview');
      const pc=document.getElementById('drawPreviewCanvas');
      if(preview&&pc){
        pc.width=canvas.width;pc.height=canvas.height;
        pc.style.maxWidth='100%';pc.style.maxHeight='200px';pc.style.borderRadius='6px';pc.style.background='#fff';
        const pctx=pc.getContext('2d');
        // Merge bgCanvas + drawCanvas for preview
        pctx.drawImage(bgCanvas,0,0);
        pctx.drawImage(canvas,0,0);
        preview.style.display='block';
      }
    }
  }
  // Remove keyboard handler and overlay
  if(drawOverlay){
    if(drawOverlay._drawKeyHandler)document.removeEventListener('keydown',drawOverlay._drawKeyHandler);
    drawOverlay.remove();drawOverlay=null;
  }
  if(drawRAF){cancelAnimationFrame(drawRAF);drawRAF=null}
  document.body.style.overflow='';
  bgCanvas=null;bgCtx=null;canvas=null;ctx=null;tempCanvas=null;tempCtx=null;
}

function setZoom(level){
  zoomLevel=level;
  const inner=document.getElementById('canvasInner');
  if(!inner||!canvasBaseW)return;

  // CSS display size = base * zoom
  const displayW=canvasBaseW*zoomLevel;
  const displayH=canvasBaseH*zoomLevel;
  inner.style.width=displayW+'px';
  inner.style.height=displayH+'px';
  inner.style.transform='none';

  // CRITICAL: Scale internal canvas resolution with zoom level.
  // This prevents pixelation when zoomed in — strokes are re-rasterized.
  // effectiveDpr = baseDpr * zoom, capped at maxDpr for memory safety.
  const baseDpr=Math.max(window.devicePixelRatio||2,2);
  const maxDpr=8;
  const effectiveDpr=Math.min(baseDpr*zoomLevel, maxDpr);

  // Only resize if DPR changed >10% AND not currently pinching.
  // During pinch, we only change CSS size (fast). On pinch-end, we re-rasterize.
  const dprChanged=Math.abs(effectiveDpr-canvasDpr)/canvasDpr>0.1;
  
  if(dprChanged && !pinching && canvas && tempCanvas){
    canvasDpr=effectiveDpr;
    
    // Resize pixel buffers
    const newW=Math.round(canvasBaseW*canvasDpr);
    const newH=Math.round(canvasBaseH*canvasDpr);
    
    // Check memory limit: 3 canvases * 4 bytes/pixel < 400MB
    const memMB=newW*newH*4*3/1024/1024;
    if(memMB>400){
      canvasDpr=baseDpr;
      const safeW=Math.round(canvasBaseW*canvasDpr);
      const safeH=Math.round(canvasBaseH*canvasDpr);
      [bgCanvas,canvas,tempCanvas].forEach(c=>{c.width=safeW;c.height=safeH});
    }else{
      [bgCanvas,canvas,tempCanvas].forEach(c=>{c.width=newW;c.height=newH});
    }

    // Re-apply transforms and smoothing
    [bgCtx,ctx,tempCtx].forEach(c=>{
      if(!c)return;
      c.setTransform(canvasDpr,0,0,canvasDpr,0,0);
      c.imageSmoothingEnabled=true;
      c.imageSmoothingQuality='high';
    });

    // Re-render everything at new resolution
    redrawStrokes();
  }

  // Update CSS sizes
  [bgCanvas,canvas,tempCanvas].forEach(c=>{
    if(c){c.style.width=displayW+'px';c.style.height=displayH+'px'}
  });
  const label=document.getElementById('zoomLabel');
  if(label)label.textContent=Math.round(zoomLevel*100)+'%';
}

function drawBackground(){
  // Re-draw background on bgCanvas (separate layer, never erased)
  if(!bgCtx||!canvasBaseW)return;
  bgCtx.fillStyle='#ffffff';
  bgCtx.fillRect(0,0,canvasBaseW,canvasBaseH);
  if(bgImg&&bgImg.naturalWidth){
    // Use the stored wrapW from setupCanvas() so background image position
    // stays consistent with stroke coordinates even after resize/split-drag
    const wrapW=canvasSetupWrapW||canvasBaseW;
    let imgDrawW=Math.min(wrapW*0.9,bgImg.naturalWidth);
    let imgDrawH=imgDrawW*(bgImg.naturalHeight/bgImg.naturalWidth);
    const PAD_LEFT=100,PAD_TOP=40;
    const contentW=Math.max(imgDrawW,wrapW*0.7);
    const imgX=PAD_LEFT,imgY=PAD_TOP;
    bgCtx.drawImage(bgImg,imgX,imgY,imgDrawW,imgDrawH);
    bgCtx.strokeStyle='#ddd';bgCtx.lineWidth=0.5;bgCtx.setLineDash([]);
    bgCtx.strokeRect(imgX,imgY,imgDrawW,imgDrawH);
    const lineY=imgY+imgDrawH+30;
    bgCtx.strokeStyle='#ccc';bgCtx.lineWidth=1;
    bgCtx.setLineDash([6,4]);
    bgCtx.beginPath();bgCtx.moveTo(PAD_LEFT,lineY);bgCtx.lineTo(PAD_LEFT+contentW,lineY);bgCtx.stroke();
    bgCtx.setLineDash([]);
    bgCtx.fillStyle='#aaa';bgCtx.font='13px -apple-system,BlinkMacSystemFont,Pretendard,sans-serif';
    bgCtx.textAlign='center';
    bgCtx.fillText('\\u2193 \\ud480\\uc774 \\uc791\\uc131 \\uc601\\uc5ed',PAD_LEFT+contentW/2,lineY+20);
    bgCtx.textAlign='start';
  }
}

function redrawStrokes(){
  if(!canvas||!ctx)return;
  // Clear stroke layer (transparent)
  ctx.setTransform(1,0,0,1,0,0);
  ctx.clearRect(0,0,canvas.width,canvas.height);
  ctx.setTransform(canvasDpr,0,0,canvasDpr,0,0);
  ctx.imageSmoothingEnabled=true;
  ctx.imageSmoothingQuality='high';

  // Redraw background on bgCanvas
  drawBackground();

  // Replay all strokes on drawCanvas (transparent layer above bg)
  for(const s of drawHistory){
    if(s.type==='shape'){
      renderShape(ctx,s);
    }else if(s.type==='text'){
      renderText(ctx,s);
    }else if(s.type==='float'){
      ctx.save();ctx.globalAlpha=1;ctx.globalCompositeOperation='source-over';
      ctx.drawImage(s.img,s.x,s.y,s.w,s.h);
      ctx.restore();
    }else{
      renderFullStroke(ctx,s);
    }
  }
  // Re-render floating objects on tempCanvas if any exist
  if(floatingObjects.length>0){
    drawFloatingObjects();
  }
}

function buildImageGalleryHTML(q){
  var images=[];
  if(q.image_keys){
    try{var _ik=JSON.parse(q.image_keys);if(Array.isArray(_ik)&&_ik.length>0)images=_ik.map(function(o){return o.key});}catch(e){}
  }
  if(images.length===0&&q.image_key)images=[q.image_key];

  // 지문형 질문: 지문 이미지 + 문제 이미지 분리 렌더링
  var passageImages=[];
  if(q.content_type==='passage'&&q.passage_image_keys){
    try{var _pk=JSON.parse(q.passage_image_keys);if(Array.isArray(_pk)&&_pk.length>0)passageImages=_pk.map(function(o){return o.key});}catch(e){}
  }

  if(images.length===0&&passageImages.length===0)return '';
  var btns='<div class="q-img-btns"><button class="q-img-btn" id="copyBtn" onclick="event.stopPropagation();copyQuestionImage()" title="클립보드에 복사 (굿노트 등에 붙여넣기)"><i class="fas fa-copy"></i> 복사</button><button class="q-img-btn" id="downloadBtn" onclick="event.stopPropagation();downloadQuestionImage()" title="이미지 파일 저장 (클래스인 업로드용)"><i class="fas fa-download"></i> 저장</button></div>';

  // 지문형: 지문 섹션 + 문제 섹션
  if(passageImages.length>0){
    var html='<div style="display:flex;flex-direction:column;gap:16px">';
    // 지문 섹션
    html+='<div><div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:8px;display:flex;align-items:center;gap:6px"><i class="fas fa-book-open"></i> 지문</div>';
    var passageItems=passageImages.map(function(key,i){
      return '<div class="q-gallery-item"><img class="q-image" alt="지문 '+(i+1)+'/'+passageImages.length+'" src="/api/images/'+key+'" style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)"><div class="q-gallery-label">지문 '+(i+1)+'/'+passageImages.length+'</div></div>';
    }).join('');
    if(passageImages.length===1){
      html+='<div class="q-image-wrap"><img class="q-image" alt="지문" src="/api/images/'+passageImages[0]+'" style="min-height:100px;background:var(--bg3)" onclick="showModal(this.src)"></div>';
    }else{
      html+='<div class="q-image-gallery"><div class="q-gallery-track" id="passageGalTrack">'+passageItems+'</div><div class="q-gallery-arrows"><button class="q-gallery-arrow" id="passageGalPrev" disabled><i class="fas fa-chevron-left"></i></button><button class="q-gallery-arrow" id="passageGalNext"><i class="fas fa-chevron-right"></i></button></div></div>';
    }
    html+='</div>';
    // 문제 섹션
    if(images.length>0){
      html+='<div><div style="font-size:12px;font-weight:700;color:var(--green);margin-bottom:8px;display:flex;align-items:center;gap:6px"><i class="fas fa-pen"></i> 문제</div>';
      html+=btns;
      if(images.length===1){
        html+='<div class="q-image-wrap"><img class="q-image" id="qImage" alt="" src="/api/images/'+images[0]+'" style="min-height:100px;background:var(--bg3)" onclick="showModal(this.src)"></div>';
      }else{
        var probItems=images.map(function(key,i){
          return '<div class="q-gallery-item">'+(i===0?'<img class="q-image" id="qImage" alt="문제 '+(i+1)+'/'+images.length+'" src="/api/images/'+key+'" style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)">':'<img class="q-image" alt="문제 '+(i+1)+'/'+images.length+'" src="/api/images/'+key+'" style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)">')+'<div class="q-gallery-label">문제 '+(i+1)+'/'+images.length+'</div></div>';
        }).join('');
        html+='<div class="q-image-gallery"><div class="q-gallery-track" id="galTrack">'+probItems+'</div><div class="q-gallery-arrows"><button class="q-gallery-arrow" id="galPrev" disabled><i class="fas fa-chevron-left"></i></button><button class="q-gallery-arrow" id="galNext"><i class="fas fa-chevron-right"></i></button></div></div>';
      }
      html+='</div>';
    }
    html+='</div>';
    return html;
  }

  // 일반 질문: 기존 로직
  if(images.length===1){
    return '<div class="q-image-wrap">'+btns+'<img class="q-image" id="qImage" alt="" src="/api/images/'+images[0]+'" style="min-height:100px;background:var(--bg3)" onclick="showModal(this.src)"></div>';
  }
  var items=images.map(function(key,i){
    return '<div class="q-gallery-item">'+
      (i===0?'<img class="q-image" id="qImage" alt="이미지 '+(i+1)+'/'+images.length+'" src="/api/images/'+key+'" style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)">':
              '<img class="q-image" alt="이미지 '+(i+1)+'/'+images.length+'" src="/api/images/'+key+'" style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)">')+
      '<div class="q-gallery-label">'+(i+1)+'/'+images.length+'</div>'+
    '</div>';
  }).join('');
  var arrows='<div class="q-gallery-arrows"><button class="q-gallery-arrow" id="galPrev" disabled><i class="fas fa-chevron-left"></i></button><button class="q-gallery-arrow" id="galNext"><i class="fas fa-chevron-right"></i></button></div>';
  return '<div class="q-image-gallery">'+btns+'<div class="q-gallery-track" id="galTrack">'+items+'</div>'+arrows+'</div>';
}
function initGallerySliderFor(trackId,prevId,nextId){
  var track=document.getElementById(trackId);if(!track)return;
  var prev=document.getElementById(prevId),next=document.getElementById(nextId);
  var total=track.children.length,cur=0;
  function goTo(i){
    cur=Math.max(0,Math.min(i,total-1));
    track.children[cur].scrollIntoView({behavior:'smooth',block:'nearest',inline:'start'});
    updateUI();
  }
  function updateUI(){
    if(prev)prev.disabled=cur===0;
    if(next)next.disabled=cur===total-1;
    var labels=track.querySelectorAll('.q-gallery-label');
    for(var l=0;l<labels.length;l++){labels[l].textContent=(l+1)+'/'+total;}
  }
  if(prev)prev.onclick=function(e){e.stopPropagation();goTo(cur-1);};
  if(next)next.onclick=function(e){e.stopPropagation();goTo(cur+1);};
  track.addEventListener('scroll',function(){
    var w=track.offsetWidth;if(w===0)return;
    var idx=Math.round(track.scrollLeft/w);
    if(idx!==cur){cur=idx;updateUI();}
  },{passive:true});
}
function initGallerySlider(){
  initGallerySliderFor('galTrack','galPrev','galNext');
  initGallerySliderFor('passageGalTrack','passageGalPrev','passageGalNext');
}

function renderQ(q){
  if(!q)return;
  questionImageData=null;
  const isDone=q.status==='채택 완료';
  const statusCls=isDone?' done':' waiting';
  const statusText=isDone?'<i class="fas fa-check" style="margin-right:3px"></i>채택 완료':'대기중';
  const killerBadge=q.difficulty==='최상'?'<span style="display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;color:#ff4500;background:rgba(255,69,0,.1);border:1px solid rgba(255,69,0,.25);padding:2px 8px;border-radius:3px"><i class="fas fa-fire"></i> 고난도'+(q.reward_points?' <span style="color:#ffd700;font-weight:800">'+q.reward_points+'CP</span>':'')+'</span>'
    :q.difficulty==='1:1심화설명'?'<span style="display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;color:#6c5ce7;background:rgba(108,92,231,.1);border:1px solid rgba(108,92,231,.25);padding:2px 8px;border-radius:3px"><i class="fas fa-chalkboard-teacher"></i> 1:1 튜터링'+(q.reward_points?' <span style="color:#ffd700;font-weight:800">'+q.reward_points+'CP</span>':'')+'</span>':'';
  
  // Build AI meta section
  let aiMetaHTML='';
  if(q.ai_analyzed && q.ai_tags){
    const stars=q.ai_difficulty||'';
    const _diffMap={'최하':1,'하':1,'중하':2,'중':3,'중상':4,'상':4,'최상':5};
    const starCount=parseInt(stars.replace(/[^0-9]/g,''))||_diffMap[stars]||0;
    let starsHTML='';
    for(let i=1;i<=5;i++) starsHTML+='<span class="ai-meta__star'+(i<=starCount?'':' empty')+'">★</span>';
    
    const tags=(q.ai_tags||'').split(/\\s+/).filter(t=>t.startsWith('#'));
    let tagsHTML='';
    for(const t of tags) tagsHTML+='<span class="ai-meta__tag">'+t+'</span>';
    
    // Question type info
    const qtLabels={'A-1':'뭐지?','A-2':'어떻게?','B-1':'왜?','B-2':'만약에?','C-1':'뭐가 더 나아?','C-2':'그러면?','R-1':'어디서 틀렸지?','R-2':'왜 틀렸지?','R-3':'다음엔 어떻게?'};
    const qtColors={'A-1':'#9ca3af','A-2':'#60a5fa','B-1':'#34d399','B-2':'#2dd4bf','C-1':'#fbbf24','C-2':'#f87171','R-1':'#a78bfa','R-2':'#c084fc','R-3':'#e879f9'};
    const qtIcons={'A-1':'🔍','A-2':'🔍','B-1':'💡','B-2':'🔀','C-1':'⚖️','C-2':'🚀','R-1':'🔬','R-2':'🔬','R-3':'🛡️'};
    let qtHTML='';
    if(q.question_type && qtLabels[q.question_type]){
      const c=qtColors[q.question_type]||'#666';
      qtHTML='<div class="ai-meta__row">'+
        '<span class="ai-meta__label">질문유형</span>'+
        '<span class="ai-meta__badge" style="background:'+c+'15;color:'+c+';border:1px solid '+c+'33">'+qtIcons[q.question_type]+' '+qtLabels[q.question_type]+' ('+q.question_type+')</span>'+
      '</div>';
    }
    let sqHTML='';
    if(q.student_question_text && q.student_question_text.indexOf('(필기 없음')===-1){
      sqHTML='<div style="margin-top:10px;padding:14px 16px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.15);border-radius:8px">'+
        '<div style="font-size:18px;font-weight:600;color:#fbbf24;margin-bottom:6px"><i class="fas fa-pencil-alt" style="margin-right:6px"></i>인식된 학생 필기</div>'+
        '<div style="font-size:20px;color:var(--text);line-height:1.7">"'+q.student_question_text+'"</div>'+
      '</div>';
    }

    // === SECTION 1: 문제 분석 ===
    aiMetaHTML='<div class="ai-meta">'+
      '<div class="ai-meta__header"><i class="fas fa-microscope"></i> 문제 분석</div>'+
      '<div class="ai-meta__row">'+
        '<span class="ai-meta__label">난이도</span>'+
        '<div class="ai-meta__stars">'+starsHTML+'</div>'+
        (q.ai_grade_level?'<span class="ai-meta__badge ai-meta__badge--level"><i class="fas fa-graduation-cap"></i> '+q.ai_grade_level+'</span>':'')+
        (q.ai_estimated_time?'<span class="ai-meta__badge ai-meta__badge--time"><i class="fas fa-clock"></i> '+q.ai_estimated_time+'분</span>':'')+
      '</div>'+
      (q.ai_topic_main?'<div class="ai-meta__row">'+
        '<span class="ai-meta__label">단원</span>'+
        '<span class="ai-meta__badge ai-meta__badge--topic"><i class="fas fa-book"></i> '+q.ai_topic_main+'</span>'+
        (q.ai_topic_sub?'<span class="ai-meta__info"><i class="fas fa-chevron-right"></i> '+q.ai_topic_sub+'</span>':'')+
      '</div>':'')+
      '<div class="ai-meta__row">'+
        '<span class="ai-meta__label">태그</span>'+
        '<div class="ai-meta__tags">'+tagsHTML+'</div>'+
      '</div>'+
      (q.ai_description?'<div class="ai-meta__desc"><i class="fas fa-info-circle" style="margin-right:4px;color:var(--muted)"></i>'+q.ai_description+'</div>':'')+
    '</div>';

    // === SECTION 2: 질문 분석 ===
    aiMetaHTML+='<div class="ai-section ai-section--question">';
    aiMetaHTML+='<div class="ai-section__header"><i class="fas fa-search-plus"></i> 질문 분석</div>';
    aiMetaHTML+=qtHTML;
    aiMetaHTML+=sqHTML;
    if(q.ai_question_analysis){
      aiMetaHTML+='<div class="ai-section__body">'+q.ai_question_analysis+'</div>';
    } else {
      aiMetaHTML+='<div class="ai-section__body" style="color:var(--muted);font-style:italic">질문 분석 데이터를 준비 중입니다...</div>';
    }
    aiMetaHTML+='</div>';

    // === SECTION 3: 질문 성장 코칭 (새 인터랙티브 구조) ===
    aiMetaHTML+='<div class="ai-section ai-section--coaching">';
    var _modelBadge = q.ai_model === 'claude' 
      ? '<span style="display:inline-block;margin-left:8px;padding:3px 10px;border-radius:10px;font-size:13px;font-weight:600;background:linear-gradient(135deg,#d97706,#f59e0b);color:#fff;vertical-align:middle">🤖 Claude</span>'
      : (q.ai_model === 'gemini' 
        ? '<span style="display:inline-block;margin-left:8px;padding:3px 10px;border-radius:10px;font-size:13px;font-weight:600;background:linear-gradient(135deg,#4285f4,#34a853);color:#fff;vertical-align:middle">✨ Gemini</span>'
        : '');
    aiMetaHTML+='<div class="ai-section__header"><i class="fas fa-graduation-cap"></i> 질문 성장 코칭' + _modelBadge + '</div>';

    var _typeEmoji = {'A-1':'🔍','A-2':'🔍','B-1':'💡','B-2':'🔀','C-1':'⚖️','C-2':'🚀','R-1':'🔬','R-2':'🔬','R-3':'🛡️'};
    var _typeName = {'A-1':'뭐지?','A-2':'어떻게?','B-1':'왜?','B-2':'만약에?','C-1':'뭐가 더 나아?','C-2':'그러면?','R-1':'어디서 틀렸지?','R-2':'왜 틀렸지?','R-3':'다음엔 어떻게?'};
    var _levelColors = {'A-1':'#9ca3af','A-2':'#60a5fa','B-1':'#34d399','B-2':'#2dd4bf','C-1':'#fbbf24','C-2':'#f87171','R-1':'#a78bfa','R-2':'#c084fc','R-3':'#e879f9'};
    var _allTypes = ['A-1','A-2','B-1','B-2','C-1','C-2'];
    var _reflectTypes = ['R-1','R-2','R-3'];
    var curType = q.question_type || '';
    var curIdx = _allTypes.indexOf(curType);

    // 2축 호기심 사다리 (Curiosity Ladder)
    var isReflect = curType && curType.startsWith('R');
    var curCuriosityIdx = _allTypes.indexOf(curType);
    var curReflectIdx = _reflectTypes.indexOf(curType);

    if(curType){
      aiMetaHTML+='<div class="q-level-bar">';
      if(!isReflect && curCuriosityIdx >= 0){
        aiMetaHTML+='<div class="q-level-label">호기심 사다리 (Curiosity)</div>';
        aiMetaHTML+='<div class="q-level-track">';
        for(var li=0; li<_allTypes.length; li++){
          var t = _allTypes[li];
          var isActive = (li === curCuriosityIdx);
          var isPast = (li < curCuriosityIdx);
          var stepColor = _levelColors[t] || '#666';
          var cls = isActive ? 'q-level-step--active' : isPast ? 'q-level-step--past' : 'q-level-step--future';
          aiMetaHTML+='<div class="q-level-step '+cls+'" style="'+(isActive?'border-color:'+stepColor+';background:'+stepColor+'18':'')+'">';
          aiMetaHTML+='<span class="q-level-emoji">'+(_typeEmoji[t]||'')+'</span>';
          aiMetaHTML+='<span class="q-level-code">'+t+'</span>';
          if(isActive) aiMetaHTML+='<span class="q-level-name">'+(_typeName[t]||'')+'</span>';
          aiMetaHTML+='</div>';
          if(li < _allTypes.length-1) aiMetaHTML+='<div class="q-level-arrow '+(isPast?'q-level-arrow--past':'')+'">&#x203A;</div>';
        }
        aiMetaHTML+='</div>';
      } else if(isReflect && curReflectIdx >= 0){
        aiMetaHTML+='<div class="q-level-label">성찰 사다리 (Reflection)</div>';
        aiMetaHTML+='<div class="q-level-track">';
        for(var ri=0; ri<_reflectTypes.length; ri++){
          var rt = _reflectTypes[ri];
          var isActive = (ri === curReflectIdx);
          var isPast = (ri < curReflectIdx);
          var stepColor = _levelColors[rt] || '#666';
          var cls = isActive ? 'q-level-step--active' : isPast ? 'q-level-step--past' : 'q-level-step--future';
          aiMetaHTML+='<div class="q-level-step '+cls+'" style="'+(isActive?'border-color:'+stepColor+';background:'+stepColor+'18':'')+'">';
          aiMetaHTML+='<span class="q-level-emoji">'+(_typeEmoji[rt]||'')+'</span>';
          aiMetaHTML+='<span class="q-level-code">'+rt+'</span>';
          if(isActive) aiMetaHTML+='<span class="q-level-name">'+(_typeName[rt]||'')+'</span>';
          aiMetaHTML+='</div>';
          if(ri < _reflectTypes.length-1) aiMetaHTML+='<div class="q-level-arrow '+(isPast?'q-level-arrow--past':'')+'">&#x203A;</div>';
        }
        aiMetaHTML+='</div>';
      }
      aiMetaHTML+='</div>';
    }

    // 3대 필수조건 진단 + coaching_questions 데이터 파싱
    var _diagData = null;
    var _coachingQuestions = [];
    var _upgradeHint = null;
    var _growthInteractions = [];
    var _selectionPrompt = '';
    try {
      if(q.ai_coaching_data) {
        var _cdParsed = JSON.parse(q.ai_coaching_data);
        if(_cdParsed.diagnosis) _diagData = _cdParsed.diagnosis;
        if(_cdParsed.coaching_questions) _coachingQuestions = _cdParsed.coaching_questions;
        if(_cdParsed.upgrade_hint) _upgradeHint = _cdParsed.upgrade_hint;
        if(_cdParsed.growth_interactions) _growthInteractions = _cdParsed.growth_interactions;
        if(_cdParsed.selection_prompt) _selectionPrompt = _cdParsed.selection_prompt;
      }
    } catch(e){}
    // question_analysis에서 추가 추출
    var _qaJSON = null;
    try {
      if(q.ai_question_analysis && q.ai_question_analysis.indexOf('{') >= 0) {
        _qaJSON = JSON.parse(q.ai_question_analysis);
      }
    } catch(e){}
    if(!_diagData && _qaJSON && _qaJSON.diagnosis) _diagData = _qaJSON.diagnosis;
    if(!_upgradeHint && _qaJSON && _qaJSON.upgrade_hint) _upgradeHint = _qaJSON.upgrade_hint;

    var _LEVEL_XP = {'A-1':8,'A-2':10,'B-1':15,'B-2':20,'C-1':25,'C-2':30,'R-1':15,'R-2':20,'R-3':25};
    var _curXP = _LEVEL_XP[curType] || 10;
    var _nextLevel = curType === 'A-1' ? 'A-2' : curType === 'A-2' ? 'B-1' : curType === 'B-1' ? 'B-2' : curType === 'B-2' ? 'C-1' : curType === 'C-1' ? 'C-2' : curType === 'R-1' ? 'R-2' : curType === 'R-2' ? 'R-3' : '';

    // ── ① 코칭 코멘트 (격려) ──
    if(q.ai_coaching_comment){
      aiMetaHTML+='<div class="ai-section__body ai-section__coaching-text">'+q.ai_coaching_comment+'</div>';
    }

    // ── ② 왜 이 단계인지? (3대 필수조건 진단) ──
    if(_diagData && curType){
      var _dMet = [_diagData.specific_target&&_diagData.specific_target.met, _diagData.own_thinking&&_diagData.own_thinking.met, _diagData.context_connection&&_diagData.context_connection.met].filter(Boolean).length;
      var _dColor = _dMet===3?'#34d399':_dMet>=2?'#fbbf24':'#f87171';
      aiMetaHTML+='<div style="margin-top:12px;padding:14px 16px;background:rgba(99,102,241,.05);border:1px solid rgba(99,102,241,.12);border-radius:12px">';
      aiMetaHTML+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
      aiMetaHTML+='<span style="font-size:18px;font-weight:800;color:#a5b4fc">&#x1F50D; 왜 '+curType+' ('+(_typeName[curType]||'')+') 단계일까?</span>';
      aiMetaHTML+='<span style="font-size:14px;padding:3px 10px;border-radius:8px;background:'+_dColor+'20;color:'+_dColor+';font-weight:700">'+_dMet+'/3 충족</span>';
      aiMetaHTML+='</div>';
      aiMetaHTML+='<div style="font-size:15px;color:#888;margin-bottom:10px">B단계 이상이 되려면 3가지 필수조건을 모두 충족해야 해요</div>';
      var _dItems = [['① 구체적 대상','문제의 어떤 부분인지 특정', _diagData.specific_target],['② 자기 생각','"나는 ~라고 생각하는데"', _diagData.own_thinking],['③ 맥락 연결','지문/조건과 연결하여 질문', _diagData.context_connection]];
      _dItems.forEach(function(item){
        var dd=item[2]||{};
        aiMetaHTML+='<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:8px;padding:8px 10px;background:'+(dd.met?'rgba(52,211,153,.04)':'rgba(248,113,113,.04)')+';border-radius:8px;border:1px solid '+(dd.met?'rgba(52,211,153,.1)':'rgba(248,113,113,.1)')+'">';
        aiMetaHTML+='<span style="font-size:16px;flex-shrink:0;margin-top:1px">'+(dd.met?'&#x2705;':'&#x274C;')+'</span>';
        aiMetaHTML+='<div>';
        aiMetaHTML+='<div style="font-size:16px;font-weight:700;color:'+(dd.met?'#34d399':'#f87171')+'">'+item[0]+'</div>';
        aiMetaHTML+='<div style="font-size:14px;color:#999;margin-bottom:2px">'+item[1]+'</div>';
        if(dd.detail) aiMetaHTML+='<div style="font-size:15px;color:#d4d4d4;line-height:1.6">'+dd.detail+'</div>';
        aiMetaHTML+='</div></div>';
      });
      aiMetaHTML+='</div>';
    }

    // ── ③ 다음 단계로 올라가려면? (필수조건 + 처방) ──
    if(_nextLevel && curType){
      aiMetaHTML+='<div style="margin-top:12px;padding:14px 16px;background:linear-gradient(135deg,rgba(251,191,36,.06),rgba(245,158,11,.03));border:1px solid rgba(251,191,36,.15);border-radius:12px">';
      aiMetaHTML+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">';
      aiMetaHTML+='<span style="font-size:18px;font-weight:800;color:#fbbf24">&#x2B06;&#xFE0F; '+_nextLevel+' "'+(_typeName[_nextLevel]||'')+'" 단계로 올라가려면?</span>';
      aiMetaHTML+='</div>';

      // 필수조건 설명
      var _reqMap = {
        'A-2': '문제를 풀어달라는 요청에서 벗어나, "왜?"라는 질문을 던져보세요.',
        'B-1': '① 구체적 대상 지정 + ② 자기 생각 포함 + ③ 맥락 연결 — 3가지를 모두 넣어야 해요!',
        'B-2': '"만약 ~이면 어떻게 될까?" 형태로, 조건을 바꿔서 질문해보세요.',
        'C-1': '"A방법 vs B방법 중 어떤 게 더 나을까?" 처럼 방법을 비교/평가해보세요.',
        'C-2': '"이걸 다른 상황에도 적용하면?" 처럼 확장하고 일반화해보세요.',
        'R-2': '"왜 이 접근이 안 됐지?" 처럼 오류의 원인을 분석해보세요.',
        'R-3': '"다음에 비슷한 문제가 나오면 뭘 먼저 할까?" 처럼 전략을 수정해보세요.'
      };
      if(_reqMap[_nextLevel]){
        aiMetaHTML+='<div style="padding:10px 12px;background:rgba(251,191,36,.08);border-radius:8px;margin-bottom:10px;border-left:3px solid #fbbf24">';
        aiMetaHTML+='<div style="font-size:14px;font-weight:700;color:#fbbf24;margin-bottom:4px">&#x1F4CB; 필수 조건</div>';
        aiMetaHTML+='<div style="font-size:15px;color:#e0e0e0;line-height:1.6">'+_reqMap[_nextLevel]+'</div>';
        aiMetaHTML+='</div>';
      }

      // 업그레이드 방법 (AI의 처방)
      if(_upgradeHint){
        aiMetaHTML+='<div style="padding:10px 12px;background:rgba(52,211,153,.05);border-radius:8px;border-left:3px solid #34d399">';
        aiMetaHTML+='<div style="font-size:14px;font-weight:700;color:#34d399;margin-bottom:4px">&#x1F48A; AI 처방</div>';
        aiMetaHTML+='<div style="font-size:15px;color:#d4d4d4;line-height:1.6">'+_upgradeHint+'</div>';
        aiMetaHTML+='</div>';
      }
      aiMetaHTML+='</div>';
    }

    // ── ④ 업그레이드 질문 예시 카드 ──
    if(_coachingQuestions && _coachingQuestions.length > 0){
      aiMetaHTML+='<div style="margin-top:12px;padding:14px 16px;background:rgba(16,185,129,.04);border:1px solid rgba(16,185,129,.12);border-radius:12px">';
      aiMetaHTML+='<div style="font-size:15px;font-weight:800;color:#34d399;margin-bottom:4px">&#x1F4A1; 이런 질문이면 업그레이드!</div>';
      aiMetaHTML+='<div style="font-size:12px;color:#888;margin-bottom:12px">다음 단계로 올라갈 수 있는 질문 예시예요</div>';
      _coachingQuestions.forEach(function(cq, idx){
        var cqColor = _levelColors[cq.type] || '#34d399';
        aiMetaHTML+='<div style="margin-bottom:'+(idx<_coachingQuestions.length-1?'10':'0')+'px;padding:12px 14px;background:rgba(255,255,255,.03);border:1px solid '+cqColor+'22;border-radius:10px;border-left:4px solid '+cqColor+'">';
        // 헤더: 유형 배지 + 성장 경로
        aiMetaHTML+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:8px;flex-wrap:wrap">';
        aiMetaHTML+='<span style="font-size:12px;font-weight:700;padding:2px 8px;border-radius:8px;background:'+cqColor+'18;color:'+cqColor+'">'+(qtIcons[cq.type]||'💡')+' '+cq.type+' '+(_typeName[cq.type]||cq.type_label||'')+'</span>';
        if(cq.growth_path) aiMetaHTML+='<span style="font-size:11px;color:#777">'+cq.growth_path+'</span>';
        aiMetaHTML+='</div>';
        // 질문 예시
        aiMetaHTML+='<div style="font-size:16px;color:#e0e0e0;line-height:1.7;margin-bottom:6px;font-weight:600">"'+cq.question+'"</div>';
        // 왜 이게 더 좋은 질문인지
        if(cq.why_important){
          aiMetaHTML+='<div style="display:flex;gap:6px;align-items:flex-start">';
          aiMetaHTML+='<span style="font-size:14px;color:#fbbf24;flex-shrink:0">&#x1F4A1;</span>';
          aiMetaHTML+='<span style="font-size:14px;color:#a0a0a0;line-height:1.5">왜 더 좋은 질문? — '+cq.why_important+'</span>';
          aiMetaHTML+='</div>';
        }
        aiMetaHTML+='</div>';
      });
      aiMetaHTML+='</div>';
    }

    // ── ⑤ 사고력 체험 (growth_interactions) ──
    if(_growthInteractions && _growthInteractions.length > 0 && _coachingQuestions.length > 0){
      aiMetaHTML+='<div id="growthInteractionSection" style="margin-top:12px;padding:16px;background:linear-gradient(135deg,rgba(99,102,241,.06),rgba(139,92,246,.03));border:1px solid rgba(99,102,241,.15);border-radius:12px">';
      aiMetaHTML+='<div style="font-size:15px;font-weight:800;color:#a5b4fc;margin-bottom:4px">&#x1F9E0; 질문 업그레이드 체험해보기</div>';
      aiMetaHTML+='<div style="font-size:12px;color:#888;margin-bottom:14px">'+ (_selectionPrompt || '아래 중 더 궁금한 걸 골라보세요!') +'</div>';

      // Selection buttons for each coaching question
      aiMetaHTML+='<div id="giSelectionBtns">';
      _growthInteractions.forEach(function(gi, giIdx){
        var linkedCQ = _coachingQuestions[gi.target_coaching_index] || _coachingQuestions[giIdx] || {};
        var giColor = _levelColors[gi.target_type] || '#a5b4fc';
        aiMetaHTML+='<button onclick="startGrowthInteraction('+giIdx+')" class="gi-select-btn" data-gi-idx="'+giIdx+'" style="display:block;width:100%;text-align:left;margin-bottom:8px;padding:12px 14px;background:rgba(255,255,255,.04);border:1px solid '+giColor+'30;border-radius:10px;color:#e0e0e0;cursor:pointer;transition:all .2s">';
        aiMetaHTML+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">';
        aiMetaHTML+='<span style="font-size:12px;font-weight:700;padding:2px 8px;border-radius:8px;background:'+giColor+'18;color:'+giColor+'">'+(qtIcons[gi.target_type]||'&#x1F4A1;')+' '+gi.target_type+' '+(_typeName[gi.target_type]||gi.target_label||'')+'</span>';
        aiMetaHTML+='</div>';
        aiMetaHTML+='<div style="font-size:14px;line-height:1.6">'+(gi.selection_button || linkedCQ.question || '')+'</div>';
        aiMetaHTML+='</button>';
      });
      aiMetaHTML+='</div>';

      // Interaction area (hidden initially, shown when a button is clicked)
      aiMetaHTML+='<div id="giInteractionArea" style="display:none"></div>';
      aiMetaHTML+='</div>';
    }

    // 도전! 섹션 (더 좋은 질문 도전)
    if(curType && curType !== 'C-2'){
      var _nextLevelForChallenge = curType === 'A-1' ? 'A-2' : curType === 'A-2' ? 'B-1' : curType === 'B-1' ? 'B-2' : curType === 'B-2' ? 'C-1' : curType === 'C-1' ? 'C-2' : curType === 'R-1' ? 'R-2' : curType === 'R-2' ? 'R-3' : '';
      var _nextXP = _LEVEL_XP[_nextLevelForChallenge] || (_curXP + 5);
      // Check if challenge already completed (saved result)
      var _challengeResult = null;
      try { _challengeResult = q.challenge_result ? JSON.parse(q.challenge_result) : null; } catch(e) { _challengeResult = null; }
      
      aiMetaHTML+='<div id="challengeSection" style="margin-top:12px;padding:16px;background:linear-gradient(135deg,rgba(251,191,36,.08),rgba(245,158,11,.04));border:1px solid rgba(251,191,36,.2);border-radius:12px">';
      aiMetaHTML+='<div style="font-size:16px;font-weight:800;color:#fbbf24;margin-bottom:6px">&#x1F3AF; 더 좋은 질문 도전해볼래?</div>';
      
      if(_challengeResult){
        // === COMPLETED: Show archived result (visible to everyone) ===
        aiMetaHTML+='<div style="padding:8px 12px;background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.2);border-radius:8px;margin-bottom:12px;display:flex;align-items:center;gap:8px">';
        aiMetaHTML+='<i class="fas fa-check-circle" style="color:#34d399;font-size:14px"></i>';
        aiMetaHTML+='<span style="font-size:13px;font-weight:700;color:#34d399">도전 완료!</span>';
        var _crDate=_challengeResult.created_at?new Date(new Date(_challengeResult.created_at+'Z').getTime()+9*3600000).toISOString().slice(0,10):'';
        aiMetaHTML+='<span style="font-size:11px;color:#888;margin-left:auto">'+_crDate+'</span>';
        aiMetaHTML+='</div>';
        // Show the challenge text
        if(_challengeResult.challenge_text){
          aiMetaHTML+='<div style="padding:10px;background:rgba(255,255,255,.04);border-radius:8px;border-left:3px solid #fbbf24;margin-bottom:10px">';
          aiMetaHTML+='<div style="font-size:11px;color:#888;margin-bottom:4px">&#x1F4DD; 도전 질문</div>';
          aiMetaHTML+='<div style="font-size:14px;color:#e0e0e0;line-height:1.6">"'+_challengeResult.challenge_text+'"</div>';
          aiMetaHTML+='</div>';
        }
        // Show result (upgraded or not)
        var _crUpgraded = _challengeResult.upgraded;
        var _crLevel = _challengeResult.question_level || curType;
        var _crPrevLevel = _challengeResult.previous_level || curType;
        var _crColor = _crUpgraded ? '#34d399' : '#fbbf24';
        aiMetaHTML+='<div style="padding:12px;border-radius:10px;text-align:center;margin-bottom:10px;background:'+(_crUpgraded?'rgba(52,211,153,.08)':'rgba(251,191,36,.06)')+';border:1px solid '+(_crUpgraded?'rgba(52,211,153,.2)':'rgba(251,191,36,.15)')+'">';
        aiMetaHTML+='<div style="font-size:22px;margin-bottom:2px">'+(_crUpgraded?'&#x1F389;':'&#x1F44F;')+'</div>';
        aiMetaHTML+='<div style="font-size:16px;font-weight:800;color:'+_crColor+'">'+(_crUpgraded?_crLevel+' 레벨 업!':'도전 보너스!')+'</div>';
        aiMetaHTML+='<div style="font-size:12px;color:#aaa;margin-top:4px">'+(_crUpgraded?_crPrevLevel+' &#x2192; '+_crLevel:_crPrevLevel+' 유지')+((_challengeResult.cp||_challengeResult.xp)?' (+'+(_challengeResult.cp||_challengeResult.xp)+' CP)':'')+'</div>';
        aiMetaHTML+='</div>';
        // Show 3-criteria diagnosis
        if(_challengeResult.diagnosis){
          var _crDiag = _challengeResult.diagnosis;
          var _crMet = [_crDiag.specific_target&&_crDiag.specific_target.met, _crDiag.own_thinking&&_crDiag.own_thinking.met, _crDiag.context_connection&&_crDiag.context_connection.met].filter(Boolean).length;
          aiMetaHTML+='<div style="padding:12px;border-radius:8px;margin-bottom:10px;background:'+(_crMet===3?'rgba(52,211,153,.04)':'rgba(255,255,255,.03)')+';border:1px solid '+(_crMet===3?'rgba(52,211,153,.1)':'rgba(255,255,255,.06)')+'">';
          aiMetaHTML+='<div style="font-size:12px;font-weight:800;margin-bottom:8px;color:'+(_crMet===3?'#34d399':'#fbbf24')+'">&#x1F511; 3대 필수조건 <span style="font-size:10px;padding:2px 6px;border-radius:6px;background:'+(_crMet===3?'rgba(52,211,153,.15)':'rgba(251,191,36,.15)')+';color:'+(_crMet===3?'#34d399':'#fbbf24')+'">'+_crMet+'/3</span></div>';
          var _crItems = [['① 구체적 대상', _crDiag.specific_target],['② 자기 생각', _crDiag.own_thinking],['③ 맥락 연결', _crDiag.context_connection]];
          _crItems.forEach(function(item){ var dd=item[1]||{}; aiMetaHTML+='<div style="display:flex;gap:6px;align-items:flex-start;margin-bottom:6px;font-size:12px"><span style="color:'+(dd.met?'#34d399':'#f87171')+';font-weight:700;flex-shrink:0;min-width:100px">'+(dd.met?'&#x2705;':'&#x274C;')+' '+item[0]+'</span><span style="color:#b0b0b0;line-height:1.5">'+(dd.detail||'')+'</span></div>'; });
          aiMetaHTML+='</div>';
        }
        // Show feedback
        if(_challengeResult.feedback){
          aiMetaHTML+='<div style="padding:10px;background:rgba(99,102,241,.05);border-radius:8px;border:1px solid rgba(99,102,241,.1)"><div style="font-size:13px;color:#d4d4d4;line-height:1.6">&#x1F4AC; '+_challengeResult.feedback+'</div></div>';
        }
      } else {
        // === NOT COMPLETED: Show challenge input (only for question owner) ===
        aiMetaHTML+='<div style="font-size:13px;color:#999;margin-bottom:12px">현재 '+curType+' ('+_curXP+' CP) &#x2192; '+_nextLevelForChallenge+'로 올리면 '+_nextXP+' CP! 실패해도 보너스!</div>';
        // Challenge input area (hidden by default, shown only for owner)
        aiMetaHTML+='<div id="challengeInputArea" style="display:none">';
        aiMetaHTML+='<textarea id="challengeText" placeholder="3대 필수조건을 모두 넣어서 도전해봐!\\n① 구체적 대상 (수식/조건 지목)\\n② 자기 생각 (~것 같은데, ~인데)\\n③ 맥락 연결 (조건 변경/확장)" style="width:100%;min-height:70px;padding:12px;background:rgba(255,255,255,.06);border:1px solid rgba(251,191,36,.3);border-radius:10px;color:#e0e0e0;font-size:14px;line-height:1.6;resize:vertical;box-sizing:border-box"></textarea>';
        aiMetaHTML+='<div style="text-align:center;color:#555;font-size:12px;margin:8px 0">&#x2500;&#x2500; 또는 펜으로 써서 올려도 돼! &#x2500;&#x2500;</div>';
        aiMetaHTML+='<div style="display:flex;gap:6px;margin-bottom:8px">';
        aiMetaHTML+='<input type="file" id="challengeImgInput" accept="image/*" capture="environment" style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none" onchange="onChallengeImage(this)">';
        aiMetaHTML+='<button onclick="document.getElementById(&apos;challengeImgInput&apos;).click()" style="flex:1;padding:10px;background:rgba(255,255,255,.04);color:#888;border:1px dashed rgba(255,255,255,.15);border-radius:8px;font-size:12px;cursor:pointer">&#x1F4F7; 사진 촬영</button>';
        aiMetaHTML+='<button onclick="challengePaste()" style="flex:1;padding:10px;background:rgba(255,255,255,.04);color:#888;border:1px dashed rgba(255,255,255,.15);border-radius:8px;font-size:12px;cursor:pointer">&#x1F4CB; 붙여넣기</button>';
        aiMetaHTML+='</div>';
        aiMetaHTML+='<div id="challengeImgPreview" style="display:none;margin-bottom:8px;padding:8px;background:rgba(99,102,241,.06);border-radius:8px;border:1px solid rgba(99,102,241,.15);position:relative"><img id="challengePreviewImg" style="max-width:100%;max-height:140px;border-radius:6px"><button onclick="removeChallengeImage()" style="position:absolute;top:4px;right:4px;width:22px;height:22px;border-radius:50%;background:rgba(248,113,113,.9);color:#fff;border:none;font-size:12px;cursor:pointer">&#x2715;</button><div style="font-size:10px;color:#818cf8;margin-top:4px">&#x1F4CC; Gemini가 필기를 인식하여 진단합니다</div></div>';
        aiMetaHTML+='<button id="challengeSubmitBtn" onclick="submitChallenge('+q.id+')" style="width:100%;padding:12px;background:#f59e0b;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:800;cursor:pointer">제출하기</button>';
        aiMetaHTML+='</div>';
        aiMetaHTML+='<div id="challengeResultArea" style="display:none"></div>';
        // Buttons: show active for owner, locked for others
        aiMetaHTML+='<div id="challengeOwnerBtns" style="display:none">';
        aiMetaHTML+='<div style="display:flex;gap:8px">';
        aiMetaHTML+='<button onclick="showChallengeInput()" style="flex:1;padding:12px 16px;background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:800;cursor:pointer">&#x1F525; 도전!</button>';
        aiMetaHTML+='<button onclick="document.getElementById(&apos;challengeSection&apos;).style.display=&apos;none&apos;" style="padding:12px 16px;background:rgba(255,255,255,.06);color:#888;border:1px solid rgba(255,255,255,.1);border-radius:10px;font-size:14px;cursor:pointer">괜찮아요</button>';
        aiMetaHTML+='</div>';
        aiMetaHTML+='</div>';
        // Locked button for non-owners
        aiMetaHTML+='<div id="challengeLockedBtns" style="display:none">';
        aiMetaHTML+='<div style="padding:12px 16px;background:rgba(251,191,36,.05);color:rgba(255,255,255,.35);border:1px solid rgba(251,191,36,.15);border-radius:10px;font-size:14px;font-weight:700;text-align:center">';
        aiMetaHTML+='<i class="fas fa-lock" style="margin-right:6px;font-size:12px"></i>&#x1F525; 도전!';
        aiMetaHTML+='<div style="font-size:11px;color:rgba(255,255,255,.3);margin-top:4px;font-weight:500"><i class="fas fa-lock" style="margin-right:4px"></i>질문을 올린 학생만 도전할 수 있습니다</div>';
        aiMetaHTML+='</div>';
        aiMetaHTML+='</div>';
      }
      aiMetaHTML+='</div>';
    }

    // === 선생님과 함께 문제해결하기 (Stage 2 - Socratic Coaching) ===
    // ⚠️ 일시 중단: 유료화 이후 재활성화 예정 (아래 주석 해제하면 복원됨)
    // Always show the section, but lock it if not the question owner
    // aiMetaHTML+='<div id="tier2Section" style="margin-top:16px">';
    // aiMetaHTML+='<div id="tier2LoadingArea" style="display:none"></div>';
    // aiMetaHTML+='<button id="tier2StartBtn" onclick="startTier2('+q.id+')" style="display:none;width:100%;padding:16px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;border-radius:12px;font-size:16px;font-weight:800;cursor:pointer;align-items:center;justify-content:center;gap:10px">';
    // aiMetaHTML+='<i class="fas fa-chalkboard-teacher"></i> 선생님과 함께 문제해결하기</button>';
    // aiMetaHTML+='<div id="tier2LockedBtn" style="display:none;width:100%;padding:16px;background:linear-gradient(135deg,rgba(99,102,241,.15),rgba(139,92,246,.1));color:rgba(255,255,255,.35);border:1px solid rgba(99,102,241,.2);border-radius:12px;font-size:16px;font-weight:800;text-align:center;position:relative">';
    // aiMetaHTML+='<i class="fas fa-lock" style="margin-right:8px;font-size:14px"></i>';
    // aiMetaHTML+='<i class="fas fa-chalkboard-teacher" style="margin-right:8px"></i>선생님과 함께 문제해결하기';
    // aiMetaHTML+='<div style="font-size:11px;color:rgba(255,255,255,.3);margin-top:6px;font-weight:500"><i class="fas fa-lock" style="margin-right:4px"></i>질문을 올린 학생만 사용할 수 있습니다</div>';
    // aiMetaHTML+='</div>';
    // aiMetaHTML+='<div id="tier2CompletedBadge" style="display:none;text-align:center;padding:14px;background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.2);border-radius:12px"><div style="font-size:15px;font-weight:800;color:#34d399"><i class="fas fa-check-circle" style="margin-right:6px"></i>선생님과 함께 하기 완료!</div><div style="font-size:12px;color:#888;margin-top:4px">이 질문에 대한 코칭을 이미 받았습니다.</div></div>';
    // aiMetaHTML+='<div id="tier2SubText" style="display:none;text-align:center;font-size:11px;color:#666;margin-top:4px">일석이조: 문제를 풀면서 + 좋은 질문 패턴을 체화!</div>';
    // aiMetaHTML+='<div id="tier2ChatArea" style="display:none;margin-top:12px"></div>';
    // aiMetaHTML+='</div>';

    aiMetaHTML+='</div>';

  } else if(q.ai_analyzed===0 && q.has_image){
    aiMetaHTML='<div class="ai-meta"><div class="ai-meta__analyzing"><i class="fas fa-spinner"></i> AI가 문제를 분석 중입니다... <span style="font-size:12px;opacity:.6">(보통 10~20초)</span></div></div>';
    // Auto-poll until analysis completes
    if(!window._aiPollTimer){
      window._aiPollCount=0;
      window._aiPollTimer=setInterval(async()=>{
        try{
          window._aiPollCount++;
          const r=await fetch('/api/questions/'+qId);
          const d=await r.json();
          if(d && d.ai_analyzed!==0){
            clearInterval(window._aiPollTimer);
            window._aiPollTimer=null;
            cachedQData=d;
            renderQ(d);
          } else if(window._aiPollCount===5){
            // After 15s still pending → trigger manual analysis as fallback
            fetch('/api/questions/'+qId+'/analyze',{method:'POST',headers:authHeaders()}).catch(()=>{});
          }
        }catch(e){}
      },3000);
      // Auto-stop after 90s and show retry button
      setTimeout(()=>{
        if(window._aiPollTimer){
          clearInterval(window._aiPollTimer);
          window._aiPollTimer=null;
          // Force show retry UI
          const el=document.querySelector('.ai-meta__analyzing');
          if(el) el.innerHTML='<i class="fas fa-exclamation-triangle" style="color:#ff6b6b"></i> 분석 시간이 초과되었습니다. <button onclick="retryAnalysis()" style="background:#ff6b6b;color:#fff;border:none;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:13px;margin-left:8px"><i class="fas fa-redo"></i> 다시 분석</button>';
        }
      },90000);
    }
  } else if(q.ai_analyzed===-1 && q.has_image){
    aiMetaHTML='<div class="ai-meta"><div class="ai-meta__analyzing" style="color:#ff6b6b"><i class="fas fa-exclamation-triangle"></i> AI 분석에 실패했습니다. <button onclick="retryAnalysis()" style="background:#ff6b6b;color:#fff;border:none;padding:4px 12px;border-radius:6px;cursor:pointer;font-size:13px;margin-left:8px"><i class="fas fa-redo"></i> 다시 분석</button></div></div>';
  }

  // 상세 페이지 선생님 스티커
  var detailTeacherSticker='';
  if(q.requested_teacher){
    var _tSubjMap={'희성':'수학','우제':'수학','우현':'수학','윤동':'수학','성희':'영어','제이든':'영어','성웅':'영어','지영':'국어','서욱':'국어','지후':'국어','동현':'과학','성현':'과학'};
    var _tSubj=_tSubjMap[q.requested_teacher]||'수학';
    var _tEmoji={'수학':'⚡','영어':'🌊','국어':'🌸','과학':'🧬'};
    detailTeacherSticker='<div class="card__teacher-sticker card__teacher-sticker--'+_tSubj+'" style="margin:12px 0;transform:rotate(-1deg)">'+
      '<div class="sticker__name"><span class="sticker__emoji">'+(_tEmoji[_tSubj]||'⭐')+'</span> '+q.requested_teacher+'쌤 <span class="sticker__emoji">'+(_tEmoji[_tSubj]||'⭐')+'</span></div>'+
      '<div class="sticker__msg">가르침 부탁해요~ 🙏</div>'+
    '</div>';
  }

  document.getElementById('questionSection').innerHTML=
    '<div class="q-head">'+
      '<div class="q-avatar"><i class="fas fa-user"></i></div>'+
      '<div class="q-meta">'+
        '<div class="q-name"><a href="/coaching/'+q.user_id+'" style="color:inherit;text-decoration:none;border-bottom:1px dashed rgba(255,255,255,.2)" title="질문 분석 보기">'+q.author_name+'</a>'+(q.author_grade?' <span class="grade-tag">'+q.author_grade+'</span>':'')+'<a href="/coaching/'+q.user_id+'" style="margin-left:6px;font-size:10px;color:#fbbf24;text-decoration:none;opacity:.7" title="질문 분석 보기"><i class="fas fa-chart-line"></i></a></div>'+
        '<div class="q-sub">'+timeAgo(q.created_at)+'</div>'+
      '</div>'+
      '<div class="q-status'+statusCls+'">'+statusText+'</div>'+
    '</div>'+
    detailTeacherSticker+
    (q.content?'<div class="q-content">'+q.content+'</div>':'')+
    (q.has_image||q.passage_image_keys?buildImageGalleryHTML(q):'')+
    '<div class="q-footer"><span class="tag"><i class="fas fa-tag"></i>'+q.subject+'</span>'+killerBadge+'<span style="margin-left:auto">답변 '+(q.comment_count||0)+'</span></div>'+
    aiMetaHTML+
    (q.difficulty==='1:1심화설명'?'<div id="tutoringPanel" style="margin-top:16px"></div>':'');
  // Load tutoring data if applicable
  if(q.difficulty==='1:1심화설명') loadTutoring(q);
  // Init image gallery slider if multi-image
  if(q.has_image) initGallerySlider();
  // Render LaTeX math in AI sections
  setTimeout(renderAllMath, 100);
}
// === Copy question image to clipboard ===
async function copyQuestionImage(){
  const btn=document.getElementById('copyBtn');
  const img=document.getElementById('qImage');
  if(!img||!img.src) return;
  btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>';

  // Helper: convert image src to PNG blob via canvas
  function imgToPngBlob(){
    return fetch(img.src)
      .then(r=>r.blob())
      .then(blob=>{
        return new Promise((resolve,reject)=>{
          const c=document.createElement('canvas');
          const t=new Image();
          t.crossOrigin='anonymous';
          t.onload=()=>{
            c.width=t.naturalWidth;c.height=t.naturalHeight;
            const ctx=c.getContext('2d');
            ctx.drawImage(t,0,0);
            URL.revokeObjectURL(t.src);
            c.toBlob(b=>{b?resolve(b):reject(new Error('toBlob failed'))},'image/png');
          };
          t.onerror=reject;
          t.src=URL.createObjectURL(blob);
        });
      });
  }

  function showSuccess(){
    btn.innerHTML='<i class="fas fa-check"></i> 완료!';
    btn.classList.add('copied');
    setTimeout(()=>{btn.innerHTML='<i class="fas fa-copy"></i> 복사';btn.classList.remove('copied')},2000);
  }
  function showFail(msg){
    btn.innerHTML='<i class="fas fa-times"></i> '+(msg||'실패');
    setTimeout(()=>{btn.innerHTML='<i class="fas fa-copy"></i> 복사'},2000);
  }

  try{
    // Safari requires ClipboardItem to accept a Promise<Blob> directly
    // This preserves the user gesture context (no awaits before clipboard.write)
    if(typeof ClipboardItem!=='undefined' && navigator.clipboard && navigator.clipboard.write){
      const pngPromise=imgToPngBlob();
      // Safari-compatible: pass Promise<Blob> inside ClipboardItem
      try{
        await navigator.clipboard.write([new ClipboardItem({'image/png':pngPromise})]);
        showSuccess();
        return;
      }catch(safariErr){
        // Some browsers don't accept Promise<Blob>, try with resolved blob
        try{
          const pngBlob=await pngPromise;
          await navigator.clipboard.write([new ClipboardItem({'image/png':pngBlob})]);
          showSuccess();
          return;
        }catch(fallbackErr){
          console.warn('clipboard.write fallback failed',fallbackErr);
        }
      }
    }
    // Fallback for browsers without ClipboardItem/clipboard.write
    // Try execCommand approach
    try{
      const pngBlob=await imgToPngBlob();
      const urlObj=URL.createObjectURL(pngBlob);
      const tempImg2=document.createElement('img');
      tempImg2.src=urlObj;
      tempImg2.style.position='fixed';tempImg2.style.opacity='0';tempImg2.style.left='-9999px';
      document.body.appendChild(tempImg2);
      const range=document.createRange();
      range.selectNode(tempImg2);
      const sel=window.getSelection();
      sel.removeAllRanges();sel.addRange(range);
      const ok=document.execCommand('copy');
      sel.removeAllRanges();
      document.body.removeChild(tempImg2);
      URL.revokeObjectURL(urlObj);
      if(ok){showSuccess();return;}
    }catch(execErr){console.warn('execCommand copy failed',execErr)}
    // Final fallback: show a message instead of downloading
    showFail('복사 불가');
  }catch(e){
    console.error('copy error',e);
    showFail('복사 실패');
  }
}
window.copyQuestionImage=copyQuestionImage;

// === Download question image as file ===
async function downloadQuestionImage(){
  const btn=document.getElementById('downloadBtn');
  const img=document.getElementById('qImage');
  if(!img||!img.src) return;
  btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 저장 중...';
  try{
    const res=await fetch(img.src);
    const blob=await res.blob();
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');
    a.href=url;
    a.download='question_'+qId+'.png';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    btn.innerHTML='<i class="fas fa-check"></i> 저장됨!';
    btn.classList.add('downloaded');
    setTimeout(()=>{btn.innerHTML='<i class="fas fa-download"></i> 저장';btn.classList.remove('downloaded')},2000);
  }catch(e){
    console.error('download error',e);
    btn.innerHTML='<i class="fas fa-times"></i> 실패';
    setTimeout(()=>{btn.innerHTML='<i class="fas fa-download"></i> 저장'},2000);
  }
}
window.downloadQuestionImage=downloadQuestionImage;

let tutoringPollTimer=null;
async function loadTutoring(q){
  try{
    const res=await fetch('/api/questions/'+qId+'/tutoring');
    const data=await res.json();
    renderTutoring(q,data.slots||[],data.matches||[]);
    // Start polling for matching updates (every 10 seconds)
    startTutoringPoll(q,data.matches||[]);
  }catch(e){console.error('tutoring load error',e)}
}
function startTutoringPoll(q,prevMatches){
  if(tutoringPollTimer) clearInterval(tutoringPollTimer);
  // Only poll if not yet confirmed
  const isConfirmed=prevMatches.some(m=>m.status==='confirmed');
  if(isConfirmed) return;
  tutoringPollTimer=setInterval(async()=>{
    try{
      const res=await fetch('/api/questions/'+qId+'/tutoring');
      const data=await res.json();
      const newMatches=data.matches||[];
      const oldPending=prevMatches.filter(m=>m.status==='pending').length;
      const newPending=newMatches.filter(m=>m.status==='pending').length;
      const newConfirmed=newMatches.some(m=>m.status==='confirmed');
      // Only re-render if matches actually changed
      const matchChanged=JSON.stringify(newMatches)!==JSON.stringify(prevMatches);
      // If new pending match appeared, show notification to question owner
      if(newPending>oldPending&&currentUser&&cachedQData&&currentUser.id===cachedQData.user_id){
        showTutoringNotification(newMatches.find(m=>m.status==='pending'));
      }
      // Re-render panel only if data changed
      if(matchChanged) renderTutoring(q,data.slots||[],newMatches);
      prevMatches=newMatches;
      // Stop polling if confirmed
      if(newConfirmed){clearInterval(tutoringPollTimer);tutoringPollTimer=null;}
    }catch(e){}
  },10000);
}
function showTutoringNotification(match){
  if(!match)return;
  // Remove existing notification
  const old=document.getElementById('tutoringNotif');
  if(old)old.remove();
  const notif=document.createElement('div');
  notif.id='tutoringNotif';
  notif.style.cssText='position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:9999;background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff;padding:14px 20px;border-radius:12px;box-shadow:0 4px 20px rgba(108,92,231,.5);display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600;animation:slideDown .4s ease;max-width:90vw';
  notif.innerHTML='<i class="fas fa-bell" style="font-size:18px;animation:ring 1s ease infinite"></i><div><div style="margin-bottom:2px">1:1 튜터링 신청이 들어왔습니다!</div><div style="font-size:11px;font-weight:400;opacity:.8">'+match.tutor_name+'님이 신청했습니다. 아래에서 확정해주세요.</div></div><button onclick="this.parentElement.remove();document.getElementById(&quot;tutoringPanel&quot;).scrollIntoView({behavior:&quot;smooth&quot;})" style="background:rgba(255,255,255,.2);border:none;color:#fff;padding:6px 12px;border-radius:6px;font-size:11px;cursor:pointer;white-space:nowrap">확인</button>';
  document.body.appendChild(notif);
  // Auto-remove after 15s
  setTimeout(()=>{if(notif.parentElement)notif.remove()},15000);
}
function renderTutoring(q,slots,matches){
  const panel=document.getElementById('tutoringPanel');
  if(!panel)return;
  const isOwner=currentUser&&currentUser.id==q.user_id;
  const confirmedMatch=matches.find(m=>m.status==='confirmed');
  const completedMatch=matches.find(m=>m.status==='completed');
  const acceptedMatch=matches.find(m=>m.status==='accepted');
  const pendingMatch=matches.find(m=>m.status==='pending');
  const myMatch=currentUser?matches.find(m=>m.tutor_id===currentUser.id&&m.status==='pending'):null;

  let html='<div style="background:linear-gradient(135deg,rgba(108,92,231,.1),rgba(108,92,231,.05));border:1px solid rgba(108,92,231,.25);border-radius:8px;padding:16px;margin-top:4px">';
  html+='<div style="font-size:22px;font-weight:700;color:#a29bfe;margin-bottom:16px;display:flex;align-items:center;gap:10px"><i class="fas fa-chalkboard-teacher" style="font-size:22px"></i> 1:1 튜터링 매칭</div>';

  if(acceptedMatch){
    // Already accepted - show tags/review
    const slotInfo=slots.find(s=>s.id===acceptedMatch.slot_id);
    let aTags=[];
    try{if(acceptedMatch.acceptance_tags)aTags=JSON.parse(acceptedMatch.acceptance_tags)}catch(e){}
    const tagMap={kind:{e:'💛',t:'친절하고 이해하기 쉽게 알려주셨어요!'},detail:{e:'📖',t:'꼼꼼하게 설명해줘서 확실히 이해됐어요.'},patience:{e:'😊',t:'모르는 부분도 인내심 있게 기다려주셨어요.'},pinpoint:{e:'🎯',t:'헷갈렸던 핵심을 정확히 짚어주셨어요!'},relief:{e:'🚀',t:'답답했던 속이 뻥 뚫리는 기분이에요.'},motivated:{e:'🔥',t:'가르쳐준 대로 하니 공부 의욕이 생겨요!'},again:{e:'🙌',t:'다음에도 또 설명 부탁드리고 싶어요!'}};
    html+='<div style="text-align:center;padding:16px">';
    html+='<div style="font-size:24px;margin-bottom:8px">⭐</div>';
    html+='<div style="font-size:14px;font-weight:700;color:#00c853;margin-bottom:4px">채택 완료!</div>';
    html+='<div style="font-size:12px;color:var(--muted);margin-bottom:12px">'+acceptedMatch.tutor_name+(acceptedMatch.tutor_grade?' ('+acceptedMatch.tutor_grade+')':'')+'님의 1:1 튜터링이 채택되었습니다</div>';
    if(aTags.length>0){
      html+='<div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-bottom:8px">';
      aTags.forEach(tid=>{const t=tagMap[tid];if(t)html+='<span style="display:inline-flex;align-items:center;gap:4px;padding:4px 10px;font-size:11px;background:rgba(0,200,83,.08);border:1px solid rgba(0,200,83,.2);border-radius:20px;color:#00c853">'+t.e+' '+t.t+'</span>'});
      html+='</div>';
    }
    if(acceptedMatch.acceptance_review){
      html+='<div style="margin-top:8px;padding:10px 14px;background:rgba(255,255,255,.04);border-radius:8px;border:1px solid rgba(255,255,255,.06);font-size:12px;color:var(--dim);text-align:left;line-height:1.5">"'+acceptedMatch.acceptance_review+'"</div>';
    }
    html+='</div>';
  } else if(confirmedMatch || completedMatch){
    const activeMatch = completedMatch || confirmedMatch;
    const slotInfo=slots.find(s=>s.id===activeMatch.slot_id);
    const slotDate=slotInfo?parseSlotTimeForTutoring(slotInfo.slot_time):null;
    const isPast=slotDate&&slotDate.getTime()<Date.now();

    html+='<div style="text-align:center;padding:16px">';
    html+='<div style="font-size:24px;margin-bottom:8px">'+(isPast?'✅':'🎉')+'</div>';
    html+='<div style="font-size:14px;font-weight:700;color:var(--green);margin-bottom:4px">'+(isPast?'수업 시간이 지났습니다':'매칭 확정!')+'</div>';
    html+='<div style="font-size:13px;color:var(--white);margin-bottom:4px"><i class="fas fa-clock" style="color:#6c5ce7"></i> '+(slotInfo?slotInfo.slot_time:'')+'</div>';
    html+='<div style="font-size:12px;color:var(--muted)">답변자: '+activeMatch.tutor_name+(activeMatch.tutor_grade?' ('+activeMatch.tutor_grade+')':'')+'</div>';

    // Show accept button if: owner + session time has passed
    if(isOwner && isPast){
      html+='<div style="margin-top:16px;padding-top:12px;border-top:1px solid rgba(108,92,231,.15)">';
      html+='<div style="font-size:12px;color:var(--muted);margin-bottom:8px">1:1 튜터링이 만족스러웠나요?</div>';
      html+='<button onclick="acceptTutor()" style="padding:12px 24px;border-radius:8px;background:linear-gradient(135deg,#7c6aef,#6c5ce7);color:#fff;border:none;font-size:14px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:6px"><i class="fas fa-star"></i> 채택하기 ('+(q.reward_points||0)+'CP 지급)</button>';
      html+='</div>';
    } else if(!isOwner && isPast){
      html+='<div style="font-size:11px;color:var(--muted);margin-top:8px"><i class="fas fa-hourglass-half"></i> 질문자의 채택을 기다리고 있습니다</div>';
    } else {
      html+='<div style="font-size:11px;color:var(--muted);margin-top:8px"><i class="fas fa-info-circle"></i> 정율톡 연동 후 자동으로 톡방이 생성됩니다</div>';
    }
    html+='</div>';
  } else if(isOwner){
    // Question owner view - show slots and pending match
    html+='<div style="font-size:11px;color:var(--muted);margin-bottom:10px">내가 선택한 시간</div>';
    html+='<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">';
    slots.forEach(s=>{html+='<span style="display:inline-flex;align-items:center;gap:4px;padding:6px 12px;font-size:12px;font-weight:600;background:rgba(108,92,231,.15);border:1px solid rgba(108,92,231,.3);border-radius:20px;color:#a29bfe"><i class="fas fa-clock"></i> '+s.slot_time+'</span>'});
    html+='</div>';

    if(pendingMatch){
      // Check if hold expired
      const heldMs=Date.now()-new Date(pendingMatch.held_at+'Z').getTime();
      const leftMin=Math.max(0,Math.ceil((15*60*1000-heldMs)/60000));
      const slotInfo=slots.find(s=>s.id===pendingMatch.slot_id);
      html+='<div style="background:rgba(255,215,0,.08);border:1px solid rgba(255,215,0,.2);border-radius:6px;padding:12px;margin-top:8px">';
      html+='<div style="font-size:12px;font-weight:700;color:#ffd700;margin-bottom:6px"><i class="fas fa-bell"></i> 신청이 들어왔습니다!</div>';
      html+='<div style="font-size:12px;color:var(--white);margin-bottom:4px">'+pendingMatch.tutor_name+(pendingMatch.tutor_grade?' ('+pendingMatch.tutor_grade+')':'')+'</div>';
      html+='<div style="font-size:11px;color:var(--muted);margin-bottom:8px">희망 시간: '+(slotInfo?slotInfo.slot_time:'')+(leftMin>0?' · 우선권 '+leftMin+'분 남음':'')+'</div>';
      html+='<div style="display:flex;gap:8px">';
      html+='<button onclick="confirmMatch('+pendingMatch.id+')" style="flex:1;padding:10px;border-radius:6px;background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer"><i class="fas fa-check"></i> 확정하기</button>';
      html+='</div></div>';
    } else {
      html+='<div style="text-align:center;padding:8px;color:var(--muted);font-size:12px"><i class="fas fa-hourglass-half"></i> 답변자 모집 중...</div>';
      // Edit slots button (only when no pending or confirmed match)
      html+='<div style="text-align:center;margin-top:8px"><button onclick="showEditSlotsModal()" style="padding:8px 16px;border-radius:6px;background:rgba(108,92,231,.1);border:1px solid rgba(108,92,231,.2);color:#a29bfe;font-size:12px;font-weight:600;cursor:pointer"><i class="fas fa-edit"></i> 시간 수정</button></div>';
    }
  } else {
    // Other users (potential tutors)
    html+='<div style="font-size:11px;color:var(--muted);margin-bottom:10px">🕒 가능한 시간</div>';
    html+='<div id="slotBtnWrap" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">';
    slots.forEach(s=>{
      const isChecked=myMatch&&myMatch.slot_id===s.id;
      html+='<button class="tutor-slot-btn'+(isChecked?' checked':'')+'" data-sid="'+s.id+'" onclick="selectSlot(this,'+s.id+')" style="padding:10px 16px;font-size:13px;font-weight:700;border-radius:24px;cursor:pointer;transition:all .25s;border:2px solid '+(isChecked?'#6c5ce7':'var(--border)')+';background:'+(isChecked?'linear-gradient(135deg,rgba(108,92,231,.3),rgba(162,155,254,.2))':'#1e1e1e')+';color:'+(isChecked?'#a29bfe':'var(--muted)')+'">'+(isChecked?'<i class="fas fa-check-circle" style="margin-right:4px"></i>':'<i class="fas fa-clock" style="margin-right:4px"></i>')+s.slot_time+'</button>'
    });
    html+='</div>';

    if(myMatch){
      html+='<div style="text-align:center;padding:10px;font-size:13px;color:#a29bfe;background:rgba(108,92,231,.08);border-radius:10px;border:1px solid rgba(108,92,231,.2)"><i class="fas fa-check-circle" style="margin-right:4px"></i> 신청 완료! 질문자 확정을 기다려주세요.</div>';
    } else if(pendingMatch){
      html+='<div style="text-align:center;padding:8px;font-size:12px;color:var(--muted)"><i class="fas fa-lock"></i> 현재 다른 답변자가 대기 중입니다.</div>';
    } else if(currentUser) {
      html+='<div id="slotGuide" style="text-align:center;padding:10px;font-size:13px;color:var(--muted);transition:all .3s"><i class="fas fa-hand-pointer" style="margin-right:4px"></i> 원하는 시간을 탭하여 선택하세요</div>';
      html+='<div id="slotConfirmWrap" style="display:none;text-align:center;margin-top:8px;animation:fadeSlideUp .3s ease">';
      html+='<div style="font-size:12px;color:#a29bfe;margin-bottom:8px"><i class="fas fa-check"></i> <span id="selectedSlotTime"></span> 선택됨</div>';
      html+='<button id="slotConfirmBtn" onclick="confirmSlotSelection()" style="padding:12px 32px;border-radius:24px;background:linear-gradient(135deg,#6c5ce7,#a29bfe);border:none;color:#fff;font-size:14px;font-weight:800;cursor:pointer;box-shadow:0 4px 15px rgba(108,92,231,.4);transition:all .2s"><i class="fas fa-paper-plane" style="margin-right:6px"></i>신청 완료하기</button>';
      html+='</div>';
    } else {
      html+='<div style="text-align:center;padding:8px;font-size:12px;color:var(--muted)"><a href="/login" style="color:#a29bfe">로그인</a> 후 신청할 수 있습니다</div>';
    }
  }
  html+='</div>';
  panel.innerHTML=html;
}

// Helper: parse slot time for tutoring panel
function parseSlotTimeForTutoring(slotTime){
  if(!slotTime)return null;
  const parts=slotTime.trim().split(' ');
  if(parts.length<3)return null;
  const dp=parts[1].split('/'),tp=parts[2].split(':');
  const now=new Date(),yr=now.getFullYear();
  const d=new Date(yr,parseInt(dp[0])-1,parseInt(dp[1]),parseInt(tp[0]),parseInt(tp[1]||'0'));
  if(d.getTime()<now.getTime()-180*86400000)d.setFullYear(yr+1);
  return d;
}

// Edit slots modal - same picker UI as new question page
let editPickedSlots=[];
let editCurDay=null;
const EDIT_TIMES=[];
for(let h=15;h<=22;h++){EDIT_TIMES.push(h+':00');if(h<22)EDIT_TIMES.push(h+':30')}

function showEditSlotsModal(){
  editPickedSlots=[];
  editCurDay=null;
  const overlay=document.createElement('div');
  overlay.id='editSlotsOverlay';
  overlay.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px';
  overlay.innerHTML=\`
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:14px;max-width:420px;width:100%;padding:24px;animation:slideUp .3s ease;max-height:90vh;overflow-y:auto">
    <div style="font-size:16px;font-weight:700;color:var(--white);margin-bottom:4px"><i class="fas fa-clock" style="color:#a29bfe"></i> 시간 수정</div>
    <div style="font-size:12px;color:var(--muted);margin-bottom:16px">기존 시간이 초기화됩니다. 새 시간을 선택하세요 (최대 3개)</div>
    <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;overflow-x:auto" id="editDayTabs"></div>
    <div id="editTimeGrid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;max-height:200px;overflow-y:auto"></div>
    <div id="editSelectedSlots" style="margin-top:12px;min-height:28px"></div>
    <div style="display:flex;gap:8px;margin-top:16px">
      <button onclick="document.getElementById('editSlotsOverlay').remove()" style="flex:1;padding:12px;border-radius:8px;background:var(--bg);color:var(--dim);border:1px solid var(--border);font-size:13px;font-weight:600;cursor:pointer">취소</button>
      <button onclick="saveEditSlots()" style="flex:1;padding:12px;border-radius:8px;background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff;border:none;font-size:13px;font-weight:700;cursor:pointer"><i class="fas fa-save"></i> 저장</button>
    </div>
  </div>\`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click',(e)=>{if(e.target===overlay)overlay.remove()});
  initEditSlotPicker();
}
function initEditSlotPicker(){
  const today=new Date();
  const dayList=[];
  for(let i=0;i<7;i++){
    const d=new Date(today);d.setDate(today.getDate()+i);
    const dayIdx=d.getDay();const dayName=['일','월','화','수','목','금','토'][dayIdx];
    const mm=(d.getMonth()+1);const dd=d.getDate();
    dayList.push({label:dayName+' '+mm+'/'+dd, value:dayName+' '+(mm<10?'0'+mm:mm)+'/'+(dd<10?'0'+dd:dd)});
  }
  const tabs=document.getElementById('editDayTabs');
  tabs.innerHTML=dayList.map((d,i)=>'<div style="padding:6px 12px;border-radius:16px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;transition:all .2s;border:1px solid '+(i===0?'#6c5ce7':'var(--border)')+';background:'+(i===0?'rgba(108,92,231,.2)':'var(--bg)')+';color:'+(i===0?'#a29bfe':'var(--dim)')+'" data-day="'+d.label+'" onclick="editPickDay(this)">'+d.label+'</div>').join('');
  editCurDay=dayList[0].label;
  renderEditTimeGrid();
  renderEditSelectedSlots();
}
function editPickDay(el){
  document.querySelectorAll('#editDayTabs > div').forEach(t=>{t.style.border='1px solid var(--border)';t.style.background='var(--bg)';t.style.color='var(--dim)'});
  el.style.border='1px solid #6c5ce7';el.style.background='rgba(108,92,231,.2)';el.style.color='#a29bfe';
  editCurDay=el.dataset.day;renderEditTimeGrid();
}
function renderEditTimeGrid(){
  const grid=document.getElementById('editTimeGrid');
  grid.innerHTML=EDIT_TIMES.map(t=>{
    const key=editCurDay+' '+t;
    const picked=editPickedSlots.includes(key);
    const full=editPickedSlots.length>=3&&!picked;
    return'<div style="padding:8px 4px;text-align:center;font-size:12px;font-weight:600;border-radius:8px;cursor:'+(full?'not-allowed':'pointer')+';transition:all .2s;border:1px solid '+(picked?'#6c5ce7':'var(--border)')+';background:'+(picked?'rgba(108,92,231,.2)':'var(--bg)')+';color:'+(picked?'#a29bfe':full?'var(--border)':'var(--dim)')+'" data-slot="'+key+'" onclick="editToggleSlot(this)">'+t+'</div>';
  }).join('');
}
function editToggleSlot(el){
  const key=el.dataset.slot;
  if(editPickedSlots.includes(key)){editPickedSlots=editPickedSlots.filter(s=>s!==key)}
  else{if(editPickedSlots.length>=3)return;editPickedSlots.push(key)}
  renderEditTimeGrid();renderEditSelectedSlots();
}
function editRemoveSlot(key){editPickedSlots=editPickedSlots.filter(s=>s!==key);renderEditTimeGrid();renderEditSelectedSlots()}
function renderEditSelectedSlots(){
  const el=document.getElementById('editSelectedSlots');
  if(!editPickedSlots.length){el.innerHTML='<div style="font-size:11px;color:var(--muted)"><i class="fas fa-info-circle"></i> 요일을 선택하고 시간을 탭하세요 (최대 3개)</div>';return}
  el.innerHTML='<div style="font-size:10px;color:var(--muted);margin-bottom:6px">선택된 시간 ('+editPickedSlots.length+'/3)</div>'+
    editPickedSlots.map(s=>'<span style="display:inline-flex;align-items:center;gap:4px;padding:5px 10px;font-size:11px;font-weight:600;background:rgba(108,92,231,.15);border:1px solid rgba(108,92,231,.3);border-radius:16px;color:#a29bfe;margin:0 4px 4px 0"><i class="fas fa-clock"></i> '+s+' <span style="cursor:pointer;margin-left:2px;color:#ff4136;font-weight:800" onclick="editRemoveSlot(&quot;'+s+'&quot;)">&times;</span></span>').join('');
}
async function saveEditSlots(){
  if(editPickedSlots.length===0){showToast('최소 1개의 시간을 선택해주세요.','warn');return}
  try{
    const res=await fetch('/api/questions/'+qId+'/tutoring/slots',{
      method:'PUT',
      headers:{...authHeaders(),'Content-Type':'application/json'},
      body:JSON.stringify({slots:editPickedSlots})
    });
    const d=await res.json();
    if(!res.ok){showToast(d.error,'error');return}
    showToast(d.message,'success');
    document.getElementById('editSlotsOverlay')?.remove();
    loadTutoring(cachedQData);
  }catch(e){showToast('저장에 실패했습니다.','error')}
}
function acceptTutor(){
  const tags=[
    {id:'kind',emoji:'💛',text:'친절하고 이해하기 쉽게 알려주셨어요!'},
    {id:'detail',emoji:'📖',text:'꼼꼼하게 설명해줘서 확실히 이해됐어요.'},
    {id:'patience',emoji:'😊',text:'모르는 부분도 인내심 있게 기다려주셨어요.'},
    {id:'pinpoint',emoji:'🎯',text:'헷갈렸던 핵심을 정확히 짚어주셨어요!'},
    {id:'relief',emoji:'🚀',text:'답답했던 속이 뻥 뚫리는 기분이에요.'},
    {id:'motivated',emoji:'🔥',text:'가르쳐준 대로 하니 공부 의욕이 생겨요!'},
    {id:'again',emoji:'🙌',text:'다음에도 또 설명 부탁드리고 싶어요!'}
  ];
  const pts=cachedQData?cachedQData.reward_points||0:0;
  const overlay=document.createElement('div');
  overlay.className='accept-modal-overlay';
  overlay.id='tutoringAcceptOverlay';
  overlay.innerHTML=
    '<div class="accept-modal">'+
      '<div class="accept-modal-header">'+
        '<h3><i class="fas fa-star" style="color:#ffd700;margin-right:6px"></i>1:1 튜터링 채택</h3>'+
        '<p>튜터링이 만족스러우셨나요? 감사의 마음을 전해보세요</p>'+
      '</div>'+
      '<div class="accept-modal-body">'+
        '<div style="font-size:12px;font-weight:600;color:var(--dim);margin-bottom:10px">감사 문구 선택 <span style="color:var(--muted);font-weight:400">(중복 선택 가능)</span></div>'+
        '<div class="accept-tag-list" id="tutoringTagList">'+
          tags.map(t=>
            '<div class="accept-tag-item" data-tag="'+t.id+'">'+
              '<span class="tag-emoji">'+t.emoji+'</span>'+
              '<span class="tag-text">'+t.text+'</span>'+
              '<span class="tag-check"><i class="fas fa-check"></i></span>'+
            '</div>'
          ).join('')+
        '</div>'+
        '<div style="font-size:12px;font-weight:600;color:var(--dim);margin-bottom:8px">채택 후기 <span style="color:var(--muted);font-weight:400">(선택사항)</span></div>'+
        '<textarea class="accept-review-input" id="tutoringReviewInput" placeholder="1:1 튜터링은 어떠셨나요? 감사의 말을 남겨보세요..." maxlength="200"></textarea>'+
      '</div>'+
      '<div class="accept-modal-footer">'+
        '<button class="accept-cancel-btn" id="tutoringAcceptCancel">취소</button>'+
        '<button class="accept-confirm-btn" id="tutoringAcceptConfirm"><i class="fas fa-star" style="margin-right:4px"></i>채택하기 ('+pts+'P 지급)</button>'+
      '</div>'+
    '</div>';
  document.body.appendChild(overlay);
  overlay.querySelectorAll('.accept-tag-item').forEach(el=>{
    el.addEventListener('click',()=>el.classList.toggle('selected'));
  });
  overlay.querySelector('#tutoringAcceptCancel').addEventListener('click',()=>overlay.remove());
  overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.remove()});
  overlay.querySelector('#tutoringAcceptConfirm').addEventListener('click',async()=>{
    const selectedTags=Array.from(overlay.querySelectorAll('.accept-tag-item.selected')).map(el=>el.getAttribute('data-tag'));
    const review=overlay.querySelector('#tutoringReviewInput').value.trim();
    const btn=overlay.querySelector('#tutoringAcceptConfirm');
    btn.disabled=true;btn.textContent='채택 중...';
    try{
      const res=await fetch('/api/questions/'+qId+'/tutoring/accept',{
        method:'POST',
        headers:{...authHeaders(),'Content-Type':'application/json'},
        body:JSON.stringify({tags:selectedTags,review:review||null})
      });
      const d=await res.json();
      if(!res.ok){showToast(d.error,'error');btn.disabled=false;btn.innerHTML='<i class="fas fa-star" style="margin-right:4px"></i>채택하기 ('+pts+'P 지급)';return}
      overlay.remove();
      showToast(d.message,'success');
      loadTutoring(cachedQData);loadQ();
    }catch(e){showToast('채택에 실패했습니다.','error');btn.disabled=false;btn.innerHTML='<i class="fas fa-star" style="margin-right:4px"></i>채택하기 ('+pts+'P 지급)'}
  });
}
let _selectedSlotId=null;
function selectSlot(btn,slotId){
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  _selectedSlotId=slotId;
  // Visual feedback: highlight selected, dim others
  document.querySelectorAll('#slotBtnWrap .tutor-slot-btn').forEach(b=>{
    if(parseInt(b.dataset.sid)===slotId){
      b.style.border='2px solid #6c5ce7';
      b.style.background='linear-gradient(135deg,rgba(108,92,231,.3),rgba(162,155,254,.2))';
      b.style.color='#a29bfe';
      b.style.transform='scale(1.05)';
      b.style.boxShadow='0 0 12px rgba(108,92,231,.4)';
      b.innerHTML='<i class="fas fa-check-circle" style="margin-right:4px"></i>'+b.textContent.trim();
    } else {
      b.style.border='2px solid var(--border)';
      b.style.background='#1e1e1e';
      b.style.color='var(--muted)';
      b.style.transform='scale(1)';
      b.style.boxShadow='none';
      b.style.opacity='0.5';
    }
  });
  // Show confirm area
  const guide=document.getElementById('slotGuide');
  const cw=document.getElementById('slotConfirmWrap');
  const st=document.getElementById('selectedSlotTime');
  if(guide)guide.style.display='none';
  if(st)st.textContent=btn.textContent.trim();
  if(cw)cw.style.display='block';
}
async function confirmSlotSelection(){
  if(!_selectedSlotId)return;
  const btn=document.getElementById('slotConfirmBtn');
  if(btn){btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 신청 중...';}
  try{
    const res=await fetch('/api/questions/'+qId+'/tutoring/check',{method:'POST',headers:authHeaders(),body:JSON.stringify({slot_id:_selectedSlotId})});
    const d=await res.json();
    if(!res.ok){showToast(d.error||'신청에 실패했습니다.','error');if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-paper-plane" style="margin-right:6px"></i>신청 완료하기';}return}
    loadTutoring(cachedQData);
  }catch(e){showToast('네트워크 오류가 발생했습니다.','error');if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-paper-plane" style="margin-right:6px"></i>신청 완료하기';}}
}
async function checkSlot(slotId){
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  try{
    const res=await fetch('/api/questions/'+qId+'/tutoring/check',{method:'POST',headers:authHeaders(),body:JSON.stringify({slot_id:slotId})});
    const d=await res.json();
    if(!res.ok){showToast(d.error||'신청에 실패했습니다.','error');return}
    showToast(d.message,'success');
    loadTutoring(cachedQData);
  }catch(e){showToast('네트워크 오류가 발생했습니다. 다시 시도해주세요.','error')}
}
async function confirmMatch(matchId){
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  try{
    const h=authHeaders();
    console.log('confirmMatch called, matchId='+matchId+', qId='+qId);
    const res=await fetch('/api/questions/'+qId+'/tutoring/confirm',{method:'POST',headers:h,body:JSON.stringify({match_id:matchId})});
    const d=await res.json();
    console.log('confirmMatch response:',res.status,JSON.stringify(d));
    if(!res.ok){showToast(d.error||'확정에 실패했습니다.','error');return}
    showToast(d.message,'success');
    loadTutoring(cachedQData);loadQ();
  }catch(e){console.error('confirmMatch error:',e);showToast('네트워크 오류가 발생했습니다. 다시 시도해주세요.','error')}
}
async function loadQ(){
  try{
    const res=await fetch('/api/questions/'+qId);
    const q=await res.json();
    if(q&&!q.error){cachedQData=q;renderQ(q)}
  }catch(e){
    var qArea=document.getElementById('splitLeft');
    if(qArea&&!cachedQData){qArea.innerHTML='<div style="text-align:center;padding:60px 20px;color:var(--dim)"><i class="fas fa-exclamation-circle" style="font-size:24px;display:block;margin-bottom:8px"></i>질문을 불러올 수 없습니다<br><button onclick="loadQ()" style="margin-top:12px;padding:8px 20px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:6px;cursor:pointer"><i class="fas fa-redo" style="margin-right:4px"></i>다시 시도</button></div>'}
  }
}

function renderA(list, qData){
    console.log('[renderA] called, list length:', Array.isArray(list)?list.length:'NOT_ARRAY', ', list:', JSON.stringify(list).substring(0,200));
    if(!Array.isArray(list))list=[];
    qData=qData||cachedQData||{};
    const isQOwner=currentUser&&currentUser.id===qData.user_id;
    const alreadyAccepted=list.some(a=>a.is_accepted);
    document.getElementById('answerCount').textContent=list.length;
    if(!list.length){
      console.log('[renderA] empty list, showing empty state');
      document.getElementById('answersContainer').innerHTML='<div class="ans-empty"><i class="fas fa-comment-dots"></i><p>아직 답변이 없습니다<br><span style="font-size:12px;color:#555">첫 번째 답변을 남겨보세요!</span></p></div>';
      return;
    }
    document.getElementById('answersContainer').innerHTML=list.map(a=>{
      const badge=a.is_accepted?'<span class="ans-badge"><i class="fas fa-check"></i> 채택된 답변</span>':'';
      const hasDrawing=!!a.has_drawing;
      const hasImage=!!a.has_image;
      const hasContent=!!a.content;
      
      let bodyHTML='';
      if(hasContent){
        bodyHTML+='<div class="ans-section">'+(hasDrawing||hasImage?'<div class="ans-section-title"><i class="fas fa-lightbulb"></i> 설명</div>':'')+
          '<div class="ans-content">'+a.content+'</div></div>';
      }
      if(hasDrawing){
        bodyHTML+='<div class="ans-section"><div class="ans-section-title"><i class="fas fa-pen-fancy"></i> 풀이 과정</div>'+
          '<div class="ans-img-wrap"><img class="ans-img" id="drawing'+a.id+'"'+(a.drawing_key?' src="/api/answers/'+a.id+'/drawing"':' data-src="/api/answers/'+a.id+'/drawing"')+' alt="풀이 로딩중..." style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)"></div></div>';
      }
      if(hasImage){
        bodyHTML+='<div class="ans-section">'+(hasDrawing?'<div class="ans-section-title"><i class="fas fa-image"></i> 첨부 이미지</div>':'')+
          '<div class="ans-img-wrap"><img class="ans-img" id="image'+a.id+'" data-src="/api/answers/'+a.id+'/image" alt="이미지 로딩중..." style="min-height:80px;background:var(--bg3)" onclick="showModal(this.src)"></div></div>';
      }
      // Voice recording - ClassIn-style custom player
      if(a.voice_key){
        bodyHTML+='<div class="ans-voice" data-voice-key="'+a.voice_key+'">'+
          '<div class="ans-voice__header">'+
            '<div class="ans-voice__icon"><i class="fas fa-microphone"></i></div>'+
            '<div class="ans-voice__label">음성 답변</div>'+
            '<div class="ans-voice__duration" id="voiceDur'+a.id+'">--:--</div>'+
          '</div>'+
          '<div class="ans-voice-player">'+
            '<button class="ans-voice-play" id="voicePlay'+a.id+'" onclick="toggleAnswerVoice('+a.id+')"><i class="fas fa-play"></i></button>'+
            '<div style="flex:1">'+
              '<div class="ans-voice-progress" onclick="seekAnswerVoice(event,'+a.id+')">'+
                '<div class="ans-voice-progress__fill" id="voiceFill'+a.id+'"></div>'+
              '</div>'+
              '<div class="ans-voice-times">'+
                '<span id="voiceCur'+a.id+'">00:00</span>'+
                '<span id="voiceTot'+a.id+'">--:--</span>'+
              '</div>'+
            '</div>'+
          '</div>'+
          '<audio id="voiceEl'+a.id+'" src="/api/voice/'+a.voice_key+'" preload="metadata" style="display:none"></audio>'+
        '</div>';
      }

      // Acceptance review section (shown on accepted answers)
      let reviewHTML='';
      if(a.is_accepted){
        let tags=[];
        try{if(a.acceptance_tags)tags=JSON.parse(a.acceptance_tags)}catch(e){}
        const tagEmojis={'aha':'💡','touched':'🥹','pinpoint':'🎯','relief':'🚀','motivated':'🔥','kind':'😊','fast':'⚡','accurate':'👍','helpful':'💡','moved':'❤️'};
        const tagTexts={'aha':"덕분에 '아하!' 하고 바로 이해됐어요!",'touched':'정성이 가득한 설명에 정말 감동했어요.','pinpoint':'헷갈렸던 핵심을 정확히 짚어주셨어요!','relief':'답답했던 속이 뻥 뚫리는 기분이에요.','motivated':'가르쳐준 대로 하니 공부 의욕이 생겨요!','kind':'친절하게 알려줬어요','fast':'빠르게 알려줬어요','accurate':'답변이 정확해요','helpful':'이해하는데 도움이 되었어요','moved':'정말 감동이에요'};
        let tagsHTML='';
        if(tags.length>0){
          tagsHTML='<div class="accept-review-tags">'+tags.map(t=>
            '<span class="accept-review-tag">'+(tagEmojis[t]||'✨')+' '+(tagTexts[t]||t)+'</span>'
          ).join('')+'</div>';
        }
        const reviewText=a.acceptance_review?'<div class="accept-review-text">'+a.acceptance_review+'</div>':'';
        if(tags.length>0||a.acceptance_review){
          reviewHTML='<div class="accept-review">'+
            '<div class="accept-review-title"><i class="fas fa-star"></i> 질문자 채택 후기</div>'+
            tagsHTML+reviewText+
          '</div>';
        }
      }

      // Accept button for question owner (only if not already accepted)
      const acceptBtn=(isQOwner&&!alreadyAccepted&&!a.is_accepted)?
        '<button class="ans-accept-btn" onclick="showAcceptModal('+a.id+')"><i class="fas fa-check-circle"></i> 채택하기</button>':'';

      return'<div class="ans-card'+(a.is_accepted?' accepted':'')+'" data-aid="'+a.id+'">'+
        '<div class="ans-card-head">'+
          '<div class="ans-avatar"><i class="fas fa-user-graduate"></i></div>'+
          '<div class="ans-meta">'+
            '<div class="ans-name">'+a.author_name+(a.author_grade?' <span class="ans-grade">'+a.author_grade+'</span>':'')+'</div>'+
            '<div class="ans-time">'+timeAgo(a.created_at)+'</div>'+
          '</div>'+
          badge+
        '</div>'+
        '<div class="ans-card-body">'+bodyHTML+'</div>'+
        reviewHTML+
        '<div class="ans-actions">'+
          '<button class="ans-act-btn" onclick="toggleReplySection('+a.id+')"><i class="far fa-comment"></i> 댓글 <span class="reply-count" id="replyCnt'+a.id+'"></span></button>'+
          (currentUser&&currentUser.id===a.user_id?'<button class="ans-act-btn ans-del-btn" onclick="deleteAnswer('+a.id+')"><i class="far fa-trash-alt"></i> 삭제</button>':'')+
          acceptBtn+
        '</div>'+
        '<div class="reply-section" id="replySection'+a.id+'" style="display:none">'+
          '<div class="reply-list" id="replyList'+a.id+'"></div>'+
          (currentUser?
            '<div class="reply-input-row">'+
              '<input class="reply-input" id="replyInput'+a.id+'" placeholder="댓글을 입력하세요..." maxlength="500" data-aid="'+a.id+'">'+
              '<button class="reply-send" onclick="submitReply('+a.id+')"><i class="fas fa-arrow-up"></i></button>'+
            '</div>':'<div style="font-size:11px;color:var(--muted);padding:4px 0"><a href="/login?redirect=/question/'+qId+'" style="color:var(--green)">로그인</a> 후 댓글을 작성할 수 있습니다</div>')+
        '</div>'+
      '</div>'
    }).join('');

    // Wire Enter key for reply inputs via event delegation
    document.getElementById('answersContainer').addEventListener('keydown',function(e){
      if(e.key==='Enter'&&e.target.classList.contains('reply-input')){
        const aid=e.target.getAttribute('data-aid');
        if(aid)submitReply(parseInt(aid));
      }
    });

    // Lazy-load drawing/image data for each answer (non-blocking)
    list.forEach(a=>{
      if(a.has_drawing){
        const img=document.getElementById('drawing'+a.id);
        if(img){
          if(a.drawing_key){
            img.src='/api/answers/'+a.id+'/drawing';
          } else {
            fetch('/api/answers/'+a.id+'/drawing').then(r=>{
              const ct=r.headers.get('content-type')||'';
              if(ct.includes('image')){return r.blob().then(b=>{img.src=URL.createObjectURL(b)})};
              return r.json().then(d=>{if(d.data)img.src=d.data});
            }).catch(()=>{});
          }
        }
      }
      if(a.has_image){
        const img=document.getElementById('image'+a.id);
        if(img){
          if(a.image_key){img.src='/api/images/'+a.image_key}
          else{fetch('/api/answers/'+a.id+'/image').then(r=>r.json()).then(d=>{if(d.data)img.src=d.data}).catch(()=>{})}
        }
      }
    });

    // Load reply counts for all answers
    list.forEach(a=>loadReplies(a.id,false));
    // Render LaTeX in answers
    setTimeout(function(){renderMath(document.getElementById('answerList'))},100);
}
async function loadA(reset){
  try{
    if(reset){_ansPage=0;_allAns=[];}
    const ansRes=await fetch('/api/questions/'+qId+'/answers?page='+_ansPage);
    const data=await ansRes.json();
    var list=data.answers||data;
    if(!Array.isArray(list))list=[];
    _allAns=_allAns.concat(list);
    renderA(_allAns, cachedQData);
    var moreBtn=document.getElementById('loadMoreAnswers');
    if(data.hasMore){
      if(!moreBtn){
        moreBtn=document.createElement('button');
        moreBtn.id='loadMoreAnswers';
        moreBtn.className='load-more-btn';
        moreBtn.style.cssText='display:block;margin:16px auto;padding:10px 24px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:13px';
        moreBtn.innerHTML='<i class="fas fa-chevron-down" style="margin-right:6px"></i>답변 더보기';
        moreBtn.onclick=function(){_ansPage++;loadA(false)};
        document.getElementById('answersContainer').parentNode.appendChild(moreBtn);
      }
    }else if(moreBtn){moreBtn.remove();}
  }catch(e){console.error('loadA error',e)}
}

// ===== Reply (대댓글) Functions =====

function toggleReplySection(answerId){
  const section=document.getElementById('replySection'+answerId);
  const btn=document.querySelector('.ans-card[data-aid="'+answerId+'"] .ans-act-btn');
  if(section.style.display==='none'){
    section.style.display='block';
    if(btn)btn.classList.add('active-reply');
    loadReplies(answerId,true);
  }else{
    section.style.display='none';
    if(btn)btn.classList.remove('active-reply');
  }
}
window.toggleReplySection=toggleReplySection;

async function loadReplies(answerId,showList){
  try{
    const replies=await(await fetch('/api/answers/'+answerId+'/replies')).json();
    const cntEl=document.getElementById('replyCnt'+answerId);
    if(cntEl)cntEl.textContent=replies.length>0?replies.length:'';
    if(!showList)return;
    const listEl=document.getElementById('replyList'+answerId);
    if(!listEl)return;
    if(!replies.length){
      listEl.innerHTML='<div style="font-size:11px;color:var(--muted);padding:6px 0">아직 댓글이 없습니다</div>';
      return;
    }
    listEl.innerHTML=replies.map(r=>{
      const canDel=currentUser&&currentUser.id===r.user_id;
      return'<div class="reply-item">'+
        '<div class="reply-avatar"><i class="fas fa-user"></i></div>'+
        '<div class="reply-body">'+
          '<div class="reply-head">'+
            '<span class="reply-name">'+r.author_name+'</span>'+
            (r.author_grade?'<span class="reply-grade">'+r.author_grade+'</span>':'')+
            '<span class="reply-time">'+timeAgo(r.created_at)+'</span>'+
            (canDel?'<button class="reply-del" onclick="deleteReply('+r.id+','+answerId+')" title="삭제"><i class="fas fa-times"></i></button>':'')+
          '</div>'+
          '<div class="reply-text">'+escapeHtml(r.content)+'</div>'+
        '</div>'+
      '</div>'
    }).join('');
  }catch(e){console.error('loadReplies error',e)}
}

var escapeHtml=esc;
window.escapeHtml=escapeHtml;

async function submitReply(answerId){
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  const input=document.getElementById('replyInput'+answerId);
  const content=input.value.trim();
  if(!content){input.focus();return}
  const btn=input.parentElement.querySelector('.reply-send');
  if(btn){btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i>'}
  try{
    await fetch('/api/answers/'+answerId+'/replies',{method:'POST',headers:authHeaders(),body:JSON.stringify({content})});
    input.value='';
    loadReplies(answerId,true);
  }catch(e){showToast('댓글 등록에 실패했습니다.','error')}
  finally{if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-arrow-up"></i>'}}
}
window.submitReply=submitReply;

async function deleteReply(replyId,answerId){
  showConfirmModal('댓글을 삭제하시겠습니까?',async function(){
    try{
      await fetch('/api/replies/'+replyId,{method:'DELETE',headers:authHeaders()});
      loadReplies(answerId,true);
    }catch(e){showToast('삭제에 실패했습니다.','error')}
  },{danger:true});
}
window.deleteReply=deleteReply;

// === ClassIn Bottom-Bar Voice Recording Functions ===
let isPaused=false;
let previewAnimFrame=null;
let voiceDurationSec=0;

function showRecBar(){
  const bar=document.getElementById('voiceRecBar');
  bar.style.display='flex';
  bar.classList.remove('paused');
  document.getElementById('voiceRecStrip').style.display='flex';
  document.getElementById('voicePreviewBar').style.display='none';
  // Hide the normal bottom bar
  document.getElementById('bottomBar').style.display='none';
  // Extend split container to above recording bar
  document.querySelector('.split-container').style.bottom='48px';
}
function showPreviewBar(){
  document.getElementById('voiceRecStrip').style.display='none';
  document.getElementById('voicePreviewBar').style.display='flex';
  document.getElementById('voiceRecBar').classList.remove('paused');
}
function hideRecBar(){
  document.getElementById('voiceRecBar').style.display='none';
  // Restore normal bottom bar
  document.getElementById('bottomBar').style.display='flex';
  var _aiBarVisible=document.getElementById('aiTutorBar').style.display==='flex';
  document.querySelector('.split-container').style.bottom=_aiBarVisible?'120px':'110px';
}

function stopRecordingCleanup(){
  if(mediaRecorder&&(mediaRecorder.state==='recording'||mediaRecorder.state==='paused')) mediaRecorder.stop();
  if(voiceTimerInterval) clearInterval(voiceTimerInterval);
  if(micStream) micStream.getTracks().forEach(t=>t.stop());
  micStream=null;mediaRecorder=null;
  if(audioCtx){try{audioCtx.close()}catch(e){}}
  audioCtx=null;analyser=null;
}

async function startRecording(){
  if(!getToken()){showToast('로그인 후 음성 녹음을 사용할 수 있습니다.','warn');return}
  try{
    micStream=await navigator.mediaDevices.getUserMedia({audio:true});
    audioChunks=[];
    const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus') ? 'audio/webm;codecs=opus'
      : MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm'
      : MediaRecorder.isTypeSupported('audio/mp4') ? 'audio/mp4' : '';
    mediaRecorder = mimeType ? new MediaRecorder(micStream,{mimeType}) : new MediaRecorder(micStream);
    mediaRecorder.ondataavailable=e=>{if(e.data.size>0)audioChunks.push(e.data)};
    mediaRecorder.onstop=()=>{
      voiceBlob=new Blob(audioChunks,{type:mediaRecorder.mimeType||'audio/webm'});
      voiceDurationSec=voiceSeconds;
      const url=URL.createObjectURL(voiceBlob);
      document.getElementById('voiceAudio').src=url;
      // Switch to preview bar
      showPreviewBar();
      const m=String(Math.floor(voiceDurationSec/60)).padStart(2,'0');
      const s=String(voiceDurationSec%60).padStart(2,'0');
      document.getElementById('voicePreviewTotal').textContent=m+':'+s;
      document.getElementById('voicePreviewCurrent').textContent='00:00';
      document.getElementById('voicePreviewFill').style.width='0%';
      document.getElementById('voicePreviewPlay').innerHTML='<i class="fas fa-play"></i>';
      document.getElementById('voicePreviewPlay').classList.remove('playing');
    };
    mediaRecorder.start(200);
    voiceSeconds=0;isPaused=false;
    document.getElementById('voiceTimer').textContent='00:00';
    voiceTimerInterval=setInterval(()=>{
      if(!isPaused){
        voiceSeconds++;
        const m=String(Math.floor(voiceSeconds/60)).padStart(2,'0');
        const s=String(voiceSeconds%60).padStart(2,'0');
        document.getElementById('voiceTimer').textContent=m+':'+s;
      }
    },1000);
    
    showRecBar();
    document.getElementById('bbMicBtn').classList.add('recording');
    // Pause button initial state
    const pauseBtn=document.getElementById('voicePauseBtn');
    pauseBtn.className='voice-rec-strip__btn voice-rec-strip__btn--pause';
    pauseBtn.innerHTML='<i class="fas fa-pause"></i>';
    
    // Waveform visualizer
    try{
      audioCtx=new(window.AudioContext||window.webkitAudioContext)();
      analyser=audioCtx.createAnalyser();
      analyser.fftSize=256;
      const src=audioCtx.createMediaStreamSource(micStream);
      src.connect(analyser);
      drawWave();
    }catch(e){}
  }catch(e){
    showToast('마이크 접근이 거부되었습니다. 브라우저 설정에서 마이크를 허용해주세요.','error');
  }
}

function drawWave(){
  if(!analyser)return;
  const cv=document.getElementById('voiceWaveCanvas');
  if(!cv)return;
  // Resize canvas to match container
  const parent=cv.parentElement;
  if(parent){cv.width=parent.clientWidth;cv.height=parent.clientHeight}
  const ctx2=cv.getContext('2d');
  const bufLen=analyser.frequencyBinCount;
  const data=new Uint8Array(bufLen);
  function draw(){
    if(!mediaRecorder||mediaRecorder.state==='inactive')return;
    requestAnimationFrame(draw);
    analyser.getByteFrequencyData(data);
    ctx2.clearRect(0,0,cv.width,cv.height);
    const totalBars=Math.min(50,Math.floor(cv.width/5));
    const barW=cv.width/totalBars;
    const gap=1;
    for(let i=0;i<totalBars;i++){
      const idx=Math.floor(i*(bufLen/totalBars));
      const val=isPaused?0:data[idx]/255;
      const h=Math.max(2,val*cv.height*0.9);
      const x=i*barW;
      const y=(cv.height-h)/2;
      ctx2.fillStyle='rgba(255,255,255,'+(0.3+val*0.7)+')';
      const bx=x+gap/2,bw=barW-gap;
      ctx2.beginPath();
      if(ctx2.roundRect){ctx2.roundRect(bx,y,bw,h,1)}else{ctx2.rect(bx,y,bw,h)}
      ctx2.fill();
    }
  }
  draw();
}

function togglePauseRecording(){
  if(!mediaRecorder)return;
  const pauseBtn=document.getElementById('voicePauseBtn');
  const bar=document.getElementById('voiceRecBar');
  if(mediaRecorder.state==='recording'){
    mediaRecorder.pause();
    isPaused=true;
    bar.classList.add('paused');
    pauseBtn.className='voice-rec-strip__btn voice-rec-strip__btn--resume';
    pauseBtn.innerHTML='<i class="fas fa-play"></i>';
    pauseBtn.title='계속 녹음';
  }else if(mediaRecorder.state==='paused'){
    mediaRecorder.resume();
    isPaused=false;
    bar.classList.remove('paused');
    pauseBtn.className='voice-rec-strip__btn voice-rec-strip__btn--pause';
    pauseBtn.innerHTML='<i class="fas fa-pause"></i>';
    pauseBtn.title='일시정지';
  }
}

function stopRecording(){
  if(voiceTimerInterval)clearInterval(voiceTimerInterval);
  if(mediaRecorder&&(mediaRecorder.state==='recording'||mediaRecorder.state==='paused'))mediaRecorder.stop();
  if(micStream)micStream.getTracks().forEach(t=>t.stop());
  micStream=null;isPaused=false;
  if(audioCtx){try{audioCtx.close()}catch(e){}}
  audioCtx=null;analyser=null;
  document.getElementById('bbMicBtn').classList.remove('recording');
}

function cancelRecording(){
  stopRecordingCleanup();
  voiceBlob=null;isPaused=false;
  document.getElementById('bbMicBtn').classList.remove('recording');
  hideRecBar();
}

function cancelFromPreview(){
  stopPreviewPlayback();
  voiceBlob=null;isPaused=false;
  document.getElementById('voiceAudio').src='';
  document.getElementById('bbMicBtn').classList.remove('recording');
  hideRecBar();
}

function rerecordVoice(){
  stopPreviewPlayback();
  voiceBlob=null;
  document.getElementById('voiceAudio').src='';
  hideRecBar();
  // Immediately start new recording
  setTimeout(()=>startRecording(),100);
}

// === Preview playback controls ===
function togglePreviewPlay(){
  const audio=document.getElementById('voiceAudio');
  const btn=document.getElementById('voicePreviewPlay');
  if(!audio.src)return;
  if(audio.paused){
    audio.play();
    btn.innerHTML='<i class="fas fa-pause"></i>';
    btn.classList.add('playing');
    startPreviewProgress();
  }else{
    audio.pause();
    btn.innerHTML='<i class="fas fa-play"></i>';
    btn.classList.remove('playing');
    cancelAnimationFrame(previewAnimFrame);
  }
}
function startPreviewProgress(){
  const audio=document.getElementById('voiceAudio');
  function update(){
    if(audio.paused||audio.ended){
      if(audio.ended){
        document.getElementById('voicePreviewFill').style.width='100%';
        document.getElementById('voicePreviewPlay').innerHTML='<i class="fas fa-play"></i>';
        document.getElementById('voicePreviewPlay').classList.remove('playing');
        const m=String(Math.floor(voiceDurationSec/60)).padStart(2,'0');
        const s=String(voiceDurationSec%60).padStart(2,'0');
        document.getElementById('voicePreviewCurrent').textContent=m+':'+s;
      }
      return;
    }
    const pct=audio.duration?(audio.currentTime/audio.duration)*100:0;
    document.getElementById('voicePreviewFill').style.width=pct+'%';
    const cm=String(Math.floor(audio.currentTime/60)).padStart(2,'0');
    const cs=String(Math.floor(audio.currentTime%60)).padStart(2,'0');
    document.getElementById('voicePreviewCurrent').textContent=cm+':'+cs;
    previewAnimFrame=requestAnimationFrame(update);
  }
  update();
}
function seekPreview(e){
  const audio=document.getElementById('voiceAudio');
  if(!audio.duration)return;
  const rect=e.currentTarget.getBoundingClientRect();
  const pct=(e.clientX-rect.left)/rect.width;
  audio.currentTime=pct*audio.duration;
  document.getElementById('voicePreviewFill').style.width=(pct*100)+'%';
}
function stopPreviewPlayback(){
  const audio=document.getElementById('voiceAudio');
  if(audio&&!audio.paused)audio.pause();
  cancelAnimationFrame(previewAnimFrame);
}

function deleteRecording(){
  voiceBlob=null;voiceKey=null;voiceDurationSec=0;
  document.getElementById('bbMicBtn').classList.remove('has-voice');
  const prev=document.getElementById('voicePreviewArea');
  if(prev)prev.style.display='none';
}

async function confirmVoice(){
  if(!voiceBlob){showToast('녹음된 음성이 없습니다.','warn');return}
  const tk=getToken();
  if(!tk){showToast('로그인이 필요합니다. 먼저 로그인해 주세요.','warn');return}
  const confirmBtn=document.getElementById('voiceConfirmBtn');
  confirmBtn.disabled=true;
  confirmBtn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 업로드';
  try{
    const fd=new FormData();
    const ext=voiceBlob.type&&voiceBlob.type.includes('mp4')?'mp4':voiceBlob.type&&voiceBlob.type.includes('ogg')?'ogg':'webm';
    fd.append('voice',voiceBlob,'recording.'+ext);
    const res=await fetch('/api/voice/upload',{method:'POST',headers:{'Authorization':'Bearer '+tk},body:fd});
    if(!res.ok){
      const errData=await res.json().catch(()=>null);
      showToast('업로드 실패 ('+res.status+'): '+(errData?.error||res.statusText),'error');
      return;
    }
    const data=await res.json();
    if(data.voice_key){
      voiceKey=data.voice_key;
      document.getElementById('bbMicBtn').classList.add('has-voice');
      // Show preview below input
      let prev=document.getElementById('voicePreviewArea');
      if(!prev){
        prev=document.createElement('div');
        prev.id='voicePreviewArea';prev.className='voice-preview';
        document.getElementById('splitRight').insertBefore(prev,document.getElementById('answerFormArea'));
      }
      prev.style.display='flex';
      const dm=String(Math.floor(voiceDurationSec/60)).padStart(2,'0');
      const ds=String(voiceDurationSec%60).padStart(2,'0');
      const audioSrc=document.getElementById('voiceAudio').src;
      prev.innerHTML='<div class="voice-preview__icon"><i class="fas fa-microphone"></i></div>'+
        '<div class="voice-preview__info"><div class="voice-preview__label">음성 녹음 첨부됨</div><div class="voice-preview__duration">'+dm+':'+ds+'</div></div>'+
        '<button class="voice-preview__play" onclick="playPreviewInline(this)" data-src="'+audioSrc+'"><i class="fas fa-play"></i></button>'+
        '<button class="voice-preview__remove" onclick="removeVoice()"><i class="fas fa-times"></i></button>';
      stopPreviewPlayback();
      hideRecBar();
    }else{
      showToast('업로드 실패: '+(data.error||'알 수 없는 오류'),'error');
    }
  }catch(e){showToast('업로드에 실패했습니다: '+(e.message||e),'error')}
  finally{confirmBtn.disabled=false;confirmBtn.innerHTML='<i class="fas fa-check"></i> 첨부'}
}

function playPreviewInline(btn){
  const src=btn.getAttribute('data-src');
  if(!src)return;
  if(btn._audio&&!btn._audio.paused){
    btn._audio.pause();
    btn.innerHTML='<i class="fas fa-play"></i>';
    btn._audio=null;
    return;
  }
  const a=new Audio(src);
  btn._audio=a;
  btn.innerHTML='<i class="fas fa-pause"></i>';
  a.play();
  a.onended=()=>{btn.innerHTML='<i class="fas fa-play"></i>';btn._audio=null;};
}
window.playPreviewInline=playPreviewInline;

function removeVoice(){
  voiceBlob=null;voiceKey=null;voiceDurationSec=0;
  document.getElementById('bbMicBtn').classList.remove('has-voice');
  const prev=document.getElementById('voicePreviewArea');
  if(prev)prev.style.display='none';
}
window.removeVoice=removeVoice;

// === Answer card voice player functions ===
const _ansVoicePlayers={};
function toggleAnswerVoice(aid){
  const audio=document.getElementById('voiceEl'+aid);
  const btn=document.getElementById('voicePlay'+aid);
  if(!audio)return;
  // Stop all other voice players
  Object.keys(_ansVoicePlayers).forEach(k=>{
    if(parseInt(k)!==aid){
      const other=document.getElementById('voiceEl'+k);
      const otherBtn=document.getElementById('voicePlay'+k);
      if(other&&!other.paused){other.pause();other.currentTime=0}
      if(otherBtn){otherBtn.innerHTML='<i class="fas fa-play"></i>';otherBtn.classList.remove('playing')}
      if(_ansVoicePlayers[k])cancelAnimationFrame(_ansVoicePlayers[k]);
    }
  });
  if(audio.paused){
    audio.play();
    btn.innerHTML='<i class="fas fa-pause"></i>';
    btn.classList.add('playing');
    _ansVoicePlayers[aid]=requestAnimationFrame(function upd(){
      if(audio.paused||audio.ended){
        if(audio.ended){
          document.getElementById('voiceFill'+aid).style.width='0%';
          document.getElementById('voiceCur'+aid).textContent='00:00';
          btn.innerHTML='<i class="fas fa-play"></i>';btn.classList.remove('playing');
        }
        return;
      }
      const pct=audio.duration?(audio.currentTime/audio.duration)*100:0;
      document.getElementById('voiceFill'+aid).style.width=pct+'%';
      const cm=String(Math.floor(audio.currentTime/60)).padStart(2,'0');
      const cs=String(Math.floor(audio.currentTime%60)).padStart(2,'0');
      document.getElementById('voiceCur'+aid).textContent=cm+':'+cs;
      _ansVoicePlayers[aid]=requestAnimationFrame(upd);
    });
    // Set total time once loaded
    audio.addEventListener('loadedmetadata',function(){
      const tm=String(Math.floor(audio.duration/60)).padStart(2,'0');
      const ts=String(Math.floor(audio.duration%60)).padStart(2,'0');
      document.getElementById('voiceTot'+aid).textContent=tm+':'+ts;
      document.getElementById('voiceDur'+aid).textContent=tm+':'+ts;
    },{once:true});
    if(audio.duration){
      const tm=String(Math.floor(audio.duration/60)).padStart(2,'0');
      const ts=String(Math.floor(audio.duration%60)).padStart(2,'0');
      document.getElementById('voiceTot'+aid).textContent=tm+':'+ts;
      document.getElementById('voiceDur'+aid).textContent=tm+':'+ts;
    }
  }else{
    audio.pause();
    btn.innerHTML='<i class="fas fa-play"></i>';
    btn.classList.remove('playing');
    if(_ansVoicePlayers[aid])cancelAnimationFrame(_ansVoicePlayers[aid]);
  }
}
window.toggleAnswerVoice=toggleAnswerVoice;
function seekAnswerVoice(e,aid){
  const audio=document.getElementById('voiceEl'+aid);
  if(!audio||!audio.duration)return;
  const rect=e.currentTarget.getBoundingClientRect();
  const pct=(e.clientX-rect.left)/rect.width;
  audio.currentTime=pct*audio.duration;
  document.getElementById('voiceFill'+aid).style.width=(pct*100)+'%';
}
window.seekAnswerVoice=seekAnswerVoice;

async function submitAnswer(){
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  const content=document.getElementById('answerContent').value.trim();
  let dd=null;
  if(drawOn&&drawHistory.length>0){
    const pc=document.getElementById('drawPreviewCanvas');
    if(pc&&pc.width>0)dd=pc.toDataURL('image/png',0.85);
  }
  if(!content&&!dd&&!ansImgData&&!voiceKey){showToast('답변 내용을 입력해주세요.','warn');return}
  const btn=document.getElementById('submitAnswer');btn.disabled=true;
  const origHtml=btn.innerHTML;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 등록 중...';
  try{
    const res=await fetch('/api/questions/'+qId+'/answers',{method:'POST',headers:authHeaders(),body:JSON.stringify({content,image_data:ansImgData,drawing_data:dd,voice_key:voiceKey})});
    if(!res.ok){const d=await res.json().catch(()=>({}));showToast(d.error||'답변 등록에 실패했습니다.','error');return}
    document.getElementById('answerContent').value='';
    drawHistory=[];drawOn=false;
    document.getElementById('drawingPreview').style.display='none';
    document.getElementById('toggleDrawing').classList.remove('active');
    removeAnsImg();
    removeVoice();
    loadQ();loadA(true);
    setTimeout(()=>{const sr=document.getElementById('splitRight');if(sr)sr.scrollTop=sr.scrollHeight},300);
  }
  catch(e){showToast('등록에 실패했습니다.','error')}
  finally{btn.disabled=false;btn.innerHTML=origHtml}
}

function showModal(src){
  const m=document.createElement('div');m.className='img-modal';
  m.innerHTML='<div class="img-modal__spinner"><i class="fas fa-spinner fa-spin" style="font-size:32px;color:#fff"></i></div><button class="img-modal__close" title="닫기"><i class="fas fa-times"></i></button><img src="'+esc(src)+'" style="opacity:0">';
  const img=m.querySelector('img');const spinner=m.querySelector('.img-modal__spinner');
  img.onload=function(){spinner.remove();img.style.opacity='1';img.style.transition='opacity .2s'};
  img.onerror=function(){spinner.remove();img.remove();var err=document.createElement('div');err.style.cssText='color:#999;font-size:14px;text-align:center';err.innerHTML='<i class="fas fa-image" style="font-size:48px;display:block;margin-bottom:12px;opacity:.4"></i>이미지를 불러올 수 없습니다.';m.appendChild(err)};
  m.addEventListener('click',function(e){if(e.target===m)closeModal()});
  m.querySelector('.img-modal__close').addEventListener('click',closeModal);
  document.body.style.overflow='hidden';
  function closeModal(){m.remove();document.body.style.overflow=''}
  function handleEsc(e){if(e.key==='Escape'){closeModal();document.removeEventListener('keydown',handleEsc)}}
  document.addEventListener('keydown',handleEsc);
  document.body.appendChild(m);
}
// ===== Accept Modal Functions =====

function showAcceptModal(answerId){
  const tags=[
    {id:'aha',emoji:'💡',text:"덕분에 '아하!' 하고 바로 이해됐어요!"},
    {id:'touched',emoji:'🥹',text:'정성이 가득한 설명에 정말 감동했어요.'},
    {id:'pinpoint',emoji:'🎯',text:'헷갈렸던 핵심을 정확히 짚어주셨어요!'},
    {id:'relief',emoji:'🚀',text:'답답했던 속이 뻥 뚫리는 기분이에요.'},
    {id:'motivated',emoji:'🔥',text:'가르쳐준 대로 하니 공부 의욕이 생겨요!'}
  ];
  const overlay=document.createElement('div');
  overlay.className='accept-modal-overlay';
  overlay.id='acceptModalOverlay';
  overlay.innerHTML=
    '<div class="accept-modal">'+
      '<div class="accept-modal-header">'+
        '<h3><i class="fas fa-check-circle" style="color:var(--green);margin-right:6px"></i>답변 채택하기</h3>'+
        '<p>이 답변을 채택하고 감사의 마음을 전해보세요</p>'+
      '</div>'+
      '<div class="accept-modal-body">'+
        '<div style="font-size:12px;font-weight:600;color:var(--dim);margin-bottom:10px">감사 문구 선택 <span style="color:var(--muted);font-weight:400">(중복 선택 가능)</span></div>'+
        '<div class="accept-tag-list" id="acceptTagList">'+
          tags.map(t=>
            '<div class="accept-tag-item" data-tag="'+t.id+'">'+
              '<span class="tag-emoji">'+t.emoji+'</span>'+
              '<span class="tag-text">'+t.text+'</span>'+
              '<span class="tag-check"><i class="fas fa-check"></i></span>'+
            '</div>'
          ).join('')+
        '</div>'+
        '<div style="font-size:12px;font-weight:600;color:var(--dim);margin-bottom:8px">채택 후기 <span style="color:var(--muted);font-weight:400">(선택사항)</span></div>'+
        '<textarea class="accept-review-input" id="acceptReviewInput" placeholder="감사의 말을 직접 작성해보세요..." maxlength="200"></textarea>'+
      '</div>'+
      '<div class="accept-modal-footer">'+
        '<button class="accept-cancel-btn" id="acceptCancelBtn">취소</button>'+
        '<button class="accept-confirm-btn" id="acceptConfirmBtn"><i class="fas fa-check" style="margin-right:4px"></i>채택 완료</button>'+
      '</div>'+
    '</div>';
  document.body.appendChild(overlay);
  // Wire tag toggle
  overlay.querySelectorAll('.accept-tag-item').forEach(el=>{
    el.addEventListener('click',()=>el.classList.toggle('selected'));
  });
  overlay.querySelector('#acceptCancelBtn').addEventListener('click',()=>overlay.remove());
  overlay.addEventListener('click',e=>{if(e.target===overlay)overlay.remove()});
  overlay.querySelector('#acceptConfirmBtn').addEventListener('click',()=>acceptAnswer(answerId));
}

async function acceptAnswer(answerId){
  const overlay=document.getElementById('acceptModalOverlay');
  const selectedTags=Array.from(overlay.querySelectorAll('.accept-tag-item.selected')).map(el=>el.getAttribute('data-tag'));
  const review=overlay.querySelector('#acceptReviewInput').value.trim();
  const btn=overlay.querySelector('#acceptConfirmBtn');
  btn.disabled=true;btn.textContent='채택 중...';
  try{
    const res=await fetch('/api/answers/'+answerId+'/accept',{
      method:'PATCH',
      headers:authHeaders(),
      body:JSON.stringify({tags:selectedTags,review:review||null})
    });
    const data=await res.json();
    if(!res.ok){showToast(data.error||'채택 실패','error');btn.disabled=false;btn.innerHTML='<i class="fas fa-check" style="margin-right:4px"></i>채택 완료';return}
    overlay.remove();
    loadQ();loadA(true);
  }catch(e){showToast('채택에 실패했습니다.','error');btn.disabled=false;btn.innerHTML='<i class="fas fa-check" style="margin-right:4px"></i>채택 완료'}
}
window.showAcceptModal=showAcceptModal;

async function deleteAnswer(id){
  showConfirmModal('이 답변을 삭제하시겠습니까?',async function(){
    try{
      const res=await fetch('/api/answers/'+id,{method:'DELETE',headers:authHeaders()});
      const data=await res.json();
      if(!res.ok){showToast(data.error||'삭제 실패','error');return}
      loadQ();loadA(true);
    }catch(e){showToast('삭제에 실패했습니다.','error')}
  },{danger:true});
}
window.deleteAnswer=deleteAnswer;
window.showModal=showModal;

async function retryAnalysis(){
  try{
    const btn=event.target.closest('button');
    if(btn){btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 분석 중...';}
    const res=await fetch('/api/questions/'+qId+'/analyze',{method:'POST',headers:authHeaders()});
    const d=await res.json();
    if(d.success){
      loadQ();
    }else{
      showToast('분석 실패: '+(d.error||d.debug?.geminiError||'알 수 없는 오류'),'error');
      if(btn){btn.disabled=false;btn.innerHTML='<i class="fas fa-redo"></i> 다시 분석';}
    }
  }catch(e){showToast('분석 요청 실패','error');loadQ();}
}
window.retryAnalysis=retryAnalysis;

// === CHALLENGE VISIBILITY (모든 학생에게 표시) ===
function showChallengeButtons(){
  var challOwnerBtns = document.getElementById('challengeOwnerBtns');
  var challLockedBtns = document.getElementById('challengeLockedBtns');
  var isOwner = currentUser && cachedQData && currentUser.id === cachedQData.user_id;
  
  if(isOwner){
    // Owner: show active challenge buttons
    if(challOwnerBtns) challOwnerBtns.style.display = 'block';
    if(challLockedBtns) challLockedBtns.style.display = 'none';
  } else {
    // Non-owner: show locked view (can see results but not challenge)
    if(challOwnerBtns) challOwnerBtns.style.display = 'none';
    if(challLockedBtns) challLockedBtns.style.display = 'block';
  }
}

// === GROWTH INTERACTION FEATURE (사고력 체험) ===
var _giDataCache = null; // cached growth_interactions from ai_coaching_data
function _getGiData(){
  if(_giDataCache) return _giDataCache;
  try {
    if(cachedQData && cachedQData.ai_coaching_data){
      var p = JSON.parse(cachedQData.ai_coaching_data);
      _giDataCache = { gi: p.growth_interactions||[], cq: p.coaching_questions||[] };
      return _giDataCache;
    }
  } catch(e){}
  return { gi:[], cq:[] };
}

function startGrowthInteraction(giIdx){
  var data = _getGiData();
  if(!data.gi[giIdx]) return;
  var gi = data.gi[giIdx];
  var linkedCQ = data.cq[gi.target_coaching_index] || data.cq[giIdx] || {};
  
  // Hide selection buttons
  var btns = document.getElementById('giSelectionBtns');
  if(btns) btns.style.display='none';
  
  var area = document.getElementById('giInteractionArea');
  if(!area) return;
  area.style.display='block';
  
  // Step 1: Show the wrong_attempt scenario
  var wa = gi.wrong_attempt || {};
  var html = '';
  html+='<div style="animation:fadeIn .3s ease">';
  html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">';
  html+='<button onclick="resetGrowthInteraction()" style="padding:4px 10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:#888;font-size:12px;cursor:pointer"><i class="fas fa-arrow-left"></i> \ub3cc\uc544\uac00\uae30</button>';
  html+='<span style="font-size:13px;font-weight:700;color:#a5b4fc">\ud0d0\uad6c \uc2dc\uc791!</span>';
  html+='</div>';

  // Wrong attempt setup
  html+='<div style="padding:14px;background:rgba(251,191,36,.05);border:1px solid rgba(251,191,36,.12);border-radius:10px;margin-bottom:12px">';
  html+='<div style="font-size:13px;font-weight:700;color:#fbbf24;margin-bottom:8px">&#x1F914; \uc774\ub7f0 \uc2dc\ub3c4\ub97c \ud574\ubd24\ub2e4\uace0 \uc0c1\uc0c1\ud574\ubd10!</div>';
  html+='<div style="font-size:14px;color:#e0e0e0;line-height:1.7;margin-bottom:10px;padding:10px 12px;background:rgba(255,255,255,.04);border-radius:8px">'+(wa.setup||'')+'</div>';
  html+='<div style="font-size:13px;color:#d4d4d4;margin-bottom:10px">'+(wa.question||'\uc774\uac70 \uad1c\ucc2e\uc744\uae4c\uc694?')+'</div>';
  
  // Choices
  var choices = wa.choices || ['\u2705 \uad1c\ucc2e\uc740 \uac83 \uac19\uc544\uc694', '\u274c \ubb54\uac00 \uc774\uc0c1\ud574\uc694'];
  choices.forEach(function(ch, chIdx){
    var isCorrect = chIdx === 1; // typically second choice (something is wrong) is the "better" answer
    html+='<button onclick="handleWaChoice('+giIdx+','+chIdx+','+isCorrect+')" style="display:block;width:100%;text-align:left;margin-bottom:6px;padding:10px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e0e0e0;font-size:14px;cursor:pointer;transition:all .2s">'+ch+'</button>';
  });
  html+='</div>';
  html+='</div>';
  
  area.innerHTML = html;
  renderMath(area);
}

function handleWaChoice(giIdx, choiceIdx, isCorrect){
  var data = _getGiData();
  var gi = data.gi[giIdx];
  if(!gi) return;
  var dh = gi.discovery_hint || {};
  var area = document.getElementById('giInteractionArea');
  if(!area) return;

  if(isCorrect){
    // Student correctly identified something is wrong -> show discovery choices
    showDiscoveryStep(giIdx, dh);
  } else {
    // Student thought it was fine -> nudge them
    var html = area.innerHTML;
    // Replace buttons with feedback
    var feedbackHTML = '<div style="padding:12px;background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.2);border-radius:8px;margin-top:10px;animation:fadeIn .3s ease">';
    feedbackHTML+='<div style="font-size:14px;color:#fbbf24;line-height:1.6">'+(dh.on_wrong||'\uc815\ub9d0\uc694? \ud55c\ubc88 \ub354 \uc0dd\uac01\ud574\ubcf4\uc138\uc694!')+'</div>';
    feedbackHTML+='<button onclick="startGrowthInteraction('+giIdx+')" style="margin-top:8px;padding:8px 14px;background:rgba(251,191,36,.15);color:#fbbf24;border:1px solid rgba(251,191,36,.3);border-radius:8px;font-size:13px;cursor:pointer">'+(dh.on_wrong_retry||'\ub2e4\uc2dc \uc0dd\uac01\ud574\ubcfc\uac8c\uc694')+'</button>';
    feedbackHTML+='</div>';
    
    // Append feedback below choices
    area.insertAdjacentHTML('beforeend', feedbackHTML);
    renderMath(area);
  }
}

function showDiscoveryStep(giIdx, dh){
  var area = document.getElementById('giInteractionArea');
  if(!area) return;
  
  var html = '<div style="animation:fadeIn .3s ease">';
  html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">';
  html+='<button onclick="resetGrowthInteraction()" style="padding:4px 10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:#888;font-size:12px;cursor:pointer"><i class="fas fa-arrow-left"></i> \ub3cc\uc544\uac00\uae30</button>';
  html+='<span style="font-size:13px;font-weight:700;color:#34d399">&#x2705; \uc798 \ubc1c\uacac\ud588\uc5b4\uc694!</span>';
  html+='</div>';

  html+='<div style="padding:14px;background:rgba(52,211,153,.05);border:1px solid rgba(52,211,153,.12);border-radius:10px;margin-bottom:12px">';
  html+='<div style="font-size:14px;color:#34d399;margin-bottom:10px;font-weight:700">'+(dh.on_correct||'\uc88b\uc544\uc694! \uc5b4\ub514\uc11c \ubb38\uc81c\uac00 \uc0dd\uae30\ub294\uc9c0 \uace8\ub77c\ubcf4\uc138\uc694.')+'</div>';
  
  // Show choices (on_correct_choices)
  var choices = dh.on_correct_choices || [];
  if(choices.length > 0){
    choices.forEach(function(ch, chIdx){
      var isLast = (ch === '\uc798 \ubaa8\ub974\uaca0\uc5b4\uc694' || chIdx === choices.length - 1);
      html+='<button onclick="handleDiscoveryChoice('+giIdx+','+chIdx+','+(isLast?'true':'false')+')" style="display:block;width:100%;text-align:left;margin-bottom:6px;padding:10px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e0e0e0;font-size:14px;cursor:pointer;transition:all .2s">'+ch+'</button>';
    });
  }
  html+='</div>';
  html+='</div>';
  
  area.innerHTML = html;
  renderMath(area);
}

function handleDiscoveryChoice(giIdx, choiceIdx, isStuck){
  var data = _getGiData();
  var gi = data.gi[giIdx];
  if(!gi) return;
  var dh = gi.discovery_hint || {};
  
  if(isStuck){
    // Show stuck hint then thinking bridge
    var hint = dh.on_stuck || '\ud78c\ud2b8: \ub2e8\uacc4\ubcc4\ub85c \uc0dd\uac01\ud574\ubcf4\uc138\uc694.';
    var html = '<div style="padding:12px;background:rgba(99,102,241,.06);border:1px solid rgba(99,102,241,.15);border-radius:8px;margin-top:10px;animation:fadeIn .3s ease">';
    html+='<div style="font-size:13px;color:#a5b4fc;font-weight:700;margin-bottom:6px">&#x1F4A1; \ud78c\ud2b8</div>';
    html+='<div style="font-size:14px;color:#d4d4d4;line-height:1.7">'+hint+'</div>';
    html+='<button onclick="showThinkingBridge('+giIdx+')" style="margin-top:10px;width:100%;padding:10px;background:rgba(99,102,241,.12);color:#a5b4fc;border:1px solid rgba(99,102,241,.25);border-radius:8px;font-size:14px;cursor:pointer;font-weight:600">&#x1F9E0; \uc0ac\uace0\uc758 \ub2e4\ub9ac \ubcf4\uae30</button>';
    html+='</div>';
    document.getElementById('giInteractionArea').insertAdjacentHTML('beforeend', html);
    renderMath(document.getElementById('giInteractionArea'));
  } else {
    // Correct identification -> show thinking bridge directly
    showThinkingBridge(giIdx);
  }
}

function showThinkingBridge(giIdx){
  var data = _getGiData();
  var gi = data.gi[giIdx];
  if(!gi) return;
  var tb = gi.thinking_bridge || {};
  var linkedCQ = data.cq[gi.target_coaching_index] || data.cq[giIdx] || {};
  var area = document.getElementById('giInteractionArea');
  if(!area) return;
  
  var stepIcons = ['&#x1F4DD;','&#x1F50D;','&#x2753;'];
  var stepLabels = ['\uc2dc\ub3c4','\ubc1c\uacac','\uc9c8\ubb38'];
  
  var html = '<div style="animation:fadeIn .3s ease">';
  html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">';
  html+='<button onclick="resetGrowthInteraction()" style="padding:4px 10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:6px;color:#888;font-size:12px;cursor:pointer"><i class="fas fa-arrow-left"></i> \ub3cc\uc544\uac00\uae30</button>';
  html+='<span style="font-size:13px;font-weight:700;color:#c084fc">&#x1F9E0; \uc0ac\uace0\uc758 \ub2e4\ub9ac</span>';
  html+='</div>';

  html+='<div style="padding:14px;background:rgba(192,132,252,.05);border:1px solid rgba(192,132,252,.12);border-radius:10px;margin-bottom:12px">';
  
  // Steps
  var steps = tb.steps || [];
  steps.forEach(function(step, sIdx){
    html+='<div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:'+(sIdx<steps.length-1?'10':'0')+'px;padding:10px 12px;background:rgba(255,255,255,.03);border-radius:8px">';
    html+='<div style="flex-shrink:0;width:32px;height:32px;border-radius:50%;background:rgba(192,132,252,.15);display:flex;align-items:center;justify-content:center;font-size:14px">'+(stepIcons[sIdx]||'&#x1F4CC;')+'</div>';
    html+='<div>';
    html+='<div style="font-size:11px;font-weight:700;color:#c084fc;margin-bottom:2px">'+(stepLabels[sIdx]||(sIdx+1)+'\ub2e8\uacc4')+'</div>';
    html+='<div style="font-size:14px;color:#e0e0e0;line-height:1.6">'+step+'</div>';
    html+='</div>';
    html+='</div>';
  });
  
  // Connection
  if(tb.connection){
    html+='<div style="margin-top:12px;padding:12px;background:linear-gradient(135deg,rgba(192,132,252,.08),rgba(99,102,241,.06));border:1px solid rgba(192,132,252,.2);border-radius:10px;text-align:center">';
    html+='<div style="font-size:15px;color:#e0e0e0;line-height:1.7;font-weight:600">'+tb.connection+'</div>';
    html+='</div>';
  }
  
  html+='</div>';
  
  // Show the linked coaching question as the destination
  if(linkedCQ.question){
    html+='<div style="padding:12px;background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.15);border-radius:10px;text-align:center">';
    html+='<div style="font-size:12px;color:#34d399;font-weight:700;margin-bottom:6px">&#x2B50; \uc774\ub7f0 \uc9c8\ubb38\uc774 \ub5a0\uc624\ub974\uc9c0 \uc54a\uc558\ub098\uc694?</div>';
    html+='<div style="font-size:15px;color:#e0e0e0;line-height:1.7;font-weight:600">"'+linkedCQ.question+'"</div>';
    if(linkedCQ.why_important){
      html+='<div style="font-size:12px;color:#a0a0a0;margin-top:6px">&#x1F4A1; '+linkedCQ.why_important+'</div>';
    }
    html+='</div>';
  }
  
  // Reset button
  html+='<div style="text-align:center;margin-top:12px">';
  html+='<button onclick="resetGrowthInteraction()" style="padding:8px 20px;background:rgba(255,255,255,.06);color:#888;border:1px solid rgba(255,255,255,.1);border-radius:8px;font-size:13px;cursor:pointer">\ub2e4\ub978 \uc9c8\ubb38 \uccb4\ud5d8\ud574\ubcf4\uae30</button>';
  html+='</div>';
  
  html+='</div>';
  area.innerHTML = html;
  renderMath(area);
}

function resetGrowthInteraction(){
  _giDataCache = null;
  var btns = document.getElementById('giSelectionBtns');
  var area = document.getElementById('giInteractionArea');
  if(btns) btns.style.display='block';
  if(area){ area.style.display='none'; area.innerHTML=''; }
}

// === CHALLENGE FEATURE (도전!) ===
var _challengeImageData = null;

function showChallengeInput(){
  document.getElementById('challengeBtns').style.display='none';
  document.getElementById('challengeInputArea').style.display='block';
  document.getElementById('challengeResultArea').style.display='none';
  document.getElementById('challengeResultArea').innerHTML='';
}

function onChallengeImage(input){
  var file = input.files && input.files[0];
  if(!file) return;
  var reader = new FileReader();
  reader.onload = function(e){
    _challengeImageData = e.target.result;
    document.getElementById('challengePreviewImg').src = _challengeImageData;
    document.getElementById('challengeImgPreview').style.display='block';
  };
  reader.readAsDataURL(file);
}

function challengePaste(){
  if(navigator.clipboard && navigator.clipboard.read){
    navigator.clipboard.read().then(function(items){
      for(var i=0;i<items.length;i++){
        var imgType = null;
        for(var j=0;j<items[i].types.length;j++){
          if(items[i].types[j].indexOf('image')===0) imgType=items[i].types[j];
        }
        if(imgType){
          items[i].getType(imgType).then(function(blob){
            var reader = new FileReader();
            reader.onload = function(e){
              _challengeImageData = e.target.result;
              document.getElementById('challengePreviewImg').src = _challengeImageData;
              document.getElementById('challengeImgPreview').style.display='block';
            };
            reader.readAsDataURL(blob);
          });
        }
      }
    }).catch(function(){});
  }
}

function removeChallengeImage(){
  _challengeImageData = null;
  document.getElementById('challengeImgPreview').style.display='none';
  document.getElementById('challengeImgInput').value='';
}

// === Tier2 Access Control ===
var _tier2Completed = false;
async function checkTier2Access(){
  var btn = document.getElementById('tier2StartBtn');
  var lockedBtn = document.getElementById('tier2LockedBtn');
  var completedBadge = document.getElementById('tier2CompletedBadge');
  var subText = document.getElementById('tier2SubText');
  // Challenge section elements
  var challOwnerBtns = document.getElementById('challengeOwnerBtns');
  var challLockedBtns = document.getElementById('challengeLockedBtns');
  if(!btn) return;

  // 1. Check if current user is the question owner
  var isOwner = currentUser && cachedQData && currentUser.id === cachedQData.user_id;
  if(!currentUser || !isOwner){
    // Show locked button for non-owners (tier2)
    btn.style.display = 'none';
    subText.style.display = 'none';
    lockedBtn.style.display = 'block';
    // Show locked button for non-owners (challenge)
    if(challOwnerBtns) challOwnerBtns.style.display = 'none';
    if(challLockedBtns) challLockedBtns.style.display = 'block';
    return;
  }

  // 2. Check tier2 status from server
  try {
    var r = await fetch('/api/coaching/tier2-status/'+cachedQData.id, { headers: authHeaders() });
    var d = await r.json();
    if(d.completed){
      _tier2Completed = true;
      btn.style.display = 'none';
      lockedBtn.style.display = 'none';
      subText.style.display = 'none';
      completedBadge.style.display = 'block';
      return;
    }
  } catch(e){}

  // 3. Show the active button for the owner who hasn't completed
  btn.style.display = 'flex';
  lockedBtn.style.display = 'none';
  subText.style.display = 'block';
  // Show challenge buttons for owner (if challenge section exists and not completed)
  if(challOwnerBtns) challOwnerBtns.style.display = 'block';
  if(challLockedBtns) challLockedBtns.style.display = 'none';
}

async function submitChallenge(questionId){
  var text = (document.getElementById('challengeText').value || '').trim();
  var hasImage = !!_challengeImageData;
  if(text.length < 5 && !hasImage){
    showToast('질문을 작성하거나 사진을 올려주세요 (최소 5자)','warn');
    return;
  }
  var btn = document.getElementById('challengeSubmitBtn');
  btn.disabled = true;
  btn.textContent = '분석 중...';
  try {
    var body = { questionId: questionId };
    if(hasImage){
      btn.textContent = '이미지 업로드 중...';
      try {
        var upResult = await uploadImageSmart(_challengeImageData, null, 'challenge');
        body.challengeImageKey = upResult.key;
      } catch(ue) { console.warn('Challenge image upload failed', ue); }
    }
    if(text.length >= 5) body.challengeText = text;
    btn.textContent = 'AI 진단 중...';
    var r = await fetch('/api/coaching/challenge', {
      method:'POST', headers: authHeaders(),
      body: JSON.stringify(body)
    });
    var d = await r.json();
    if(!r.ok || !d.success){
      showToast(d.error || 'AI 분석에 실패했습니다','error');
      return;
    }
    // Display result
    var upgraded = d.upgraded;
    // Show CP toast animation
    var cpAmt = d.cp || d.xp || 0;
    if(cpAmt > 0){
      var cpDesc = upgraded ? (d.previous_level + ' \\u2192 ' + d.question_level + ' \\ub808\\ubca8\\uc5c5!') : '\\ub3c4\\uc804 \\ubcf4\\ub108\\uc2a4';
      animateCpGain(cpAmt, d.totalCp || d.totalXp || (_totalCp + cpAmt), cpDesc);
    }
    var LEVEL_META = {'A-1':{name:'뭐지?',icon:'\\ud83d\\udd0d',color:'#9ca3af'},'A-2':{name:'어떻게?',icon:'\\ud83d\\udd0d',color:'#60a5fa'},'B-1':{name:'왜?',icon:'\\ud83d\\udca1',color:'#34d399'},'B-2':{name:'만약에?',icon:'\\ud83d\\udd00',color:'#2dd4bf'},'C-1':{name:'뭐가 더 나아?',icon:'\\u2696\\ufe0f',color:'#fbbf24'},'C-2':{name:'그러면?',icon:'\\ud83d\\ude80',color:'#f87171'},'R-1':{name:'어디서 틀렸지?',icon:'\\ud83d\\udd2c',color:'#a78bfa'},'R-2':{name:'왜 틀렸지?',icon:'\\ud83d\\udd2c',color:'#c084fc'},'R-3':{name:'다음엔 어떻게?',icon:'\\ud83d\\udee1\\ufe0f',color:'#e879f9'}};
    var resultColor = upgraded ? '#34d399' : '#fbbf24';
    var resultHTML = '';
    // Recognized text from image
    if(d.recognized_text){
      resultHTML+='<div style="padding:10px;background:rgba(99,102,241,.06);border-radius:8px;border-left:3px solid #818cf8;margin-bottom:10px"><div style="font-size:11px;color:#818cf8;margin-bottom:4px">\\ud83d\\udccc Gemini 인식 결과</div><div style="font-size:14px;color:#e0e0e0;line-height:1.6">"'+d.recognized_text+'"</div></div>';
    }
    // Submitted text
    if(text){
      resultHTML+='<div style="padding:10px;background:rgba(255,255,255,.04);border-radius:8px;border-left:3px solid '+(LEVEL_META[d.question_level]||{color:'#666'}).color+';margin-bottom:10px"><div style="font-size:11px;color:#888;margin-bottom:4px">\\ud83d\\udcdd 내가 쓴 도전 질문</div><div style="font-size:14px;color:#e0e0e0;line-height:1.6">"'+text+'"</div></div>';
    }
    // Result header
    resultHTML+='<div style="padding:14px;border-radius:10px;text-align:center;margin-bottom:12px;background:'+(upgraded?'rgba(52,211,153,.1)':'rgba(251,191,36,.08)')+';border:1px solid '+(upgraded?'rgba(52,211,153,.3)':'rgba(251,191,36,.2)')+'">';
    resultHTML+='<div style="font-size:28px;margin-bottom:4px">'+(upgraded?'\\ud83c\\udf89':'\\ud83d\\udc4f')+'</div>';
    resultHTML+='<div style="font-size:18px;font-weight:800;color:'+resultColor+'">'+(upgraded?(d.question_level||'')+' 레벨 업!':'도전 보너스!')+'</div>';
    resultHTML+='<div style="font-size:14px;color:#ccc;margin-top:4px">'+(upgraded?d.previous_level+' \\u2192 '+d.question_level+' ('+(d.cp||d.xp)+' CP)':d.previous_level+' 유지 + 보너스 = '+(d.cp||d.xp)+' CP')+'</div></div>';
    // 3대 조건 진단
    if(d.diagnosis){
      var metCount = [d.diagnosis.specific_target?.met, d.diagnosis.own_thinking?.met, d.diagnosis.context_connection?.met].filter(Boolean).length;
      resultHTML+='<div style="padding:14px;border-radius:10px;margin-bottom:12px;background:'+(metCount===3?'rgba(52,211,153,.04)':'rgba(255,255,255,.03)')+';border:1px solid '+(metCount===3?'rgba(52,211,153,.1)':'rgba(255,255,255,.06)')+'">';
      resultHTML+='<div style="font-size:13px;font-weight:800;margin-bottom:10px;color:'+(metCount===3?'#34d399':'#fbbf24')+'">\\ud83d\\udd11 3대 필수조건 진단 <span style="font-size:10px;padding:2px 8px;border-radius:6px;background:'+(metCount===3?'rgba(52,211,153,.15)':'rgba(251,191,36,.15)')+';color:'+(metCount===3?'#34d399':'#fbbf24')+'">'+metCount+'/3</span></div>';
      var diagItems = [['\\u2460 구체적 대상', d.diagnosis.specific_target],['\\u2461 자기 생각', d.diagnosis.own_thinking],['\\u2462 맥락 연결', d.diagnosis.context_connection]];
      diagItems.forEach(function(item){
        var dd = item[1] || {};
        resultHTML+='<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:8px;font-size:13px"><span style="color:'+(dd.met?'#34d399':'#f87171')+';font-weight:700;flex-shrink:0;min-width:110px">'+(dd.met?'\\u2705':'\\u274c')+' '+item[0]+'</span><span style="color:#b0b0b0;line-height:1.6">'+(dd.detail||'')+'</span></div>';
      });
      resultHTML+='</div>';
    }
    // Feedback
    if(d.feedback){
      resultHTML+='<div style="padding:12px;background:rgba(99,102,241,.06);border-radius:8px;border:1px solid rgba(99,102,241,.15);margin-bottom:12px"><div style="font-size:14px;color:#e0e0e0;line-height:1.7">\\ud83d\\udcac '+d.feedback+'</div></div>';
    }
    // Upgrade hint
    if(d.upgrade_hint){
      resultHTML+='<div style="padding:10px;background:rgba(251,191,36,.06);border-radius:8px;border:1px solid rgba(251,191,36,.15);margin-bottom:10px"><div style="font-size:13px;color:#d4d4d4;line-height:1.6">\\u2b06\\ufe0f '+d.upgrade_hint+'</div></div>';
    }
    // No retry - challenge is one-time only
    // Show completion badge
    resultHTML+='<div style="padding:10px;text-align:center;background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.2);border-radius:8px;margin-top:10px">';
    resultHTML+='<i class="fas fa-check-circle" style="color:#34d399;margin-right:6px"></i>';
    resultHTML+='<span style="font-size:13px;font-weight:700;color:#34d399">도전 완료! 결과가 저장되었습니다.</span>';
    resultHTML+='</div>';
    document.getElementById('challengeInputArea').style.display='none';
    document.getElementById('challengeResultArea').style.display='block';
    document.getElementById('challengeResultArea').innerHTML=resultHTML;
    renderMath(document.getElementById('challengeResultArea'));
    // Hide challenge buttons permanently
    var ownerBtns = document.getElementById('challengeOwnerBtns');
    if(ownerBtns) ownerBtns.style.display='none';
  } catch(e){
    showToast('오류가 발생했습니다: '+(e.message||e),'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '제출하기';
  }
}

function retryChallengeUI(){
  // Disabled - challenge is one-time only
}

// === TIER 2: 선생님과 함께 문제해결하기 ===
var _tier2Data = null;
var _tier2Step = 0;
var _tier2Answers = [];
var _tier2ImageData = null;
var _tier2QuestionId = null;

// Simple logging for tier2 interactions
function tier2Log(step, choice){
  if(!_tier2QuestionId) return;
  try {
    fetch('/api/coaching/log', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ questionId: Number(_tier2QuestionId), step: String(step), choice: String(choice), timeSpentMs: 0 })
    }).catch(function(){});
  } catch(e){}
}

async function startTier2(questionId){
  if(_tier2Completed){
    showToast('이 질문에 대해 이미 "선생님과 함께 하기"를 완료했습니다.','warn');
    return;
  }
  var btn = document.getElementById('tier2StartBtn');
  var loadingArea = document.getElementById('tier2LoadingArea');
  btn.style.display = 'none';
  document.getElementById('tier2SubText').style.display = 'none';

  // Show loading progress bar UI
  loadingArea.style.display = 'block';
  loadingArea.innerHTML = '<div style="padding:20px;background:linear-gradient(135deg,#312e81,#1e1b4b);border-radius:14px;border:1px solid rgba(99,102,241,.3)">'
    +'<div style="text-align:center;margin-bottom:14px">'
    +'<div style="font-size:40px;margin-bottom:8px">\\ud83d\\udc68\\u200d\\ud83c\\udfeb</div>'
    +'<div style="font-size:16px;font-weight:800;color:#fff;margin-bottom:4px">선생님이 수업을 준비하고 있습니다</div>'
    +'<div style="font-size:13px;color:#818cf8">문제를 분석하고 맞춤 코칭을 만들고 있어요!</div>'
    +'</div>'
    +'<div style="background:rgba(255,255,255,.1);border-radius:10px;height:24px;overflow:hidden;position:relative">'
    +'<div id="tier2ProgressBar" style="height:100%;width:0%;background:linear-gradient(90deg,#6366f1,#8b5cf6,#a78bfa);border-radius:10px;transition:width 0.5s ease;position:relative">'
    +'<div style="position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);animation:shimmer 1.5s infinite"></div>'
    +'</div></div>'
    +'<div style="text-align:center;margin-top:8px"><span id="tier2ProgressText" style="font-size:13px;font-weight:700;color:#c7d2fe">0%</span></div>'
    +'<div id="tier2ProgressStep" style="text-align:center;margin-top:6px;font-size:12px;color:#666">AI 모델 초기화 중...</div>'
    +'</div>'
    +'<style>@keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}</style>';

  // Animate the progress bar
  var progressSteps = [
    {pct:10, text:'문제 이미지 분석 중...', time:800},
    {pct:25, text:'교과서 개념 매칭 중...', time:1500},
    {pct:40, text:'풀이 단계 설계 중...', time:2000},
    {pct:55, text:'소크라테스 질문 생성 중...', time:2500},
    {pct:70, text:'난이도 조절 중...', time:3000},
    {pct:80, text:'맞춤 피드백 준비 중...', time:4000},
    {pct:90, text:'거의 다 됐어요!', time:6000}
  ];
  var progressInterval = null;
  var stepIdx = 0;
  function updateProgress(){
    if(stepIdx >= progressSteps.length) return;
    var step = progressSteps[stepIdx];
    var bar = document.getElementById('tier2ProgressBar');
    var txt = document.getElementById('tier2ProgressText');
    var stepTxt = document.getElementById('tier2ProgressStep');
    if(bar) bar.style.width = step.pct+'%';
    if(txt) txt.textContent = step.pct+'%';
    if(stepTxt) stepTxt.textContent = step.text;
    stepIdx++;
  }
  updateProgress();
  progressInterval = setInterval(function(){
    if(stepIdx < progressSteps.length) updateProgress();
  }, 2000);

  _tier2QuestionId = questionId;
  try {
    var r = await fetch('/api/coaching/tier2-generate', {
      method:'POST', headers: authHeaders(),
      body: JSON.stringify({ questionId: questionId })
    });
    var d = await r.json();

    // Stop progress animation
    clearInterval(progressInterval);

    if(!r.ok || d.error){
      loadingArea.style.display = 'none';
      if(r.status === 403 || r.status === 409){
        showToast(d.error,'error');
        if(r.status === 409){
          _tier2Completed = true;
          document.getElementById('tier2CompletedBadge').style.display = 'block';
        }
      } else {
        showToast(d.error || 'AI 튜터 생성에 실패했습니다','error');
        btn.style.display = 'flex';
        document.getElementById('tier2SubText').style.display = 'block';
      }
      return;
    }

    // Complete progress to 100%
    var bar = document.getElementById('tier2ProgressBar');
    var txt = document.getElementById('tier2ProgressText');
    var stepTxt = document.getElementById('tier2ProgressStep');
    if(bar) bar.style.width = '100%';
    if(txt) txt.textContent = '100%';
    if(stepTxt) stepTxt.textContent = '준비 완료!';

    // Small delay for 100% animation then show chat
    await new Promise(function(res){ setTimeout(res, 600) });
    loadingArea.style.display = 'none';

    _tier2Data = d;
    _tier2Step = 0;
    _tier2Answers = [];
    tier2Log('tier2_start', 'started');
    renderTier2Chat(questionId);
  } catch(e){
    clearInterval(progressInterval);
    loadingArea.style.display = 'none';
    showToast('오류: '+(e.message||e),'error');
    btn.style.display = 'flex';
    document.getElementById('tier2SubText').style.display = 'block';
  }
}

function renderTier2Chat(questionId){
  var area = document.getElementById('tier2ChatArea');
  if(!area || !_tier2Data) return;
  area.style.display = 'block';

  var LEVEL_META = {'A-1':{name:'뭐지?',icon:'\\ud83d\\udd0d',color:'#9ca3af'},'A-2':{name:'어떻게?',icon:'\\ud83d\\udd0d',color:'#60a5fa'},'B-1':{name:'왜?',icon:'\\ud83d\\udca1',color:'#34d399'},'B-2':{name:'만약에?',icon:'\\ud83d\\udd00',color:'#2dd4bf'},'C-1':{name:'뭐가 더 나아?',icon:'\\u2696\\ufe0f',color:'#fbbf24'},'C-2':{name:'그러면?',icon:'\\ud83d\\ude80',color:'#f87171'},'R-1':{name:'어디서 틀렸지?',icon:'\\ud83d\\udd2c',color:'#a78bfa'},'R-2':{name:'왜 틀렸지?',icon:'\\ud83d\\udd2c',color:'#c084fc'},'R-3':{name:'다음엔 어떻게?',icon:'\\ud83d\\udee1\\ufe0f',color:'#e879f9'}};

  var html = '';
  // Header
  html+='<div style="padding:16px 20px;background:linear-gradient(135deg,#312e81,#1e1b4b);border-radius:14px;border:1px solid rgba(99,102,241,.3);margin-bottom:12px">';
  html+='<div style="display:flex;justify-content:space-between;align-items:center"><div>';
  html+='<div style="font-size:15px;font-weight:800;color:#fff"><i class="fas fa-chalkboard-teacher" style="margin-right:6px"></i>선생님과 함께 문제해결하기</div>';
  html+='<div style="font-size:12px;color:#818cf8;margin-top:2px">문제를 풀면서 + 고도화된 질문법 체화</div>';
  html+='</div>';
  html+='<button onclick="closeTier2()" style="padding:6px 12px;background:rgba(255,255,255,.08);color:#888;border:none;border-radius:8px;font-size:12px;cursor:pointer">\\u2190 닫기</button>';
  html+='</div>';
  // Model badge
  if(_tier2Data.model){
    html+='<div style="margin-top:8px;display:flex;align-items:center;gap:6px"><span style="font-size:10px;padding:2px 8px;border-radius:4px;background:'+(_tier2Data.model==='claude'?'rgba(217,119,6,.15)':'rgba(59,130,246,.15)')+';color:'+(_tier2Data.model==='claude'?'#f59e0b':'#60a5fa')+';font-weight:700">'+(_tier2Data.model==='claude'?'Claude':'Gemini')+'</span></div>';
  }
  html+='</div>';

  // Intro
  if(_tier2Data.intro){
    html+='<div style="padding:12px;background:rgba(99,102,241,.06);border-radius:10px;border-left:3px solid #6366f1;margin-bottom:12px"><div style="font-size:14px;color:#e0e0e0;line-height:1.7">'+_tier2Data.intro+'</div></div>';
  }

  // Steps (new structure: steps[] with title, explanation, question)
  var steps = _tier2Data.steps || [];
  var completed = _tier2Step >= steps.length;
  var showUpTo = completed ? steps.length : _tier2Step + 1;

  for(var i=0; i<showUpTo; i++){
    var step = steps[i];
    if(!step) continue;
    var sq = step.question || {};
    var m = LEVEL_META[sq.level] || {color:'#6366f1',name:'',icon:''};
    var hasAnswer = _tier2Answers[i];
    var isCurrent = (i === _tier2Step && !completed);
    var stepNum = i+1;

    html+='<div style="margin-bottom:16px">';

    // Step header + explanation (teacher solving the problem)
    html+='<div style="padding:14px;background:rgba(99,102,241,.04);border:1px solid rgba(99,102,241,.15);border-radius:12px;margin-bottom:8px">';
    html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">';
    html+='<span style="width:26px;height:26px;border-radius:50%;background:#6366f1;color:#fff;font-size:12px;font-weight:800;display:flex;align-items:center;justify-content:center">'+stepNum+'</span>';
    html+='<span style="font-size:14px;font-weight:800;color:#c7d2fe">'+(step.title||'풀이 단계 '+stepNum)+'</span>';
    html+='</div>';
    html+='<div style="font-size:14px;color:#d4d4d4;line-height:1.8;padding-left:34px">'+(step.explanation||'')+'</div>';
    html+='</div>';

    // Teacher question (upgraded question for the student)
    if(sq.text){
      html+='<div style="padding:14px;background:linear-gradient(135deg,rgba(99,102,241,.08),rgba(139,92,246,.06));border-left:3px solid '+m.color+';border-radius:0 12px 12px 0;margin-bottom:'+(hasAnswer?'8':'0')+'px">';
      html+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">';
      html+='<span style="font-size:11px;color:#818cf8;font-weight:700"><i class="fas fa-comment-dots" style="margin-right:4px"></i>선생님 질문</span>';
      html+='<span style="display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;background:'+m.color+'18;color:'+m.color+';border:1px solid '+m.color+'44">'+(m.icon?m.icon+' ':'')+sq.level+' '+m.name+'</span>';
      html+='</div>';
      html+='<div style="font-size:15px;color:#e0e0e0;line-height:1.7;font-weight:600">'+sq.text+'</div>';
      html+='</div>';
    }

    // Student answer (if exists)
    if(hasAnswer){
      html+='<div style="padding:10px 14px;background:rgba(255,255,255,.05);border-radius:10px;text-align:right;margin-bottom:8px">';
      html+='<div style="font-size:10px;color:#666;margin-bottom:4px">내 답변</div>';
      if(hasAnswer.image) html+='<div style="margin-bottom:6px"><img src="'+hasAnswer.image+'" style="max-width:100%;max-height:160px;border-radius:8px;border:1px solid rgba(255,255,255,.1)"></div>';
      if(hasAnswer.recognized) html+='<div style="font-size:11px;color:#818cf8;margin-bottom:4px;text-align:left">Gemini 인식: '+hasAnswer.recognized+'</div>';
      if(hasAnswer.text && hasAnswer.text !== '(이미지 답변)') html+='<span style="font-size:13px;color:#d4d4d4">'+hasAnswer.text+'</span>';
      html+='</div>';
      // Teacher response - ONLY use dynamic feedback from API, never fall back to pre-generated teacherResponse
      var feedbackText = hasAnswer.feedback || '';
      var qualityIcon = '';
      var qualityColor = '#34d399';
      if(hasAnswer.quality === 'good'){ qualityIcon = '\\u2705'; qualityColor = '#34d399'; }
      else if(hasAnswer.quality === 'partial'){ qualityIcon = '\\ud83d\\udca1'; qualityColor = '#fbbf24'; }
      else if(hasAnswer.quality === 'off_track'){ qualityIcon = '\\ud83d\\udd04'; qualityColor = '#f59e0b'; }
      else if(hasAnswer.quality === 'no_attempt'){ qualityIcon = '\\u26a0\\ufe0f'; qualityColor = '#f87171'; }
      if(!feedbackText && !hasAnswer.quality){
        feedbackText = '피드백을 생성하지 못했습니다. 다음 단계로 진행하세요.';
        qualityColor = '#888';
      }
      if(feedbackText){
        html+='<div style="padding:10px 14px;background:rgba(52,211,153,.06);border-left:3px solid '+qualityColor+';border-radius:0 8px 8px 0">';
        html+='<div style="font-size:10px;color:'+qualityColor+';margin-bottom:4px;font-weight:700"><i class="fas fa-chalkboard-teacher" style="margin-right:4px"></i>\\uc120\\uc0dd\\ub2d8 '+qualityIcon+'</div>';
        html+='<span style="font-size:14px;color:#a7f3d0;line-height:1.7">'+feedbackText+'</span></div>';
      }
    }

    // Current question input
    if(isCurrent && !hasAnswer && sq.text){
      html+='<div style="margin-top:10px" id="tier2AnswerArea">';
      // Hint area (hidden initially)
      html+='<div id="tier2HintArea" style="display:none;padding:10px;background:rgba(251,191,36,.06);border:1px solid rgba(251,191,36,.15);border-radius:8px;margin-bottom:8px">';
      html+='<div style="font-size:12px;color:#fbbf24;font-weight:700;margin-bottom:2px"><i class="fas fa-lightbulb" style="margin-right:4px"></i>힌트</div>';
      html+='<div style="font-size:13px;color:#d4d4d4;line-height:1.6">'+(sq.hint||sq.goodAnswer||'')+'</div></div>';
      // Text input
      html+='<textarea id="tier2Answer" placeholder="네 생각을 적어봐! (한 문장이라도 OK)" style="width:100%;padding:10px;min-height:44px;background:rgba(255,255,255,.06);border:1px solid rgba(99,102,241,.3);border-radius:8px;color:#e0e0e0;font-size:14px;resize:vertical;box-sizing:border-box" onkeydown="if(event.key===&apos;Enter&apos;&&!event.shiftKey){event.preventDefault();submitTier2Answer('+questionId+','+i+')}"></textarea>';
      // Image upload row
      html+='<div style="display:flex;align-items:center;gap:6px;margin-top:6px;padding:6px 0">';
      html+='<input type="file" accept="image/*" capture="environment" id="tier2ImgInput" style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none" onchange="onTier2Image(this)">';
      html+='<button onclick="document.getElementById(&apos;tier2ImgInput&apos;).click()" style="padding:6px 10px;background:rgba(255,255,255,.04);color:#888;border:1px dashed rgba(255,255,255,.12);border-radius:6px;font-size:11px;cursor:pointer">\\ud83d\\udcf7 사진</button>';
      html+='<button onclick="tier2Paste()" style="padding:6px 10px;background:rgba(255,255,255,.04);color:#888;border:1px dashed rgba(255,255,255,.12);border-radius:6px;font-size:11px;cursor:pointer">\\ud83d\\udccb 붙여넣기</button>';
      html+='<span style="font-size:10px;color:#555;margin-left:auto">펜으로 써서 올려도 돼!</span></div>';
      // Image preview
      html+='<div id="tier2ImgPreview" style="display:none;margin-top:6px;padding:8px;background:rgba(99,102,241,.06);border-radius:8px;border:1px solid rgba(99,102,241,.15);position:relative"><img id="tier2PreviewImg" style="max-width:100%;max-height:140px;border-radius:6px"><button onclick="removeTier2Image()" style="position:absolute;top:4px;right:4px;width:22px;height:22px;border-radius:50%;background:rgba(248,113,113,.9);color:#fff;border:none;font-size:12px;cursor:pointer">\\u2715</button></div>';
      // Submit + Hint buttons
      html+='<div style="display:flex;gap:6px;margin-top:6px">';
      html+='<button id="tier2SubmitBtn" onclick="submitTier2Answer('+questionId+','+i+')" style="flex:1;padding:10px;background:#6366f1;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer">답변하기</button>';
      html+='<button onclick="document.getElementById(&apos;tier2HintArea&apos;).style.display=&apos;block&apos;" style="padding:10px 14px;background:rgba(251,191,36,.1);color:#fbbf24;border:1px solid rgba(251,191,36,.2);border-radius:8px;font-size:12px;cursor:pointer"><i class="fas fa-lightbulb"></i> 힌트</button>';
      html+='</div></div>';
    }
    html+='</div>';
  }

  // Completed view (summary)
  var summary = _tier2Data.summary;
  if(completed && summary){
    html+='<div style="padding:16px;background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.2);border-radius:14px">';
    html+='<div style="font-size:20px;font-weight:800;color:#34d399;margin-bottom:14px;text-align:center">\\ud83c\\udf89 문제 해결 완료!</div>';

    // Full solution
    if(summary.fullSolution){
      html+='<div style="padding:12px;background:rgba(255,255,255,.04);border-radius:10px;margin-bottom:12px">';
      html+='<div style="font-size:13px;font-weight:700;color:#888;margin-bottom:6px"><i class="fas fa-check-double" style="margin-right:4px;color:#34d399"></i>전체 풀이 요약</div>';
      html+='<div style="font-size:14px;color:#e0e0e0;line-height:1.8;white-space:pre-wrap">'+summary.fullSolution+'</div></div>';
    }

    // Key insight
    if(summary.keyInsight){
      html+='<div style="padding:10px 14px;background:rgba(99,102,241,.06);border-left:3px solid #6366f1;border-radius:0 8px 8px 0;margin-bottom:12px">';
      html+='<div style="font-size:12px;color:#818cf8;font-weight:700;margin-bottom:2px">\\ud83d\\udca1 핵심 포인트</div>';
      html+='<div style="font-size:14px;color:#e0e0e0;line-height:1.7">'+summary.keyInsight+'</div></div>';
    }

    // Upgraded question
    if(summary.upgradedQuestion){
      var uLevel = summary.upgradedLevel || 'C-1';
      var uMeta = LEVEL_META[uLevel] || {color:'#fbbf24',name:'',icon:''};
      html+='<div style="padding:14px;background:linear-gradient(135deg,rgba(251,191,36,.08),rgba(245,158,11,.04));border:1px solid rgba(251,191,36,.2);border-radius:12px;margin-bottom:12px">';
      html+='<div style="font-size:13px;font-weight:800;color:#fbbf24;margin-bottom:8px">\\ud83c\\udf93 이제 이런 질문을 할 수 있어!</div>';
      html+='<div style="padding:10px;background:rgba(255,255,255,.04);border-left:3px solid '+uMeta.color+';border-radius:0 8px 8px 0">';
      html+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px"><span style="padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;background:'+uMeta.color+'18;color:'+uMeta.color+';border:1px solid '+uMeta.color+'44">'+(uMeta.icon?uMeta.icon+' ':'')+uLevel+' '+uMeta.name+'</span></div>';
      html+='<div style="font-size:15px;color:#e0e0e0;line-height:1.7;font-weight:600">"'+summary.upgradedQuestion+'"</div></div></div>';
    }

    // Level badges experienced
    html+='<div style="padding:12px;background:rgba(99,102,241,.06);border-radius:10px;border:1px solid rgba(99,102,241,.15);margin-bottom:12px">';
    html+='<div style="font-size:13px;font-weight:700;color:#818cf8;margin-bottom:8px"><i class="fas fa-chart-line" style="margin-right:4px"></i>체험한 질문 단계</div>';
    html+='<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px">';
    steps.forEach(function(s){
      var sq = s.question || {};
      var m = LEVEL_META[sq.level] || {color:'#666',name:'',icon:''};
      html+='<span style="display:inline-flex;align-items:center;gap:3px;padding:3px 8px;border-radius:10px;font-size:11px;font-weight:700;background:'+m.color+'18;color:'+m.color+';border:1px solid '+m.color+'44">'+(m.icon?m.icon+' ':'')+sq.level+' '+m.name+'</span>';
    });
    html+='</div>';
    html+='<div style="font-size:12px;color:#888;line-height:1.6">A→B→C 질문이 점점 깊어지는 흐름을 직접 체험했어요!</div></div>';

    // Closing message
    if(summary.closingMessage){
      html+='<div style="padding:12px;text-align:center"><div style="font-size:14px;color:#e0e0e0;line-height:1.7">'+summary.closingMessage+'</div></div>';
    }

    // Action buttons (no retry - one time only)
    html+='<div style="display:flex;gap:8px;margin-top:12px">';
    html+='<button onclick="completeTier2('+questionId+')" style="flex:1;padding:12px;background:linear-gradient(135deg,#34d399,#10b981);color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer"><i class="fas fa-check" style="margin-right:4px"></i>완료</button>';
    html+='</div>';

    html+='</div>';
  }

  area.innerHTML = html;
  renderMath(area);
  // Scroll to current step
  if(!completed){
    var answerArea = document.getElementById('tier2AnswerArea');
    if(answerArea) answerArea.scrollIntoView({behavior:'smooth',block:'center'});
    else area.scrollIntoView({behavior:'smooth',block:'start'});
  } else {
    area.scrollIntoView({behavior:'smooth',block:'start'});
  }
}

function closeTier2(){
  _tier2Data = null;
  _tier2Step = 0;
  _tier2Answers = [];
  var area = document.getElementById('tier2ChatArea');
  if(area){ area.style.display='none'; area.innerHTML=''; }
  // Don't restore start button - show completed badge
  if(_tier2Completed){
    var badge = document.getElementById('tier2CompletedBadge');
    if(badge) badge.style.display = 'block';
  }
}

// Called after warning termination
function closeTier2AfterWarning(){
  _tier2Data = null;
  _tier2Step = 0;
  _tier2Answers = [];
  var area = document.getElementById('tier2ChatArea');
  if(area){ area.style.display='none'; area.innerHTML=''; }
  var badge = document.getElementById('tier2CompletedBadge');
  if(badge){
    badge.style.display = 'block';
    badge.innerHTML = '<div style="font-size:15px;font-weight:800;color:#f87171"><i class="fas fa-exclamation-triangle" style="margin-right:6px"></i>경고로 인해 종료됨</div><div style="font-size:12px;color:#888;margin-top:4px">의미없는 답변으로 세션이 종료되었습니다.</div>';
  }
}

// Called when tier2 is completed normally
async function completeTier2(questionId){
  _tier2Completed = true;
  // Mark as completed on the server
  try {
    await fetch('/api/coaching/tier2-complete', {
      method:'POST', headers: authHeaders(),
      body: JSON.stringify({ questionId: questionId })
    });
  } catch(e){}
  closeTier2();
}

function onTier2Image(input){
  var file = input.files && input.files[0];
  if(!file) return;
  var reader = new FileReader();
  reader.onload = function(e){
    _tier2ImageData = e.target.result;
    document.getElementById('tier2PreviewImg').src = _tier2ImageData;
    document.getElementById('tier2ImgPreview').style.display='block';
  };
  reader.readAsDataURL(file);
}

function tier2Paste(){
  if(navigator.clipboard && navigator.clipboard.read){
    navigator.clipboard.read().then(function(items){
      for(var i=0;i<items.length;i++){
        var imgType = null;
        for(var j=0;j<items[i].types.length;j++){
          if(items[i].types[j].indexOf('image')===0) imgType=items[i].types[j];
        }
        if(imgType){
          items[i].getType(imgType).then(function(blob){
            var reader = new FileReader();
            reader.onload = function(e){
              _tier2ImageData = e.target.result;
              document.getElementById('tier2PreviewImg').src = _tier2ImageData;
              document.getElementById('tier2ImgPreview').style.display='block';
            };
            reader.readAsDataURL(blob);
          });
        }
      }
    }).catch(function(){});
  }
}

function removeTier2Image(){
  _tier2ImageData = null;
  document.getElementById('tier2ImgPreview').style.display='none';
  document.getElementById('tier2ImgInput').value='';
}

async function submitTier2Answer(questionId, stepIdx){
  var text = (document.getElementById('tier2Answer').value || '').trim();
  var hasImage = !!_tier2ImageData;
  if(!text && !hasImage) return;

  var btn = document.getElementById('tier2SubmitBtn');
  btn.disabled = true;
  btn.textContent = '분석 중...';

  try {
    var body = { questionId: questionId, stepIndex: stepIdx };
    var imageKey = null;
    if(hasImage){
      btn.textContent = '이미지 업로드 중...';
      try {
        var upResult = await uploadImageSmart(_tier2ImageData, null, 'tier2');
        body.answerImageKey = upResult.key;
        imageKey = upResult.key;
      } catch(ue) { console.warn('Tier2 image upload failed', ue); }
    }
    if(text) body.answerText = text;

    var r = await fetch('/api/coaching/tier2-answer', {
      method:'POST', headers: authHeaders(),
      body: JSON.stringify(body)
    });
    var d = await r.json();

    // Handle no_attempt: warning + terminate
    if(d.terminated && d.quality === 'no_attempt'){
      // Show warning UI
      var warningHtml = '<div style="padding:16px;background:linear-gradient(135deg,rgba(248,113,113,.1),rgba(239,68,68,.05));border:2px solid rgba(239,68,68,.3);border-radius:14px;margin-top:12px;animation:fadeSlideUp .3s ease">';
      warningHtml += '<div style="text-align:center;font-size:32px;margin-bottom:8px">\\u26a0\\ufe0f</div>';
      warningHtml += '<div style="font-size:16px;font-weight:800;color:#f87171;text-align:center;margin-bottom:8px">경고: 의미없는 답변이 감지되었습니다</div>';
      warningHtml += '<div style="font-size:14px;color:#fca5a5;text-align:center;line-height:1.6;margin-bottom:10px">'+(d.feedback||'진지하게 답변해주세요.')+'</div>';
      warningHtml += '<div style="font-size:12px;color:#f87171;text-align:center;padding:8px;background:rgba(239,68,68,.08);border-radius:8px;margin-bottom:10px">';
      warningHtml += '<i class="fas fa-exclamation-triangle" style="margin-right:4px"></i>경고 누적: '+(d.warningCount||1)+'회 | CP 미지급 | 세션 종료됨</div>';
      warningHtml += '<div style="font-size:11px;color:#888;text-align:center">선생님과 함께 하기는 이 질문에 대해 종료되었습니다.</div>';
      warningHtml += '<button onclick="closeTier2AfterWarning()" style="width:100%;margin-top:12px;padding:12px;background:rgba(255,255,255,.06);color:#888;border:1px solid rgba(255,255,255,.1);border-radius:10px;font-size:14px;cursor:pointer">확인</button>';
      warningHtml += '</div>';
      
      var area = document.getElementById('tier2ChatArea');
      if(area) area.innerHTML += warningHtml;

      // Mark as completed (cannot retry)
      _tier2Completed = true;
      try {
        await fetch('/api/coaching/tier2-complete', {
          method:'POST', headers: authHeaders(),
          body: JSON.stringify({ questionId: questionId })
        });
      } catch(e2){}
      return;
    }

    // Show CP toast for tier2 answer (only if actually earned)
    var t2cp = d.cpEarned || d.xpEarned || 0;
    if(t2cp > 0){
      animateCpGain(t2cp, d.totalCp || d.totalXp || (_totalCp + t2cp), '\\uc120\\uc0dd\\ub2d8 \\uc9c8\\ubb38 ' + ((stepIdx||0)+1) + '\\ubc88 \\ub2f5\\ubcc0');
    }

    // Record answer
    _tier2Answers[stepIdx] = {
      text: text || (hasImage ? '(이미지 답변)' : ''),
      image: hasImage ? _tier2ImageData : null,
      recognized: d.recognizedText || null,
      feedback: d.feedback || null,
      quality: d.quality || null
    };
    _tier2ImageData = null;

    // Move to next step
    _tier2Step = stepIdx + 1;

    // Also log to coaching_logs
    tier2Log('tier2_q'+stepIdx, text || d.recognizedText || '(이미지)');

    // Re-render
    renderTier2Chat(questionId);
  } catch(e){
    showToast('오류: '+(e.message||e),'error');
    btn.disabled = false;
    btn.textContent = '답변하기';
  }
}


// === CP (크로켓포인트) SYSTEM ===
function toP(cp){return (cp||0)*100}
function fmtP(cp){return toP(cp).toLocaleString()+' 크로켓포인트'}
var _totalCp = 0;
var _questionCp = 0;
var _cpToastQueue = [];

async function loadCpData(){
  try{
    var r = await fetch('/api/cp/question/'+qId, { headers: authHeaders() });
    var d = await r.json();
    _totalCp = d.totalCp || d.totalXp || 0;
    _questionCp = d.questionCp || d.questionXp || 0;
    updateCpBadge();
  }catch(e){}
}

function updateCpBadge(){
  var badge = document.getElementById('cpBadge');
  var totalEl = document.getElementById('cpTotal');
  var qEl = document.getElementById('cpQuestion');
  if(!badge) return;
  badge.style.display = 'flex';
  // CP levels
  var levels=[{min:0,name:'\\ud83c\\udf31',next:30},{min:30,name:'\\ud83d\\udcd6',next:100},{min:100,name:'\\ud83e\\udd1d',next:250},{min:250,name:'\\u2b50',next:500},{min:500,name:'\\ud83d\\udc51',next:1000},{min:1000,name:'\\ud83c\\udfc6',next:null}];
  var lv=levels[0];
  for(var i=levels.length-1;i>=0;i--){if(_totalCp>=levels[i].min){lv=levels[i];break}}
  totalEl.textContent = lv.name + ' ' + toP(_totalCp).toLocaleString() + ' 크로켓포인트';
  qEl.textContent = _questionCp > 0 ? ('이 질문: +' + toP(_questionCp).toLocaleString() + ' 크로켓포인트') : '';
}

function animateCpGain(amount, totalAfter, desc){
  _totalCp = totalAfter;
  _questionCp += amount;

  var badge = document.getElementById('cpBadge');
  if(badge){
    badge.classList.remove('cp-badge--gain');
    void badge.offsetWidth;
    badge.classList.add('cp-badge--gain');
    setTimeout(function(){ badge.classList.remove('cp-badge--gain'); }, 700);
  }

  var totalEl = document.getElementById('cpTotal');
  var qEl = document.getElementById('cpQuestion');
  if(totalEl){
    var startVal = totalAfter - amount;
    var duration = 800;
    var startTime = null;
    function animateCount(ts){
      if(!startTime) startTime = ts;
      var progress = Math.min((ts - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var current = Math.round(startVal + (amount * eased));
      totalEl.textContent = toP(current).toLocaleString() + ' 크로켓포인트';
      if(progress < 1) requestAnimationFrame(animateCount);
    }
    requestAnimationFrame(animateCount);
  }
  if(qEl) qEl.textContent = '이 질문: +' + toP(_questionCp).toLocaleString() + ' 크로켓포인트';

  showCpToast(amount, desc);
}

function showCpToast(amount, desc){
  var container = document.getElementById('cpToast');
  if(!container) return;
  var item = document.createElement('div');
  item.className = 'cp-toast__item';
  var sign = amount > 0 ? '+' : '';
  item.innerHTML = '<span class="cp-toast__icon">\\ud83c\\udf69</span><div class="cp-toast__text"><span class="cp-toast__amount">' + sign + toP(amount).toLocaleString() + ' 크로켓포인트</span><span class="cp-toast__desc">' + (desc||'') + '</span></div>';
  container.appendChild(item);
  setTimeout(function(){ if(item.parentNode) item.parentNode.removeChild(item); }, 2800);

  spawnCpParticles(amount);
}

function spawnCpParticles(amount){
  var badge = document.getElementById('cpBadge');
  if(!badge || amount <= 0) return;
  var rect = badge.getBoundingClientRect();
  var cx = rect.left + rect.width/2;
  var cy = rect.top + rect.height/2;
  for(var i=0; i<Math.min(amount, 8); i++){
    (function(idx){
      setTimeout(function(){
        var p = document.createElement('div');
        p.textContent = '+' + Math.ceil(amount/(Math.min(amount,8)));
        p.style.cssText = 'position:fixed;left:'+(cx + (Math.random()*60-30))+'px;top:'+(cy)+'px;color:#a29bfe;font-size:13px;font-weight:900;pointer-events:none;z-index:99999;text-shadow:0 0 6px rgba(124,106,239,.6);transition:all .8s cubic-bezier(.23,1,.32,1);opacity:1;';
        document.body.appendChild(p);
        requestAnimationFrame(function(){
          p.style.top = (cy - 40 - Math.random()*30) + 'px';
          p.style.left = (cx + (Math.random()*80-40)) + 'px';
          p.style.opacity = '0';
          p.style.transform = 'scale(1.5)';
        });
        setTimeout(function(){ if(p.parentNode) p.parentNode.removeChild(p); }, 900);
      }, idx * 80);
    })(i);
  }
}

window.loadXpData = loadXpData;
window.animateXpGain = animateXpGain;
window.showXpToast = showXpToast;

window.showChallengeInput = showChallengeInput;
window.onChallengeImage = onChallengeImage;
window.challengePaste = challengePaste;
window.removeChallengeImage = removeChallengeImage;
window.submitChallenge = submitChallenge;
window.retryChallengeUI = retryChallengeUI;
window.startTier2 = startTier2;
window.closeTier2 = closeTier2;
window.closeTier2AfterWarning = closeTier2AfterWarning;
window.completeTier2 = completeTier2;
window.onTier2Image = onTier2Image;
window.tier2Paste = tier2Paste;
window.removeTier2Image = removeTier2Image;
window.submitTier2Answer = submitTier2Answer;
</script>
</body>
</html>`
}

// ===== New Question Page =====

function newQuestionHTML() {
  return `${htmlHead('질문하기')}

.detail-nav{height:56px;display:flex;align-items:center;padding:0 4%;border-bottom:1px solid var(--glass-border);position:sticky;top:0;z-index:100;background:rgba(11,14,20,.9);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%)}
.detail-nav__back{font-size:15px;font-weight:500;color:var(--dim);background:none;border:none;padding:0;display:flex;align-items:center;gap:8px;transition:color .2s}
.detail-nav__back:hover{color:var(--white)}

.new-q{max-width:600px;margin:0 auto;padding:var(--sp-8) 4% 80px}
.new-q__user{text-align:center;margin-bottom:var(--sp-6);padding:var(--sp-5);background:var(--glass-bg);border-radius:16px;border:1px solid var(--glass-border);backdrop-filter:var(--glass-blur)}
.new-q__user-name{font-size:16px;font-weight:700;color:var(--white);font-family:var(--font-display)}
.new-q__user-sub{font-size:13px;color:var(--muted);margin-top:4px}
.new-q__section{margin-bottom:var(--sp-6)}
.new-q__label{font-size:13px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:var(--sp-2);display:block}
.new-q__label em{color:var(--accent);font-style:normal}
.f-input{width:100%;padding:12px 16px;font-size:15px;border:1px solid var(--glass-border);border-radius:14px;background:rgba(255,255,255,.04);color:var(--white);outline:none;transition:all .2s var(--spring)}
.f-input:focus{border-color:var(--accent);box-shadow:var(--focus-ring);background:rgba(255,255,255,.06)}
.f-input::placeholder{color:var(--muted)}
textarea.f-input{resize:none;min-height:120px;line-height:1.7}
select.f-input{appearance:none}
.subj-group{display:flex;gap:8px;flex-wrap:wrap}
.subj-btn{flex:1 1 0;min-width:0;padding:11px 8px;text-align:center;font-size:14px;font-weight:600;color:var(--muted);border:1px solid var(--glass-border);border-radius:14px;background:var(--glass-bg);cursor:pointer;transition:all .25s var(--spring);backdrop-filter:blur(8px);user-select:none}
.subj-btn:hover{border-color:rgba(255,255,255,.2);color:var(--dim);transform:translateY(-1px)}
.subj-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(139,92,246,.08);box-shadow:0 0 12px rgba(139,92,246,.15)}

.upload-zone{position:relative;border:2px dashed var(--glass-border);border-radius:16px;padding:48px 24px;text-align:center;cursor:pointer;transition:all .3s var(--spring);background:var(--glass-bg)}
.upload-zone:hover{border-color:var(--accent);background:rgba(139,92,246,.04)}
.upload-zone.drag-over{border-color:var(--green);background:rgba(16,185,129,.04);transform:scale(1.01)}
.upload-zone__icon{font-size:28px;color:var(--accent);margin-bottom:10px}
.upload-zone__text{font-size:14px;color:var(--dim)}
.upload-zone__sub{font-size:12px;color:var(--muted);margin-top:4px}
.upload-methods{display:flex;gap:8px;margin-top:10px}
.upload-method{flex:1;text-align:center;padding:8px;font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:4px;background:none;cursor:pointer;transition:all .15s}
.upload-method:hover{border-color:var(--dim)}
.preview-wrap{position:relative;margin-top:12px}
.preview-wrap img{max-width:100%;border-radius:6px}
.preview-remove{position:absolute;top:8px;right:8px;width:28px;height:28px;border-radius:50%;background:rgba(0,0,0,.7);color:var(--white);border:none;font-size:11px;display:flex;align-items:center;justify-content:center}
.img-thumb-item{position:relative;width:80px;height:80px;border-radius:6px;overflow:hidden;border:1px solid var(--border);background:#1a1a1a;flex-shrink:0}
.img-thumb-item img{width:100%;height:100%;object-fit:cover}
.img-thumb-remove{position:absolute;top:2px;right:2px;width:18px;height:18px;border-radius:50%;background:rgba(0,0,0,.75);border:none;color:#fff;font-size:9px;cursor:pointer;display:flex;align-items:center;justify-content:center;line-height:1;padding:0}
.img-thumb-num{position:absolute;bottom:2px;left:2px;background:rgba(0,0,0,.6);color:#fff;font-size:9px;padding:1px 4px;border-radius:3px}
/* 선생님 도와주세요 버튼 */
.teacher-request-btn{width:100%;padding:16px;border-radius:16px;background:linear-gradient(135deg,rgba(139,92,246,.08),rgba(59,130,246,.08));border:2px dashed rgba(139,92,246,.3);cursor:pointer;text-align:center;transition:all .3s var(--spring);display:flex;flex-direction:column;align-items:center;gap:4px}
.teacher-request-btn:hover{border-color:rgba(139,92,246,.6);background:linear-gradient(135deg,rgba(139,92,246,.12),rgba(59,130,246,.12));transform:translateY(-2px)}
.teacher-request-btn.active{border-color:var(--accent);border-style:solid;background:rgba(139,92,246,.1)}
.teacher-request-btn__icon{font-size:28px}
.teacher-request-btn__text{font-size:15px;font-weight:700;color:var(--white);font-family:var(--font-display)}
.teacher-request-btn__sub{font-size:12px;color:var(--muted)}
/* 선생님 선택 피커 */
.teacher-picker{margin-top:12px;padding:16px;background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:16px;backdrop-filter:blur(12px);animation:fadeSlideIn .25s ease}
.teacher-picker__group{margin-bottom:12px}
.teacher-picker__group:last-child{margin-bottom:0}
.teacher-picker__subj{font-size:12px;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:6px}
.teacher-picker__list{display:flex;gap:8px;flex-wrap:wrap}
.teacher-chip{padding:8px 16px;font-size:14px;font-weight:600;color:var(--dim);border:1px solid var(--glass-border);border-radius:20px;background:rgba(255,255,255,.04);cursor:pointer;transition:all .2s var(--spring)}
.teacher-chip:hover{border-color:rgba(255,255,255,.2);color:var(--white);transform:translateY(-1px)}
.teacher-chip.selected{border-color:var(--accent);color:var(--accent);background:rgba(139,92,246,.15);box-shadow:0 0 12px rgba(139,92,246,.2)}
/* 선택된 선생님 표시 */
.teacher-selected{margin-top:10px;display:flex;align-items:center;gap:10px;padding:12px 16px;background:linear-gradient(135deg,rgba(139,92,246,.12),rgba(59,130,246,.08));border:1px solid rgba(139,92,246,.3);border-radius:14px;animation:fadeSlideIn .25s ease}
.teacher-selected span{font-size:15px;font-weight:700;color:var(--accent);font-family:var(--font-display)}
.teacher-selected__remove{background:none;border:none;color:var(--muted);font-size:14px;cursor:pointer;padding:4px 8px;border-radius:8px;transition:all .15s}
.teacher-selected__remove:hover{color:var(--white);background:rgba(255,255,255,.1)}

.info-box{padding:12px 14px;background:#1e1e1e;border-radius:4px;border-left:3px solid var(--muted);font-size:12px;color:var(--muted);line-height:1.5;margin-bottom:24px}
.btn-submit{width:100%;padding:14px;border-radius:16px;background:var(--accent-gradient);color:#fff;border:none;font-size:16px;font-weight:700;font-family:var(--font-display);transition:all .2s var(--spring);box-shadow:0 4px 16px rgba(139,92,246,.3)}
.btn-submit:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(139,92,246,.4)}
.btn-submit:active{transform:scale(0.97)}
.btn-submit:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}

.killer-check{display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none;padding:8px 14px;border:1px solid var(--border);border-radius:4px;background:#1e1e1e;transition:all .2s}
.killer-check:hover{border-color:var(--muted)}
.killer-check input{display:none}
.killer-check__box{width:22px;height:22px;border-radius:4px;background:var(--bg3);display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--muted);transition:all .2s}
.killer-check input:checked~.killer-check__box{background:linear-gradient(135deg,#ff4500,#e50914);color:#fff}
.killer-check__text{font-size:13px;font-weight:600;color:var(--dim);transition:color .2s}
.killer-check input:checked~.killer-check__text{color:#ff4500}
.killer-check.glow{border-color:#ff4500;background:rgba(255,69,0,.08)}

.q-type-group{display:flex;gap:var(--sp-2);margin-bottom:var(--sp-3)}
.q-type-btn{flex:1;padding:12px 10px;text-align:center;font-size:13px;font-weight:600;color:var(--muted);border:1px solid var(--glass-border);border-radius:14px;background:var(--glass-bg);cursor:pointer;transition:all .25s var(--spring);position:relative;backdrop-filter:blur(8px)}
.q-type-btn:hover{border-color:rgba(255,255,255,.2);color:var(--dim);transform:translateY(-1px)}
.q-type-btn.active-normal{border-color:var(--green);color:var(--green);background:rgba(16,185,129,.06);box-shadow:0 0 16px rgba(16,185,129,.15)}
.q-type-btn.active-killer{border-color:#F97316;color:#F97316;background:rgba(249,115,22,.06);animation:killerPulse 2.5s infinite}
.q-type-btn.active-tutor{border-color:var(--accent);color:var(--accent);background:rgba(139,92,246,.06);animation:tutorPulse 2.5s infinite}
@keyframes tutorPulse{0%,100%{box-shadow:0 0 4px rgba(139,92,246,.2)}50%{box-shadow:0 0 16px rgba(139,92,246,.5)}}
.q-type-btn i{display:block;font-size:18px;margin-bottom:4px}

.points-select{display:none;margin-top:8px;padding:12px;border:1px solid var(--border);border-radius:6px;background:#1a1a2e}
.points-select.show{display:block;animation:fadeSlideIn .25s ease}
@keyframes fadeSlideIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeSlideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.points-select__title{font-size:11px;font-weight:600;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.points-chips{display:flex;gap:8px}
.points-chip{flex:1;padding:10px 6px;text-align:center;border:2px solid var(--border);border-radius:8px;cursor:pointer;transition:all .2s;background:#1e1e1e}
.points-chip:hover{border-color:var(--dim)}
.points-chip.selected{border-color:#ffd700;background:rgba(255,215,0,.08)}
.points-chip__val{font-size:18px;font-weight:800;color:var(--white)}
.points-chip__won{font-size:10px;color:var(--muted);margin-top:2px}
.points-chip.selected .points-chip__val{color:#ffd700}
.points-chip.selected .points-chip__won{color:#ffd700}

.day-tab{padding:6px 12px;font-size:11px;font-weight:600;border:1px solid var(--border);border-radius:4px;background:#1e1e1e;color:var(--muted);cursor:pointer;transition:all .15s}
.day-tab:hover{border-color:var(--dim);color:var(--dim)}
.day-tab.active{border-color:#6c5ce7;color:#6c5ce7;background:rgba(108,92,231,.1)}
.time-slot{padding:8px 4px;text-align:center;font-size:11px;font-weight:500;border:1px solid var(--border);border-radius:4px;background:#1e1e1e;color:var(--muted);cursor:pointer;transition:all .15s}
.time-slot:hover{border-color:var(--dim);color:var(--white)}
.time-slot.picked{border-color:#6c5ce7;color:#fff;background:rgba(108,92,231,.3)}
.time-slot.disabled{opacity:.3;cursor:not-allowed}
.slot-tag{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;font-size:11px;font-weight:600;background:rgba(108,92,231,.15);border:1px solid rgba(108,92,231,.3);border-radius:20px;color:#a29bfe;margin:3px 3px 3px 0}
.slot-tag__x{cursor:pointer;opacity:.6;transition:opacity .15s}
.slot-tag__x:hover{opacity:1}
</style>
</head>
<body>
<div class="detail-nav">
  <a href="javascript:void(0)" class="detail-nav__back" onclick="history.back()"><i class="fas fa-arrow-left"></i> 뒤로</a>
</div>

<div class="new-q">
  <div class="new-q__user" id="userInfo">
    <div class="new-q__user-name" id="userName">-</div>
    <div class="new-q__user-sub" id="userSub">로그인 확인 중...</div>
  </div>

  <div class="new-q__section">
    <label class="new-q__label" style="text-transform:none;letter-spacing:0">몇 학년 수준의 문제인가요? <em>*</em> <span style="font-size:11px;color:var(--muted);font-weight:400">(예: 고2여도 고3 문제라면 고3 선택)</span></label>
    <input type="hidden" id="questionGrade" value="">
    <div class="subj-group" id="gradeGroup">
      <div class="subj-btn" onclick="selectGrade('중1',this)">중1</div>
      <div class="subj-btn" onclick="selectGrade('중2',this)">중2</div>
      <div class="subj-btn" onclick="selectGrade('중3',this)">중3</div>
      <div class="subj-btn" onclick="selectGrade('고1',this)">고1</div>
      <div class="subj-btn" onclick="selectGrade('고2',this)">고2</div>
      <div class="subj-btn" onclick="selectGrade('고3',this)">고3</div>
    </div>
  </div>

  <div class="new-q__section">
    <label class="new-q__label">과목 <em>*</em></label>
    <input type="hidden" id="questionSubject" value="">
    <div class="subj-group" id="subjectGroup">
      <div class="subj-btn" onclick="selectSubject('영어',this)">영어</div>
      <div class="subj-btn" onclick="selectSubject('수학',this)">수학</div>
      <div class="subj-btn" onclick="selectSubject('국어',this)">국어</div>
      <div class="subj-btn" onclick="selectSubject('과학',this)">과학</div>
      <div class="subj-btn" onclick="selectSubject('기타',this)">기타</div>
    </div>
  </div>

  <!-- 국어 과목 전용: 지문형 질문 토글 -->
  <div id="passageTypeSection" class="new-q__section" style="display:none">
    <label class="new-q__label">질문 형식 <em>*</em></label>
    <div class="subj-group">
      <div class="subj-btn" id="passageTypeNormal" onclick="setPassageMode(false,this)">일반 질문</div>
      <div class="subj-btn" id="passageTypePassage" onclick="setPassageMode(true,this)">지문형 질문</div>
    </div>
    <div id="passageTypeHint" style="display:none;font-size:11px;color:var(--muted);margin-top:6px;line-height:1.5">
      지문(본문) 이미지와 문제 이미지를 따로 올려주세요. AI가 지문과 문제를 구분하여 더 정확하게 분석합니다.
    </div>
  </div>

  <div class="new-q__section">
    <label class="new-q__label">질문 유형</label>
    <div class="q-type-group">
      <div class="q-type-btn active-normal" id="typeNormal" onclick="selectQType('normal')">
        <i class="fas fa-comment-dots"></i>일반 질문
      </div>
      <div class="q-type-btn" id="typeKiller" onclick="selectQType('killer')">
        <i class="fas fa-fire"></i>고난도
      </div>
      <div class="q-type-btn" id="typeTutor" onclick="selectQType('tutor')">
        <i class="fas fa-chalkboard-teacher"></i>1:1 튜터링
      </div>
    </div>

    <div class="points-select" id="killerPoints">
      <div class="points-select__title"><i class="fas fa-cookie-bite" style="color:#a29bfe"></i> 고난도 상금 CP 설정 (1CP = ₩100)</div>
      <div class="points-chips">
        <div class="points-chip" onclick="selectPoints(3)"><div class="points-chip__val">3CP</div><div class="points-chip__won">₩300</div></div>
        <div class="points-chip" onclick="selectPoints(5)"><div class="points-chip__val">5CP</div><div class="points-chip__won">₩500</div></div>
        <div class="points-chip" onclick="selectPoints(8)"><div class="points-chip__val">8CP</div><div class="points-chip__won">₩800</div></div>
      </div>
    </div>

    <div class="points-select" id="tutorPoints">
      <div class="points-select__title"><i class="fas fa-cookie-bite" style="color:#a29bfe"></i> 1:1 튜터링 CP 설정 (1CP = ₩100)</div>
      <div class="points-chips">
        <div class="points-chip" onclick="selectPoints(10)"><div class="points-chip__val">10CP</div><div class="points-chip__won">₩1,000</div></div>
        <div class="points-chip" onclick="selectPoints(15)"><div class="points-chip__val">15CP</div><div class="points-chip__won">₩1,500</div></div>
        <div class="points-chip" onclick="selectPoints(20)"><div class="points-chip__val">20CP</div><div class="points-chip__won">₩2,000</div></div>
      </div>
      <div style="margin-top:14px;border-top:1px solid var(--border);padding-top:14px">
        <div class="points-select__title"><i class="fas fa-clock" style="color:#6c5ce7"></i> 가능한 시간 3개 선택 <span style="color:var(--muted);font-weight:400">(30분 단위)</span></div>
        <div id="slotPicker" style="margin-top:8px">
          <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap" id="dayTabs"></div>
          <div id="timeGrid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;max-height:180px;overflow-y:auto"></div>
        </div>
        <div id="selectedSlots" style="margin-top:10px"></div>
      </div>
    </div>
  </div>

  <div class="new-q__section">
    <label class="new-q__label">질문 내용 <em>*</em></label>
    <textarea id="questionContent" class="f-input" rows="5" placeholder="어떤 부분이 이해가 안 되는지 구체적으로 적어주세요 (최소 10자)" oninput="checkContentLength()"></textarea>
    <div id="contentCounter" style="text-align:right;font-size:11px;color:var(--muted);margin-top:4px">0 / 10자 이상</div>
  </div>

  <!-- 지문 이미지 업로드 (국어 지문형 전용) -->
  <div id="passageUploadSection" class="new-q__section" style="display:none">
    <label class="new-q__label">지문 이미지 <span style="font-size:11px;color:var(--muted);font-weight:400">(최대 5장)</span></label>
    <div id="passageUploadArea" class="upload-zone">
      <div class="upload-zone__icon"><i class="fas fa-book-open"></i></div>
      <div class="upload-zone__text">지문(본문) 이미지를 드래그하거나 클릭</div>
      <div class="upload-zone__sub">최대 5장 · 지문/본문 사진을 올려주세요</div>
      <input id="passageImageInput" type="file" accept="image/*" multiple style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none">
    </div>
    <div id="passageImagePreview" style="display:none;margin-top:10px">
      <div id="passageImagePreviewList" style="display:flex;gap:8px;flex-wrap:wrap"></div>
      <div id="passageImageCountLabel" style="font-size:11px;color:var(--muted);margin-top:6px"></div>
    </div>
  </div>

  <div class="new-q__section">
    <label class="new-q__label"><span id="problemImageLabel">문제 이미지</span></label>
    <div id="uploadLock" style="padding:32px 20px;text-align:center;border:1px solid var(--border);border-radius:6px;background:#1a1a1a">
      <div style="font-size:20px;color:var(--muted);margin-bottom:6px"><i class="fas fa-lock"></i></div>
      <div style="font-size:13px;color:var(--muted)">질문 내용을 10자 이상 작성하면 이미지를 첨부할 수 있습니다</div>
      <div id="lockProgress" style="margin-top:10px;height:3px;background:#333;border-radius:2px;overflow:hidden"><div id="lockBar" style="height:100%;width:0%;background:var(--red);transition:width .2s;border-radius:2px"></div></div>
    </div>
    <div id="uploadAreaWrap" style="display:none">
      <div id="uploadArea" class="upload-zone">
        <div class="upload-zone__icon"><i class="fas fa-arrow-up-from-bracket"></i></div>
        <div class="upload-zone__text">이미지를 드래그하거나 클릭</div>
        <div class="upload-zone__sub">최대 3장 · 캡처한 문제 사진을 올려주세요</div>
        <input id="imageInput" type="file" accept="image/*" multiple style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none">
      </div>
      <div class="upload-methods">
        <label class="upload-method"><i class="fas fa-camera" style="margin-right:4px"></i>카메라
          <input id="cameraInput" type="file" accept="image/*" capture="environment" style="position:absolute;width:1px;height:1px;opacity:0;overflow:hidden;pointer-events:none">
        </label>
        <button id="pasteBtn" class="upload-method"><i class="fas fa-paste" style="margin-right:4px"></i>붙여넣기</button>
      </div>
      <div id="multiImagePreview" style="display:none;margin-top:10px">
        <div id="imagePreviewList" style="display:flex;gap:8px;flex-wrap:wrap"></div>
        <div id="imageCountLabel" style="font-size:11px;color:var(--muted);margin-top:6px"></div>
      </div>
    </div>
  </div>

  <!-- 선생님 도와주세요 스티커 -->
  <div class="new-q__section">
    <button type="button" id="teacherRequestBtn" class="teacher-request-btn" onclick="toggleTeacherPicker()">
      <span class="teacher-request-btn__icon">🙋</span>
      <span class="teacher-request-btn__text">선생님 도와주세요!</span>
      <span class="teacher-request-btn__sub">특정 선생님께 도움을 요청해보세요</span>
    </button>
    <div id="teacherPicker" class="teacher-picker" style="display:none">
      <div class="teacher-picker__group" data-subj="수학">
        <div class="teacher-picker__subj" style="color:#3B82F6"><i class="fas fa-square-root-alt"></i> 수학</div>
        <div class="teacher-picker__list">
          <button class="teacher-chip" data-teacher="희성" onclick="selectTeacher(this)">희성쌤</button>
          <button class="teacher-chip" data-teacher="우제" onclick="selectTeacher(this)">우제쌤</button>
          <button class="teacher-chip" data-teacher="우현" onclick="selectTeacher(this)">우현쌤</button>
          <button class="teacher-chip" data-teacher="윤동" onclick="selectTeacher(this)">윤동쌤</button>
        </div>
      </div>
      <div class="teacher-picker__group" data-subj="영어">
        <div class="teacher-picker__subj" style="color:#10B981"><i class="fas fa-language"></i> 영어</div>
        <div class="teacher-picker__list">
          <button class="teacher-chip" data-teacher="성희" onclick="selectTeacher(this)">성희쌤</button>
          <button class="teacher-chip" data-teacher="제이든" onclick="selectTeacher(this)">제이든쌤</button>
          <button class="teacher-chip" data-teacher="성웅" onclick="selectTeacher(this)">성웅쌤</button>
        </div>
      </div>
      <div class="teacher-picker__group" data-subj="국어">
        <div class="teacher-picker__subj" style="color:#EC4899"><i class="fas fa-book-open"></i> 국어</div>
        <div class="teacher-picker__list">
          <button class="teacher-chip" data-teacher="지영" onclick="selectTeacher(this)">지영쌤</button>
          <button class="teacher-chip" data-teacher="서욱" onclick="selectTeacher(this)">서욱쌤</button>
          <button class="teacher-chip" data-teacher="지후" onclick="selectTeacher(this)">지후쌤</button>
        </div>
      </div>
      <div class="teacher-picker__group" data-subj="과학">
        <div class="teacher-picker__subj" style="color:#8B5CF6"><i class="fas fa-flask"></i> 과학</div>
        <div class="teacher-picker__list">
          <button class="teacher-chip" data-teacher="동현" onclick="selectTeacher(this)">동현쌤</button>
          <button class="teacher-chip" data-teacher="성현" onclick="selectTeacher(this)">성현쌤</button>
        </div>
      </div>
    </div>
    <div id="teacherSelected" class="teacher-selected" style="display:none">
      <span id="teacherSelectedName"></span>
      <button type="button" class="teacher-selected__remove" onclick="removeTeacher()"><i class="fas fa-times"></i></button>
    </div>
  </div>

  <div class="info-box">구체적으로 질문할수록 좋은 답변을 받을 수 있습니다.</div>
  <button id="submitQuestion" class="btn-submit">질문 등록</button>
</div>

<script>
${sharedAuthJS()}

let imagesData=[],imageUnlocked=false,currentUser=null;
let qType='normal',selectedPoints=0,pickedSlots=[],selectedTeacher=null;
let passageImagesData=[],isPassageMode=false,passageTypeSelected=false;

function toggleTeacherPicker(){
  var picker=document.getElementById('teacherPicker');
  var btn=document.getElementById('teacherRequestBtn');
  if(picker.style.display==='none'){picker.style.display='block';btn.classList.add('active')}
  else{picker.style.display='none';btn.classList.remove('active')}
}
function selectTeacher(el){
  var name=el.getAttribute('data-teacher');
  selectedTeacher=name;
  document.querySelectorAll('.teacher-chip').forEach(c=>c.classList.remove('selected'));
  el.classList.add('selected');
  document.getElementById('teacherPicker').style.display='none';
  document.getElementById('teacherRequestBtn').style.display='none';
  var sel=document.getElementById('teacherSelected');
  sel.style.display='flex';
  document.getElementById('teacherSelectedName').textContent='🙋 '+name+'쌤에게 도움 요청!';
}
function removeTeacher(){
  selectedTeacher=null;
  document.querySelectorAll('.teacher-chip').forEach(c=>c.classList.remove('selected'));
  document.getElementById('teacherSelected').style.display='none';
  document.getElementById('teacherRequestBtn').style.display='';
  document.getElementById('teacherRequestBtn').classList.remove('active');
}
window.toggleTeacherPicker=toggleTeacherPicker;
window.selectTeacher=selectTeacher;
window.removeTeacher=removeTeacher;

const DAYS=['월','화','수','목','금','토','일'];
const TIMES=[];
for(let h=15;h<=22;h++){TIMES.push(h+':00');if(h<22)TIMES.push(h+':30')}

function selectGrade(val,el){
  document.getElementById('questionGrade').value=val;
  document.querySelectorAll('#gradeGroup .subj-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
}
function selectSubject(val,el){
  document.getElementById('questionSubject').value=val;
  document.querySelectorAll('#subjectGroup .subj-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  // 수학 외 과목에서 지문형 질문 토글 표시
  var passageSec=document.getElementById('passageTypeSection');
  if(passageSec){
    if(val!=='수학'){passageSec.style.display='block';resetPassageToggle()}
    else{passageSec.style.display='none';setPassageMode(false,null)}
  }
  updateUploadVisibility();
}
function setPassageMode(enabled,el){
  isPassageMode=enabled;
  passageTypeSelected=true;
  passageImagesData=[];
  var sec=document.getElementById('passageUploadSection');
  var hint=document.getElementById('passageTypeHint');
  var label=document.getElementById('problemImageLabel');
  if(sec)sec.style.display=enabled?'block':'none';
  if(hint)hint.style.display=enabled?'block':'none';
  if(label)label.textContent=enabled?'문제 이미지 (지문과 별도로 올려주세요)':'문제 이미지';
  // 토글 버튼 활성화 상태
  var btnNormal=document.getElementById('passageTypeNormal');
  var btnPassage=document.getElementById('passageTypePassage');
  if(btnNormal){btnNormal.classList.toggle('active',!enabled)}
  if(btnPassage){btnPassage.classList.toggle('active',enabled)}
  renderPassageImagePreviews();
  updateUploadVisibility();
}
function resetPassageToggle(){
  isPassageMode=false;
  passageTypeSelected=false;
  passageImagesData=[];
  var btnNormal=document.getElementById('passageTypeNormal');
  var btnPassage=document.getElementById('passageTypePassage');
  if(btnNormal)btnNormal.classList.remove('active');
  if(btnPassage)btnPassage.classList.remove('active');
  var sec=document.getElementById('passageUploadSection');
  if(sec)sec.style.display='none';
  var hint=document.getElementById('passageTypeHint');
  if(hint)hint.style.display='none';
  var label=document.getElementById('problemImageLabel');
  if(label)label.textContent='문제 이미지';
  renderPassageImagePreviews();
}
function processPassageFile(file){
  if(passageImagesData.length>=5){showToast('지문 이미지는 최대 5장까지 첨부할 수 있습니다.','warn');return}
  var url=URL.createObjectURL(file);
  var img=new Image();
  img.onload=function(){
    URL.revokeObjectURL(url);
    try{
      var max=1200,w=img.width,h=img.height;
      if(w>max||h>max){var s=max/Math.max(w,h);w=Math.round(w*s);h=Math.round(h*s)}
      var c=document.createElement('canvas');c.width=w;c.height=h;c.getContext('2d').drawImage(img,0,0,w,h);
      var main=c.toDataURL('image/jpeg',0.82);
      var tmax=480,tw=img.width,th=img.height;
      if(tw>tmax||th>tmax){var ts=tmax/Math.max(tw,th);tw=Math.round(tw*ts);th=Math.round(th*ts)}
      var tc=document.createElement('canvas');tc.width=tw;tc.height=th;tc.getContext('2d').drawImage(img,0,0,tw,th);
      var thumb=tc.toDataURL('image/jpeg',0.7);
      passageImagesData.push({main:main,thumb:thumb});
      renderPassageImagePreviews();
    }catch(e){showToast('이미지 처리에 실패했습니다.','error')}
  };
  img.onerror=function(){URL.revokeObjectURL(url);showToast('이미지를 불러올 수 없습니다.','error')};
  img.src=url;
}
function renderPassageImagePreviews(){
  var list=document.getElementById('passageImagePreviewList');
  var wrap=document.getElementById('passageImagePreview');
  var label=document.getElementById('passageImageCountLabel');
  if(!list)return;
  if(passageImagesData.length===0){if(wrap)wrap.style.display='none';list.innerHTML='';return}
  if(wrap)wrap.style.display='block';
  list.innerHTML=passageImagesData.map(function(d,i){
    return '<div class="img-thumb-item" style="position:relative"><img src="'+d.thumb+'" style="width:80px;height:80px;object-fit:cover;border-radius:8px;border:1px solid var(--border)"><div class="img-thumb-num">'+(i+1)+'</div><button class="img-thumb-remove" onclick="removePassageImage('+i+')">&times;</button></div>';
  }).join('');
  if(label)label.textContent=passageImagesData.length+'/5장 첨부됨';
}
function removePassageImage(idx){
  passageImagesData.splice(idx,1);
  renderPassageImagePreviews();
}
function selectQType(type){
  qType=type;selectedPoints=0;pickedSlots=[];
  document.querySelectorAll('.q-type-btn').forEach(b=>b.className='q-type-btn');
  document.querySelectorAll('.points-chip').forEach(c=>c.classList.remove('selected'));
  if(type==='normal'){document.getElementById('typeNormal').className='q-type-btn active-normal';document.getElementById('killerPoints').classList.remove('show');document.getElementById('tutorPoints').classList.remove('show')}
  else if(type==='killer'){document.getElementById('typeKiller').className='q-type-btn active-killer';document.getElementById('killerPoints').classList.add('show');document.getElementById('tutorPoints').classList.remove('show')}
  else if(type==='tutor'){document.getElementById('typeTutor').className='q-type-btn active-tutor';document.getElementById('tutorPoints').classList.add('show');document.getElementById('killerPoints').classList.remove('show');initSlotPicker()}
}
function selectPoints(p){
  selectedPoints=p;
  const container=qType==='killer'?document.getElementById('killerPoints'):document.getElementById('tutorPoints');
  container.querySelectorAll('.points-chip').forEach(c=>{c.classList.toggle('selected',c.querySelector('.points-chip__val').textContent===p+'P')});
}

let curDay=null;
function initSlotPicker(){
  // 오늘부터 7일 계산
  const today=new Date();
  const dayList=[];
  for(let i=0;i<7;i++){
    const d=new Date(today);d.setDate(today.getDate()+i);
    const dayIdx=d.getDay();const dayName=['일','월','화','수','목','금','토'][dayIdx];
    const mm=(d.getMonth()+1);const dd=d.getDate();
    dayList.push({label:dayName+' '+mm+'/'+dd,value:dayName+' '+(mm<10?'0'+mm:mm)+'/'+(dd<10?'0'+dd:dd),dateStr:(d.getMonth()+1)+'/'+d.getDate()});
  }
  const tabs=document.getElementById('dayTabs');
  tabs.innerHTML=dayList.map((d,i)=>'<div class="day-tab'+(i===0?' active':'')+'" data-day="'+d.label+'" onclick="pickDay(this)">'+d.label+'</div>').join('');
  curDay=dayList[0].label;
  renderTimeGrid();
  renderSelectedSlots();
}
function pickDay(el){
  document.querySelectorAll('.day-tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');curDay=el.dataset.day;renderTimeGrid();
}
function renderTimeGrid(){
  const grid=document.getElementById('timeGrid');
  grid.innerHTML=TIMES.map(t=>{
    const key=curDay+' '+t;
    const picked=pickedSlots.includes(key);
    const full=pickedSlots.length>=3&&!picked;
    return'<div class="time-slot'+(picked?' picked':'')+(full?' disabled':'')+'" data-slot="'+key+'" onclick="toggleSlot(this)">'+t+'</div>';
  }).join('');
}
function toggleSlot(el){
  if(el.classList.contains('disabled'))return;
  const key=el.dataset.slot;
  if(pickedSlots.includes(key)){pickedSlots=pickedSlots.filter(s=>s!==key)}
  else{if(pickedSlots.length>=3)return;pickedSlots.push(key)}
  renderTimeGrid();renderSelectedSlots();
}
function removeSlot(key){pickedSlots=pickedSlots.filter(s=>s!==key);renderTimeGrid();renderSelectedSlots()}
function renderSelectedSlots(){
  const el=document.getElementById('selectedSlots');
  if(!pickedSlots.length){el.innerHTML='<div style="font-size:11px;color:var(--muted)"><i class="fas fa-info-circle"></i> 요일을 선택하고 시간을 탭하세요 (최대 3개)</div>';return}
  el.innerHTML='<div style="font-size:10px;color:var(--muted);margin-bottom:4px">선택된 시간 ('+pickedSlots.length+'/3)</div>'+
    pickedSlots.map(s=>'<span class="slot-tag"><i class="fas fa-clock"></i> '+s+' <span class="slot-tag__x" onclick="removeSlot(&quot;'+s+'&quot;)">&times;</span></span>').join('');
}
const uploadArea=document.getElementById('uploadArea'),imageInput=document.getElementById('imageInput');

// Auth check
(async()=>{
  currentUser=await checkAuth();
  if(!currentUser){showToast('정율톡에서 접속해주세요.','warn');return}
  document.getElementById('userName').textContent=currentUser.nickname;
  document.getElementById('userSub').textContent=(currentUser.grade||'학년 미설정')+' · @'+currentUser.username;
})();

function checkContentLength(){
  const len=document.getElementById('questionContent').value.trim().length;
  const counter=document.getElementById('contentCounter');
  const lockBar=document.getElementById('lockBar');
  const pct=Math.min(len/10*100,100);
  counter.textContent=len+' / 10자 이상';
  counter.style.color=len>=10?'#46d369':'var(--muted)';
  lockBar.style.width=pct+'%';
  if(len>=10)lockBar.style.background='#46d369';
  else lockBar.style.background='var(--red)';
  updateUploadVisibility();
}
function updateUploadVisibility(){
  var len=document.getElementById('questionContent').value.trim().length;
  var subj=document.getElementById('questionSubject').value;
  var needsPassageType=(subj&&subj!=='수학');
  var canUnlock=len>=10&&(!needsPassageType||passageTypeSelected);
  if(canUnlock&&!imageUnlocked){imageUnlocked=true;document.getElementById('uploadLock').style.display='none';document.getElementById('uploadAreaWrap').style.display='block'}
  else if(!canUnlock&&imageUnlocked&&imagesData.length===0){imageUnlocked=false;document.getElementById('uploadLock').style.display='';document.getElementById('uploadAreaWrap').style.display='none'}
  // 잠금 메시지 업데이트
  var lockMsg=document.querySelector('#uploadLock div:nth-child(2)');
  if(lockMsg){
    if(len<10)lockMsg.textContent='질문 내용을 10자 이상 작성하면 이미지를 첨부할 수 있습니다';
    else if(needsPassageType&&!passageTypeSelected)lockMsg.textContent='질문 형식(일반/지문형)을 선택하면 이미지를 첨부할 수 있습니다';
  }
}

uploadArea.addEventListener('click',()=>imageInput.click());
uploadArea.addEventListener('dragover',e=>{e.preventDefault();uploadArea.classList.add('drag-over')});
uploadArea.addEventListener('dragleave',()=>uploadArea.classList.remove('drag-over'));
uploadArea.addEventListener('drop',e=>{e.preventDefault();uploadArea.classList.remove('drag-over');Array.from(e.dataTransfer.files).forEach(f=>{if(!f.type||f.type.startsWith('image/'))processFile(f)})});
imageInput.addEventListener('change',e=>{Array.from(e.target.files).forEach(f=>processFile(f));e.target.value=''});
document.getElementById('cameraInput').addEventListener('change',e=>{if(e.target.files[0])processFile(e.target.files[0]);e.target.value=''});

document.getElementById('pasteBtn').addEventListener('click',async()=>{
  try{const items=await navigator.clipboard.read();for(const item of items)for(const type of item.types)if(type.startsWith('image/')){processFile(await item.getType(type));return}showToast('클립보드에 이미지가 없습니다.','warn')}
  catch(e){showToast('클립보드 접근이 허용되지 않았습니다.','error')}
});

// 지문 이미지 업로드 영역 이벤트 바인딩
(function(){
  var pa=document.getElementById('passageUploadArea'),pi=document.getElementById('passageImageInput');
  if(!pa||!pi)return;
  pa.addEventListener('click',function(){pi.click()});
  pa.addEventListener('dragover',function(e){e.preventDefault();pa.classList.add('drag-over')});
  pa.addEventListener('dragleave',function(){pa.classList.remove('drag-over')});
  pa.addEventListener('drop',function(e){e.preventDefault();pa.classList.remove('drag-over');Array.from(e.dataTransfer.files).forEach(function(f){if(!f.type||f.type.startsWith('image/'))processPassageFile(f)})});
  pi.addEventListener('change',function(e){Array.from(e.target.files).forEach(function(f){processPassageFile(f)});e.target.value=''});
})();

document.addEventListener('paste',e=>{const items=e.clipboardData?.items;if(!items)return;for(const item of items)if(item.type.startsWith('image/')){const f=item.getAsFile();if(f)processFile(f);return}});

function processFile(file){
  if(imagesData.length>=3){showToast('이미지는 최대 3장까지 첨부할 수 있습니다.','warn');return}
  const url=URL.createObjectURL(file);
  const img=new Image();
  img.onload=()=>{
    URL.revokeObjectURL(url);
    try{
      // Original (1200px, quality 0.82)
      const max=1200;let w=img.width,h=img.height;
      if(w>max||h>max){const s=max/Math.max(w,h);w=Math.round(w*s);h=Math.round(h*s)}
      const c=document.createElement('canvas');c.width=w;c.height=h;c.getContext('2d').drawImage(img,0,0,w,h);
      const main=c.toDataURL('image/jpeg',0.82);
      // Thumbnail (480px, quality 0.7)
      const tmax=480;let tw=img.width,th=img.height;
      if(tw>tmax||th>tmax){const ts=tmax/Math.max(tw,th);tw=Math.round(tw*ts);th=Math.round(th*ts)}
      const tc=document.createElement('canvas');tc.width=tw;tc.height=th;tc.getContext('2d').drawImage(img,0,0,tw,th);
      const thumb=tc.toDataURL('image/jpeg',0.7);
      imagesData.push({main,thumb});
      renderImagePreviews();
    }catch(e){showToast('이미지 처리에 실패했습니다. 다른 이미지를 시도해주세요.','error')}
  };
  img.onerror=()=>{URL.revokeObjectURL(url);showToast('이미지를 불러올 수 없습니다. 다른 이미지를 시도해주세요.','error')};
  img.src=url;
}

function renderImagePreviews(){
  const list=document.getElementById('imagePreviewList');
  const wrap=document.getElementById('multiImagePreview');
  const countLabel=document.getElementById('imageCountLabel');
  if(imagesData.length===0){
    wrap.style.display='none';
    uploadArea.style.display='';
    return;
  }
  wrap.style.display='block';
  uploadArea.style.display=imagesData.length>=3?'none':'';
  countLabel.textContent=imagesData.length+'/3장';
  list.innerHTML=imagesData.map((img,i)=>
    '<div class="img-thumb-item">'+
      '<img src="'+img.main+'" alt="이미지 '+(i+1)+'">'+
      '<button class="img-thumb-remove" onclick="removeUploadedImage('+i+')" type="button"><i class="fas fa-times"></i></button>'+
      '<span class="img-thumb-num">'+(i+1)+'</span>'+
    '</div>'
  ).join('');
}

function removeUploadedImage(idx){
  imagesData.splice(idx,1);
  renderImagePreviews();
  document.getElementById('imageInput').value='';
}

document.getElementById('submitQuestion').addEventListener('click',async()=>{
  const contentVal=document.getElementById('questionContent').value.trim();
  if(contentVal.length<10){showToast('질문 내용을 10자 이상 작성해주세요.','warn');return}
  const gradeVal=document.getElementById('questionGrade').value;
  if(!gradeVal){showToast('학년을 선택해주세요.','warn');return}
  const subjectVal=document.getElementById('questionSubject').value;
  if(!subjectVal){showToast('과목을 선택해주세요.','warn');return}
  if(subjectVal!=='수학'&&!passageTypeSelected){showToast('질문 형식(일반/지문형)을 선택해주세요.','warn');return}
  if((qType==='killer'||qType==='tutor')&&selectedPoints===0){showToast('CP를 선택해주세요.','warn');return}
  if(qType==='tutor'&&pickedSlots.length===0){showToast('가능한 시간을 최소 1개 선택해주세요.','warn');return}
  const btn=document.getElementById('submitQuestion');btn.disabled=true;btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 등록 중...';
  try{
    // 지문 이미지 업로드 (국어 지문형일 때)
    let passageUploadedKeys=[];
    if(isPassageMode&&passageImagesData.length>0){
      for(let i=0;i<passageImagesData.length;i++){
        btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 지문 이미지 업로드 중... ('+(i+1)+'/'+passageImagesData.length+')';
        try{
          const upResult=await uploadImageSmart(passageImagesData[i].main,passageImagesData[i].thumb,'passage');
          passageUploadedKeys.push({key:upResult.key,thumbnailKey:upResult.thumbnailKey});
        }catch(ue){showToast('지문 이미지 '+(i+1)+' 업로드 실패: '+(ue.message||''),'error');btn.disabled=false;btn.innerHTML='질문 등록';return}
      }
    }
    // 문제 이미지 업로드
    let uploadedKeys=[];
    if(imagesData.length>0){
      for(let i=0;i<imagesData.length;i++){
        btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 이미지 업로드 중... ('+(i+1)+'/'+imagesData.length+')';
        try{
          const upResult=await uploadImageSmart(imagesData[i].main,imagesData[i].thumb,'question');
          uploadedKeys.push({key:upResult.key,thumbnailKey:upResult.thumbnailKey});
        }catch(ue){showToast('이미지 '+(i+1)+' 업로드 실패: '+(ue.message||''),'error');btn.disabled=false;btn.innerHTML='질문 등록';return}
      }
    }
    btn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 질문 등록 중...';
    const firstKey=uploadedKeys[0]||null;
    const body={content:contentVal,image_key:firstKey?firstKey.key:null,thumbnail_key:firstKey?firstKey.thumbnailKey:null,image_keys:uploadedKeys.length>0?uploadedKeys:undefined,subject:subjectVal,question_grade:gradeVal,is_killer:qType==='killer',is_tutoring:qType==='tutor',reward_points:selectedPoints,tutoring_slots:qType==='tutor'?pickedSlots:undefined,requested_teacher:selectedTeacher||undefined,content_type:isPassageMode?'passage':'normal',passage_image_keys:passageUploadedKeys.length>0?passageUploadedKeys:undefined};
    const res=await fetch('/api/questions',{method:'POST',headers:authHeaders(),body:JSON.stringify(body)});
    const data=await res.json();
    if(!res.ok){showToast(data.error||'등록에 실패했습니다.','error');btn.disabled=false;btn.innerHTML='질문 등록';return}
    showToast('질문이 등록되었습니다!','success');
    showConfetti();
    // 플래너에서 진입 시 등록 후 목록(내 질문 필터)으로 이동
    const _fromParams=new URLSearchParams(location.search);
    setTimeout(function(){
      if(_fromParams.get('from')==='creditplanner'){
        location.href='/?filter=my&user_id='+encodeURIComponent(_fromParams.get('user_id')||'')+'&nick_name='+encodeURIComponent(_fromParams.get('nick_name')||'')+'&from=creditplanner';
      } else {
        location.href='/question/'+data.id;
      }
    },800);
  }catch(e){showToast('등록에 실패했습니다.','error');btn.disabled=false;btn.innerHTML='질문 등록'}
});
</script>
</body>
</html>`
}

// ============================================================================
// ===== 어드민 대시보드 HTML =====
// ============================================================================

function adminLoginHTML() {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>관리자 로그인</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b0e14;color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#151922;border:1px solid #2a2f3a;border-radius:16px;padding:40px;width:100%;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
h1{font-size:22px;font-weight:700;margin-bottom:8px;text-align:center}
.sub{color:#9ca3af;font-size:14px;text-align:center;margin-bottom:28px}
label{display:block;font-size:13px;color:#9ca3af;margin-bottom:8px;font-weight:500}
input[type=password]{width:100%;padding:14px 16px;background:#0b0e14;border:1px solid #2a2f3a;border-radius:10px;color:#fff;font-size:15px;outline:none;transition:border .15s}
input[type=password]:focus{border-color:#6366f1}
button{width:100%;margin-top:20px;padding:14px;background:#6366f1;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .15s}
button:hover{opacity:.9}
button:disabled{opacity:.5;cursor:not-allowed}
.err{color:#ef4444;font-size:13px;margin-top:12px;text-align:center;min-height:18px}
</style>
</head>
<body>
<div class="card">
<h1>관리자 대시보드</h1>
<p class="sub">ADMIN_SECRET을 입력하세요</p>
<form id="f">
<label>비밀번호</label>
<input type="password" id="pw" autofocus autocomplete="current-password">
<button type="submit" id="btn">로그인</button>
<div class="err" id="err"></div>
</form>
</div>
<script>
document.getElementById('f').addEventListener('submit', async function(e){
  e.preventDefault();
  var pw = document.getElementById('pw').value;
  var btn = document.getElementById('btn');
  var err = document.getElementById('err');
  err.textContent = '';
  btn.disabled = true;
  btn.textContent = '로그인 중...';
  try {
    var res = await fetch('/api/admin/login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ secret: pw }) });
    if (res.ok) { location.href = '/admin'; return; }
    var j = await res.json().catch(function(){ return {} });
    err.textContent = j.error || '로그인 실패';
  } catch (ex) { err.textContent = '네트워크 오류'; }
  btn.disabled = false;
  btn.textContent = '로그인';
});
</script>
</body>
</html>`
}

function adminDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>관리자 대시보드</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0b0e14;color:#e5e7eb;min-height:100vh;line-height:1.5}
.wrap{max-width:1400px;margin:0 auto;padding:20px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-bottom:20px;border-bottom:1px solid #2a2f3a;margin-bottom:24px}
h1{font-size:20px;font-weight:700}
.range{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.range button{background:#151922;border:1px solid #2a2f3a;color:#9ca3af;padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer;transition:all .15s}
.range button:hover{color:#fff;border-color:#3a4050}
.range button.active{background:#6366f1;color:#fff;border-color:#6366f1}
.range input[type=date]{background:#151922;border:1px solid #2a2f3a;color:#fff;padding:7px 10px;border-radius:8px;font-size:13px;color-scheme:dark}
.ft-select{background:#151922;border:1px solid #2a2f3a;color:#fff;padding:7px 10px;border-radius:8px;font-size:13px;cursor:pointer;appearance:none;padding-right:24px;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 6' fill='%239ca3af'><path d='M0 0l5 6 5-6z'/></svg>");background-repeat:no-repeat;background-position:right 8px center;background-size:10px}
.ft-select:focus{outline:none;border-color:#6366f1}
.filter-chip{display:inline-flex;align-items:center;gap:6px;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.4);color:#c7d2fe;padding:4px 10px;border-radius:12px;font-size:12px;font-weight:500}
.dow-label{color:#9ca3af;font-size:12px;margin:0 2px;font-weight:500}
.active-filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;min-height:18px}
.logout-btn{background:transparent;border:1px solid #2a2f3a;color:#9ca3af;padding:8px 14px;border-radius:8px;font-size:13px;cursor:pointer}
.logout-btn:hover{color:#ef4444;border-color:#ef4444}
section{margin-bottom:32px}
section h2{font-size:15px;font-weight:600;color:#9ca3af;margin-bottom:14px;text-transform:uppercase;letter-spacing:.5px}
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.kpi{background:#151922;border:1px solid #2a2f3a;border-radius:12px;padding:18px}
.kpi-label{font-size:12px;color:#9ca3af;margin-bottom:6px;font-weight:500}
.kpi-value{font-size:32px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.kpi-delta{font-size:12px;margin-top:6px;color:#9ca3af}
.kpi-delta.up{color:#10b981}
.kpi-delta.down{color:#ef4444}
.card{background:#151922;border:1px solid #2a2f3a;border-radius:12px;padding:20px}
.trend-card{display:flex;flex-direction:column;gap:12px}
.trend-toolbar{display:flex;justify-content:flex-end;gap:6px}
.trend-toolbar button{background:#0b0e14;border:1px solid #2a2f3a;color:#9ca3af;padding:5px 12px;border-radius:6px;font-size:12px;cursor:pointer}
.trend-toolbar button.active{background:#6366f1;color:#fff;border-color:#6366f1}
.chart-box{position:relative;height:320px}
.segments-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.segments-grid .card{min-width:0}
.heatmap{display:grid;gap:3px;font-size:12px}
.hm-cell{background:#0b0e14;border-radius:4px;padding:8px 6px;text-align:center;min-height:32px;display:flex;align-items:center;justify-content:center}
.hm-label{background:transparent;color:#9ca3af;font-weight:600;font-size:11px}
.hm-val{color:#fff;font-weight:600;font-variant-numeric:tabular-nums}
.hm-legend{display:flex;align-items:center;gap:8px;font-size:11px;color:#9ca3af;margin-top:10px}
.hm-legend-bar{flex:1;height:8px;border-radius:4px;background:linear-gradient(to right,#0b0e14,#6366f1)}
.feat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.part-section{margin-bottom:40px;padding-top:8px;border-top:2px solid #2a2f3a}
.part-title{font-size:18px!important;font-weight:700!important;color:#fff!important;margin-bottom:16px!important;letter-spacing:normal!important;text-transform:none!important}
.part-sub{font-size:14px;font-weight:600;color:#fff;margin-bottom:12px}
.tutor-split-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.ai-kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.ai-kpi{background:#0b0e14;border:1px solid #1f2430;border-radius:10px;padding:14px}
.ai-kpi-label{font-size:11px;color:#9ca3af;margin-bottom:4px}
.ai-kpi-value{font-size:22px;font-weight:700;color:#fff;font-variant-numeric:tabular-nums}
.ai-kpi-sub{font-size:11px;color:#6b7280;margin-top:2px}
.ai-chart-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.ai-chart-grid-3{display:grid;grid-template-columns:1fr 1fr 260px;gap:16px}
.ai-chart-box{position:relative;height:260px}
.feat-card h3{font-size:14px;font-weight:600;color:#fff;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.feat-card .badge{background:#f59e0b;color:#000;font-size:10px;padding:2px 8px;border-radius:10px;font-weight:700}
.feat-stat{display:flex;justify-content:space-between;align-items:baseline;padding:8px 0;border-bottom:1px solid #1f2430;font-size:13px}
.feat-stat:last-child{border-bottom:none}
.feat-stat-label{color:#9ca3af}
.feat-stat-val{color:#fff;font-weight:600;font-variant-numeric:tabular-nums;font-size:15px}
.feat-chart-box{position:relative;height:180px;margin-top:12px}
.top-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.top-list{list-style:none;padding:0}
.top-list li{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #1f2430;font-size:13px}
.top-list li:last-child{border-bottom:none}
.top-rank{font-weight:700;color:#6366f1;width:24px;text-align:center;font-variant-numeric:tabular-nums}
.top-name{flex:1;color:#fff;font-weight:500}
.top-grade{color:#9ca3af;font-size:12px;margin-right:6px}
.top-cnt{color:#10b981;font-weight:700;font-variant-numeric:tabular-nums}
.ext-badge{display:inline-block;background:#1f2937;color:#6b7280;font-size:10px;padding:1px 6px;border-radius:8px;margin-left:4px;font-weight:500;font-variant-numeric:tabular-nums}
.tutor-tabs{display:flex;gap:4px;margin-bottom:10px}
.tutor-tabs button{flex:1;background:#0b0e14;border:1px solid #2a2f3a;color:#9ca3af;padding:6px 8px;border-radius:6px;font-size:12px;cursor:pointer}
.tutor-tabs button.active{background:#6366f1;color:#fff;border-color:#6366f1}
.student-table{width:100%;font-size:12px;border-collapse:collapse}
.student-table th{text-align:left;color:#6b7280;font-weight:500;padding:6px 4px;border-bottom:1px solid #1f2430;position:sticky;top:0;background:#151922;z-index:1}
.student-table td{padding:6px 4px;border-bottom:1px solid #1f2430;color:#e5e7eb}
.student-table tr:last-child td{border-bottom:none}
.student-table .cnt{color:#10b981;font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.student-scroll{max-height:260px;overflow-y:auto;border:1px solid #1f2430;border-radius:6px}
.student-scroll::-webkit-scrollbar{width:8px}
.student-scroll::-webkit-scrollbar-track{background:#0b0e14}
.student-scroll::-webkit-scrollbar-thumb{background:#2a2f3a;border-radius:4px}
.student-count{font-size:11px;color:#9ca3af;margin-top:6px;text-align:right}
.qt-bar-row{display:grid;grid-template-columns:50px 110px 1fr 60px 24px;gap:10px;align-items:center;padding:8px 6px;border-radius:6px;cursor:pointer;transition:background .15s}
.qt-bar-row:hover{background:rgba(255,255,255,.03)}
.qt-bar-row.open{background:rgba(99,102,241,.08)}
.qt-type{font-weight:700;color:#fff;font-size:13px;font-variant-numeric:tabular-nums}
.qt-label{color:#9ca3af;font-size:12px}
.qt-bar-track{height:8px;background:#0b0e14;border-radius:4px;overflow:hidden}
.qt-bar-fill{height:100%;border-radius:4px;transition:width .3s}
.qt-cnt{color:#fff;font-weight:600;font-variant-numeric:tabular-nums;text-align:right;font-size:13px}
.qt-chev{color:#6b7280;font-size:11px;text-align:center;transition:transform .2s}
.qt-bar-row.open .qt-chev{transform:rotate(90deg);color:#a5b4fc}
.qt-students{margin:4px 0 10px 60px;padding:10px;background:#0b0e14;border-radius:6px;border-left:2px solid #6366f1;display:none}
.qt-students.open{display:block}
.empty{color:#6b7280;text-align:center;padding:30px;font-size:13px}
.loading{color:#6b7280;text-align:center;padding:20px;font-size:13px}
@media (max-width:900px){
  .kpi-grid{grid-template-columns:repeat(2,1fr)}
  .segments-grid{grid-template-columns:1fr}
  .feat-grid{grid-template-columns:1fr}
  .top-grid-3{grid-template-columns:1fr}
  .tutor-split-grid{grid-template-columns:1fr}
  .ai-kpi-grid{grid-template-columns:repeat(2,1fr)}
  .ai-chart-grid{grid-template-columns:1fr}
  .ai-chart-grid-3{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>📊 질문방 대시보드</h1>
  <div class="range">
    <button data-preset="1">오늘</button>
    <button data-preset="7" class="active">최근 7일</button>
    <button data-preset="30">최근 30일</button>
    <input type="date" id="fromDate">
    <span id="fromDow" class="dow-label"></span>
    <span style="color:#6b7280;font-size:12px">→</span>
    <input type="date" id="toDate">
    <span id="toDow" class="dow-label"></span>
    <select id="subjectFilter" class="ft-select">
      <option value="all">전체 과목</option>
      <option value="국어">국어</option><option value="영어">영어</option>
      <option value="수학">수학</option><option value="과학">과학</option><option value="기타">기타</option>
    </select>
    <select id="gradeFilter" class="ft-select">
      <option value="all">전체 학년</option>
      <option value="초등">초등</option>
      <option value="중1">중1</option><option value="중2">중2</option><option value="중3">중3</option>
      <option value="고1">고1</option><option value="고2">고2</option><option value="고3">고3</option>
      <option value="N수">N수</option><option value="미분류">미분류</option>
    </select>
    <button id="applyBtn" style="background:#1f2937;border-color:#374151">적용</button>
  </div>
  <button class="logout-btn" id="logoutBtn">로그아웃</button>
</header>

<div class="active-filters" id="activeFilters"></div>

<section>
  <h2>한눈에 현황</h2>
  <div class="kpi-grid" id="kpiGrid"><div class="loading">로딩 중...</div></div>
</section>

<section>
  <h2>사용량 트렌드</h2>
  <div class="card trend-card">
    <div class="trend-toolbar">
      <button data-unit="day" class="active">일</button>
      <button data-unit="week">주</button>
      <button data-unit="month">월</button>
    </div>
    <div class="chart-box"><canvas id="trendChart"></canvas></div>
  </div>
</section>

<section>
  <h2>과목·학년 분포</h2>
  <div class="segments-grid">
    <div class="card">
      <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">과목 × 학년 (질문 수)</h3>
      <div id="heatmapGrade"></div>
    </div>
    <div class="card">
      <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">과목 × 난이도 (질문 수)</h3>
      <div id="heatmapDiff"></div>
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">과목별 질문·답변·채택</h3>
    <div class="chart-box" style="height:280px"><canvas id="subjectChart"></canvas></div>
  </div>
</section>

<section class="part-section">
  <h2 class="part-title">📝 질문방</h2>
  <div class="card">
    <div id="featQuestionRoom"><div class="loading">로딩 중...</div></div>
  </div>
  <div class="card" style="margin-top:16px">
    <h3 class="part-sub">질문 유형 분포 <span style="font-size:11px;color:#6b7280;font-weight:400">· 유형 클릭 시 학생 명단 펼치기</span></h3>
    <div id="qtChart"><div class="loading">로딩 중...</div></div>
  </div>
  <div class="top-grid-3" style="margin-top:16px">
    <div class="card">
      <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">📝 최다 질문자</h3>
      <ol class="top-list" id="topQuestioners"><li class="loading">로딩 중...</li></ol>
    </div>
    <div class="card">
      <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">💬 최다 답변자</h3>
      <ol class="top-list" id="topAnswerers"><li class="loading">로딩 중...</li></ol>
    </div>
    <div class="card">
      <h3 style="font-size:14px;font-weight:600;color:#fff;margin-bottom:12px">🏅 최다 채택자</h3>
      <ol class="top-list" id="topAccepted"><li class="loading">로딩 중...</li></ol>
    </div>
  </div>
</section>

<section class="part-section">
  <h2 class="part-title">🎯 1:1 튜터</h2>
  <div class="tutor-split-grid">
    <div class="card">
      <h3 class="part-sub">튜티 신청 (질문자)</h3>
      <div id="featTutee"><div class="loading">로딩 중...</div></div>
      <div class="feat-chart-box"><canvas id="tuteeStatusChart"></canvas></div>
      <div style="margin-top:12px">
        <div style="font-size:12px;color:#9ca3af;font-weight:600;margin-bottom:6px">신청 학생 명단</div>
        <div id="tuteeUsersList"><div class="loading">로딩 중...</div></div>
      </div>
    </div>
    <div class="card">
      <h3 class="part-sub">튜터 신청 (답변자)</h3>
      <div id="featTutor"><div class="loading">로딩 중...</div></div>
      <div class="feat-chart-box"><canvas id="tutorStatusChart"></canvas></div>
      <div style="margin-top:12px">
        <div style="font-size:12px;color:#9ca3af;font-weight:600;margin-bottom:6px">신청 학생 명단</div>
        <div id="tutorUsersList"><div class="loading">로딩 중...</div></div>
      </div>
    </div>
  </div>
</section>

<section class="part-section">
  <h2 class="part-title">🤖 AI 튜터 (정율 선생님)</h2>

  <div class="card">
    <h3 class="part-sub">💬 대화 사용 현황</h3>
    <div class="ai-kpi-grid" id="aiKpiGrid"><div class="loading">로딩 중...</div></div>
    <div class="ai-chart-grid-3" style="margin-top:18px">
      <div>
        <h3 class="part-sub">과목별 사용 세션</h3>
        <div class="ai-chart-box"><canvas id="aiSubjectChart"></canvas></div>
      </div>
      <div>
        <h3 class="part-sub">학년별 사용 세션 <span style="font-size:11px;color:#6b7280;font-weight:400">· 학년 미설정자 제외</span></h3>
        <div class="ai-chart-box"><canvas id="aiGradeChart"></canvas></div>
      </div>
      <div>
        <h3 class="part-sub">모드 비중 <span style="font-size:11px;color:#6b7280;font-weight:400">· 빠른해결 / 실력업</span></h3>
        <div class="ai-chart-box" style="height:260px;display:flex;align-items:center;justify-content:center"><canvas id="aiModeChart"></canvas></div>
      </div>
    </div>
    <div style="margin-top:18px">
      <h3 class="part-sub">과목 × 학년 분포</h3>
      <div id="aiHeatmap"></div>
    </div>
  </div>

  <div class="card" style="margin-top:16px">
    <h3 class="part-sub">📐 수학 문제 풀이</h3>
    <div class="ai-kpi-grid" id="mathKpiGrid"><div class="loading">로딩 중...</div></div>
    <div class="ai-chart-grid" style="margin-top:18px">
      <div>
        <h3 class="part-sub">학년별 풀이량</h3>
        <div class="ai-chart-box"><canvas id="mathGradeChart"></canvas></div>
      </div>
      <div>
        <h3 class="part-sub">최다 풀이 학생 Top 10</h3>
        <div id="mathTopStudents"><div class="loading">로딩 중...</div></div>
      </div>
    </div>
  </div>
</section>

</div>
<script>
(function(){
  var state = { from: null, to: null, unit: 'day', subject: 'all', grade: 'all' };
  var charts = {};
  var featureData = null;

  function fmtInt(n){ return (n==null?'-':Number(n).toLocaleString('ko-KR')); }
  function kstDate(offsetDays){ var d = new Date(Date.now() + 9*3600000 + (offsetDays||0)*86400000); return d.toISOString().slice(0,10); }
  var DOW = ['일','월','화','수','목','금','토'];
  function dowOf(ymd){ if (!ymd) return ''; var d = new Date(ymd + 'T00:00:00Z'); return DOW[d.getUTCDay()]; }
  function updateDowLabels(){
    var fd = document.getElementById('fromDow');
    var td = document.getElementById('toDow');
    var fDow = dowOf(state.from), tDow = dowOf(state.to);
    if (fd) fd.textContent = fDow ? '(' + fDow + ')' : '';
    if (td) td.textContent = tDow ? '(' + tDow + ')' : '';
  }
  function extBadge(ext){ if (!ext) return ''; return '<span class="ext-badge">ext_' + ext + '</span>'; }
  // 실명이 있으면 "이름(닉네임)", 없으면 닉네임만
  function displayName(u){
    var nick = u.nickname || '익명';
    if (u.real_name) return u.real_name + '<span style="color:#9ca3af;font-weight:400">(' + nick + ')</span>';
    return nick;
  }

  function syncUrl(){
    var q = new URLSearchParams();
    q.set('from', state.from); q.set('to', state.to); q.set('unit', state.unit);
    if (state.subject !== 'all') q.set('subject', state.subject);
    if (state.grade !== 'all') q.set('grade', state.grade);
    history.replaceState(null, '', location.pathname + '?' + q.toString());
  }
  function initState(){
    var q = new URLSearchParams(location.search);
    state.from = q.get('from') || kstDate(-6);
    state.to = q.get('to') || kstDate(0);
    state.unit = q.get('unit') || 'day';
    state.subject = q.get('subject') || 'all';
    state.grade = q.get('grade') || 'all';
    document.getElementById('fromDate').value = state.from;
    document.getElementById('toDate').value = state.to;
    document.getElementById('subjectFilter').value = state.subject;
    document.getElementById('gradeFilter').value = state.grade;
    document.querySelectorAll('.trend-toolbar button').forEach(function(b){
      b.classList.toggle('active', b.getAttribute('data-unit') === state.unit);
    });
    renderFilterChips();
    updateDowLabels();
  }
  function renderFilterChips(){
    var el = document.getElementById('activeFilters');
    var chips = [];
    if (state.subject !== 'all') chips.push('<span class="filter-chip">과목: ' + state.subject + ' <span style="cursor:pointer" data-clear="subject">✕</span></span>');
    if (state.grade !== 'all') chips.push('<span class="filter-chip">학년: ' + state.grade + ' <span style="cursor:pointer" data-clear="grade">✕</span></span>');
    el.innerHTML = chips.join('');
    el.querySelectorAll('[data-clear]').forEach(function(b){
      b.addEventListener('click', function(){
        var k = b.getAttribute('data-clear');
        state[k] = 'all';
        document.getElementById(k+'Filter').value = 'all';
        syncUrl(); renderFilterChips(); loadAll();
      });
    });
  }
  function applyPreset(days){
    state.from = kstDate(-(days-1));
    state.to = kstDate(0);
    document.getElementById('fromDate').value = state.from;
    document.getElementById('toDate').value = state.to;
    document.querySelectorAll('.range button[data-preset]').forEach(function(b){
      b.classList.toggle('active', b.getAttribute('data-preset') === String(days));
    });
    syncUrl(); updateDowLabels(); loadAll();
  }
  async function api(path){
    var params = new URLSearchParams();
    params.set('from', state.from);
    params.set('to', state.to);
    if (state.subject !== 'all') params.set('subject', state.subject);
    if (state.grade !== 'all') params.set('grade', state.grade);
    if (path.indexOf('/api/admin/trend') === 0) params.set('unit', state.unit);
    var sep = path.indexOf('?') >= 0 ? '&' : '?';
    var res = await fetch(path + sep + params.toString(), { credentials: 'same-origin' });
    if (res.status === 401) { location.href = '/admin/login'; return null; }
    if (!res.ok) throw new Error('API ' + path + ' failed: ' + res.status);
    return res.json();
  }

  function pctDelta(cur, prev){
    if (prev === 0 || prev == null) return cur > 0 ? '+∞' : '0';
    var d = ((cur - prev) / prev) * 100;
    var sign = d >= 0 ? '+' : '';
    return sign + d.toFixed(1) + '%';
  }
  function deltaClass(cur, prev){ if (prev == null || cur === prev) return ''; return cur > prev ? 'up' : 'down'; }

  async function loadOverview(){
    var d = await api('/api/admin/overview');
    if (!d) return;
    var cards = [
      { label: '활성 학생', cur: d.active_users.current, prev: d.active_users.previous },
      { label: '질문 등록', cur: d.questions.current, prev: d.questions.previous },
      { label: '답변 작성', cur: d.answers.current, prev: d.answers.previous },
      { label: '1:1 튜터 신청', cur: d.tutoring_matches.current, prev: d.tutoring_matches.previous },
    ];
    document.getElementById('kpiGrid').innerHTML = cards.map(function(c){
      return '<div class="kpi">' +
        '<div class="kpi-label">' + c.label + '</div>' +
        '<div class="kpi-value">' + fmtInt(c.cur) + '</div>' +
        '<div class="kpi-delta ' + deltaClass(c.cur, c.prev) + '">이전 기간 ' + fmtInt(c.prev) + ' · ' + pctDelta(c.cur, c.prev) + '</div>' +
      '</div>';
    }).join('');
  }

  async function loadTrend(){
    var d = await api('/api/admin/trend');
    if (!d) return;
    var buckets = {};
    ['questions','answers','tutoring_matches','active_users','coaching_requests'].forEach(function(k){
      if (d[k]) Object.keys(d[k]).forEach(function(b){ buckets[b] = true });
    });
    var rawLabels = Object.keys(buckets).sort();
    var labels = state.unit === 'day'
      ? rawLabels.map(function(ymd){ return ymd + ' (' + dowOf(ymd) + ')' })
      : rawLabels.slice();
    var qData = rawLabels.map(function(l){ return d.questions[l] || 0; });
    var aData = rawLabels.map(function(l){ return d.answers[l] || 0; });
    var cData = rawLabels.map(function(l){ return (d.coaching_requests && d.coaching_requests[l]) || 0; });
    if (charts.trend) charts.trend.destroy();
    charts.trend = new Chart(document.getElementById('trendChart').getContext('2d'), {
      data: {
        labels: labels,
        datasets: [
          { type:'line', label:'질문 등록', data: qData, borderColor:'#6366f1', backgroundColor:'rgba(99,102,241,.1)', tension:0.3, fill:true, order:1 },
          { type:'line', label:'답변 작성', data: aData, borderColor:'#10b981', backgroundColor:'rgba(16,185,129,.08)', tension:0.3, fill:false, order:2 },
          { type:'line', label:'1:1 튜터 신청', data: cData, borderColor:'#f59e0b', backgroundColor:'rgba(245,158,11,.08)', tension:0.3, fill:false, order:3 },
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ labels:{ color:'#9ca3af' } } },
        scales: {
          x: { ticks:{ color:'#9ca3af' }, grid:{ color:'#1f2430' } },
          y: { beginAtZero:true, ticks:{ color:'#9ca3af', precision:0 }, grid:{ color:'#1f2430' }, title:{ display:true, text:'건수', color:'#9ca3af' } }
        }
      }
    });
  }

  function renderHeatmap(targetId, rows, keyX, keyY, orderX, orderY){
    var target = document.getElementById(targetId);
    var xSet = {}, ySet = {};
    rows.forEach(function(r){ xSet[r[keyX]] = true; ySet[r[keyY]] = true });
    var xs = orderX.filter(function(x){ return xSet[x] }).concat(Object.keys(xSet).filter(function(x){ return orderX.indexOf(x) < 0 }));
    var ys = orderY.filter(function(y){ return ySet[y] }).concat(Object.keys(ySet).filter(function(y){ return orderY.indexOf(y) < 0 }));
    if (xs.length === 0 || ys.length === 0) { target.innerHTML = '<div class="empty">데이터 없음</div>'; return; }
    var map = {};
    rows.forEach(function(r){ var k = r[keyX] + '||' + r[keyY]; map[k] = (map[k] || 0) + r.cnt; });
    var max = 0;
    Object.keys(map).forEach(function(k){ if (map[k] > max) max = map[k]; });
    var rowSums = ys.map(function(y){ return xs.reduce(function(s, x){ return s + (map[x+'||'+y] || 0) }, 0); });
    var colSums = xs.map(function(x){ return ys.reduce(function(s, y){ return s + (map[x+'||'+y] || 0) }, 0); });
    var grandTotal = colSums.reduce(function(s, v){ return s + v }, 0);

    var html = '<div class="heatmap" style="grid-template-columns:80px repeat(' + xs.length + ',1fr) 70px">';
    html += '<div class="hm-cell hm-label"></div>';
    xs.forEach(function(x){ html += '<div class="hm-cell hm-label">' + x + '</div>'; });
    html += '<div class="hm-cell hm-label" style="color:#a5b4fc">합계</div>';
    ys.forEach(function(y, yi){
      html += '<div class="hm-cell hm-label" style="text-align:right;padding-right:10px">' + y + '</div>';
      xs.forEach(function(x){
        var v = map[x + '||' + y] || 0;
        var alpha = max > 0 ? (v / max) : 0;
        var bg = v > 0 ? 'rgba(99,102,241,' + (0.15 + alpha * 0.75) + ')' : '#0b0e14';
        html += '<div class="hm-cell hm-val" style="background:' + bg + '" title="' + y + ' · ' + x + ': ' + v + '건">' + (v || '') + '</div>';
      });
      html += '<div class="hm-cell hm-val" style="color:#a5b4fc;font-weight:700;background:rgba(99,102,241,.08)">' + rowSums[yi] + '</div>';
    });
    html += '<div class="hm-cell hm-label" style="color:#a5b4fc">합계</div>';
    xs.forEach(function(x, xi){
      html += '<div class="hm-cell hm-val" style="color:#a5b4fc;font-weight:700;background:rgba(99,102,241,.08)">' + colSums[xi] + '</div>';
    });
    html += '<div class="hm-cell hm-val" style="color:#fff;font-weight:800;background:#6366f1">' + grandTotal + '</div>';
    html += '</div>';
    html += '<div class="hm-legend"><span>0</span><div class="hm-legend-bar"></div><span>' + max + '</span></div>';
    target.innerHTML = html;
  }

  async function loadSegments(){
    var d = await api('/api/admin/segments');
    if (!d) return;
    var subjectOrder = ['국어','영어','수학','과학','기타'];
    var gradeOrder = ['초등','중1','중2','중3','고1','고2','고3','N수','미분류'];
    var diffOrder = ['최상','상','중','하','1:1심화설명'];
    renderHeatmap('heatmapGrade', d.subject_grade, 'subject', 'grade', subjectOrder, gradeOrder);
    renderHeatmap('heatmapDiff', d.subject_difficulty, 'subject', 'difficulty', subjectOrder, diffOrder);

    var subjects = subjectOrder.slice();
    var qMap = {}, aMap = {}, accMap = {};
    d.subject_questions.forEach(function(r){ qMap[r.subject] = r.cnt });
    d.subject_answers.forEach(function(r){ aMap[r.subject] = r.answers; accMap[r.subject] = r.accepted });
    var allSubj = {};
    subjects.forEach(function(s){ allSubj[s] = true });
    Object.keys(qMap).concat(Object.keys(aMap)).forEach(function(s){ allSubj[s] = true });
    subjects = Object.keys(allSubj);
    var qData = subjects.map(function(s){ return qMap[s] || 0 });
    var aData = subjects.map(function(s){ return (aMap[s] || 0) - (accMap[s] || 0) });
    var accData = subjects.map(function(s){ return accMap[s] || 0 });

    if (charts.subject) charts.subject.destroy();
    charts.subject = new Chart(document.getElementById('subjectChart').getContext('2d'), {
      type: 'bar',
      data: {
        labels: subjects,
        datasets: [
          { label: '질문', data: qData, backgroundColor: '#6366f1' },
          { label: '답변 (채택 전)', data: aData, backgroundColor: '#10b981' },
          { label: '채택된 답변', data: accData, backgroundColor: '#f59e0b' },
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#9ca3af' } } },
        scales: { x: { ticks: { color: '#9ca3af' }, grid: { color: '#1f2430' } }, y: { beginAtZero: true, ticks: { color: '#9ca3af', precision: 0 }, grid: { color: '#1f2430' } } }
      }
    });
  }

  async function loadFeatures(){
    var d = await api('/api/admin/feature-usage');
    if (!d) return;
    featureData = d;
    var qr = d.question_room;
    document.getElementById('featQuestionRoom').innerHTML =
      '<div class="feat-stat"><span class="feat-stat-label">총 질문</span><span class="feat-stat-val">' + fmtInt(qr.questions) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">총 답변</span><span class="feat-stat-val">' + fmtInt(qr.answers) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">채택된 답변</span><span class="feat-stat-val">' + fmtInt(qr.accepted) + '</span></div>';
    renderTutee();
    renderTutor();
    loadTutoringUsers();
  }

  function renderDoughnut(chartKey, canvasId, labels, data, colors){
    if (charts[chartKey]) charts[chartKey].destroy();
    if (!data.some(function(v){ return v > 0 })) return;
    charts[chartKey] = new Chart(document.getElementById(canvasId).getContext('2d'), {
      type: 'doughnut',
      data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 11 } } } } }
    });
  }

  function renderTutee(){
    if (!featureData) return;
    var c = (featureData.tutoring && featureData.tutoring.coaching) || { by_stage: { pending:0, matched:0, completed:0, cancelled:0 }, total: 0 };
    document.getElementById('featTutee').innerHTML =
      '<div class="feat-stat"><span class="feat-stat-label">튜티 신청 총계</span><span class="feat-stat-val">' + fmtInt(c.total) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">신청(대기)</span><span class="feat-stat-val">' + fmtInt(c.by_stage.pending) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">매칭됨</span><span class="feat-stat-val">' + fmtInt(c.by_stage.matched) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">완료</span><span class="feat-stat-val">' + fmtInt(c.by_stage.completed) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">취소</span><span class="feat-stat-val">' + fmtInt(c.by_stage.cancelled) + '</span></div>';
    renderDoughnut(
      'tuteeStatus', 'tuteeStatusChart',
      ['신청','매칭됨','완료','취소'],
      [c.by_stage.pending||0, c.by_stage.matched||0, c.by_stage.completed||0, c.by_stage.cancelled||0],
      ['#f59e0b','#6366f1','#10b981','#6b7280']
    );
  }

  function renderTutor(){
    if (!featureData) return;
    var t = featureData.tutoring || {};
    var by = t.by_status || {};
    document.getElementById('featTutor').innerHTML =
      '<div class="feat-stat"><span class="feat-stat-label">튜터 매칭 총계</span><span class="feat-stat-val">' + fmtInt(t.total || 0) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">대기(pending)</span><span class="feat-stat-val">' + fmtInt(by.pending || 0) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">확정(confirmed)</span><span class="feat-stat-val">' + fmtInt(by.confirmed || 0) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">수락(accepted)</span><span class="feat-stat-val">' + fmtInt(by.accepted || 0) + '</span></div>' +
      '<div class="feat-stat"><span class="feat-stat-label">취소(cancelled)</span><span class="feat-stat-val">' + fmtInt(by.cancelled || 0) + '</span></div>';
    renderDoughnut(
      'tutorStatus', 'tutorStatusChart',
      ['대기','확정','수락','취소'],
      [by.pending||0, by.confirmed||0, by.accepted||0, by.cancelled||0],
      ['#f59e0b','#6366f1','#10b981','#6b7280']
    );
  }

  async function loadTutoringUsers(){
    var results = await Promise.all([
      api('/api/admin/tutoring-users?role=tutee&limit=30'),
      api('/api/admin/tutoring-users?role=tutor&limit=30'),
    ]);
    var tuteeData = results[0], tutorData = results[1];
    function render(listId, data, emptyMsg){
      var el = document.getElementById(listId);
      if (!data || !data.users || data.users.length === 0) {
        el.innerHTML = '<div class="empty" style="padding:14px">' + emptyMsg + '</div>'; return;
      }
      var rows = data.users.map(function(u){
        var grade = u.grade || '-';
        return '<tr><td>' + displayName(u) + '</td><td style="color:#9ca3af">' + grade + '</td><td class="cnt">' + fmtInt(u.cnt) + '</td></tr>';
      }).join('');
      el.innerHTML =
        '<div class="student-scroll"><table class="student-table"><thead><tr><th>닉네임</th><th>학년</th><th style="text-align:right">건수</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
        '<div class="student-count">' + data.users.length + '명 표시' + (data.users.length >= 30 ? ' (상위 30명)' : '') + '</div>';
    }
    render('tuteeUsersList', tuteeData, '신청한 튜티가 없습니다');
    render('tutorUsersList', tutorData, '신청한 튜터가 없습니다');
  }

  function drawHBar(chartKey, canvasId, rows, labelKey, valueKey, color){
    if (charts[chartKey]) charts[chartKey].destroy();
    var ctx = document.getElementById(canvasId).getContext('2d');
    if (!rows.length) { ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height); return; }
    charts[chartKey] = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: rows.map(function(r){ return r[labelKey] }),
        datasets: [{ data: rows.map(function(r){ return r[valueKey] }), backgroundColor: color, borderRadius: 4 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: '#9ca3af', precision: 0 }, grid: { color: '#1f2430' } },
          y: { ticks: { color: '#e5e7eb', font: { size: 12 } }, grid: { display: false } }
        }
      }
    });
  }

  async function loadAITutor(){
    var d = await api('/api/admin/ai-tutor');
    var kpiEl = document.getElementById('aiKpiGrid');
    if (!d) return;
    if (d.connected === false || d.error) {
      kpiEl.innerHTML = '<div class="empty" style="padding:14px;grid-column:1/-1">연동 오류: ' + (d.error || '알 수 없음') + '</div>';
      return;
    }
    var total = d.total_sessions || 0;
    var avg = d.avg_turns != null ? d.avg_turns : '-';
    // by_mode: flat 배열 [{mode,sessions}] / 객체 {quick,normal} 둘 다 대응
    var mode = { quick: 0, normal: 0 };
    if (Array.isArray(d.by_mode)) {
      d.by_mode.forEach(function(r){ if (r && r.mode) mode[r.mode] = r.sessions || 0; });
    } else if (d.by_mode && typeof d.by_mode === 'object') {
      mode.quick = d.by_mode.quick || 0; mode.normal = d.by_mode.normal || 0;
    }
    var modeTotal = mode.quick + mode.normal;
    var quickPct = modeTotal > 0 ? Math.round(mode.quick / modeTotal * 100) : 0;
    var bySubj = (d.by_subject || []).slice().sort(function(a,b){ return b.sessions - a.sessions });
    var byGrade = (d.by_grade || []).slice().sort(function(a,b){ return b.sessions - a.sessions });
    var topSubj = bySubj[0];

    kpiEl.innerHTML =
      '<div class="ai-kpi"><div class="ai-kpi-label">총 세션</div><div class="ai-kpi-value">' + fmtInt(total) + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">평균 사용 턴수</div><div class="ai-kpi-value">' + avg + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">빠른해결 비중</div><div class="ai-kpi-value">' + quickPct + '%</div><div class="ai-kpi-sub">빠른 ' + fmtInt(mode.quick) + ' / 실력업 ' + fmtInt(mode.normal) + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">가장 많이 쓴 과목</div><div class="ai-kpi-value">' + (topSubj ? topSubj.subject : '-') + '</div><div class="ai-kpi-sub">' + (topSubj ? fmtInt(topSubj.sessions) + '건' : '') + '</div></div>';

    drawHBar('aiSubject', 'aiSubjectChart', bySubj, 'subject', 'sessions', '#f59e0b');
    drawHBar('aiGrade', 'aiGradeChart', byGrade, 'grade', 'sessions', '#f59e0b');

    // 모드 비중 도넛
    if (charts.aiMode) charts.aiMode.destroy();
    var modeCtx = document.getElementById('aiModeChart').getContext('2d');
    if (modeTotal > 0) {
      charts.aiMode = new Chart(modeCtx, {
        type: 'doughnut',
        data: {
          labels: ['빠른해결', '실력업'],
          datasets: [{ data: [mode.quick, mode.normal], backgroundColor: ['#f59e0b', '#6366f1'], borderWidth: 0 }]
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: '62%',
          plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af', font: { size: 12 } } } }
        }
      });
    } else {
      modeCtx.clearRect(0, 0, modeCtx.canvas.width, modeCtx.canvas.height);
    }

    // 과목 × 학년 히트맵 — 기존 renderHeatmap은 r.cnt를 읽으므로 sessions → cnt 매핑
    var heatmapRows = (d.by_subject_grade || []).map(function(r){ return { subject: r.subject, grade: r.grade, cnt: r.sessions }; });
    var subjectOrder = ['국어','영어','수학','과학','기타'];
    var gradeOrder = ['초등','중1','중2','중3','고1','고2','고3','N수','미분류'];
    renderHeatmap('aiHeatmap', heatmapRows, 'subject', 'grade', subjectOrder, gradeOrder);
  }

  async function loadMathPractice(){
    var d = await api('/api/admin/math-practice');
    var kpiEl = document.getElementById('mathKpiGrid');
    var topEl = document.getElementById('mathTopStudents');
    if (!d) return;
    if (d.connected === false || d.error) {
      kpiEl.innerHTML = '<div class="empty" style="padding:14px;grid-column:1/-1">연동 오류: ' + (d.error || '알 수 없음') + '</div>';
      topEl.innerHTML = '';
      return;
    }
    var students = d.total_students || 0;
    var solved = d.total_solved || 0;
    var accPct = d.accuracy != null ? (d.accuracy * 100).toFixed(1) + '%' : '-';
    var avgPer = students > 0 ? (solved / students).toFixed(1) : '-';

    kpiEl.innerHTML =
      '<div class="ai-kpi"><div class="ai-kpi-label">풀이 학생 수</div><div class="ai-kpi-value">' + fmtInt(students) + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">총 풀이 수</div><div class="ai-kpi-value">' + fmtInt(solved) + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">정답률</div><div class="ai-kpi-value">' + accPct + '</div></div>' +
      '<div class="ai-kpi"><div class="ai-kpi-label">학생당 평균</div><div class="ai-kpi-value">' + avgPer + '</div><div class="ai-kpi-sub">풀이 수/학생</div></div>';

    var byGrade = (d.by_grade || []).slice().sort(function(a,b){ return b.solved - a.solved });
    drawHBar('mathGrade', 'mathGradeChart', byGrade, 'grade', 'solved', '#10b981');

    var top = d.top_students || [];
    if (top.length === 0) {
      topEl.innerHTML = '<div class="empty" style="padding:14px">풀이 기록이 없습니다</div>';
      return;
    }
    var rows = top.map(function(u, i){
      return '<tr>' +
        '<td style="color:#6366f1;font-weight:700;width:24px;text-align:center">' + (i+1) + '</td>' +
        '<td>' + displayName(u) + '</td>' +
        '<td class="cnt">' + fmtInt(u.solved) + '</td>' +
      '</tr>';
    }).join('');
    topEl.innerHTML = '<table class="student-table"><thead><tr><th>#</th><th>학생</th><th style="text-align:right">풀이 수</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  var qtMeta = {
    'A-1': { label: '뭐지?', color: '#60a5fa' },
    'A-2': { label: '어떻게?', color: '#3b82f6' },
    'B-1': { label: '왜?', color: '#a78bfa' },
    'B-2': { label: '만약에?', color: '#8b5cf6' },
    'C-1': { label: '뭐가 더 나아?', color: '#f472b6' },
    'C-2': { label: '그러면?', color: '#ec4899' },
    'R-1': { label: '어디서 틀렸지?', color: '#fb923c' },
    'R-2': { label: '왜 틀렸지?', color: '#f97316' },
    'R-3': { label: '다음엔 어떻게?', color: '#ea580c' }
  };
  var qtOrder = ['A-1','A-2','B-1','B-2','C-1','C-2','R-1','R-2','R-3'];

  async function loadQuestionTypes(){
    var d = await api('/api/admin/question-types');
    if (!d) return;
    var el = document.getElementById('qtChart');
    var counts = d.type_counts || {};
    var users = d.users_by_type || {};
    var max = 0;
    qtOrder.forEach(function(t){ if ((counts[t]||0) > max) max = counts[t]; });
    if (max === 0) { el.innerHTML = '<div class="empty">분류된 질문이 아직 없습니다</div>'; return; }

    var html = '';
    qtOrder.forEach(function(t){
      var cnt = counts[t] || 0;
      var meta = qtMeta[t];
      var pct = max > 0 ? (cnt / max * 100) : 0;
      html += '<div class="qt-bar-row" data-qt="' + t + '">' +
        '<div class="qt-type" style="color:' + meta.color + '">' + t + '</div>' +
        '<div class="qt-label">' + meta.label + '</div>' +
        '<div class="qt-bar-track"><div class="qt-bar-fill" style="width:' + pct + '%;background:' + meta.color + '"></div></div>' +
        '<div class="qt-cnt">' + fmtInt(cnt) + '</div>' +
        '<div class="qt-chev">▶</div>' +
        '</div>';
      var ulist = users[t] || [];
      var listHtml;
      if (ulist.length === 0) {
        listHtml = '<div style="color:#6b7280;font-size:12px;padding:4px">이 유형에 학생 명단 없음</div>';
      } else {
        var rows = ulist.map(function(u){
          var grade = u.grade || '-';
          return '<tr><td>' + displayName(u) + '</td><td style="color:#9ca3af">' + grade + '</td><td class="cnt">' + fmtInt(u.cnt) + '</td><td style="color:#6b7280;text-align:right;font-size:11px">#' + (u.last_question_id || '-') + '</td></tr>';
        }).join('');
        listHtml =
          '<div class="student-scroll"><table class="student-table"><thead><tr><th>닉네임</th><th>학년</th><th style="text-align:right">건수</th><th style="text-align:right">최근 질문</th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
          '<div class="student-count">' + ulist.length + '명 표시' + (ulist.length >= 20 ? ' (상위 20명)' : '') + '</div>';
      }
      html += '<div class="qt-students" data-qt-list="' + t + '">' + listHtml + '</div>';
    });
    el.innerHTML = html;

    el.querySelectorAll('.qt-bar-row').forEach(function(row){
      row.addEventListener('click', function(){
        var t = row.getAttribute('data-qt');
        var list = el.querySelector('[data-qt-list="' + t + '"]');
        var isOpen = row.classList.contains('open');
        if (isOpen) { row.classList.remove('open'); list.classList.remove('open'); }
        else { row.classList.add('open'); list.classList.add('open'); }
      });
    });
  }

  async function loadTopUsers(){
    var results = await Promise.all([
      api('/api/admin/top-users?type=question&limit=10'),
      api('/api/admin/top-users?type=answer&limit=10'),
      api('/api/admin/top-users?type=accepted&limit=10'),
    ]);
    var tq = results[0], ta = results[1], tc = results[2];
    function render(target, data, emptyMsg){
      var el = document.getElementById(target);
      if (!data || !data.users || data.users.length === 0) {
        el.innerHTML = '<li class="empty">' + emptyMsg + '</li>'; return;
      }
      el.innerHTML = data.users.map(function(u, i){
        var grade = u.grade ? '<span class="top-grade">' + u.grade + '</span>' : '';
        return '<li>' +
          '<span class="top-rank">' + (i+1) + '</span>' +
          '<span class="top-name">' + displayName(u) + '</span>' +
          grade +
          '<span class="top-cnt">' + fmtInt(u.cnt) + '</span>' +
        '</li>';
      }).join('');
    }
    if (tq) render('topQuestioners', tq, '아직 질문이 없습니다');
    if (ta) render('topAnswerers', ta, '아직 답변이 없습니다');
    if (tc) render('topAccepted', tc, '아직 채택이 없습니다');
  }

  async function loadAll(){
    try {
      await Promise.all([
        loadOverview(), loadTrend(), loadSegments(),
        loadFeatures(), loadAITutor(), loadMathPractice(), loadQuestionTypes(), loadTopUsers(),
      ]);
    } catch (e) { console.error('dashboard load error', e); }
  }

  document.querySelectorAll('.range button[data-preset]').forEach(function(b){
    b.addEventListener('click', function(){ applyPreset(Number(b.getAttribute('data-preset'))) });
  });
  document.getElementById('applyBtn').addEventListener('click', function(){
    state.from = document.getElementById('fromDate').value;
    state.to = document.getElementById('toDate').value;
    state.subject = document.getElementById('subjectFilter').value;
    state.grade = document.getElementById('gradeFilter').value;
    document.querySelectorAll('.range button[data-preset]').forEach(function(b){ b.classList.remove('active') });
    syncUrl(); renderFilterChips(); updateDowLabels(); loadAll();
  });
  document.getElementById('subjectFilter').addEventListener('change', function(){
    state.subject = this.value;
    syncUrl(); renderFilterChips(); loadAll();
  });
  document.getElementById('gradeFilter').addEventListener('change', function(){
    state.grade = this.value;
    syncUrl(); renderFilterChips(); loadAll();
  });
  document.querySelectorAll('.trend-toolbar button').forEach(function(b){
    b.addEventListener('click', function(){
      state.unit = b.getAttribute('data-unit');
      document.querySelectorAll('.trend-toolbar button').forEach(function(x){ x.classList.remove('active') });
      b.classList.add('active');
      syncUrl(); loadTrend();
    });
  });
  document.getElementById('logoutBtn').addEventListener('click', async function(){
    try { await fetch('/api/admin/logout', { method: 'POST', credentials: 'same-origin' }) } catch(e) {}
    location.href = '/admin/login';
  });

  initState();
  loadAll();
})();
</script>
</body>
</html>`
}
