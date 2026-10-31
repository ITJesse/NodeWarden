import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { StorageService } from '../src/services/storage';
import { createPasswordVerifier, verifyPasswordVerifier } from '../src/services/password-verifier';
import { handleAuthenticatedRoute } from '../src/router-authenticated';

const owner = '00000000-0000-4000-8000-000000000001';
const email = 'user@example.test';
const currentHash = 'Y3VycmVudC1tYXN0ZXItcGFzc3dvcmQtaGFzaA==';
const nextHash = 'bmV4dC1tYXN0ZXItcGFzc3dvcmQtaGFzaA==';
const currentKey = '2.AAAAAAAAAAAAAAAAAAAAAA==|YWJj|ZGVm';
const nextKey = '2.BBBBBBBBBBBBBBBBBBBBBB==|Z2hp|amts';
const keyId = '0123456789abcdef0123456789abcdef';
const otherKeyId = 'fedcba9876543210fedcba9876543210';

async function fixture(ctx: TestContext, kdfIterations = 100_000) {
  // Production SQL runs against an in-memory SQLite database; only the D1
  // result wrapper and unrelated audit/cache/notification integrations are substituted.
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, name TEXT, master_password_hint TEXT,
      master_password_hash TEXT, key TEXT, private_key TEXT, public_key TEXT, kdf_type INTEGER,
      kdf_iterations INTEGER, kdf_memory INTEGER, kdf_parallelism INTEGER, security_stamp TEXT,
      role TEXT, status TEXT, verify_devices INTEGER, totp_secret TEXT, totp_recovery_code TEXT,
      yubikey_key1 TEXT, yubikey_key2 TEXT, yubikey_key3 TEXT, yubikey_key4 TEXT, yubikey_key5 TEXT,
      yubikey_nfc INTEGER, api_key TEXT, user_key_id TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE user_revisions(user_id TEXT PRIMARY KEY, revision_date TEXT NOT NULL);
    CREATE TABLE devices(user_id TEXT, push_token TEXT);
  `);
  sqlite.prepare(`INSERT INTO users VALUES(?, ?, NULL, NULL, ?, ?, NULL, NULL, 0, ?, NULL, NULL, 'stamp',
    'user', 'active', 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`)
    .run(owner, email, await createPasswordVerifier(currentHash), currentKey, kdfIterations);
  const db: any = {
    prepare(sql: string) {
      let values: any[] = [];
      const statement = {
        bind(...bound: any[]) { values = bound; return statement; },
        async run() { const result = sqlite.prepare(sql).run(...values); return { success: true, meta: { changes: Number(result.changes) } }; },
        async all() { return { success: true, results: sqlite.prepare(sql).all(...values) }; },
        async first() { return sqlite.prepare(sql).get(...values) ?? null; },
      };
      return statement;
    },
  };
  const audits: any[] = [];
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async (log: any) => { audits.push(log); });
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  ctx.mock.method(StorageService.prototype, 'getAccountPasskeyCredentialsByUserId', async () => []);
  ctx.mock.method(StorageService.prototype, 'getAllCiphers', async () => []);
  ctx.mock.method(StorageService.prototype, 'getAllFolders', async () => []);
  ctx.mock.method(StorageService.prototype, 'getAllSends', async () => []);
  ctx.mock.method(StorageService.prototype, 'getAttachmentsByUserId', async () => new Map());
  ctx.mock.method(StorageService.prototype, 'getUserDomainSettings', async () => null);
  const cache = new Map<string, Response>();
  (globalThis as any).caches = {
    default: {
      match: async (request: Request) => cache.get(request.url)?.clone(),
      put: async (request: Request, response: Response) => { cache.set(request.url, response.clone()); },
    },
  };
  ctx.after(() => { delete (globalThis as any).caches; });
  const notifications: any[] = [];
  const env: any = {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (_url: string, init: RequestInit) => { notifications.push(JSON.parse(init.body as string)); return new Response(null, { status: 204 }); } }),
    },
  };
  const route = async (path: string, method: string, body?: unknown) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method, headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const response = await handleAuthenticatedRoute(request, env, owner, { id: owner } as any, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  };
  const userRow = () => sqlite.prepare('SELECT * FROM users WHERE id = ?').get(owner) as any;
  return { route, userRow, audits, notifications };
}

function kdfChangeBody(overrides: { iterations?: number; salt?: string; containedKeyId?: string; unlockIterations?: number } = {}) {
  const iterations = overrides.iterations ?? 600_000;
  const salt = overrides.salt ?? email;
  return {
    masterPasswordHash: currentHash,
    authenticationData: {
      kdf: { kdfType: 0, iterations, memory: null, parallelism: null },
      masterPasswordAuthenticationHash: nextHash,
      salt,
    },
    unlockData: {
      kdf: { kdfType: 0, iterations: overrides.unlockIterations ?? iterations, memory: null, parallelism: null },
      masterKeyWrappedUserKey: nextKey,
      salt,
      ...(overrides.containedKeyId ? { containedKeyId: overrides.containedKeyId } : {}),
    },
  };
}

test('user key id backfill is recorded once and reported by sync', async (ctx) => {
  const f = await fixture(ctx);
  const before: any = await (await f.route('/api/sync', 'GET')).json();
  assert.equal('UserKeyId' in before.UserDecryption, false);

  const response = await f.route('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: keyId });
  assert.equal(response.status, 200);
  assert.equal(f.userRow().user_key_id, keyId);

  // The revision moves so a cached sync without the key id is not reused.
  const after: any = await (await f.route('/api/sync', 'GET')).json();
  assert.equal(after.UserDecryption.UserKeyId, keyId);

  const repeated = await f.route('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: otherKeyId });
  assert.equal(repeated.status, 400);
  assert.match(JSON.stringify(await repeated.json()), /already set/);
  assert.equal(f.userRow().user_key_id, keyId);
});

test('user key id backfill rejects malformed key ids', async (ctx) => {
  const f = await fixture(ctx);
  for (const userKeyId of [undefined, '', keyId.toUpperCase(), keyId.slice(1), `${keyId}00`, 'zz' + keyId.slice(2), 42]) {
    assert.equal((await f.route('/api/accounts/key-management/user-key-id', 'POST', { userKeyId })).status, 400);
  }
  assert.equal((await f.route('/api/accounts/key-management/user-key-id', 'GET')).status, 405);
  assert.equal(f.userRow().user_key_id, null);
});

test('KDF change raises PBKDF2 iterations without ending the current session', async (ctx) => {
  const f = await fixture(ctx);
  const response = await f.route('/api/accounts/kdf', 'POST', kdfChangeBody());
  assert.equal(response.status, 200);
  const row = f.userRow();
  assert.equal(row.kdf_iterations, 600_000);
  assert.equal(row.kdf_type, 0);
  assert.equal(row.key, nextKey);
  assert.equal(row.security_stamp, 'stamp');
  assert.equal(await verifyPasswordVerifier(nextHash, row.master_password_hash, email), true);
  assert.equal(await verifyPasswordVerifier(currentHash, row.master_password_hash, email), false);
  assert.ok(f.audits.some((log) => log.action === 'account.kdf.change'));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.notifications.length, 1);

  const sync: any = await (await f.route('/api/sync', 'GET')).json();
  assert.equal(sync.UserDecryption.MasterPasswordUnlock.Kdf.Iterations, 600_000);
  assert.equal(sync.UserDecryption.MasterPasswordUnlock.MasterKeyWrappedUserKey, nextKey);
});

test('KDF change rejects invalid requests without changing the account', async (ctx) => {
  const f = await fixture(ctx);
  await f.route('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: keyId });
  const original = f.userRow();
  const invalid = [
    { ...kdfChangeBody(), masterPasswordHash: nextHash },
    kdfChangeBody({ iterations: 100_000 }),
    kdfChangeBody({ iterations: 2_000_001 }),
    kdfChangeBody({ unlockIterations: 700_000 }),
    kdfChangeBody({ salt: 'other@example.test' }),
    kdfChangeBody({ containedKeyId: otherKeyId }),
    kdfChangeBody({ containedKeyId: 'not-a-key-id' }),
    { masterPasswordHash: currentHash },
    { ...kdfChangeBody(), unlockData: { ...kdfChangeBody().unlockData, masterKeyWrappedUserKey: 'plain' } },
  ];
  for (const body of invalid) {
    assert.equal((await f.route('/api/accounts/kdf', 'POST', body)).status, 400, JSON.stringify(body));
  }
  assert.deepEqual(f.userRow(), original);

  assert.equal((await f.route('/api/accounts/kdf', 'POST', kdfChangeBody({ containedKeyId: keyId }))).status, 200);
});
