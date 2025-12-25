import { describe, expect, it, beforeEach } from 'vitest';
import { createApp, fnv1a } from '../src/worker';
import { normalizeHumanizeConfig, RECOMMENDED_HUMANIZE_DEFAULTS } from '../src/config';
import type { Env } from '../src/worker';

class MockKV {
  private store = new Map<string, string>();

  async get(key: string, options?: { type?: 'text' | 'json' | 'arrayBuffer' }): Promise<any> {
    if (!this.store.has(key)) return null;
    const value = this.store.get(key)!;
    if (!options || options.type === 'text' || options.type === 'json') {
      if (options?.type === 'json') {
        return JSON.parse(value);
      }
      return value;
    }
    if (options.type === 'arrayBuffer') {
      return Uint8Array.from(value, (c) => c.charCodeAt(0)).buffer;
    }
    return value;
  }

  async put(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options?: { prefix?: string }): Promise<{ keys: Array<{ name: string }>; list_complete: boolean }> {
    const prefix = options?.prefix ?? '';
    const keys = Array.from(this.store.keys())
      .filter((key) => key.startsWith(prefix))
      .map((name) => ({ name, expiration: undefined, metadata: undefined }));
    return { keys, list_complete: true }; // eslint-disable-line @typescript-eslint/naming-convention
  }

  async getWithMetadata(): Promise<null> {
    return null;
  }
}

const AUTH_HEADER = { authorization: 'Bearer token', 'content-type': 'application/json' };

const noopDurableObjectNamespace = {
  idFromName: () => ({}),
  idFromString: () => ({}),
  newUniqueId: () => ({}),
  get: () => ({
    fetch: async () =>
      new Response(JSON.stringify({ error: 'durable_not_configured' }), {
        status: 500,
        headers: { 'content-type': 'application/json' }
      })
  })
} as unknown as DurableObjectNamespace;

function createEnv(): Env {
  return {
    SESSIONS_KV: new MockKV() as unknown as KVNamespace,
    LOGIN_SESSIONS: noopDurableObjectNamespace,
    SESSIONS_API_TOKEN: 'token',
    TELEGRAM_API_ID: '100',
    TELEGRAM_API_HASH: 'hash'
  };
}

function executionContext(): ExecutionContext {
  return {
    waitUntil: () => {},
    passThroughOnException: () => {},
    props: {}
  } as ExecutionContext;
}

describe('session lifecycle endpoints', () => {
  let env: Env;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    env = createEnv();
    app = createApp();
  });

  it('enables and disables sessions while bumping version', async () => {
    const baseBody = {
      id: 'acct_1',
      phone: '+1000000000',
      session_string: 'plaintext-session',
      webhook_url: 'https://example.com/hook',
      webhook_enabled: true,
      enabled: true
    };

    const createRequest = new Request('https://example.com/v1/telegram/sessions', {
      method: 'POST',
      headers: AUTH_HEADER,
      body: JSON.stringify(baseBody)
    });
    const createResponse = await app.fetch(createRequest, env, executionContext());
    expect(createResponse.status).toBe(200);

    const disableRequest = new Request('https://example.com/v1/telegram/sessions/acct_1/disable', {
      method: 'POST',
      headers: AUTH_HEADER,
      body: JSON.stringify({ reason: 'maintenance' })
    });
    const disableResponse = await app.fetch(disableRequest, env, executionContext());
    expect(disableResponse.status).toBe(200);
    const storedAfterDisable = await env.SESSIONS_KV.get('tgs:acct:acct_1', { type: 'json' }) as any;
    expect(storedAfterDisable.account_id).toBe('acct_1');
    expect(storedAfterDisable.enabled).toBe(false);
    expect(storedAfterDisable.disabled_reason).toBe('maintenance');
    expect(storedAfterDisable.telegram_api_id).toBe(100);
    expect(storedAfterDisable.telegram_api_hash).toBe('hash');

    const enableRequest = new Request('https://example.com/v1/telegram/sessions/acct_1/enable', {
      method: 'POST',
      headers: AUTH_HEADER
    });
    const enableResponse = await app.fetch(enableRequest, env, executionContext());
    expect(enableResponse.status).toBe(200);
    const storedAfterEnable = await env.SESSIONS_KV.get('tgs:acct:acct_1', { type: 'json' }) as any;
    expect(storedAfterEnable.enabled).toBe(true);
    expect(storedAfterEnable.disabled_reason).toBeNull();

    const version = await env.SESSIONS_KV.get('tgs:version');
    expect(Number(version)).toBeGreaterThanOrEqual(3);
  });

  it('shards sessions deterministically', async () => {
    const base = {
      phone: '+1000000000',
      session_string: 'plaintext-session',
      webhook_url: 'https://example.com/hook',
      webhook_enabled: true,
      enabled: true
    };

    for (let i = 0; i < 4; i += 1) {
      const req = new Request('https://example.com/v1/telegram/sessions', {
        method: 'POST',
        headers: AUTH_HEADER,
        body: JSON.stringify({ ...base, id: `acct_${i}` })
      });
      const res = await app.fetch(req, env, executionContext());
      expect(res.status).toBe(200);
    }

    const shard = 1;
    const total = 3;
    const response = await app.fetch(
      new Request(`https://example.com/v1/telegram/sessions?shard=${shard}&total=${total}`, { headers: AUTH_HEADER }),
      env,
      executionContext()
    );
    expect(response.status).toBe(200);
    const json = await response.json() as any;
    const expectedIds = Array.from({ length: 4 }, (_, i) => `acct_${i}`).filter((id) => fnv1a(id) % total === shard);
    const returnedIds = json.sessions.map((session: any) => session.id);
    expect(returnedIds.sort()).toEqual(expectedIds.sort());
    for (const session of json.sessions) {
      expect(session).toHaveProperty('session_string');
      expect(session.session_string.length).toBeGreaterThan(0);
      expect(session.account_id).toBe(session.id);
      expect(session.canonical_account_id).toBe(session.id);
      expect(session.telegram_api_id).toBe(100);
      expect(session.telegram_api_hash).toBe('hash');
    }
  });

  it('stores and retrieves rules under canonical account ids', async () => {
    const baseBody = {
      id: 'acct_rules',
      phone: '+1000000000',
      session_string: 'plaintext-session',
      webhook_url: 'https://example.com/hook',
      webhook_enabled: true,
      enabled: true
    };

    const createRequest = new Request('https://example.com/v1/telegram/sessions', {
      method: 'POST',
      headers: AUTH_HEADER,
      body: JSON.stringify(baseBody)
    });
    const createResponse = await app.fetch(createRequest, env, executionContext());
    expect(createResponse.status).toBe(200);

    const putRules = new Request('https://example.com/v1/telegram/rules/acct_rules', {
      method: 'PUT',
      headers: AUTH_HEADER,
      body: JSON.stringify({ rules: [{ chat_ids: [], chat_usernames: ['foo'] }] })
    });

    const putResponse = await app.fetch(putRules, env, executionContext());
    expect(putResponse.status).toBe(200);
    const storedRules = await env.SESSIONS_KV.get('auto_reply:rules:acct_rules', { type: 'json' }) as any;
    expect(storedRules.rules[0].chat_ids).toEqual([]);
    expect(storedRules.rules[0].chat_usernames).toEqual(['foo']);

    const getRules = await app.fetch(
      new Request('https://example.com/v1/telegram/rules/acct_rules', { headers: AUTH_HEADER }),
      env,
      executionContext()
    );
    expect(getRules.status).toBe(200);
    const rulesJson = await getRules.json() as any;
    expect(rulesJson.id).toBe('acct_rules');
    expect(rulesJson.canonical_account_id).toBe('acct_rules');
    expect(rulesJson.rules[0].chat_ids).toEqual([]);
    expect(rulesJson.wildcard_note).toBeDefined();
  });

  it('migrates legacy self-id rule keys to canonical ids', async () => {
    await env.SESSIONS_KV.put('auto_reply:rules:old_self', JSON.stringify({ rules: [{ keywords: ['hi'] }] }));

    const migrateRequest = new Request('https://example.com/v1/admin/migrate-rules', {
      method: 'POST',
      headers: AUTH_HEADER,
      body: JSON.stringify({ self_id: 'old_self', internal_id: 'acct_rules' })
    });

    const migrateResponse = await app.fetch(migrateRequest, env, executionContext());
    expect(migrateResponse.status).toBe(200);
    const migrateJson = await migrateResponse.json() as any;
    expect(migrateJson.migrated).toBe(true);
    const copied = await env.SESSIONS_KV.get('auto_reply:rules:acct_rules', { type: 'json' }) as any;
    expect(copied.rules[0].keywords).toEqual(['hi']);
  });

  it('persists a session automatically on signed-in responses', async () => {
    const signedInResponse = {
      status: 'SIGNED_IN',
      stored: false,
      id: 'acct_auto',
      version: null,
      preview_user: null,
      session_string: 'session-data',
      telegram_api_id: 100,
      telegram_api_hash: 'hash'
    };

    env.LOGIN_SESSIONS = {
      idFromName: () => ({}),
      get: () => ({
        fetch: async () =>
          new Response(JSON.stringify(signedInResponse), {
            status: 200,
            headers: { 'content-type': 'application/json' }
          })
      })
    } as unknown as DurableObjectNamespace;

    const codeRequest = new Request('https://example.com/v1/auth/code', {
      method: 'POST',
      headers: AUTH_HEADER,
      body: JSON.stringify({ login_id: 'lg_1', code: '00000' })
    });

    const codeResponse = await app.fetch(codeRequest, env, executionContext());
    expect(codeResponse.status).toBe(200);
    const body = (await codeResponse.json()) as any;
    expect(body.status).toBe('SIGNED_IN');
    expect(body.stored).toBe(true);
    expect(body.version).toBe(1);

    const sessionsResponse = await app.fetch(
      new Request('https://example.com/v1/telegram/sessions?shard=0&total=1', {
        headers: AUTH_HEADER
      }),
      env,
      executionContext()
    );
    expect(sessionsResponse.status).toBe(200);
    const sessionsBody = (await sessionsResponse.json()) as any;
    expect(Array.isArray(sessionsBody.sessions)).toBe(true);
    expect(sessionsBody.sessions.length).toBe(1);
    expect(sessionsBody.sessions[0].id).toBe('acct_auto');
  });

  it('normalizes humanize configs with clamping and cleanup', () => {
    const normalized = normalizeHumanizeConfig({
      reply_probability: 2,
      delay_min_ms: 600_001,
      delay_max_ms: -10,
      typing_min_ms: 5_000,
      typing_max_ms: 100_000,
      cooldown_sender_sec: -5,
      keywords: [' Test ', 'test', ''],
      variation_openers: [' hi ', ''],
      emoji_probability: 1.5,
      max_emojis: 10
    });

    expect(normalized.reply_probability).toBe(1);
    expect(normalized.delay_min_ms).toBe(0);
    expect(normalized.delay_max_ms).toBe(600_000);
    expect(normalized.typing_min_ms).toBe(5_000);
    expect(normalized.typing_max_ms).toBe(10_000);
    expect(normalized.cooldown_sender_sec).toBe(0);
    expect(normalized.keywords).toEqual(['test']);
    expect(normalized.variation_openers).toEqual(['hi']);
    expect(normalized.emoji_probability).toBe(1);
    expect(normalized.max_emojis).toBe(2);
  });

  it('returns humanize defaults when routes lack the field', async () => {
    await env.SESSIONS_KV.put('routes_config_v1', JSON.stringify({ routes: { BUY: { foo: 'bar' } } }));

    const response = await app.fetch(
      new Request('https://example.com/v1/routes', { headers: AUTH_HEADER }),
      env,
      executionContext()
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect(body.routes.BUY.humanize.enabled).toBe(true);
    expect(body.routes.BUY.humanize.max_emojis).toBe(1);
    expect(body.routes.BUY.foo).toBe('bar');
  });

  it('stores normalized humanize configs on PUT', async () => {
    const putRequest = new Request('https://example.com/v1/routes', {
      method: 'PUT',
      headers: AUTH_HEADER,
      body: JSON.stringify({
        routes: {
          BUY: {
            humanize: {
              reply_probability: 2,
              delay_min_ms: 1000,
              delay_max_ms: 500,
              keywords: ['Hello', 'hello']
            }
          }
        }
      })
    });

    const putResponse = await app.fetch(putRequest, env, executionContext());
    expect(putResponse.status).toBe(200);
    const stored = (await env.SESSIONS_KV.get('routes_config_v1', { type: 'json' })) as any;
    expect(stored.routes.BUY.humanize.reply_probability).toBe(1);
    expect(stored.routes.BUY.humanize.delay_min_ms).toBe(500);
    expect(stored.routes.BUY.humanize.keywords).toEqual(['hello']);

    const getResponse = await app.fetch(
      new Request('https://example.com/v1/routes', { headers: AUTH_HEADER }),
      env,
      executionContext()
    );
    const getBody = (await getResponse.json()) as any;
    expect(getBody.routes.BUY.humanize.delay_min_ms).toBe(500);
    expect(getBody.routes.BUY.humanize.delay_max_ms).toBe(1000);
  });

  it('rejects invalid humanize payloads on PATCH', async () => {
    const patchRequest = new Request('https://example.com/v1/routes/BUY', {
      method: 'PATCH',
      headers: AUTH_HEADER,
      body: JSON.stringify({ humanize: { reply_probability: 'yes' } })
    });

    const patchResponse = await app.fetch(patchRequest, env, executionContext());
    expect(patchResponse.status).toBe(400);
    const errorBody = (await patchResponse.json()) as any;
    expect(errorBody.error).toBe('humanize.reply_probability_number_required');
  });

  it('exposes recommended humanize defaults', async () => {
    const response = await app.fetch(
      new Request('https://example.com/v1/routes/humanize-defaults', { headers: AUTH_HEADER }),
      env,
      executionContext()
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as any;
    expect(body.defaults).toEqual(RECOMMENDED_HUMANIZE_DEFAULTS);
  });
});
