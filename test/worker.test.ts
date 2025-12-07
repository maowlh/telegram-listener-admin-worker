import { describe, expect, it, beforeEach } from 'vitest';
import { createApp, fnv1a } from '../src/worker';
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
      expect(session.telegram_api_id).toBe(100);
      expect(session.telegram_api_hash).toBe('hash');
    }
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

  it('returns sessions when indexed ids exist without throwing', async () => {
    const record = {
      id: 'my-acc',
      account_id: 'my-acc',
      phone: '+989936965879',
      telegram_api_id: 21968017,
      telegram_api_hash: '5a3084a74c58dbffb50300796ce6a430',
      session_string: 'session-data',
      webhook_url: null,
      webhook_enabled: true,
      allowed_chat_types: 'group,supergroup,channel,private',
      group_allowlist: '',
      enrich_deep: true,
      enrich_reply: false,
      heavy_sender_resolve: true,
      participants_limit: 200,
      cache_ttl_ms: 600000,
      enabled: true,
      disabled_reason: null,
      created_at: 1764865714,
      updated_at: 1764865714
    };

    await env.SESSIONS_KV.put('sessions_index_v1', JSON.stringify(['my-acc']));
    await env.SESSIONS_KV.put('tgs:acct:my-acc', JSON.stringify(record));
    await env.SESSIONS_KV.put('tgs:version', '1');

    const response = await app.fetch(
      new Request('https://example.com/v1/telegram/sessions?shard=0&total=1', { headers: AUTH_HEADER }),
      env,
      executionContext()
    );

    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.version).toBe(1);
    expect(Array.isArray(body.sessions)).toBe(true);
    expect(body.sessions.length).toBe(1);
    expect(body.sessions[0].id).toBe('my-acc');
  });
});
