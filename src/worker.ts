import { Hono } from 'hono';
import type { Context } from 'hono';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { Api, TelegramClient } from 'telegram';
import { computeCheck } from 'telegram/Password';
import { StringSession } from 'telegram/sessions';
import { ApiError } from './errors';
import {
  HumanizeConfig,
  NormalizedHumanizeConfig,
  RECOMMENDED_HUMANIZE_DEFAULTS,
  RouteConfig,
  normalizeHumanizeConfig
} from './config';

type LoginStatus = 'CODE_SENT' | 'PASSWORD_REQUIRED' | 'SIGNED_IN' | 'ERROR';

export interface PreviewUser {
  id: string | number | null;
  username: string | null;
  first_name: string | null;
  last_name: string | null;
}

export interface SignedInResponse {
  status: 'SIGNED_IN';
  stored: boolean;
  id: string;
  version: number | null;
  preview_user: PreviewUser | null;
  session_string: string;
  telegram_api_id: number;
  telegram_api_hash: string | null;
}

export interface SessionDefaults {
  webhook_url?: string | null;
  webhook_enabled?: boolean;
  enabled?: boolean;
  allowed_chat_types?: string;
  group_allowlist?: string;
  enrich_deep?: boolean;
  enrich_reply?: boolean;
  heavy_sender_resolve?: boolean;
  participants_limit?: number;
  cache_ttl_ms?: number;
}

interface PersistSessionContext {
  accountId: string;
  phone: string;
  apiId: number;
  apiHash: string;
  sessionDefaults: SessionDefaults;
}

const JSON_HEADERS = { 'content-type': 'application/json' } as const;
const SESSION_PREFIX = 'tgs:acct:';
const LOGIN_SESSION_PREFIX = 'tgs:login:';
const INDEX_KEY = 'sessions_index_v1';
const VERSION_KEY = 'tgs:version';
const LOGIN_STATE_KEY = 'login_state';
const RULES_PREFIX = 'auto_reply:rules:';
const ROUTES_KEY = 'routes_config_v1';
const DEFAULT_ALLOWED_CHAT_TYPES = 'group,supergroup,channel,private';
const DEFAULT_CACHE_TTL = 600_000;
const DEFAULT_PARTICIPANTS_LIMIT = 200;
const DEFAULT_LOGIN_TTL = 600_000;

interface StartPayload extends SessionDefaults {
  phone?: unknown;
  account_id?: unknown;
  telegram_api_id?: unknown;
  telegram_api_hash?: unknown;
}

interface CodePayload {
  login_id?: unknown;
  code?: unknown;
}

interface PasswordPayload {
  login_id?: unknown;
  password?: unknown;
}

interface CancelPayload {
  login_id?: unknown;
}

interface PersistResult {
  ok: true;
  id: string;
  version: number;
}

interface LoginSessionSnapshot {
  loginId: string;
  accountId: string;
  phone: string;
  apiId: number;
  apiHash: string;
  sessionString: string;
  stored: boolean;
  persistedId: string | null;
  version: number | null;
}

export interface Env {
  SESSIONS_KV: KVNamespace;
  LOGIN_SESSIONS: DurableObjectNamespace;
  SESSIONS_API_TOKEN: string;
  TELEGRAM_API_ID?: string;
  TELEGRAM_API_HASH?: string;
  LOGIN_TTL_MS?: string;
}

export interface SessionRecord {
  id: string;
  account_id: string;
  phone: string | null;
  telegram_api_id: number;
  telegram_api_hash: string | null;
  session_string: string;
  webhook_url: string | null;
  webhook_enabled: boolean;
  allowed_chat_types: string;
  group_allowlist: string;
  enrich_deep: boolean;
  enrich_reply: boolean;
  heavy_sender_resolve: boolean;
  participants_limit: number;
  cache_ttl_ms: number;
  enabled: boolean;
  disabled_reason: string | null;
  created_at: number;
  updated_at: number;
}

export interface SessionResponse {
  id: string;
  account_id: string;
  canonical_account_id: string;
  telegram_api_id: number;
  telegram_api_hash: string | null;
  session_string: string;
  enabled: boolean;
  webhook_enabled: boolean;
  disabled_reason: string | null;
  webhook_url: string | null;
  allowed_chat_types: string;
  group_allowlist: string;
  enrich_deep: boolean;
  enrich_reply: boolean;
  heavy_sender_resolve: boolean;
  participants_limit: number;
  cache_ttl_ms: number;
}

type RuleArrayField = Array<string | number>;

interface AutoReplyRule {
  chat_ids?: RuleArrayField;
  chat_usernames?: RuleArrayField;
  senders?: RuleArrayField;
  keywords?: RuleArrayField;
  kinds?: RuleArrayField;
  languages?: RuleArrayField;
  [key: string]: unknown;
}

interface RulesEnvelope {
  rules: AutoReplyRule[];
  wildcard_note?: string;
}

interface RoutesEnvelope {
  routes: Record<string, RouteConfig>;
  [key: string]: unknown;
}

const METADATA_FIELDS: Array<keyof SessionRecord> = [
  'phone',
  'telegram_api_id',
  'telegram_api_hash',
  'webhook_url',
  'webhook_enabled',
  'allowed_chat_types',
  'group_allowlist',
  'enrich_deep',
  'enrich_reply',
  'heavy_sender_resolve',
  'participants_limit',
  'cache_ttl_ms',
  'enabled',
  'disabled_reason'
];

const SESSION_DEFAULT_KEYS: Array<keyof SessionDefaults> = [
  'webhook_url',
  'webhook_enabled',
  'enabled',
  'allowed_chat_types',
  'group_allowlist',
  'enrich_deep',
  'enrich_reply',
  'heavy_sender_resolve',
  'participants_limit',
  'cache_ttl_ms'
];

export const createApp = () => {
  const app = new Hono<{ Bindings: Env }>();

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,OPTIONS,DELETE',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  } as const;

  app.use('*', async (c, next) => {
    if (c.req.method === 'OPTIONS') {
      return c.newResponse(null, 204, corsHeaders);
    }

    await next();

    for (const [key, value] of Object.entries(corsHeaders)) {
      c.res.headers.set(key, value);
    }
  });

  app.use('*', async (c, next) => {
    const authHeader = c.req.header('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return c.newResponse('Unauthorized', 401);
    }
    const token = authHeader.slice(7).trim();
    if (!token || token !== c.env.SESSIONS_API_TOKEN) {
      return c.newResponse('Unauthorized', 401);
    }
    await next();
  });

  app.post('/v1/auth/start', async (c) => {
    const payload = (await parseJsonBody(c)) as StartPayload;
    const phone = typeof payload.phone === 'string' ? payload.phone.trim() : '';
    const accountId = typeof payload.account_id === 'string' ? payload.account_id.trim() : '';
    if (!phone) {
      return jsonError(c, 'phone_required', 400);
    }
    if (!accountId) {
      return jsonError(c, 'account_id_required', 400);
    }

    const apiId = resolveTelegramApiId(payload.telegram_api_id, undefined, c.env);
    if (apiId === null) {
      return jsonError(c, 'telegram_api_id_required', 400);
    }
    const apiHash = resolveTelegramApiHash(payload.telegram_api_hash, undefined, c.env);
    if (!apiHash) {
      return jsonError(c, 'telegram_api_hash_required', 400);
    }

    const loginId = `lg_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const sessionDefaults = extractSessionDefaults(payload);
    const response = await callLoginSessionDurable(c.env, loginId, 'start', {
      account_id: accountId,
      phone,
      api_id: apiId,
      api_hash: apiHash,
      session_defaults: sessionDefaults
    });
    const body = await readDurableJson(response);
    if (!response.ok) {
      return c.json(
        body ?? { error: 'send_code_failed' },
        response.status as ContentfulStatusCode,
        JSON_HEADERS
      );
    }
    return c.json({ login_id: loginId, ...body }, 200, JSON_HEADERS);
  });

  app.post('/v1/auth/code', async (c) => {
    const payload = (await parseJsonBody(c)) as CodePayload;
    const loginId = typeof payload.login_id === 'string' ? payload.login_id : '';
    const code = typeof payload.code === 'string' ? payload.code.trim() : '';
    if (!loginId || !code) {
      return jsonError(c, 'login_id_and_code_required', 400);
    }
    const response = await callLoginSessionDurable(c.env, loginId, 'code', { code });
    const body = await readDurableJson(response);
    if (!response.ok) {
      return c.json(
        body ?? { error: 'sign_in_failed' },
        response.status as ContentfulStatusCode,
        JSON_HEADERS
      );
    }
    if (body && typeof body === 'object' && (body as any).status === 'SIGNED_IN') {
      const signedIn = body as SignedInResponse;
      const result = await persistSignedInResult(c.env, signedIn);
      signedIn.stored = result.stored;
      signedIn.version = result.version;
      return c.json(signedIn, 200, JSON_HEADERS);
    }
    return c.json(body, 200, JSON_HEADERS);
  });

  app.post('/v1/auth/password', async (c) => {
    const payload = (await parseJsonBody(c)) as PasswordPayload;
    const loginId = typeof payload.login_id === 'string' ? payload.login_id : '';
    const password = typeof payload.password === 'string' ? payload.password : '';

    if (!loginId || !password) {
      return jsonError(c, 'login_id_and_password_required', 400);
    }
    const response = await callLoginSessionDurable(c.env, loginId, 'password', { password });
    const body = await readDurableJson(response);
    if (!response.ok) {
      console.error('Password login failed', {
        loginId,
        status: response.status,
        body
      });
      return c.json(
        body ?? { error: 'password_check_failed' },
        response.status as ContentfulStatusCode,
        JSON_HEADERS
      );
    }
    if (body && typeof body === 'object' && (body as any).status === 'SIGNED_IN') {
      const signedIn = body as SignedInResponse;
      const result = await persistSignedInResult(c.env, signedIn);
      signedIn.stored = result.stored;
      signedIn.version = result.version;
      return c.json(signedIn, 200, JSON_HEADERS);
    }
    return c.json(body, 200, JSON_HEADERS);
  });

  app.post('/v1/auth/cancel', async (c) => {
    const payload = (await parseJsonBody(c)) as CancelPayload;
    const loginId = typeof payload.login_id === 'string' ? payload.login_id : '';
    if (!loginId) {
      return jsonError(c, 'login_id_required', 400);
    }
    const response = await callLoginSessionDurable(c.env, loginId, 'cancel', {});
    const body = await readDurableJson(response);
    if (!response.ok) {
      return c.json(
        body ?? { error: 'cancel_failed' },
        response.status as ContentfulStatusCode,
        JSON_HEADERS
      );
    }
    return c.json(body, 200, JSON_HEADERS);
  });

  app.post('/v1/telegram/sessions', async (c) => {
    const payload = await parseJsonBody(c);
    if (!payload || typeof payload !== 'object') {
      return jsonError(c, 'invalid_json', 400);
    }
    try {
      const result = await upsertSessionRecord(c.env, payload);
      return c.json(result, 200, JSON_HEADERS);
    } catch (error) {
      if (error instanceof ApiError) {
        return jsonError(c, error.code, error.status);
      }
      throw error;
    }
  });

  app.post('/v1/telegram/sessions/:id/enable', async (c) => {
    return handleToggleEnable(c, true);
  });

  app.post('/v1/telegram/sessions/:id/disable', async (c) => {
    return handleToggleEnable(c, false);
  });

  app.post('/v1/telegram/sessions/:id/webhook', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    const key = accountKey(id);
    const record = (await kv.get(key, { type: 'json' })) as SessionRecord | null;
    if (!record) {
      return jsonError(c, 'not_found', 404);
    }
    record.account_id = record.account_id ?? record.id;

    const body = await parseJsonBody(c);
    if (!body || typeof body !== 'object') {
      return jsonError(c, 'invalid_json', 400);
    }

    if ('webhook_enabled' in body) {
      if (typeof body.webhook_enabled !== 'boolean') {
        return jsonError(c, 'webhook_enabled_boolean_required', 400);
      }
      record.webhook_enabled = body.webhook_enabled;
    }

    if ('webhook_url' in body) {
      record.webhook_url = body.webhook_url ? String(body.webhook_url) : null;
    }

    record.updated_at = currentTimestamp();
    await kv.put(key, JSON.stringify(record));
    const version = await bumpVersion(c.env);
    return c.json({ ok: true, id, webhook_enabled: record.webhook_enabled, version }, 200, JSON_HEADERS);
  });

  app.patch('/v1/telegram/sessions/:id', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    const key = accountKey(id);
    const record = (await kv.get(key, { type: 'json' })) as SessionRecord | null;
    if (!record) {
      return jsonError(c, 'not_found', 404);
    }
    record.account_id = record.account_id ?? record.id;

    const body = await parseJsonBody(c);
    if (!body || typeof body !== 'object') {
      return jsonError(c, 'invalid_json', 400);
    }

    for (const field of METADATA_FIELDS) {
      if (!(field in body)) continue;
      const value = body[field];
      switch (field) {
        case 'webhook_enabled':
        case 'enrich_deep':
        case 'enrich_reply':
        case 'heavy_sender_resolve':
        case 'enabled':
          if (typeof value !== 'boolean') {
            return jsonError(c, `${field}_boolean_required`, 400);
          }
          (record as any)[field] = value;
          if (field === 'enabled' && value) {
            record.disabled_reason = null;
          }
          if (field === 'enabled' && !value && 'disabled_reason' in body) {
            record.disabled_reason = body.disabled_reason ? String(body.disabled_reason) : 'disabled';
          }
          break;
        case 'participants_limit':
        case 'cache_ttl_ms':
        case 'telegram_api_id':
          if (typeof value !== 'number') {
            return jsonError(c, `${field}_number_required`, 400);
          }
          (record as any)[field] = value;
          break;
        case 'allowed_chat_types':
        case 'group_allowlist':
          if (typeof value !== 'string') {
            return jsonError(c, `${field}_string_required`, 400);
          }
          (record as any)[field] = value;
          break;
        default:
          (record as any)[field] = value === undefined ? record[field] : value ?? null;
          break;
      }
    }

    if ('disabled_reason' in body && typeof body.disabled_reason === 'string') {
      record.disabled_reason = body.disabled_reason;
    }

    record.updated_at = currentTimestamp();
    await kv.put(key, JSON.stringify(record));
    const version = await bumpVersion(c.env);
    return c.json({ ok: true, id, version }, 200, JSON_HEADERS);
  });

  app.delete('/v1/telegram/sessions/:id', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    const key = accountKey(id);
    const existing = await kv.get(key);
    await kv.delete(key);
    if (existing) {
      await updateIndex(kv, id, false);
    }
    const version = await bumpVersion(c.env);
    return c.json({ ok: true, version }, 200, JSON_HEADERS);
  });

  app.get('/v1/telegram/sessions', async (c) => {
    try {
      const params = c.req.query();
      const shardParam = params['shard'] ?? '0';
      const totalParam = params['total'] ?? '1';
      const enabledParam = params['enabled'];

      if (!isIntegerString(shardParam) || !isIntegerString(totalParam)) {
        return jsonError(c, 'invalid_shard_parameters', 400);
      }

      const shard = Number(shardParam);
      const total = Number(totalParam);

      if (total <= 0 || shard < 0 || shard >= total) {
        return jsonError(c, 'invalid_shard_range', 400);
      }

      const enabledOnly = enabledParam === undefined ? true : enabledParam !== 'false';

      const kv = c.env.SESSIONS_KV;

    const ids = await readIndex(kv);
    const sessions: SessionResponse[] = [];

    for (const accountId of ids) {
      try {
        const record = (await kv.get(accountKey(accountId), { type: 'json' })) as SessionRecord | null;
        
        // بررسی اینکه رکورد وجود دارد و همچنین دارای id است
        if (!record || !record.id) continue;

        if (enabledOnly && (!record.enabled || record.webhook_enabled === false)) {
          continue;
        }

        if ((fnv1a(record.id) % total) !== shard) {
          continue;
        }

        const finalAccountId = record.account_id ?? record.id;
        const canonicalId = record.id ?? finalAccountId;
        if (finalAccountId !== canonicalId) {
          console.warn('account_id/id mismatch detected; using canonical id', {
            recordAccountId: finalAccountId,
            recordId: canonicalId
          });
        }

        sessions.push({
          id: canonicalId,
          account_id: canonicalId,
          canonical_account_id: canonicalId,
          telegram_api_id: record.telegram_api_id,
          telegram_api_hash: record.telegram_api_hash,
          session_string: record.session_string,
          enabled: !!record.enabled,
          webhook_enabled: !!record.webhook_enabled,
          disabled_reason: record.disabled_reason ?? null,
          webhook_url: record.webhook_url,
          allowed_chat_types: record.allowed_chat_types,
          group_allowlist: record.group_allowlist,
          enrich_deep: !!record.enrich_deep,
          enrich_reply: !!record.enrich_reply,
          heavy_sender_resolve: !!record.heavy_sender_resolve,
          participants_limit: record.participants_limit ?? DEFAULT_PARTICIPANTS_LIMIT,
          cache_ttl_ms: record.cache_ttl_ms ?? DEFAULT_CACHE_TTL
        });
      } catch (err) {
        console.error(`Error processing session ${accountId}:`, err);
      }
    }

      const versionRaw = await kv.get(VERSION_KEY);
      const version = Number.isFinite(Number(versionRaw)) ? Number(versionRaw) : 0;
      return c.json({ version, sessions }, 200, JSON_HEADERS);
    } catch (error) {
      console.error('failed to list sessions', error);
      return jsonError(c, 'internal_error', 500);
    }
  });

  app.get('/v1/telegram/rules/:id', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    const session = (await kv.get(accountKey(id), { type: 'json' })) as SessionRecord | null;
    if (!session) {
      return jsonError(c, 'not_found', 404);
    }

    const rulesRaw = await kv.get(rulesKey(id));
    let parsed: RulesEnvelope | null = null;
    if (rulesRaw) {
      try {
        parsed = JSON.parse(rulesRaw) as RulesEnvelope;
      } catch (err) {
        console.warn('failed to parse rules', { id, err });
      }
    }

    const envelope: RulesEnvelope = {
      rules: parsed?.rules ?? [],
      wildcard_note: 'Empty arrays are treated as wildcards'
    };

    return c.json(
      {
        id,
        canonical_account_id: session.id ?? id,
        rules: envelope.rules,
        wildcard_note: envelope.wildcard_note
      },
      200,
      JSON_HEADERS
    );
  });

  app.put('/v1/telegram/rules/:id', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    const session = (await kv.get(accountKey(id), { type: 'json' })) as SessionRecord | null;
    if (!session) {
      return jsonError(c, 'not_found', 404);
    }

    const body = await parseJsonBody(c);
    try {
      const rules = normalizeRulesPayload(body);
      const envelope: RulesEnvelope = {
        rules,
        wildcard_note: 'Empty arrays are treated as wildcards'
      };
      await kv.put(rulesKey(id), JSON.stringify(envelope));
      return c.json({ ok: true, id, canonical_account_id: session.id ?? id, rules }, 200, JSON_HEADERS);
    } catch (error) {
      if (error instanceof ApiError) {
        return jsonError(c, error.code, error.status);
      }
      console.error('failed to persist rules', { id, error });
      return jsonError(c, 'invalid_rules', 400);
    }
  });

  app.delete('/v1/telegram/rules/:id', async (c) => {
    const id = c.req.param('id');
    const kv = c.env.SESSIONS_KV;
    await kv.delete(rulesKey(id));
    return c.json({ ok: true, id }, 200, JSON_HEADERS);
  });

  app.get('/v1/routes', async (c) => {
    const kv = c.env.SESSIONS_KV;
    const envelope = await readRoutesEnvelope(kv);
    const normalizedRoutes = normalizeRoutesForResponse(envelope.routes);
    const versionRaw = await kv.get(VERSION_KEY);
    const version = Number.isFinite(Number(versionRaw)) ? Number(versionRaw) : 0;
    return c.json({ ...envelope, routes: normalizedRoutes, version }, 200, JSON_HEADERS);
  });

  app.get('/v1/routes/humanize-defaults', (c) => {
    return c.json({ defaults: RECOMMENDED_HUMANIZE_DEFAULTS }, 200, JSON_HEADERS);
  });

  app.put('/v1/routes', async (c) => {
    const body = await parseJsonBody(c);
    if (!isPlainObject(body)) {
      return jsonError(c, 'routes_object_required', 400);
    }
    if (!isPlainObject((body as any).routes)) {
      return jsonError(c, 'routes_map_required', 400);
    }

    const routesBody = (body as any).routes as Record<string, RouteConfig>;
    try {
      const normalizedRoutes = normalizeRoutesForStorage(routesBody);
      const envelope: RoutesEnvelope = { ...body, routes: normalizedRoutes };
      await c.env.SESSIONS_KV.put(ROUTES_KEY, JSON.stringify(envelope));
      const version = await bumpVersion(c.env);
      return c.json({ ok: true, routes: normalizedRoutes, version }, 200, JSON_HEADERS);
    } catch (error) {
      if (error instanceof ApiError) {
        return jsonError(c, error.code, error.status);
      }
      console.error('failed to store routes', error);
      return jsonError(c, 'invalid_routes', 400);
    }
  });

  app.patch('/v1/routes/:key', async (c) => {
    const routeKey = c.req.param('key');
    const kv = c.env.SESSIONS_KV;
    const envelope = await readRoutesEnvelope(kv);
    const body = await parseJsonBody(c);
    if (!isPlainObject(body)) {
      return jsonError(c, 'route_object_required', 400);
    }

    try {
      const existingRoute = ensureRouteObject(envelope.routes[routeKey]);
      const incomingRoute = validateRoute(body, routeKey);
      const merged: RouteConfig = { ...existingRoute, ...incomingRoute };
      if (incomingRoute.humanize !== undefined || !existingRoute.humanize) {
        merged.humanize = incomingRoute.humanize ?? existingRoute.humanize;
      }
      const normalized = normalizeRouteConfigForStorage(merged);
      const updatedEnvelope: RoutesEnvelope = {
        ...envelope,
        routes: { ...envelope.routes, [routeKey]: normalized }
      };
      await kv.put(ROUTES_KEY, JSON.stringify(updatedEnvelope));
      const version = await bumpVersion(c.env);
      return c.json({ ok: true, key: routeKey, route: normalized, version }, 200, JSON_HEADERS);
    } catch (error) {
      if (error instanceof ApiError) {
        return jsonError(c, error.code, error.status);
      }
      console.error('failed to patch route', { routeKey, error });
      return jsonError(c, 'invalid_route', 400);
    }
  });

  app.get('/v1/debug/mapping', async (c) => {
    const kv = c.env.SESSIONS_KV;
    const ids = await readIndex(kv);
    const accounts = [] as Array<{ id: string; phone: string | null; telegram_self_id: string | number | null; rules_key: string; rules_present: boolean }>;

    for (const accountId of ids) {
      try {
        const record = (await kv.get(accountKey(accountId), { type: 'json' })) as SessionRecord | null;
        if (!record) continue;
        const canonicalId = record.id ?? record.account_id ?? accountId;
        const key = rulesKey(canonicalId);
        const rulesPresent = Boolean(await kv.get(key));
        accounts.push({
          id: canonicalId,
          phone: record.phone ?? null,
          telegram_self_id: (record as any).telegram_self_id ?? null,
          rules_key: key,
          rules_present: rulesPresent
        });
      } catch (error) {
        console.warn('failed to build mapping entry', { accountId, error });
      }
    }

    const listedRules = await kv.list({ prefix: RULES_PREFIX });
    const orphan_rule_keys = listedRules.keys
      .map((entry) => entry.name)
      .filter((name) => !accounts.some((acct) => acct.rules_key === name));

    return c.json({ accounts, orphan_rule_keys }, 200, JSON_HEADERS);
  });

  app.post('/v1/admin/migrate-rules', async (c) => {
    const body = await parseJsonBody(c);
    const selfId = typeof body.self_id === 'string' ? body.self_id.trim() : '';
    const internalId = typeof body.internal_id === 'string' ? body.internal_id.trim() : '';

    if (!selfId || !internalId) {
      return jsonError(c, 'self_id_and_internal_id_required', 400);
    }

    const kv = c.env.SESSIONS_KV;
    const sourceKey = rulesKey(selfId);
    const destKey = rulesKey(internalId);
    const payload = await kv.get(sourceKey);
    if (!payload) {
      return c.json({ migrated: false, reason: 'source_not_found', source: sourceKey, destination: destKey }, 200, JSON_HEADERS);
    }

    await kv.put(destKey, payload);
    console.log('migrated rules key', { from: sourceKey, to: destKey });
    return c.json({ migrated: true, source: sourceKey, destination: destKey }, 200, JSON_HEADERS);
  });

  app.all('*', (c) => c.newResponse('Not found', 404));

  return app;
};

async function callLoginSessionDurable(
  env: Env,
  loginId: string,
  action: 'start' | 'code' | 'password' | 'cancel',
  payload: Record<string, unknown>
): Promise<Response> {
  const id = env.LOGIN_SESSIONS.idFromName(loginId);
  const stub = env.LOGIN_SESSIONS.get(id);
  return stub.fetch(`https://login-session/${action}`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ ...payload, login_id: loginId })
  });
}

async function readDurableJson(response: Response): Promise<any | null> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    console.warn('failed to parse durable object response', error);
    return null;
  }
}

async function handleToggleEnable(c: Context<{ Bindings: Env }>, enable: boolean) {
  const id = c.req.param('id');
  const kv = c.env.SESSIONS_KV;
  const key = accountKey(id);
  const record = (await kv.get(key, { type: 'json' })) as SessionRecord | null;
  if (!record) {
    return jsonError(c, 'not_found', 404);
  }
  record.account_id = record.account_id ?? record.id;
  const body = await parseJsonBody(c);
  const reason = !enable && body && typeof body === 'object' && typeof body.reason === 'string'
    ? body.reason
    : 'disabled';

  record.enabled = enable;
  record.disabled_reason = enable ? null : reason;
  record.updated_at = currentTimestamp();
  await kv.put(key, JSON.stringify(record));
  const version = await bumpVersion(c.env);
  return c.json({ ok: true, id, enabled: record.enabled, version }, 200, JSON_HEADERS);
}

function accountKey(id: string): string {
  return `${SESSION_PREFIX}${id}`;
}

function loginSessionKey(id: string): string {
  return `${LOGIN_SESSION_PREFIX}${id}`;
}

function rulesKey(id: string): string {
  return `${RULES_PREFIX}${id}`;
}

function currentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

function normalizeRuleArray(value: unknown, field: string): RuleArrayField {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new ApiError(400, `${field}_array_required`);
  }
  return value.filter((entry) => entry !== undefined && entry !== null) as RuleArrayField;
}

function normalizeRule(rule: unknown): AutoReplyRule {
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    throw new ApiError(400, 'rule_object_required');
  }

  const normalized: AutoReplyRule = {};
  const obj = rule as Record<string, unknown>;
  const arrayFields = ['chat_ids', 'chat_usernames', 'senders', 'keywords', 'kinds', 'languages'];

  for (const [key, value] of Object.entries(obj)) {
    if (arrayFields.includes(key)) {
      normalized[key] = normalizeRuleArray(value, key);
    } else {
      normalized[key] = value as any;
    }
  }

  for (const missingField of arrayFields) {
    if (!(missingField in normalized)) {
      normalized[missingField] = [];
    }
  }

  return normalized;
}

function normalizeRulesPayload(body: any): AutoReplyRule[] {
  if (!body || typeof body !== 'object') {
    throw new ApiError(400, 'invalid_rules_payload');
  }
  if (!Array.isArray((body as any).rules)) {
    throw new ApiError(400, 'rules_array_required');
  }
  const rules = (body as any).rules as unknown[];
  return rules.map((rule) => normalizeRule(rule));
}

async function readRoutesEnvelope(kv: KVNamespace): Promise<RoutesEnvelope> {
  const raw = (await kv.get(ROUTES_KEY, { type: 'json' })) as RoutesEnvelope | null;
  if (raw && isPlainObject(raw)) {
    const routes = isPlainObject((raw as any).routes) ? ((raw as any).routes as Record<string, RouteConfig>) : {};
    const { routes: _routes, ...rest } = raw as any;
    return { ...rest, routes };
  }
  return { routes: {} };
}

function normalizeRoutesForResponse(
  routes: Record<string, RouteConfig> | undefined
): Record<string, RouteConfig & { humanize: NormalizedHumanizeConfig }> {
  const normalized: Record<string, RouteConfig & { humanize: NormalizedHumanizeConfig }> = {};
  if (!routes || typeof routes !== 'object') {
    return normalized;
  }
  for (const [key, value] of Object.entries(routes)) {
    const route = ensureRouteObject(value);
    normalized[key] = normalizeRouteConfigForStorage(route);
  }
  return normalized;
}

function normalizeRoutesForStorage(
  routes: Record<string, RouteConfig>
): Record<string, RouteConfig & { humanize: NormalizedHumanizeConfig }> {
  const normalized: Record<string, RouteConfig & { humanize: NormalizedHumanizeConfig }> = {};
  for (const [key, value] of Object.entries(routes)) {
    const validated = validateRoute(value, key);
    normalized[key] = normalizeRouteConfigForStorage(validated);
  }
  return normalized;
}

function normalizeRouteConfigForStorage(route: RouteConfig): RouteConfig & { humanize: NormalizedHumanizeConfig } {
  const { humanize, ...rest } = ensureRouteObject(route);
  return { ...rest, humanize: normalizeHumanizeConfig(humanize as HumanizeConfig | undefined) };
}

function validateRoute(route: unknown, routeKey: string): RouteConfig {
  if (!isPlainObject(route)) {
    throw new ApiError(400, `route.${routeKey}_object_required`);
  }
  return route as RouteConfig;
}

function ensureRouteObject(value: unknown): RouteConfig {
  return isPlainObject(value) ? (value as RouteConfig) : {};
}

async function parseJsonBody(c: Context): Promise<any> {
  try {
    if (!c.req.header('content-type')?.includes('application/json')) {
      const text = await c.req.text();
      if (!text) return {};
      return JSON.parse(text);
    }
    return await c.req.json();
  } catch (err) {
    return {};
  }
}

function jsonError(c: Context, error: string, status: number = 400) {
  return c.json({ error }, status as any, JSON_HEADERS);
}

function resolveAccountId(payload: Record<string, unknown>, existing: SessionRecord | null): string {
  const idValue = typeof payload.id === 'string' ? payload.id.trim() : '';
  const accountIdValue = typeof payload.account_id === 'string' ? payload.account_id.trim() : '';
  const existingId = existing?.account_id ?? existing?.id ?? '';

  if (idValue && accountIdValue && idValue !== accountIdValue) {
    throw new ApiError(400, 'account_id_mismatch');
  }

  const resolved = idValue || accountIdValue || existingId;
  if (!resolved) {
    throw new ApiError(400, 'id_required');
  }
  return resolved;
}

function resolveTelegramApiId(value: unknown, existing: number | undefined, env: Env): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof existing === 'number' && Number.isFinite(existing)) {
    return existing;
  }
  if (typeof env.TELEGRAM_API_ID === 'string') {
    const trimmed = env.TELEGRAM_API_ID.trim();
    if (trimmed) {
      const parsed = Number(trimmed);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }
  return null;
}

function resolveTelegramApiHash(value: unknown, existing: string | null | undefined, env: Env): string | null {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? trimmed : null;
  }
  if (typeof existing === 'string') {
    return existing;
  }
  if (typeof env.TELEGRAM_API_HASH === 'string') {
    const trimmed = env.TELEGRAM_API_HASH.trim();
    if (trimmed) {
      return trimmed;
    }
  }
  return existing ?? null;
}

function coalesce<T>(...values: Array<T | null | undefined>): T {
  for (const value of values) {
    if (value !== undefined) {
      return value as T;
    }
  }
  throw new Error('Unable to coalesce value');
}

function coalesceBoolean(value: unknown, fallback: boolean | undefined | null, defaultValue: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof fallback === 'boolean') return fallback;
  return defaultValue;
}

function coalesceNumber(value: unknown, fallback: number | undefined | null, defaultValue: number): number {
  if (typeof value === 'number') return value;
  if (typeof fallback === 'number') return fallback;
  return defaultValue;
}

function resolveDisabledReason(payload: any, existing: SessionRecord | null): string | null {
  if (payload && typeof payload.enabled === 'boolean') {
    if (payload.enabled) return null;
    if (typeof payload.disabled_reason === 'string') return payload.disabled_reason;
    return existing?.disabled_reason ?? 'disabled';
  }
  if (existing) return existing.disabled_reason ?? null;
  return null;
}

function isIntegerString(value: string): boolean {
  return /^\d+$/.test(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function fnv1a(input: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

async function bumpVersion(env: Env): Promise<number> {
  const kv = env.SESSIONS_KV;
  const currentRaw = await kv.get(VERSION_KEY);
  const current = currentRaw ? Number(currentRaw) : 0;
  const next = Number.isFinite(current) ? current + 1 : 1;
  await kv.put(VERSION_KEY, String(next));
  return next;
}

async function readIndex(kv: KVNamespace): Promise<string[]> {
  const raw = await kv.get(INDEX_KEY);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.filter((entry) => typeof entry === 'string' && entry.length > 0);
    }
  } catch (err) {
    // fall through to empty
  }
  return [];
}

async function updateIndex(kv: KVNamespace, id: string, add: boolean) {
  try {
    const current = await readIndex(kv);
    const set = new Set(current);
    if (add) {
      set.add(id);
    } else {
      set.delete(id);
    }
    await kv.put(INDEX_KEY, JSON.stringify(Array.from(set)));
  } catch (err) {
    // Index is best-effort; ignore errors.
  }
}

async function fetchPasswordHint(client: TelegramClient): Promise<string | null> {
  try {
    const password = await client.invoke(new Api.account.GetPassword());
    if ('hint' in password) {
      return password.hint ?? null;
    }
    return null;
  } catch (error) {
    console.warn('failed to fetch password hint', error);
    return null;
  }
}

function isPasswordNeededError(error: any): boolean {
  if (!error) return false;
  if (typeof error === 'string') {
    return error.includes('SESSION_PASSWORD_NEEDED');
  }
  const message = (error as any).errorMessage ?? (error as any).message ?? '';
  return typeof message === 'string' && message.includes('SESSION_PASSWORD_NEEDED');
}

async function persistSession(
  env: Env,
  context: PersistSessionContext,
  sessionString: string
): Promise<PersistResult> {
  const body: Record<string, unknown> = {
    id: context.accountId,
    account_id: context.accountId,
    phone: context.phone,
    session_string: sessionString,
    telegram_api_id: context.apiId,
    telegram_api_hash: context.apiHash
  };

  for (const [key, value] of Object.entries(context.sessionDefaults)) {
    if (value !== undefined) {
      (body as any)[key] = value;
    }
  }

  if ((body as any).enabled === undefined) {
    (body as any).enabled = true;
  }
  if ((body as any).webhook_enabled === undefined) {
    (body as any).webhook_enabled = true;
  }

  return upsertSessionRecord(env, body);
}

async function saveLoginSessionSnapshot(
  env: Env,
  snapshot: LoginSessionSnapshot,
  ttlMs: number
): Promise<void> {
  try {
    const record = {
      login_id: snapshot.loginId,
      account_id: snapshot.accountId,
      phone: snapshot.phone,
      telegram_api_id: snapshot.apiId,
      telegram_api_hash: snapshot.apiHash,
      stored: snapshot.stored,
      persisted_id: snapshot.persistedId,
      version: snapshot.version,
      session_string: snapshot.sessionString,
      created_at: currentTimestamp()
    };
    const ttlSeconds = Math.ceil(ttlMs / 1000);
    const options = ttlSeconds > 0 ? { expirationTtl: ttlSeconds } : undefined;
    await env.SESSIONS_KV.put(
      loginSessionKey(snapshot.loginId),
      JSON.stringify(record),
      options as any
    );
  } catch (error) {
    console.error('failed to save login session snapshot', {
      loginId: snapshot.loginId,
      error
    });
  }
}

function extractSessionDefaults(input: SessionDefaults): SessionDefaults {
  const defaults: SessionDefaults = {};
  for (const key of SESSION_DEFAULT_KEYS) {
    const value = input[key];
    if (value !== undefined) {
      (defaults as any)[key] = value;
    }
  }
  return defaults;
}

function formatPreviewUser(user: any) {
  if (!user) return null;
  return {
    id: user.id ?? null,
    username: user.username ?? null,
    first_name: user.firstName ?? user.first_name ?? null,
    last_name: user.lastName ?? user.last_name ?? null
  };
}

async function sessionRecordExists(env: Env, accountId: string): Promise<boolean> {
  try {
    const existing = await env.SESSIONS_KV.get(accountKey(accountId), { type: 'json' });
    return Boolean(existing);
  } catch (error) {
    console.warn('failed to check session existence', { accountId, error });
    return false;
  }
}

interface LoginSessionStored {
  loginId: string;
  accountId: string;
  phone: string;
  apiId: number;
  apiHash: string;
  status: LoginStatus;
  sessionDefaults: SessionDefaults;
  phoneCodeHash?: string;
  passwordHint?: string | null;
  sessionString: string;
}

interface LoginSessionRuntime extends LoginSessionStored {
  session: StringSession;
  client: TelegramClient;
}

export class LoginSessionDurable {
  private stateData: LoginSessionRuntime | null = null;
  private clientConnected = false;
  private readonly ttlMs: number;

  constructor(private readonly state: DurableObjectState, private readonly env: Env) {
    const ttlEnv = typeof env.LOGIN_TTL_MS === 'string' ? Number(env.LOGIN_TTL_MS) : NaN;
    this.ttlMs = Number.isFinite(ttlEnv) && ttlEnv > 0 ? ttlEnv : DEFAULT_LOGIN_TTL;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'POST') {
      return new Response('Not found', { status: 404 });
    }

    switch (url.pathname) {
      case '/start':
        return this.handleStart(request);
      case '/code':
        return this.handleCode(request);
      case '/password':
        return this.handlePassword(request);
      case '/cancel':
        return this.handleCancel();
      default:
        return new Response('Not found', { status: 404 });
    }
  }

  async alarm(): Promise<void> {
    await this.cleanup();
  }

  private async handleStart(request: Request): Promise<Response> {
    const body = await this.readJson(request);
    if (!body || typeof body !== 'object') {
      return this.jsonError('invalid_json', 400);
    }

    const loginId = typeof (body as any).login_id === 'string' ? (body as any).login_id : '';
    const accountId = typeof (body as any).account_id === 'string' ? (body as any).account_id : '';
    const phone = typeof (body as any).phone === 'string' ? (body as any).phone : '';
    const apiId = Number((body as any).api_id);
    const apiHash = typeof (body as any).api_hash === 'string' ? (body as any).api_hash : '';
    const sessionDefaults = (body as any).session_defaults as SessionDefaults | undefined;

    if (!loginId || !accountId || !phone || !Number.isFinite(apiId) || !apiHash) {
      return this.jsonError('invalid_start_payload', 400);
    }

    await this.cleanup();

    const session = new StringSession('');
    const client = new TelegramClient(session, apiId, apiHash, {
      connectionRetries: 5,
      useWSS: true
    });

    try {
      await client.connect();
      this.clientConnected = true;
      const sent = await client.sendCode({ apiId, apiHash }, phone);

      this.stateData = {
        loginId,
        accountId,
        phone,
        apiId,
        apiHash,
        status: 'CODE_SENT',
        sessionDefaults: sessionDefaults ? { ...sessionDefaults } : {},
        phoneCodeHash: sent.phoneCodeHash,
        passwordHint: null,
        sessionString: session.save(),
        session,
        client
      };

      await this.saveState();
      await this.scheduleExpiration();

      return this.json({ status: 'CODE_SENT', expires_in: Math.floor(this.ttlMs / 1000) });
    } catch (error) {
      console.error('durable auth/start error', error);
      await this.disconnectClient();
      await this.cleanupStorage();
      return this.jsonError('send_code_failed', 500);
    }
  }

  private async handleCode(request: Request): Promise<Response> {
    const body = await this.readJson(request);
    const code = body && typeof body === 'object' && typeof (body as any).code === 'string'
      ? (body as any).code.trim()
      : '';
    if (!code) {
      return this.jsonError('login_id_and_code_required', 400);
    }

    const state = await this.loadState();
    if (!state) {
      return this.jsonError('login_not_found', 404);
    }

    if (state.status !== 'CODE_SENT') {
      return this.json({ error: 'invalid_state', status: state.status }, 409);
    }

    try {
      await this.ensureClient();
      await state.client.invoke(
        new Api.auth.SignIn({
          phoneNumber: state.phone,
          phoneCode: code,
          phoneCodeHash: state.phoneCodeHash ?? ''
        })
      );

      const me = await state.client.getMe();
      state.sessionString = state.session.save();
      const existingStored = await sessionRecordExists(this.env, state.accountId);
      let persistResult: PersistResult | null = null;
      try {
        persistResult = await persistSession(
          this.env,
          {
            accountId: state.accountId,
            phone: state.phone,
            apiId: state.apiId,
            apiHash: state.apiHash,
            sessionDefaults: state.sessionDefaults
          },
          state.sessionString
        );
      } catch (persistError) {
        console.error('failed to persist session after code login', persistError);
      }

      const stored = existingStored || (persistResult?.ok ?? false);

      await saveLoginSessionSnapshot(
        this.env,
        {
          loginId: state.loginId,
          accountId: state.accountId,
          phone: state.phone,
          apiId: state.apiId,
          apiHash: state.apiHash,
          sessionString: state.sessionString,
          stored,
          persistedId: persistResult?.id ?? null,
          version: persistResult?.version ?? null
        },
        this.ttlMs
      );

      await this.disconnectClient();
      await this.cleanupStorage();
      this.stateData = null;

      const response: SignedInResponse = {
        status: 'SIGNED_IN',
        stored,
        id: persistResult?.id ?? state.accountId,
        version: persistResult?.version ?? null,
        preview_user: formatPreviewUser(me),
        session_string: state.sessionString,
        telegram_api_id: state.apiId,
        telegram_api_hash: state.apiHash
      };

      return this.json(response);
    } catch (err: any) {
      if (isPasswordNeededError(err)) {
        await this.ensureClient();
        const hint = await fetchPasswordHint(state.client);
        state.status = 'PASSWORD_REQUIRED';
        state.passwordHint = hint ?? null;
        state.sessionString = state.session.save();
        await this.saveState();
        await this.scheduleExpiration();
        return this.json({ status: 'PASSWORD_REQUIRED', hint });
      }
      console.error('durable auth/code error', err);
      await this.disconnectClient();
      await this.cleanup();
      return this.jsonError('sign_in_failed', 500);
    }
  }

  private async handlePassword(request: Request): Promise<Response> {
    const body = await this.readJson(request);
    const password = body && typeof body === 'object' && typeof (body as any).password === 'string'
      ? (body as any).password
      : '';
    if (!password) {
      return this.jsonError('login_id_and_password_required', 400);
    }

    const state = await this.loadState();
    if (!state) {
      return this.jsonError('login_not_found', 404);
    }

    if (state.status !== 'PASSWORD_REQUIRED') {
      return this.json({ error: 'invalid_state', status: state.status }, 409);
    }

    try {
      await this.ensureClient();
      const passwordInfo = await state.client.invoke(new Api.account.GetPassword());
      const passwordCheck = await computeCheck(passwordInfo, password);
      await state.client.invoke(new Api.auth.CheckPassword({ password: passwordCheck }));
      const me = await state.client.getMe();
      state.sessionString = state.session.save();
      const existingStored = await sessionRecordExists(this.env, state.accountId);
      let persistResult: PersistResult | null = null;
      try {
        persistResult = await persistSession(
          this.env,
          {
            accountId: state.accountId,
            phone: state.phone,
            apiId: state.apiId,
            apiHash: state.apiHash,
            sessionDefaults: state.sessionDefaults
          },
          state.sessionString
        );
      } catch (persistError) {
        console.error('failed to persist session after password login', persistError);
      }

      const stored = existingStored || (persistResult?.ok ?? false);

      await saveLoginSessionSnapshot(
        this.env,
        {
          loginId: state.loginId,
          accountId: state.accountId,
          phone: state.phone,
          apiId: state.apiId,
          apiHash: state.apiHash,
          sessionString: state.sessionString,
          stored,
          persistedId: persistResult?.id ?? null,
          version: persistResult?.version ?? null
        },
        this.ttlMs
      );

      await this.disconnectClient();
      await this.cleanupStorage();
      this.stateData = null;

      const response: SignedInResponse = {
        status: 'SIGNED_IN',
        stored,
        id: persistResult?.id ?? state.accountId,
        version: persistResult?.version ?? null,
        preview_user: formatPreviewUser(me),
        session_string: state.sessionString,
        telegram_api_id: state.apiId,
        telegram_api_hash: state.apiHash
      };

      return this.json(response);
    } catch (err) {
      console.error('durable auth/password error', err);
      await this.disconnectClient();
      await this.cleanup();
      return this.jsonError('password_check_failed', 500);
    }
  }

  private async handleCancel(): Promise<Response> {
    const state = await this.loadState();
    if (!state) {
      return this.json({ ok: true, cancelled: false });
    }
    await this.cleanup();
    return this.json({ ok: true, cancelled: true });
  }

  private async loadState(): Promise<LoginSessionRuntime | null> {
    if (this.stateData) {
      return this.stateData;
    }
    const stored = await this.state.storage.get<LoginSessionStored>(LOGIN_STATE_KEY);
    if (!stored) {
      return null;
    }
    const session = new StringSession(stored.sessionString ?? '');
    const client = new TelegramClient(session, stored.apiId, stored.apiHash, {
      connectionRetries: 5,
      useWSS: true
    });
    this.stateData = {
      ...stored,
      session,
      client
    };
    this.clientConnected = false;
    await this.saveState();
    await this.scheduleExpiration();
    return this.stateData;
  }

  private async ensureClient(): Promise<void> {
    const state = this.stateData;
    if (!state) {
      throw new Error('login state not initialized');
    }
    if (!this.clientConnected) {
      await state.client.connect();
      this.clientConnected = true;
    }
  }

  private async saveState(): Promise<void> {
    if (!this.stateData) {
      return;
    }
    const { session, client, ...rest } = this.stateData;
    const stored: LoginSessionStored = {
      ...rest,
      sessionString: session.save()
    };
    this.stateData.sessionString = stored.sessionString;
    await this.state.storage.put(LOGIN_STATE_KEY, stored);
  }

  private async scheduleExpiration(): Promise<void> {
    await this.state.storage.setAlarm(Date.now() + this.ttlMs);
  }

  private async disconnectClient(): Promise<void> {
    if (this.stateData && this.clientConnected) {
      try {
        await this.stateData.client.disconnect();
      } catch (err) {
        console.warn('failed to disconnect telegram client', err);
      }
    }
    this.clientConnected = false;
  }

  private async cleanupStorage(): Promise<void> {
    await this.state.storage.delete(LOGIN_STATE_KEY);
  }

  private async cleanup(): Promise<void> {
    await this.disconnectClient();
    await this.cleanupStorage();
    this.stateData = null;
  }

  private async readJson(request: Request): Promise<any> {
    try {
      return await request.json();
    } catch {
      return null;
    }
  }

  private json(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
  }

  private jsonError(code: string, status: number): Response {
    return this.json({ error: code }, status);
  }
}

async function upsertSessionRecord(env: Env, payload: Record<string, unknown>): Promise<PersistResult> {
  const kv = env.SESSIONS_KV;
  const provisionalId =
    typeof payload.id === 'string'
      ? payload.id.trim()
      : typeof payload.account_id === 'string'
        ? payload.account_id.trim()
        : '';
  const existing = provisionalId
    ? ((await kv.get(accountKey(provisionalId), { type: 'json' })) as SessionRecord | null)
    : null;
  const idRaw = resolveAccountId(payload, existing);
  const key = accountKey(idRaw);
  
  let sessionString = existing?.session_string ?? null;
  if (typeof payload.session_string === 'string' && payload.session_string.length > 0) {
    sessionString = payload.session_string;
  }

  if (!sessionString) {
    throw new ApiError(400, 'session_string_required');
  }

  const now = currentTimestamp();
  const telegramApiId = resolveTelegramApiId(payload.telegram_api_id, existing?.telegram_api_id, env);
  if (telegramApiId === null) {
    throw new ApiError(400, 'telegram_api_id_required');
  }

  const telegramApiHash = resolveTelegramApiHash(payload.telegram_api_hash, existing?.telegram_api_hash, env);

  const record: SessionRecord = {
    id: idRaw,
    account_id: idRaw,
    phone: coalesce(payload.phone as any, existing?.phone, null),
    telegram_api_id: telegramApiId,
    telegram_api_hash: telegramApiHash,
    session_string: sessionString,
    webhook_url:
      typeof payload.webhook_url === 'string'
        ? payload.webhook_url
        : typeof existing?.webhook_url === 'string'
          ? existing.webhook_url
          : null,
    webhook_enabled: coalesceBoolean(payload.webhook_enabled, existing?.webhook_enabled, true),
    allowed_chat_types: coalesce(payload.allowed_chat_types as any, existing?.allowed_chat_types, DEFAULT_ALLOWED_CHAT_TYPES),
    group_allowlist: coalesce(payload.group_allowlist as any, existing?.group_allowlist, ''),
    enrich_deep: coalesceBoolean(payload.enrich_deep, existing?.enrich_deep, true),
    enrich_reply: coalesceBoolean(payload.enrich_reply, existing?.enrich_reply, false),
    heavy_sender_resolve: coalesceBoolean(payload.heavy_sender_resolve, existing?.heavy_sender_resolve, true),
    participants_limit: coalesceNumber(payload.participants_limit, existing?.participants_limit, DEFAULT_PARTICIPANTS_LIMIT),
    cache_ttl_ms: coalesceNumber(payload.cache_ttl_ms, existing?.cache_ttl_ms, DEFAULT_CACHE_TTL),
    enabled: coalesceBoolean(payload.enabled, existing?.enabled, true),
    disabled_reason: resolveDisabledReason(payload, existing),
    created_at: existing?.created_at ?? now,
    updated_at: now
  };

  await kv.put(key, JSON.stringify(record));
  await updateIndex(kv, idRaw, true);
  const version = await bumpVersion(env);
  return { ok: true, id: idRaw, version };
}

async function persistSignedInResult(env: Env, signedIn: SignedInResponse): Promise<{ stored: boolean; version: number | null }> {
  if (signedIn.stored && signedIn.version !== null) {
    return { stored: signedIn.stored, version: signedIn.version };
  }

  try {
    const payload: Record<string, unknown> = {
      id: signedIn.id,
      account_id: signedIn.id,
      session_string: signedIn.session_string,
      telegram_api_id: signedIn.telegram_api_id,
      telegram_api_hash: signedIn.telegram_api_hash,
      webhook_url: null,
      webhook_enabled: true,
      enabled: true
    };

    const result = await upsertSessionRecord(env, payload);
    return { stored: true, version: result.version };
  } catch (error) {
    console.error('failed to persist session from signed-in response', {
      id: signedIn.id,
      error
    });
    return { stored: signedIn.stored, version: signedIn.version ?? null };
  }
}

const app = createApp();

export default {
  fetch(request: Request, env: Env, executionCtx: ExecutionContext): Promise<Response> {
    return Promise.resolve(app.fetch(request, env, executionCtx));
  }
};
