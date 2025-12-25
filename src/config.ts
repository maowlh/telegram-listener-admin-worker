import { ApiError } from './errors';

export interface HumanizeConfig {
  enabled?: boolean;
  reply_probability?: number;
  delay_min_ms?: number;
  delay_max_ms?: number;
  typing_min_ms?: number;
  typing_max_ms?: number;
  cooldown_sender_sec?: number;
  cooldown_chat_sec?: number;
  require_question_or_keywords?: boolean;
  keywords?: string[];
  ignore_short_messages_lt?: number;
  max_replies_per_chat_per_hour?: number;
  max_replies_per_account_per_day?: number;
  variation_openers?: string[];
  variation_closers?: string[];
  emoji_pool?: string[];
  emoji_probability?: number;
  max_emojis?: number;
  allow_reply_to_self_without_keywords?: boolean;
  queue_on_cooldown?: boolean;
  queue_on_rate_limit?: boolean;
  queue_on_probability?: boolean;
  queue_on_filter?: boolean;
}

export type NormalizedHumanizeConfig = Required<HumanizeConfig>;

export interface RouteConfig {
  humanize?: HumanizeConfig;
  [key: string]: unknown;
}

export const RECOMMENDED_HUMANIZE_DEFAULTS: NormalizedHumanizeConfig = {
  enabled: true,
  reply_probability: 0.65,
  delay_min_ms: 10_000,
  delay_max_ms: 60_000,
  typing_min_ms: 800,
  typing_max_ms: 2_500,
  cooldown_sender_sec: 900,
  cooldown_chat_sec: 180,
  require_question_or_keywords: true,
  keywords: ['خرید', 'قیمت', 'بخر', 'از کجا', 'چطور', 'chatgpt', 'gpt', 'اشتراک', 'تحریم'],
  ignore_short_messages_lt: 3,
  max_replies_per_chat_per_hour: 25,
  max_replies_per_account_per_day: 250,
  variation_openers: ['ببین', 'راستش', 'آره دقیقاً', 'اوکی', 'یه نکته'],
  variation_closers: ['اگه خواستی راهنمایی‌ت می‌کنم', 'بگو دقیقاً چی مدنظرتِ', 'اگه سوال داری بپرس'],
  emoji_pool: ['🙂', '😅', '👌'],
  emoji_probability: 0.25,
  max_emojis: 1,
  allow_reply_to_self_without_keywords: true,
  queue_on_cooldown: true,
  queue_on_rate_limit: true,
  queue_on_probability: false,
  queue_on_filter: false
};

type NumericField =
  | 'reply_probability'
  | 'delay_min_ms'
  | 'delay_max_ms'
  | 'typing_min_ms'
  | 'typing_max_ms'
  | 'cooldown_sender_sec'
  | 'cooldown_chat_sec'
  | 'ignore_short_messages_lt'
  | 'max_replies_per_chat_per_hour'
  | 'max_replies_per_account_per_day'
  | 'emoji_probability'
  | 'max_emojis';

const NUMERIC_LIMITS: Record<NumericField, { min: number; max: number }> = {
  reply_probability: { min: 0, max: 1 },
  delay_min_ms: { min: 0, max: 600_000 },
  delay_max_ms: { min: 0, max: 600_000 },
  typing_min_ms: { min: 0, max: 10_000 },
  typing_max_ms: { min: 0, max: 10_000 },
  cooldown_sender_sec: { min: 0, max: 86_400 },
  cooldown_chat_sec: { min: 0, max: 86_400 },
  ignore_short_messages_lt: { min: 0, max: 50 },
  max_replies_per_chat_per_hour: { min: 0, max: 1_000 },
  max_replies_per_account_per_day: { min: 0, max: 100_000 },
  emoji_probability: { min: 0, max: 1 },
  max_emojis: { min: 0, max: 2 }
};

export function normalizeHumanizeConfig(routeHumanize?: HumanizeConfig): NormalizedHumanizeConfig {
  const normalized: NormalizedHumanizeConfig = {
    enabled: true,
    reply_probability: 1,
    delay_min_ms: 0,
    delay_max_ms: 0,
    typing_min_ms: 0,
    typing_max_ms: 0,
    cooldown_sender_sec: 0,
    cooldown_chat_sec: 0,
    require_question_or_keywords: false,
    keywords: [],
    ignore_short_messages_lt: 0,
    max_replies_per_chat_per_hour: 0,
    max_replies_per_account_per_day: 0,
    variation_openers: [],
    variation_closers: [],
    emoji_pool: [],
    emoji_probability: 0,
    max_emojis: 1,
    allow_reply_to_self_without_keywords: true,
    queue_on_cooldown: true,
    queue_on_rate_limit: true,
    queue_on_probability: false,
    queue_on_filter: false
  };

  if (!routeHumanize) {
    return normalized;
  }

  if (typeof routeHumanize !== 'object' || Array.isArray(routeHumanize)) {
    throw new ApiError(400, 'humanize_object_required');
  }

  const humanize = routeHumanize as Record<string, unknown>;

  if ('enabled' in humanize) {
    normalized.enabled = asBoolean(humanize.enabled, 'humanize.enabled');
  }

  for (const field of Object.keys(NUMERIC_LIMITS) as NumericField[]) {
    if (field in humanize) {
      const value = asNumber(humanize[field], `humanize.${field}`);
      normalized[field] = clamp(value, NUMERIC_LIMITS[field].min, NUMERIC_LIMITS[field].max) as any;
    }
  }

  normalized.keywords = normalizeKeywords(humanize.keywords);
  if ('require_question_or_keywords' in humanize) {
    normalized.require_question_or_keywords = asBoolean(
      humanize.require_question_or_keywords,
      'humanize.require_question_or_keywords'
    );
  }

  if ('allow_reply_to_self_without_keywords' in humanize) {
    normalized.allow_reply_to_self_without_keywords = asBoolean(
      humanize.allow_reply_to_self_without_keywords,
      'humanize.allow_reply_to_self_without_keywords'
    );
  }

  if ('queue_on_cooldown' in humanize) {
    normalized.queue_on_cooldown = asBoolean(humanize.queue_on_cooldown, 'humanize.queue_on_cooldown');
  }

  if ('queue_on_rate_limit' in humanize) {
    normalized.queue_on_rate_limit = asBoolean(humanize.queue_on_rate_limit, 'humanize.queue_on_rate_limit');
  }

  if ('queue_on_probability' in humanize) {
    normalized.queue_on_probability = asBoolean(humanize.queue_on_probability, 'humanize.queue_on_probability');
  }

  if ('queue_on_filter' in humanize) {
    normalized.queue_on_filter = asBoolean(humanize.queue_on_filter, 'humanize.queue_on_filter');
  }

  normalized.variation_openers = normalizeStringList(humanize.variation_openers, 'humanize.variation_openers', 20, false);
  normalized.variation_closers = normalizeStringList(humanize.variation_closers, 'humanize.variation_closers', 20, false);
  normalized.emoji_pool = normalizeStringList(humanize.emoji_pool, 'humanize.emoji_pool', 20, false);

  const [delayMin, delayMax] = swapIfNeeded(normalized.delay_min_ms, normalized.delay_max_ms);
  normalized.delay_min_ms = delayMin;
  normalized.delay_max_ms = delayMax;

  const [typingMin, typingMax] = swapIfNeeded(normalized.typing_min_ms, normalized.typing_max_ms);
  normalized.typing_min_ms = typingMin;
  normalized.typing_max_ms = typingMax;

  return normalized;
}

function swapIfNeeded(min: number, max: number): [number, number] {
  return min > max ? [max, min] : [min, max];
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function asBoolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    throw new ApiError(400, `${field}_boolean_required`);
  }
  return value;
}

function asNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    throw new ApiError(400, `${field}_number_required`);
  }
  return value;
}

function normalizeKeywords(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ApiError(400, 'humanize.keywords_array_required');
  }
  const seen = new Set<string>();
  const keywords: string[] = [];

  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new ApiError(400, 'humanize.keywords_string_required');
    }
    const normalized = entry.trim().toLowerCase();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    keywords.push(normalized);
    if (keywords.length >= 50) break;
  }
  return keywords;
}

function normalizeStringList(
  value: unknown,
  field: string,
  maxLength: number,
  lowercase: boolean
): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ApiError(400, `${field}_array_required`);
  }
  const list: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new ApiError(400, `${field}_string_required`);
    }
    const normalized = lowercase ? entry.trim().toLowerCase() : entry.trim();
    if (!normalized) continue;
    list.push(normalized);
    if (list.length >= maxLength) break;
  }
  return list;
}
