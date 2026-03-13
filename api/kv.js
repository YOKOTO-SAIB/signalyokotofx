import { Redis } from '@upstash/redis';

const kv = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const ADMIN_TOKEN = 'yokotoadminfx';

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function ok(res, data) {
  cors(res);
  return res.status(200).json({ ok: true, ...data });
}

function err(res, msg, code = 400) {
  cors(res);
  return res.status(code).json({ ok: false, error: msg });
}

// ── helpers ──────────────────────────────────────────
function genToken(len = 16) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let t = '';
  for (let i = 0; i < len; i++) t += chars[Math.floor(Math.random() * chars.length)];
  return 'NX-' + t;
}

function parseDuration(str) {
  // e.g. "30d" "7d" "24h" "60m"
  const m = String(str).match(/^(\d+)(d|h|m)$/i);
  if (!m) return null;
  const n = parseInt(m[1]);
  const unit = m[2].toLowerCase();
  if (unit === 'd') return n * 86400 * 1000;
  if (unit === 'h') return n * 3600 * 1000;
  if (unit === 'm') return n * 60 * 1000;
  return null;
}

// ── main handler ─────────────────────────────────────
export default async function handler(req, res) {
  if (req.method === 'OPTIONS') { cors(res); return res.status(200).end(); }
  cors(res);

  const { action } = req.query;

  // ══════════════════════════════════════════
  //  AUTH CHECK (admin actions)
  // ══════════════════════════════════════════
  const adminActions = [
    'admin.tokens.list','admin.tokens.add','admin.tokens.edit','admin.tokens.delete',
    'admin.products.list','admin.products.add','admin.products.edit','admin.products.delete',
    'admin.config.get','admin.config.set',
    'admin.history.all',
  ];
  if (adminActions.includes(action)) {
    const auth = req.headers.authorization || '';
    if (auth !== `Bearer ${ADMIN_TOKEN}`) return err(res, 'Unauthorized', 401);
  }

  try {
    // ══════════════════════════════════════════
    //  TOKEN: VALIDATE (user login)
    // ══════════════════════════════════════════
    if (action === 'token.validate') {
      const { token } = req.body || {};
      if (!token) return err(res, 'Token required');
      if (token === ADMIN_TOKEN) return ok(res, { role: 'admin' });

      const data = await kv.hgetall(`token:${token}`);
      if (!data) return err(res, 'Token tidak ditemukan');

      // Check activated
      const now = Date.now();
      if (!data.activated_at) {
        // First use — activate now
        const dur = parseDuration(data.duration);
        if (!dur) return err(res, 'Durasi token invalid');
        const expires_at = now + dur;
        await kv.hset(`token:${token}`, { activated_at: now, expires_at });
        data.activated_at = now;
        data.expires_at = expires_at;
      }

      if (parseInt(data.expires_at) < now) return err(res, 'Token sudah expired');

      // Check delay (cooldown)
      const config = await kv.hgetall('config') || {};
      const delayMs = parseDuration(data.delay || config.default_delay || '0m') || 0;
      if (delayMs > 0 && data.last_analysis) {
        const since = now - parseInt(data.last_analysis);
        if (since < delayMs) {
          const wait = Math.ceil((delayMs - since) / 1000);
          return err(res, `Cooldown aktif. Tunggu ${Math.floor(wait/3600)}j ${Math.floor((wait%3600)/60)}m ${wait%60}d lagi.`);
        }
      }

      return ok(res, {
        role: 'user',
        name: data.name,
        expires_at: parseInt(data.expires_at),
        activated_at: parseInt(data.activated_at),
        analysis_count: parseInt(data.analysis_count || 0),
        delay: data.delay || config.default_delay || '0m',
        last_analysis: data.last_analysis ? parseInt(data.last_analysis) : null,
        gemini_key: config.gemini_key || '',
        gemini_model: config.gemini_model || 'gemini-2.5-flash',
      });
    }

    // ══════════════════════════════════════════
    //  TOKEN: RECORD ANALYSIS
    // ══════════════════════════════════════════
    if (action === 'token.record') {
      const { token, signal, pair, tf, confidence } = req.body || {};
      if (!token) return err(res, 'Token required');

      const now = Date.now();
      const count = parseInt((await kv.hget(`token:${token}`, 'analysis_count')) || 0) + 1;
      await kv.hset(`token:${token}`, { last_analysis: now, analysis_count: count });

      // Push to history list (keep last 100)
      const entry = JSON.stringify({ ts: now, signal, pair, tf, confidence });
      await kv.lpush(`history:${token}`, entry);
      await kv.ltrim(`history:${token}`, 0, 99);

      return ok(res, { count });
    }

    // ══════════════════════════════════════════
    //  PRODUCTS: PUBLIC LIST
    // ══════════════════════════════════════════
    if (action === 'products.list') {
      const raw = await kv.get('products') || '[]';
      const products = typeof raw === 'string' ? JSON.parse(raw) : raw;
      return ok(res, { products });
    }

    // ══════════════════════════════════════════
    //  ADMIN: TOKENS LIST
    // ══════════════════════════════════════════
    if (action === 'admin.tokens.list') {
      const keys = await kv.keys('token:*');
      const tokens = [];
      for (const k of keys) {
        const d = await kv.hgetall(k);
        if (d) tokens.push({ token: k.replace('token:', ''), ...d });
      }
      tokens.sort((a, b) => parseInt(b.created_at || 0) - parseInt(a.created_at || 0));
      return ok(res, { tokens });
    }

    // ══════════════════════════════════════════
    //  ADMIN: TOKEN ADD
    // ══════════════════════════════════════════
    if (action === 'admin.tokens.add') {
      const { name, duration, delay, custom_token } = req.body || {};
      if (!name || !duration) return err(res, 'name dan duration wajib');
      if (!parseDuration(duration)) return err(res, 'Format duration salah. Contoh: 30d, 24h, 60m');
      const token = custom_token || genToken();
      const exists = await kv.hgetall(`token:${token}`);
      if (exists) return err(res, 'Token sudah ada');
      await kv.hset(`token:${token}`, {
        name,
        duration,
        delay: delay || '0m',
        created_at: Date.now(),
        activated_at: '',
        expires_at: '',
        last_analysis: '',
        analysis_count: 0,
      });
      return ok(res, { token });
    }

    // ══════════════════════════════════════════
    //  ADMIN: TOKEN EDIT
    // ══════════════════════════════════════════
    if (action === 'admin.tokens.edit') {
      const { token, name, duration, delay, reset_expiry } = req.body || {};
      if (!token) return err(res, 'Token required');
      const exists = await kv.hgetall(`token:${token}`);
      if (!exists) return err(res, 'Token tidak ditemukan');
      const upd = {};
      if (name) upd.name = name;
      if (duration) {
        if (!parseDuration(duration)) return err(res, 'Format duration salah');
        upd.duration = duration;
      }
      if (delay !== undefined) upd.delay = delay;
      if (reset_expiry) {
        // Reset: clear activated so next use restarts timer
        upd.activated_at = '';
        upd.expires_at = '';
      }
      await kv.hset(`token:${token}`, upd);
      return ok(res, { token });
    }

    // ══════════════════════════════════════════
    //  ADMIN: TOKEN DELETE
    // ══════════════════════════════════════════
    if (action === 'admin.tokens.delete') {
      const { token } = req.body || {};
      if (!token) return err(res, 'Token required');
      await kv.del(`token:${token}`);
      await kv.del(`history:${token}`);
      return ok(res, { deleted: token });
    }

    // ══════════════════════════════════════════
    //  ADMIN: TOKEN HISTORY
    // ══════════════════════════════════════════
    if (action === 'admin.history.all') {
      const { token } = req.query;
      if (!token) return err(res, 'Token required');
      const raw = await kv.lrange(`history:${token}`, 0, 99);
      const history = raw.map(r => typeof r === 'string' ? JSON.parse(r) : r);
      return ok(res, { history });
    }

    // ══════════════════════════════════════════
    //  ADMIN: PRODUCTS
    // ══════════════════════════════════════════
    if (action === 'admin.products.list') {
      const raw = await kv.get('products') || '[]';
      const products = typeof raw === 'string' ? JSON.parse(raw) : raw;
      return ok(res, { products });
    }

    if (action === 'admin.products.add') {
      const { name, price, duration, description, buy_link, badge } = req.body || {};
      if (!name || !price || !buy_link) return err(res, 'name, price, buy_link wajib');
      const raw = await kv.get('products') || '[]';
      const products = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const id = 'p_' + Date.now();
      products.push({ id, name, price, duration, description, buy_link, badge, created_at: Date.now() });
      await kv.set('products', JSON.stringify(products));
      return ok(res, { id });
    }

    if (action === 'admin.products.edit') {
      const { id, ...fields } = req.body || {};
      if (!id) return err(res, 'id required');
      const raw = await kv.get('products') || '[]';
      const products = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const idx = products.findIndex(p => p.id === id);
      if (idx === -1) return err(res, 'Produk tidak ditemukan');
      products[idx] = { ...products[idx], ...fields };
      await kv.set('products', JSON.stringify(products));
      return ok(res, { id });
    }

    if (action === 'admin.products.delete') {
      const { id } = req.body || {};
      if (!id) return err(res, 'id required');
      const raw = await kv.get('products') || '[]';
      let products = typeof raw === 'string' ? JSON.parse(raw) : raw;
      products = products.filter(p => p.id !== id);
      await kv.set('products', JSON.stringify(products));
      return ok(res, { deleted: id });
    }

    // ══════════════════════════════════════════
    //  ADMIN: CONFIG (gemini key, model, delay)
    // ══════════════════════════════════════════
    if (action === 'admin.config.get') {
      const config = await kv.hgetall('config') || {};
      return ok(res, { config });
    }

    if (action === 'admin.config.set') {
      const fields = req.body || {};
      await kv.hset('config', fields);
      return ok(res, { saved: true });
    }

    return err(res, 'Unknown action');

  } catch (e) {
    console.error(e);
    return err(res, 'Server error: ' + e.message, 500);
  }
}
