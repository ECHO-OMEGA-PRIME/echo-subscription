// Echo Subscription v1.0.0 — AI-Powered Subscription Billing
// Cloudflare Worker: D1 + KV + Service Bindings

interface Env {
  DB: D1Database;
  SB_CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY: string;
}

interface RLState { c: number; t: number }

function sanitize(s: unknown, max = 500): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x1f]/g, '').slice(0, max);
}

function jsonOk(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}
function jsonErr(msg: string, status = 400) {
  return jsonOk({ ok: false, error: msg }, status);
}

function authOk(req: Request, env: Env): boolean {
  const key = req.headers.get('X-Echo-API-Key') || req.headers.get('Authorization')?.replace('Bearer ', '') || '';
  return key === env.ECHO_API_KEY;
}

async function rateLimit(kv: KVNamespace, key: string, max: number, windowMs: number): Promise<boolean> {
  const raw = await kv.get(key);
  const now = Date.now();
  if (!raw) { await kv.put(key, JSON.stringify({ c: 1, t: now }), { expirationTtl: Math.ceil(windowMs / 1000) + 60 }); return true; }
  const state: RLState = JSON.parse(raw);
  const elapsed = now - state.t;
  const decay = elapsed / windowMs;
  const count = Math.max(0, state.c * (1 - decay)) + 1;
  await kv.put(key, JSON.stringify({ c: count, t: now }), { expirationTtl: Math.ceil(windowMs / 1000) + 60 });
  return count <= max;
}

function ip(req: Request): string { return req.headers.get('CF-Connecting-IP') || 'unknown'; }

function calcPeriodEnd(start: string, interval: string, count: number): string {
  const d = new Date(start);
  if (interval === 'yearly') d.setFullYear(d.getFullYear() + count);
  else if (interval === 'weekly') d.setDate(d.getDate() + 7 * count);
  else if (interval === 'daily') d.setDate(d.getDate() + count);
  else d.setMonth(d.getMonth() + count);
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function now(): string { return new Date().toISOString().slice(0, 19).replace('T', ' '); }
function today(): string { return new Date().toISOString().slice(0, 10); }

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,X-Echo-API-Key,Authorization' } });

    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;

    // Health
    if (p === '/health' || p === '/') return jsonOk({ ok: true, service: 'echo-subscription', version: '1.0.0', timestamp: now() });

    // Rate limit GET
    if (m === 'GET' && !(await rateLimit(env.SB_CACHE, `rl:${ip(req)}`, 60, 60000))) return jsonErr('Rate limited', 429);
    // Rate limit + auth for writes
    if (m !== 'GET') {
      if (!authOk(req, env)) return jsonErr('Unauthorized', 401);
      if (!(await rateLimit(env.SB_CACHE, `rl:w:${ip(req)}`, 30, 60000))) return jsonErr('Rate limited', 429);
    }

    const db = env.DB;
    let body: Record<string, unknown> = {};
    if (m === 'POST' || m === 'PUT') { try { body = await req.json() as Record<string, unknown>; } catch { return jsonErr('Invalid JSON'); } }

    // ── Organizations ──
    if (p === '/orgs' && m === 'GET') {
      const rows = await db.prepare('SELECT * FROM organizations WHERE status=? ORDER BY created_at DESC').bind('active').all();
      return jsonOk({ ok: true, organizations: rows.results });
    }
    if (p === '/orgs' && m === 'POST') {
      const name = sanitize(body.name); const slug = sanitize(body.slug, 100);
      if (!name || !slug) return jsonErr('name, slug required');
      await db.prepare('INSERT INTO organizations (name,slug,currency,tax_rate,dunning_attempts,dunning_interval_days,grace_period_days,webhook_url) VALUES (?,?,?,?,?,?,?,?)').bind(name, slug, sanitize(body.currency as string) || 'USD', Number(body.tax_rate) || 0, Number(body.dunning_attempts) || 3, Number(body.dunning_interval_days) || 3, Number(body.grace_period_days) || 7, sanitize(body.webhook_url as string, 1000) || null).run();
      return jsonOk({ ok: true, message: 'Organization created' }, 201);
    }
    const orgMatch = p.match(/^\/orgs\/(\d+)$/);
    if (orgMatch && m === 'GET') {
      const org = await db.prepare('SELECT * FROM organizations WHERE id=?').bind(Number(orgMatch[1])).first();
      return org ? jsonOk({ ok: true, organization: org }) : jsonErr('Not found', 404);
    }
    if (orgMatch && m === 'PUT') {
      const id = Number(orgMatch[1]);
      const fields: string[] = []; const vals: unknown[] = [];
      for (const k of ['name', 'currency', 'tax_rate', 'dunning_attempts', 'dunning_interval_days', 'grace_period_days', 'webhook_url', 'webhook_secret']) {
        if (body[k] !== undefined) { fields.push(`${k}=?`); vals.push(typeof body[k] === 'string' ? sanitize(body[k] as string, 1000) : body[k]); }
      }
      if (!fields.length) return jsonErr('No fields to update');
      fields.push('updated_at=?'); vals.push(now()); vals.push(id);
      await db.prepare(`UPDATE organizations SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
      return jsonOk({ ok: true, message: 'Updated' });
    }

    // ── Plans ──
    if (p === '/plans' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const q = orgId ? 'SELECT * FROM plans WHERE org_id=? ORDER BY sort_order,price' : 'SELECT * FROM plans ORDER BY sort_order,price';
      const rows = orgId ? await db.prepare(q).bind(Number(orgId)).all() : await db.prepare(q).all();
      return jsonOk({ ok: true, plans: rows.results });
    }
    if (p === '/plans' && m === 'POST') {
      const { org_id, name: pname, slug: pslug, price, interval } = body as Record<string, unknown>;
      if (!org_id || !pname || !pslug || price === undefined) return jsonErr('org_id, name, slug, price required');
      await db.prepare('INSERT INTO plans (org_id,name,slug,description,price,currency,interval,interval_count,trial_days,setup_fee,features,is_public,sort_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
        Number(org_id), sanitize(pname), sanitize(pslug, 100), sanitize(body.description as string, 1000) || null, Number(price), sanitize(body.currency as string) || 'USD',
        sanitize(interval as string) || 'monthly', Number(body.interval_count) || 1, Number(body.trial_days) || 0, Number(body.setup_fee) || 0,
        JSON.stringify(body.features || []), body.is_public === false ? 0 : 1, Number(body.sort_order) || 0
      ).run();
      return jsonOk({ ok: true, message: 'Plan created' }, 201);
    }
    const planMatch = p.match(/^\/plans\/(\d+)$/);
    if (planMatch && m === 'GET') {
      const plan = await db.prepare('SELECT * FROM plans WHERE id=?').bind(Number(planMatch[1])).first();
      return plan ? jsonOk({ ok: true, plan }) : jsonErr('Not found', 404);
    }
    if (planMatch && m === 'PUT') {
      const id = Number(planMatch[1]);
      const fields: string[] = []; const vals: unknown[] = [];
      for (const k of ['name', 'description', 'price', 'interval', 'interval_count', 'trial_days', 'setup_fee', 'is_public', 'sort_order', 'status']) {
        if (body[k] !== undefined) { fields.push(`${k}=?`); vals.push(typeof body[k] === 'string' ? sanitize(body[k] as string) : body[k]); }
      }
      if (body.features !== undefined) { fields.push('features=?'); vals.push(JSON.stringify(body.features)); }
      if (!fields.length) return jsonErr('No fields');
      fields.push('updated_at=?'); vals.push(now()); vals.push(id);
      await db.prepare(`UPDATE plans SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
      return jsonOk({ ok: true, message: 'Plan updated' });
    }

    // ── Addons ──
    if (p === '/addons' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const rows = orgId ? await db.prepare('SELECT * FROM addons WHERE org_id=? AND status=?').bind(Number(orgId), 'active').all() : await db.prepare('SELECT * FROM addons WHERE status=?').bind('active').all();
      return jsonOk({ ok: true, addons: rows.results });
    }
    if (p === '/addons' && m === 'POST') {
      const { org_id, name: aname, slug: aslug, price: aprice } = body as Record<string, unknown>;
      if (!org_id || !aname || !aslug || aprice === undefined) return jsonErr('org_id, name, slug, price required');
      await db.prepare('INSERT INTO addons (org_id,name,slug,description,price,billing_type,unit_name,included_units,overage_price) VALUES (?,?,?,?,?,?,?,?,?)').bind(
        Number(org_id), sanitize(aname), sanitize(aslug, 100), sanitize(body.description as string, 1000) || null, Number(aprice),
        sanitize(body.billing_type as string) || 'flat', sanitize(body.unit_name as string) || 'unit', Number(body.included_units) || 0, Number(body.overage_price) || 0
      ).run();
      return jsonOk({ ok: true, message: 'Addon created' }, 201);
    }

    // ── Customers ──
    if (p === '/customers' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const rows = orgId ? await db.prepare('SELECT * FROM customers WHERE org_id=? ORDER BY created_at DESC LIMIT 100').bind(Number(orgId)).all() : await db.prepare('SELECT * FROM customers ORDER BY created_at DESC LIMIT 100').all();
      return jsonOk({ ok: true, customers: rows.results });
    }
    if (p === '/customers' && m === 'POST') {
      const { org_id, email, name: cname } = body as Record<string, unknown>;
      if (!org_id || !email) return jsonErr('org_id, email required');
      await db.prepare('INSERT INTO customers (org_id,email,name,company,phone,payment_method,tax_id,metadata) VALUES (?,?,?,?,?,?,?,?)').bind(
        Number(org_id), sanitize(email as string, 255), sanitize(cname as string) || null, sanitize(body.company as string) || null,
        sanitize(body.phone as string, 20) || null, sanitize(body.payment_method as string) || null, sanitize(body.tax_id as string, 50) || null,
        JSON.stringify(body.metadata || {})
      ).run();
      return jsonOk({ ok: true, message: 'Customer created' }, 201);
    }
    const custMatch = p.match(/^\/customers\/(\d+)$/);
    if (custMatch && m === 'GET') {
      const c = await db.prepare('SELECT * FROM customers WHERE id=?').bind(Number(custMatch[1])).first();
      if (!c) return jsonErr('Not found', 404);
      const subs = await db.prepare('SELECT s.*,p.name as plan_name,p.price as plan_price,p.interval as plan_interval FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.customer_id=? ORDER BY s.created_at DESC').bind(c.id).all();
      return jsonOk({ ok: true, customer: c, subscriptions: subs.results });
    }
    if (custMatch && m === 'PUT') {
      const id = Number(custMatch[1]);
      const fields: string[] = []; const vals: unknown[] = [];
      for (const k of ['name', 'email', 'company', 'phone', 'payment_method', 'payment_token', 'tax_id', 'status']) {
        if (body[k] !== undefined) { fields.push(`${k}=?`); vals.push(sanitize(body[k] as string, 500)); }
      }
      if (body.metadata !== undefined) { fields.push('metadata=?'); vals.push(JSON.stringify(body.metadata)); }
      if (!fields.length) return jsonErr('No fields');
      fields.push('updated_at=?'); vals.push(now()); vals.push(id);
      await db.prepare(`UPDATE customers SET ${fields.join(',')} WHERE id=?`).bind(...vals).run();
      return jsonOk({ ok: true, message: 'Customer updated' });
    }

    // ── Coupons ──
    if (p === '/coupons' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const rows = orgId ? await db.prepare('SELECT * FROM coupons WHERE org_id=? AND status=?').bind(Number(orgId), 'active').all() : await db.prepare('SELECT * FROM coupons WHERE status=?').bind('active').all();
      return jsonOk({ ok: true, coupons: rows.results });
    }
    if (p === '/coupons' && m === 'POST') {
      const { org_id, code, discount_type, discount_value } = body as Record<string, unknown>;
      if (!org_id || !code || discount_value === undefined) return jsonErr('org_id, code, discount_value required');
      await db.prepare('INSERT INTO coupons (org_id,code,name,discount_type,discount_value,duration,duration_months,max_redemptions,valid_from,valid_until) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(
        Number(org_id), sanitize(code as string, 50).toUpperCase(), sanitize(body.name as string) || null, sanitize(discount_type as string) || 'percent',
        Number(discount_value), sanitize(body.duration as string) || 'once', Number(body.duration_months) || null,
        Number(body.max_redemptions) || null, sanitize(body.valid_from as string) || null, sanitize(body.valid_until as string) || null
      ).run();
      return jsonOk({ ok: true, message: 'Coupon created' }, 201);
    }
    const couponValidate = p.match(/^\/coupons\/validate\/(.+)$/);
    if (couponValidate && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const coupon = await db.prepare('SELECT * FROM coupons WHERE code=? AND org_id=? AND status=?').bind(couponValidate[1].toUpperCase(), Number(orgId), 'active').first();
      if (!coupon) return jsonOk({ ok: true, valid: false, reason: 'Coupon not found or inactive' });
      if (coupon.max_redemptions && (coupon.redemptions as number) >= (coupon.max_redemptions as number)) return jsonOk({ ok: true, valid: false, reason: 'Max redemptions reached' });
      if (coupon.valid_until && new Date(coupon.valid_until as string) < new Date()) return jsonOk({ ok: true, valid: false, reason: 'Expired' });
      return jsonOk({ ok: true, valid: true, coupon });
    }

    // ── Subscriptions ──
    if (p === '/subscriptions' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const status = url.searchParams.get('status');
      let q = 'SELECT s.*,c.email as customer_email,c.name as customer_name,p.name as plan_name,p.price as plan_price,p.interval as plan_interval FROM subscriptions s JOIN customers c ON s.customer_id=c.id JOIN plans p ON s.plan_id=p.id';
      const conditions: string[] = []; const binds: unknown[] = [];
      if (orgId) { conditions.push('s.org_id=?'); binds.push(Number(orgId)); }
      if (status) { conditions.push('s.status=?'); binds.push(status); }
      if (conditions.length) q += ' WHERE ' + conditions.join(' AND ');
      q += ' ORDER BY s.created_at DESC LIMIT 200';
      const rows = await db.prepare(q).bind(...binds).all();
      return jsonOk({ ok: true, subscriptions: rows.results });
    }
    if (p === '/subscriptions' && m === 'POST') {
      const { org_id, customer_id, plan_id } = body as Record<string, unknown>;
      if (!org_id || !customer_id || !plan_id) return jsonErr('org_id, customer_id, plan_id required');
      const plan = await db.prepare('SELECT * FROM plans WHERE id=?').bind(Number(plan_id)).first();
      if (!plan) return jsonErr('Plan not found', 404);
      const n = now();
      const trialDays = Number(plan.trial_days) || 0;
      const trialEnd = trialDays > 0 ? calcPeriodEnd(n, 'daily', trialDays) : null;
      const periodStart = trialEnd || n;
      const periodEnd = calcPeriodEnd(periodStart, plan.interval as string, Number(plan.interval_count) || 1);
      const status = trialDays > 0 ? 'trialing' : 'active';
      // Apply coupon
      let discount = 0; let couponCode: string | null = null;
      if (body.coupon_code) {
        const coupon = await db.prepare('SELECT * FROM coupons WHERE code=? AND org_id=? AND status=?').bind(String(body.coupon_code).toUpperCase(), Number(org_id), 'active').first();
        if (coupon) {
          couponCode = coupon.code as string;
          if (coupon.discount_type === 'percent') discount = Number(coupon.discount_value);
          await db.prepare('UPDATE coupons SET redemptions=redemptions+1 WHERE id=?').bind(coupon.id).run();
        }
      }
      const priceOverride = body.price_override !== undefined ? Number(body.price_override) : null;
      await db.prepare('INSERT INTO subscriptions (org_id,customer_id,plan_id,quantity,price_override,discount_percent,coupon_code,trial_start,trial_end,current_period_start,current_period_end,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(
        Number(org_id), Number(customer_id), Number(plan_id), Number(body.quantity) || 1, priceOverride, discount, couponCode,
        trialDays > 0 ? n : null, trialEnd, periodStart, periodEnd, status
      ).run();
      // Update customer MRR
      const price = priceOverride ?? Number(plan.price);
      const effectivePrice = price * (1 - discount / 100) * (Number(body.quantity) || 1);
      const monthlyPrice = (plan.interval as string) === 'yearly' ? effectivePrice / 12 : (plan.interval as string) === 'weekly' ? effectivePrice * 4.33 : effectivePrice;
      await db.prepare('UPDATE customers SET mrr=mrr+?,updated_at=? WHERE id=?').bind(monthlyPrice, n, Number(customer_id)).run();
      // Log
      await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(Number(org_id), 'system', 'subscription.created', `customer:${customer_id}`, `plan:${plan.name} status:${status}`).run();
      return jsonOk({ ok: true, message: 'Subscription created', status }, 201);
    }
    const subMatch = p.match(/^\/subscriptions\/(\d+)$/);
    if (subMatch && m === 'GET') {
      const sub = await db.prepare('SELECT s.*,p.name as plan_name,p.price as plan_price,p.interval as plan_interval,c.email as customer_email FROM subscriptions s JOIN plans p ON s.plan_id=p.id JOIN customers c ON s.customer_id=c.id WHERE s.id=?').bind(Number(subMatch[1])).first();
      if (!sub) return jsonErr('Not found', 404);
      const addons = await db.prepare('SELECT sa.*,a.name,a.price FROM subscription_addons sa JOIN addons a ON sa.addon_id=a.id WHERE sa.subscription_id=?').bind(sub.id).all();
      const invoices = await db.prepare('SELECT * FROM invoices WHERE subscription_id=? ORDER BY created_at DESC LIMIT 20').bind(sub.id).all();
      return jsonOk({ ok: true, subscription: sub, addons: addons.results, invoices: invoices.results });
    }

    // Cancel subscription
    const cancelMatch = p.match(/^\/subscriptions\/(\d+)\/cancel$/);
    if (cancelMatch && m === 'POST') {
      const id = Number(cancelMatch[1]);
      const immediate = body.immediate === true;
      const reason = sanitize(body.reason as string, 500);
      if (immediate) {
        await db.prepare('UPDATE subscriptions SET status=?,canceled_at=?,cancel_reason=?,updated_at=? WHERE id=?').bind('canceled', now(), reason, now(), id).run();
      } else {
        await db.prepare('UPDATE subscriptions SET status=?,canceled_at=?,cancel_reason=?,updated_at=? WHERE id=?').bind('pending_cancel', now(), reason, now(), id).run();
      }
      const sub = await db.prepare('SELECT * FROM subscriptions WHERE id=?').bind(id).first();
      if (sub) await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(sub.org_id, 'system', 'subscription.canceled', `sub:${id}`, `immediate:${immediate} reason:${reason}`).run();
      return jsonOk({ ok: true, message: immediate ? 'Canceled immediately' : 'Will cancel at period end' });
    }

    // Pause subscription
    const pauseMatch = p.match(/^\/subscriptions\/(\d+)\/pause$/);
    if (pauseMatch && m === 'POST') {
      const id = Number(pauseMatch[1]);
      const resumeDate = sanitize(body.resume_date as string, 30) || null;
      await db.prepare('UPDATE subscriptions SET status=?,pause_start=?,pause_end=?,updated_at=? WHERE id=?').bind('paused', now(), resumeDate, now(), id).run();
      return jsonOk({ ok: true, message: 'Subscription paused' });
    }

    // Resume subscription
    const resumeMatch = p.match(/^\/subscriptions\/(\d+)\/resume$/);
    if (resumeMatch && m === 'POST') {
      const id = Number(resumeMatch[1]);
      await db.prepare('UPDATE subscriptions SET status=?,pause_start=null,pause_end=null,updated_at=? WHERE id=?').bind('active', now(), id).run();
      return jsonOk({ ok: true, message: 'Subscription resumed' });
    }

    // Change plan (upgrade/downgrade with proration)
    const changePlanMatch = p.match(/^\/subscriptions\/(\d+)\/change-plan$/);
    if (changePlanMatch && m === 'POST') {
      const id = Number(changePlanMatch[1]);
      const newPlanId = Number(body.plan_id);
      if (!newPlanId) return jsonErr('plan_id required');
      const sub = await db.prepare('SELECT s.*,p.price as old_price,p.interval as old_interval FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.id=?').bind(id).first();
      if (!sub) return jsonErr('Subscription not found', 404);
      const newPlan = await db.prepare('SELECT * FROM plans WHERE id=?').bind(newPlanId).first();
      if (!newPlan) return jsonErr('New plan not found', 404);

      // Calculate proration
      const periodStart = new Date(sub.current_period_start as string).getTime();
      const periodEnd = new Date(sub.current_period_end as string).getTime();
      const nowMs = Date.now();
      const totalDays = (periodEnd - periodStart) / 86400000;
      const usedDays = (nowMs - periodStart) / 86400000;
      const remainingRatio = Math.max(0, (totalDays - usedDays) / totalDays);
      const oldDailyRate = Number(sub.old_price) / totalDays;
      const newDailyRate = Number(newPlan.price) / totalDays;
      const prorationCredit = oldDailyRate * (totalDays - usedDays);
      const prorationCharge = newDailyRate * (totalDays - usedDays);
      const netAmount = prorationCharge - prorationCredit;

      await db.prepare('UPDATE subscriptions SET plan_id=?,updated_at=? WHERE id=?').bind(newPlanId, now(), id).run();
      // Create proration invoice if significant
      if (Math.abs(netAmount) > 0.5) {
        const invNum = `PRO-${id}-${Date.now()}`;
        await db.prepare('INSERT INTO invoices (org_id,customer_id,subscription_id,invoice_number,subtotal,total,period_start,period_end,status) VALUES (?,?,?,?,?,?,?,?,?)').bind(
          sub.org_id, sub.customer_id, id, invNum, netAmount, netAmount, now(), sub.current_period_end, netAmount > 0 ? 'open' : 'credit'
        ).run();
        await db.prepare('INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,amount,item_type) VALUES ((SELECT id FROM invoices WHERE invoice_number=?),?,1,?,?,?)').bind(
          invNum, `Proration: ${sub.old_interval} → ${newPlan.interval} (${newPlan.name})`, netAmount, netAmount, 'proration'
        ).run();
      }
      await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(sub.org_id, 'system', 'subscription.plan_changed', `sub:${id}`, `old_plan:${sub.plan_id} new_plan:${newPlanId} proration:${netAmount.toFixed(2)}`).run();
      return jsonOk({ ok: true, message: 'Plan changed', proration: { credit: prorationCredit.toFixed(2), charge: prorationCharge.toFixed(2), net: netAmount.toFixed(2) } });
    }

    // ── Usage Records ──
    if (p === '/usage' && m === 'POST') {
      const { org_id, subscription_id, addon_id, quantity } = body as Record<string, unknown>;
      if (!org_id || !subscription_id || !addon_id || !quantity) return jsonErr('org_id, subscription_id, addon_id, quantity required');
      const period = today().slice(0, 7);
      await db.prepare('INSERT INTO usage_records (org_id,subscription_id,addon_id,quantity,period,metadata) VALUES (?,?,?,?,?,?)').bind(
        Number(org_id), Number(subscription_id), Number(addon_id), Number(quantity), period, JSON.stringify(body.metadata || {})
      ).run();
      return jsonOk({ ok: true, message: 'Usage recorded' }, 201);
    }
    const usageMatch = p.match(/^\/usage\/(\d+)$/);
    if (usageMatch && m === 'GET') {
      const subId = Number(usageMatch[1]);
      const period = url.searchParams.get('period') || today().slice(0, 7);
      const rows = await db.prepare('SELECT ur.*,a.name as addon_name,a.included_units,a.overage_price FROM usage_records ur JOIN addons a ON ur.addon_id=a.id WHERE ur.subscription_id=? AND ur.period=? ORDER BY ur.recorded_at DESC').bind(subId, period).all();
      // Sum usage per addon
      const totals: Record<string, { total: number; included: number; overage: number; overage_cost: number }> = {};
      for (const r of rows.results as Record<string, unknown>[]) {
        const key = String(r.addon_id);
        if (!totals[key]) totals[key] = { total: 0, included: Number(r.included_units), overage: 0, overage_cost: 0 };
        totals[key].total += Number(r.quantity);
        totals[key].overage = Math.max(0, totals[key].total - totals[key].included);
        totals[key].overage_cost = totals[key].overage * Number(r.overage_price);
      }
      return jsonOk({ ok: true, records: rows.results, totals, period });
    }

    // ── Invoices ──
    if (p === '/invoices' && m === 'GET') {
      const orgId = url.searchParams.get('org_id'); const custId = url.searchParams.get('customer_id');
      let q = 'SELECT i.*,c.email as customer_email,c.name as customer_name FROM invoices i JOIN customers c ON i.customer_id=c.id';
      const conds: string[] = []; const binds: unknown[] = [];
      if (orgId) { conds.push('i.org_id=?'); binds.push(Number(orgId)); }
      if (custId) { conds.push('i.customer_id=?'); binds.push(Number(custId)); }
      if (conds.length) q += ' WHERE ' + conds.join(' AND ');
      q += ' ORDER BY i.created_at DESC LIMIT 100';
      const rows = await db.prepare(q).bind(...binds).all();
      return jsonOk({ ok: true, invoices: rows.results });
    }
    const invMatch = p.match(/^\/invoices\/(\d+)$/);
    if (invMatch && m === 'GET') {
      const inv = await db.prepare('SELECT i.*,c.email,c.name as customer_name FROM invoices i JOIN customers c ON i.customer_id=c.id WHERE i.id=?').bind(Number(invMatch[1])).first();
      if (!inv) return jsonErr('Not found', 404);
      const items = await db.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(inv.id).all();
      return jsonOk({ ok: true, invoice: inv, items: items.results });
    }
    // Pay invoice
    const payMatch = p.match(/^\/invoices\/(\d+)\/pay$/);
    if (payMatch && m === 'POST') {
      const id = Number(payMatch[1]);
      await db.prepare('UPDATE invoices SET status=?,paid_at=?,payment_method=?,payment_ref=? WHERE id=?').bind('paid', now(), sanitize(body.payment_method as string) || 'manual', sanitize(body.payment_ref as string) || null, id).run();
      const inv = await db.prepare('SELECT * FROM invoices WHERE id=?').bind(id).first();
      if (inv) {
        await db.prepare('UPDATE customers SET lifetime_value=lifetime_value+?,updated_at=? WHERE id=?').bind(Number(inv.total), now(), inv.customer_id).run();
        // Reset dunning on subscription
        if (inv.subscription_id) await db.prepare('UPDATE subscriptions SET dunning_count=0,last_dunning_at=null,status=CASE WHEN status=? THEN ? ELSE status END,updated_at=? WHERE id=?').bind('past_due', 'active', now(), inv.subscription_id).run();
      }
      return jsonOk({ ok: true, message: 'Invoice paid' });
    }

    // ── Webhook Events ──
    if (p === '/webhooks' && m === 'GET') {
      const orgId = url.searchParams.get('org_id');
      const rows = orgId ? await db.prepare('SELECT * FROM webhook_events WHERE org_id=? ORDER BY created_at DESC LIMIT 50').bind(Number(orgId)).all() : await db.prepare('SELECT * FROM webhook_events ORDER BY created_at DESC LIMIT 50').all();
      return jsonOk({ ok: true, events: rows.results });
    }

    // ── Dashboard / Revenue Metrics ──
    const dashMatch = p.match(/^\/dashboard\/(\d+)$/);
    if (dashMatch && m === 'GET') {
      const orgId = Number(dashMatch[1]);
      const [activeSubs, trialSubs, pastDueSubs, canceledSubs, totalCustomers, openInvoices, paidLast30, mrrResult] = await Promise.all([
        db.prepare('SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status=?').bind(orgId, 'active').first(),
        db.prepare('SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status=?').bind(orgId, 'trialing').first(),
        db.prepare('SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status=?').bind(orgId, 'past_due').first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status=? AND canceled_at>=datetime('now','-30 days')").bind(orgId, 'canceled').first(),
        db.prepare('SELECT COUNT(*) as c FROM customers WHERE org_id=? AND status=?').bind(orgId, 'active').first(),
        db.prepare("SELECT COUNT(*) as c,COALESCE(SUM(total),0) as total FROM invoices WHERE org_id=? AND status IN ('open','past_due')").bind(orgId).first(),
        db.prepare("SELECT COALESCE(SUM(total),0) as total FROM invoices WHERE org_id=? AND status=? AND paid_at>=datetime('now','-30 days')").bind(orgId, 'paid').first(),
        db.prepare('SELECT COALESCE(SUM(mrr),0) as total FROM customers WHERE org_id=? AND status=?').bind(orgId, 'active').first(),
      ]);
      const mrr = Number(mrrResult?.total) || 0;
      const topPlans = await db.prepare('SELECT p.name,COUNT(*) as count FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.org_id=? AND s.status IN (?,?) GROUP BY s.plan_id ORDER BY count DESC LIMIT 5').bind(orgId, 'active', 'trialing').all();
      const recentActivity = await db.prepare('SELECT * FROM activity_log WHERE org_id=? ORDER BY created_at DESC LIMIT 10').bind(orgId).all();
      return jsonOk({
        ok: true,
        dashboard: {
          mrr, arr: mrr * 12,
          active_subscriptions: activeSubs?.c || 0,
          trialing: trialSubs?.c || 0,
          past_due: pastDueSubs?.c || 0,
          recently_churned: canceledSubs?.c || 0,
          total_customers: totalCustomers?.c || 0,
          open_invoices: { count: openInvoices?.c || 0, total: Number(openInvoices?.total) || 0 },
          revenue_last_30d: Number(paidLast30?.total) || 0,
          top_plans: topPlans.results,
          recent_activity: recentActivity.results,
        }
      });
    }

    // ── Revenue Analytics (daily) ──
    const revenueMatch = p.match(/^\/revenue\/(\d+)$/);
    if (revenueMatch && m === 'GET') {
      const orgId = Number(revenueMatch[1]);
      const days = Number(url.searchParams.get('days')) || 30;
      const rows = await db.prepare('SELECT * FROM revenue_daily WHERE org_id=? ORDER BY date DESC LIMIT ?').bind(orgId, days).all();
      return jsonOk({ ok: true, revenue: rows.results });
    }

    // ── AI Churn Prediction ──
    const churnMatch = p.match(/^\/ai\/churn-risk\/(\d+)$/);
    if (churnMatch && m === 'GET') {
      const orgId = Number(churnMatch[1]);
      const customers = await db.prepare("SELECT c.*,COUNT(s.id) as sub_count,MAX(s.updated_at) as last_activity FROM customers c LEFT JOIN subscriptions s ON c.id=s.customer_id AND s.status IN ('active','trialing') WHERE c.org_id=? AND c.status=? GROUP BY c.id ORDER BY c.churn_risk DESC LIMIT 20").bind(orgId, 'active').all();
      try {
        const resp = await env.ENGINE_RUNTIME.fetch('https://echo-engine-runtime.bmcii1976.workers.dev/query', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ engine_category: 'business', query: `Analyze these subscription customers for churn risk. Consider: subscription count, lifetime value, MRR contribution, and last activity date. Provide risk scores and recommended retention actions.\n\nCustomers: ${JSON.stringify(customers.results.slice(0, 10))}` })
        });
        const aiResult = await resp.json() as Record<string, unknown>;
        return jsonOk({ ok: true, customers: customers.results, ai_analysis: aiResult });
      } catch {
        return jsonOk({ ok: true, customers: customers.results, ai_analysis: null });
      }
    }

    // ── AI Revenue Forecast ──
    const forecastMatch = p.match(/^\/ai\/forecast\/(\d+)$/);
    if (forecastMatch && m === 'GET') {
      const orgId = Number(forecastMatch[1]);
      const revenue = await db.prepare('SELECT * FROM revenue_daily WHERE org_id=? ORDER BY date DESC LIMIT 90').bind(orgId).all();
      const subs = await db.prepare("SELECT status,COUNT(*) as c FROM subscriptions WHERE org_id=? GROUP BY status").bind(orgId).all();
      try {
        const resp = await env.ENGINE_RUNTIME.fetch('https://echo-engine-runtime.bmcii1976.workers.dev/query', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ engine_category: 'business', query: `Forecast subscription revenue for the next 3 months based on this data. Consider MRR trends, churn rate, and growth patterns.\n\nRevenue history: ${JSON.stringify(revenue.results.slice(0, 30))}\nSubscription breakdown: ${JSON.stringify(subs.results)}` })
        });
        const aiResult = await resp.json() as Record<string, unknown>;
        return jsonOk({ ok: true, historical: revenue.results, subscription_breakdown: subs.results, forecast: aiResult });
      } catch {
        return jsonOk({ ok: true, historical: revenue.results, subscription_breakdown: subs.results, forecast: null });
      }
    }

    // ── Export ──
    const exportMatch = p.match(/^\/export\/(\d+)$/);
    if (exportMatch && m === 'GET') {
      const orgId = Number(exportMatch[1]);
      const format = url.searchParams.get('format') || 'json';
      const subs = await db.prepare('SELECT s.*,c.email,c.name as customer_name,p.name as plan_name,p.price FROM subscriptions s JOIN customers c ON s.customer_id=c.id JOIN plans p ON s.plan_id=p.id WHERE s.org_id=? ORDER BY s.created_at DESC').bind(orgId).all();
      if (format === 'csv') {
        const headers = 'id,customer_email,customer_name,plan,price,quantity,status,period_start,period_end,created_at';
        const rows = (subs.results as Record<string, unknown>[]).map(r => `${r.id},"${r.email}","${r.customer_name}","${r.plan_name}",${r.price},${r.quantity},${r.status},"${r.current_period_start}","${r.current_period_end}","${r.created_at}"`);
        return new Response(headers + '\n' + rows.join('\n'), { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=subscriptions.csv', 'Access-Control-Allow-Origin': '*' } });
      }
      return jsonOk({ ok: true, subscriptions: subs.results });
    }

    return jsonErr('Not found', 404);
  },

  async scheduled(event: ScheduledEvent, env: Env) {
    const db = env.DB;
    const n = now();
    const t = today();

    // 1. Process renewals — subscriptions whose period has ended
    const dueRenewals = await db.prepare("SELECT s.*,p.price,p.interval,p.interval_count FROM subscriptions s JOIN plans p ON s.plan_id=p.id WHERE s.status='active' AND s.current_period_end<=?").bind(n).all();
    for (const sub of dueRenewals.results as Record<string, unknown>[]) {
      const price = (sub.price_override ?? sub.price) as number;
      const qty = Number(sub.quantity) || 1;
      const discount = Number(sub.discount_percent) || 0;
      const subtotal = price * qty * (1 - discount / 100);
      const org = await db.prepare('SELECT * FROM organizations WHERE id=?').bind(sub.org_id).first();
      const tax = subtotal * (Number(org?.tax_rate) || 0) / 100;
      const total = subtotal + tax;
      const invNum = `INV-${sub.id}-${Date.now()}`;

      // Create invoice
      const newPeriodStart = sub.current_period_end as string;
      const newPeriodEnd = calcPeriodEnd(newPeriodStart, sub.interval as string, Number(sub.interval_count) || 1);
      await db.prepare('INSERT INTO invoices (org_id,customer_id,subscription_id,invoice_number,subtotal,tax,discount,total,period_start,period_end,due_date,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(
        sub.org_id, sub.customer_id, sub.id, invNum, subtotal, tax, discount, total, newPeriodStart, newPeriodEnd, newPeriodStart, 'open'
      ).run();
      await db.prepare('INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,amount) VALUES ((SELECT id FROM invoices WHERE invoice_number=?),?,?,?,?)').bind(invNum, `Subscription renewal`, qty, price * (1 - discount / 100), subtotal).run();

      // Advance period
      await db.prepare('UPDATE subscriptions SET current_period_start=?,current_period_end=?,updated_at=? WHERE id=?').bind(newPeriodStart, newPeriodEnd, n, sub.id).run();
    }

    // 2. Cancel pending_cancel subscriptions at period end
    await db.prepare("UPDATE subscriptions SET status='canceled',updated_at=? WHERE status='pending_cancel' AND current_period_end<=?").bind(n, n).run();

    // 3. Dunning — retry past_due subscriptions
    const pastDue = await db.prepare("SELECT s.*,o.dunning_attempts,o.dunning_interval_days FROM subscriptions s JOIN organizations o ON s.org_id=o.id WHERE s.status='past_due' AND s.dunning_count<o.dunning_attempts").bind().all();
    for (const sub of pastDue.results as Record<string, unknown>[]) {
      const lastDunning = sub.last_dunning_at ? new Date(sub.last_dunning_at as string).getTime() : 0;
      const intervalMs = (Number(sub.dunning_interval_days) || 3) * 86400000;
      if (Date.now() - lastDunning >= intervalMs) {
        await db.prepare('UPDATE subscriptions SET dunning_count=dunning_count+1,last_dunning_at=?,updated_at=? WHERE id=?').bind(n, n, sub.id).run();
        // Create webhook event for payment retry
        await db.prepare('INSERT INTO webhook_events (org_id,event_type,payload) VALUES (?,?,?)').bind(sub.org_id, 'subscription.dunning', JSON.stringify({ subscription_id: sub.id, attempt: (sub.dunning_count as number) + 1 })).run();
      }
    }

    // 4. Expire trials
    await db.prepare("UPDATE subscriptions SET status='past_due',updated_at=? WHERE status='trialing' AND trial_end<=?").bind(n, n).run();

    // 5. Resume paused subscriptions
    await db.prepare("UPDATE subscriptions SET status='active',pause_start=null,pause_end=null,updated_at=? WHERE status='paused' AND pause_end IS NOT NULL AND pause_end<=?").bind(n, n).run();

    // 6. Snapshot daily revenue
    const orgs = await db.prepare("SELECT id FROM organizations WHERE status='active'").all();
    for (const org of orgs.results as Record<string, unknown>[]) {
      const orgId = org.id as number;
      const [active, newSubs, churned, trials, mrr, paidToday, outstanding] = await Promise.all([
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status='active'").bind(orgId).first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND DATE(created_at)=?").bind(orgId, t).first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status='canceled' AND DATE(canceled_at)=?").bind(orgId, t).first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE org_id=? AND status='trialing'").bind(orgId).first(),
        db.prepare("SELECT COALESCE(SUM(mrr),0) as total FROM customers WHERE org_id=? AND status='active'").bind(orgId).first(),
        db.prepare("SELECT COALESCE(SUM(total),0) as total FROM invoices WHERE org_id=? AND status='paid' AND DATE(paid_at)=?").bind(orgId, t).first(),
        db.prepare("SELECT COALESCE(SUM(total),0) as total FROM invoices WHERE org_id=? AND status IN ('open','past_due')").bind(orgId).first(),
      ]);
      const mrrVal = Number(mrr?.total) || 0;
      await db.prepare('INSERT OR REPLACE INTO revenue_daily (org_id,date,mrr,arr,active_subscriptions,new_subscriptions,churned_subscriptions,trial_subscriptions,invoices_paid,invoices_outstanding) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(
        orgId, t, mrrVal, mrrVal * 12, active?.c || 0, newSubs?.c || 0, churned?.c || 0, trials?.c || 0, Number(paidToday?.total) || 0, Number(outstanding?.total) || 0
      ).run();
    }
  }
};
