// Echo Subscription v2.0.0 — AI-Powered Subscription Billing + Stripe Checkout
// Cloudflare Worker: D1 + KV + Service Bindings

interface Env {
  DB: D1Database;
  SB_CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  SITE_URL?: string;
}

interface RLState { c: number; t: number }

function sanitize(s: unknown, max = 500): string {
  if (typeof s !== 'string') return '';
  return s.replace(/[\x00-\x1f]/g, '').slice(0, max);
}

const ALLOWED_ORIGINS = ['https://echo-ept.com','https://www.echo-ept.com','https://echo-op.com','https://www.echo-op.com','http://localhost:3000','http://localhost:3001'];

let _corsOrigin = 'https://echo-ept.com';
function setCorsOrigin(req: Request) {
  const origin = req.headers.get('Origin') || '';
  _corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
}

function jsonOk(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': _corsOrigin } });
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

async function verifyStripeSignature(body: string, sigHeader: string, secret: string): Promise<boolean> {
  const parts = sigHeader.split(',').reduce((acc: Record<string, string>, part) => {
    const [key, value] = part.split('=');
    acc[key] = value;
    return acc;
  }, {});

  const timestamp = parts['t'];
  const signature = parts['v1'];
  if (!timestamp || !signature) return false;

  // Reject timestamps older than 5 minutes (replay protection)
  const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
  if (age > 300) return false;

  const payload = `${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const expected = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

  // Constant-time comparison
  if (expected.length !== signature.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return result === 0;
}

function log(level: string, message: string, meta: Record<string, any> = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, worker: 'echo-subscription', message, ...meta }));
}

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


// Security headers
const SEC_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
};
function withSecHeaders(res: Response): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(SEC_HEADERS)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    setCorsOrigin(req);
    if (req.method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': _corsOrigin, 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,X-Echo-API-Key,Authorization' } });

    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;

    // Health
    if (p === '/health' || p === '/') {
      log('info', 'Health check', { path: p, ip: ip(req) });
      return jsonOk({ ok: true, service: 'echo-subscription', version: '2.0.0', timestamp: now(), stripe: !!env.STRIPE_SECRET_KEY });
    }

    // ── Revenue Metrics ── (authenticated — key KPIs for dashboards)
    if (p === '/metrics' && m === 'GET') {
      if (!authOk(req, env)) return jsonErr('Unauthorized', 401);
      const db = env.DB;
      const [active, trialing, canceled, pastDue, totalCustomers, totalRevenue, recentTrials, recentConversions] = await Promise.all([
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='active'").first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='trialing'").first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='canceled'").first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='past_due'").first(),
        db.prepare("SELECT COUNT(*) as c FROM customers").first(),
        db.prepare("SELECT COALESCE(SUM(c.lifetime_value),0) as total FROM customers c WHERE c.status='active'").first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='trialing' AND created_at>=datetime('now','-30 days')").first(),
        db.prepare("SELECT COUNT(*) as c FROM subscriptions WHERE status='active' AND trial_end IS NOT NULL AND created_at>=datetime('now','-30 days')").first(),
      ]);
      const activeCount = Number(active?.c) || 0;
      const trialingCount = Number(trialing?.c) || 0;
      const canceledCount = Number(canceled?.c) || 0;
      const trialCount30d = Number(recentTrials?.c) || 0;
      const conversionCount30d = Number(recentConversions?.c) || 0;
      const conversionRate = trialCount30d > 0 ? Math.round((conversionCount30d / trialCount30d) * 100) : 0;
      const churnRate = (activeCount + canceledCount) > 0 ? Math.round((canceledCount / (activeCount + canceledCount)) * 100) : 0;
      return jsonOk({
        ok: true,
        metrics: {
          active_subscriptions: activeCount,
          trialing: trialingCount,
          canceled: canceledCount,
          past_due: Number(pastDue?.c) || 0,
          total_customers: Number(totalCustomers?.c) || 0,
          lifetime_revenue: Number(totalRevenue?.total) || 0,
          trial_conversion_rate_30d: conversionRate,
          churn_rate: churnRate,
          trials_last_30d: trialCount30d,
          conversions_last_30d: conversionCount30d,
        },
        timestamp: now(),
      });
    }

    // Rate limit GET
    if (m === 'GET' && !(await rateLimit(env.SB_CACHE, `rl:${ip(req)}`, 60, 60000))) {
      log('warn', 'Rate limited (GET)', { path: p, ip: ip(req) });
      return jsonErr('Rate limited', 429);
    }
    // ── Free Trial Signup ── (public — no auth required, rate limited)
    if (p === '/trial/start' && m === 'POST') {
      if (!(await rateLimit(env.SB_CACHE, `rl:trial:${ip(req)}`, 5, 3600000))) return jsonErr('Too many trial requests', 429);
      const rawBody = await req.text();
      let trialBody: Record<string, unknown>;
      try { trialBody = JSON.parse(rawBody); } catch { return jsonErr('Invalid JSON', 400); }

      const email = sanitize(String(trialBody.email || ''), 255).toLowerCase().trim();
      const name = sanitize(String(trialBody.name || ''), 200);
      const serviceId = sanitize(String(trialBody.service_id || ''), 100);
      const tierName = sanitize(String(trialBody.tier || 'professional'), 50);
      const trialDays = 14;

      if (!email || !email.includes('@')) return jsonErr('Valid email required');
      if (!serviceId) return jsonErr('service_id required');

      const db = env.DB;

      // Check if email already has a trial or active subscription
      const existing = await db.prepare("SELECT id,status FROM customers WHERE email=? LIMIT 1").bind(email).first();
      if (existing) {
        const activeSub = await db.prepare("SELECT id,status FROM subscriptions WHERE customer_id=? AND status IN ('active','trialing') LIMIT 1").bind(existing.id).first();
        if (activeSub) return jsonErr('You already have an active subscription or trial', 409);
      }

      // Create or update customer
      let customerId: number;
      if (existing) {
        customerId = existing.id as number;
        await db.prepare("UPDATE customers SET name=COALESCE(NULLIF(?,''),name),status='active',updated_at=? WHERE id=?").bind(name, now(), customerId).run();
      } else {
        const res = await db.prepare('INSERT INTO customers (org_id,email,name,payment_method,metadata) VALUES (?,?,?,?,?)').bind(
          1, email, name || email.split('@')[0], 'trial', JSON.stringify({ service_id: serviceId, tier: tierName, trial_start: now() })
        ).run();
        customerId = res.meta.last_row_id as number;
      }

      // Find or create trial plan
      const planSlug = `${serviceId}-${tierName}-trial`;
      let plan = await db.prepare('SELECT * FROM plans WHERE slug=? AND org_id=1 LIMIT 1').bind(planSlug).first();
      if (!plan) {
        await db.prepare('INSERT INTO plans (org_id,name,slug,price,interval,trial_days,is_public) VALUES (?,?,?,?,?,?,?)').bind(
          1, `${serviceId} ${tierName} (14-day trial)`, planSlug, 0, 'monthly', trialDays, 0
        ).run();
        plan = await db.prepare('SELECT * FROM plans WHERE slug=? AND org_id=1 LIMIT 1').bind(planSlug).first();
      }

      if (!plan) return jsonErr('Failed to create trial plan', 500);

      // Create trial subscription
      const n = now();
      const trialEnd = calcPeriodEnd(n, 'daily', trialDays);
      const periodEnd = calcPeriodEnd(trialEnd, 'monthly', 1);
      await db.prepare('INSERT INTO subscriptions (org_id,customer_id,plan_id,quantity,status,trial_start,trial_end,current_period_start,current_period_end) VALUES (?,?,?,?,?,?,?,?,?)').bind(
        1, customerId, plan.id, 1, 'trialing', n, trialEnd, n, periodEnd
      ).run();

      await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(
        1, 'trial_signup', 'trial.started', `customer:${customerId}`, `service:${serviceId} tier:${tierName} email:${email} expires:${trialEnd}`
      ).run();

      log('info', 'Free trial started', { email, service: serviceId, tier: tierName, trial_end: trialEnd, customer_id: customerId });

      // Send branded onboarding welcome email
      try {
        const productName = serviceId.replace(/^echo-/, '').replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
        const tierLabel = tierName.charAt(0).toUpperCase() + tierName.slice(1);
        const expiryDate = new Date(trialEnd.replace(' ', 'T') + 'Z').toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        const productSlug = serviceId.replace(/^echo-/, '');
        await env.EMAIL_SENDER.fetch('https://echo-email-sender.bmcii1976.workers.dev/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: email,
            subject: `Your ${productName} trial is live — here's how to get started`,
            html: `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;margin-top:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,#0d7377 0%,#14b8a6 100%);padding:32px 24px;text-align:center">
    <h1 style="color:#ffffff;margin:0;font-size:24px;font-weight:700">Welcome to Echo Prime</h1>
    <p style="color:rgba(255,255,255,0.9);margin:8px 0 0;font-size:15px">Your ${productName} trial is active</p>
  </div>
  <div style="padding:32px 24px">
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 16px">Hi ${name || 'there'},</p>
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 24px">Your <strong>14-day free trial</strong> of <strong>${productName} — ${tierLabel}</strong> is now active. No credit card needed. Full access to all features.</p>
    <div style="background:#f0fdfa;border:1px solid #99f6e4;border-radius:8px;padding:16px;margin:0 0 24px">
      <p style="margin:0 0 8px;color:#0d7377;font-weight:600;font-size:14px">Quick Start Guide</p>
      <table style="width:100%;border-collapse:collapse"><tbody>
        <tr><td style="padding:6px 0;color:#475569;font-size:14px">1. Open your dashboard</td></tr>
        <tr><td style="padding:6px 0;color:#475569;font-size:14px">2. Explore the API at <code style="background:#e2e8f0;padding:2px 6px;border-radius:4px;font-size:13px">${serviceId}.bmcii1976.workers.dev</code></td></tr>
        <tr><td style="padding:6px 0;color:#475569;font-size:14px">3. Read the docs at <a href="https://echo-ept.com/docs/${productSlug}" style="color:#0d7377">echo-ept.com/docs/${productSlug}</a></td></tr>
      </tbody></table>
    </div>
    <div style="text-align:center;margin:0 0 24px">
      <a href="https://echo-ept.com/dashboard" style="display:inline-block;background:#0d7377;color:#ffffff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px">Open Dashboard</a>
    </div>
    <div style="background:#fefce8;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;margin:0 0 24px">
      <p style="margin:0;color:#92400e;font-size:13px"><strong>Trial expires:</strong> ${expiryDate}. Upgrade anytime from your dashboard to keep your data.</p>
    </div>
    <p style="color:#64748b;font-size:14px;line-height:1.6;margin:0 0 8px">Need help? Reply to this email or visit <a href="https://echo-ept.com/support" style="color:#0d7377">echo-ept.com/support</a></p>
  </div>
  <div style="background:#f8fafc;padding:20px 24px;border-top:1px solid #e2e8f0;text-align:center">
    <p style="color:#94a3b8;font-size:12px;margin:0">Echo Prime Technologies — Midland, TX</p>
    <p style="color:#94a3b8;font-size:11px;margin:4px 0 0"><a href="https://echo-ept.com" style="color:#94a3b8">echo-ept.com</a></p>
  </div>
</div></body></html>`,
          }),
        });
      } catch (emailErr) {
        log('warn', 'Trial welcome email failed', { email, error: String(emailErr) });
      }

      return jsonOk({ ok: true, trial: { email, service_id: serviceId, tier: tierName, trial_days: trialDays, trial_end: trialEnd, customer_id: customerId } }, 201);
    }

    // ── Stripe Checkout Session ── (public — creates a payment session)
    if (p === '/stripe/checkout-session' && m === 'POST') {
      if (!env.STRIPE_SECRET_KEY) return jsonErr('Stripe not configured', 503);
      const rawBody = await req.text();
      let checkoutBody: Record<string, unknown>;
      try { checkoutBody = JSON.parse(rawBody); } catch { return jsonErr('Invalid JSON', 400); }

      const { plan_name, price_cents, interval, customer_email, customer_name, service_id, tier, success_url, cancel_url, coupon_code } = checkoutBody as Record<string, string>;
      if (!price_cents || !plan_name) return jsonErr('plan_name, price_cents required');

      const siteUrl = env.SITE_URL || 'https://echo-ept.com';
      const successRedirect = success_url || `${siteUrl}/checkout/success?method=stripe&session_id={CHECKOUT_SESSION_ID}&service=${service_id || ''}&tier=${tier || ''}`;
      const cancelRedirect = cancel_url || `${siteUrl}/checkout?service=${service_id || ''}&tier=${tier || ''}`;

      // Build Stripe Checkout Session via REST API
      const params = new URLSearchParams();
      params.append('mode', interval === 'year' || interval === 'yearly' ? 'subscription' : (interval === 'month' || interval === 'monthly' ? 'subscription' : 'payment'));
      params.append('success_url', successRedirect);
      params.append('cancel_url', cancelRedirect);
      params.append('line_items[0][price_data][currency]', 'usd');
      params.append('line_items[0][price_data][product_data][name]', String(plan_name));
      if (service_id) params.append('line_items[0][price_data][product_data][metadata][service_id]', String(service_id));
      if (tier) params.append('line_items[0][price_data][product_data][metadata][tier]', String(tier));
      params.append('line_items[0][price_data][unit_amount]', String(Math.round(Number(price_cents))));
      if (params.get('mode') === 'subscription') {
        const recInterval = (interval === 'year' || interval === 'yearly') ? 'year' : 'month';
        params.append('line_items[0][price_data][recurring][interval]', recInterval);
      }
      params.append('line_items[0][quantity]', '1');
      if (customer_email) params.append('customer_email', String(customer_email));
      params.append('automatic_tax[enabled]', 'true');
      params.append('allow_promotion_codes', 'true');
      params.append('billing_address_collection', 'required');
      params.append('payment_method_types[0]', 'card');
      if (service_id) params.append('metadata[service_id]', String(service_id));
      if (tier) params.append('metadata[tier]', String(tier));
      if (customer_name) params.append('metadata[customer_name]', String(customer_name));

      try {
        const stripeResp = await fetch('https://api.stripe.com/v1/checkout/sessions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: params.toString(),
        });
        const session = await stripeResp.json() as Record<string, unknown>;
        if (!stripeResp.ok) {
          log('error', 'Stripe checkout session creation failed', { status: stripeResp.status, error: session });
          return jsonErr(`Stripe error: ${(session.error as Record<string, string>)?.message || 'Unknown'}`, 502);
        }
        log('info', 'Stripe checkout session created', { session_id: session.id, amount: price_cents, plan: plan_name });
        return jsonOk({ ok: true, session_id: session.id, url: session.url });
      } catch (err) {
        log('error', 'Stripe API call failed', { error: String(err) });
        return jsonErr('Stripe API unreachable', 502);
      }
    }

    // ── Stripe Customer Portal ── (authenticated — manage billing)
    if (p === '/stripe/portal-session' && m === 'POST') {
      if (!env.STRIPE_SECRET_KEY) return jsonErr('Stripe not configured', 503);
      if (!authOk(req, env)) return jsonErr('Unauthorized', 401);
      const rawBody = await req.text();
      let portalBody: Record<string, unknown>;
      try { portalBody = JSON.parse(rawBody); } catch { return jsonErr('Invalid JSON', 400); }

      const customerId = String(portalBody.stripe_customer_id || '');
      if (!customerId) return jsonErr('stripe_customer_id required');

      const siteUrl = env.SITE_URL || 'https://echo-ept.com';
      const returnUrl = String(portalBody.return_url || `${siteUrl}/dashboard`);

      const params = new URLSearchParams();
      params.append('customer', customerId);
      params.append('return_url', returnUrl);

      try {
        const stripeResp = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: params.toString(),
        });
        const session = await stripeResp.json() as Record<string, unknown>;
        if (!stripeResp.ok) {
          log('error', 'Stripe portal session creation failed', { status: stripeResp.status, error: session });
          return jsonErr(`Stripe error: ${(session.error as Record<string, string>)?.message || 'Unknown'}`, 502);
        }
        log('info', 'Stripe portal session created', { customer: customerId });
        return jsonOk({ ok: true, url: session.url });
      } catch (err) {
        log('error', 'Stripe portal API call failed', { error: String(err) });
        return jsonErr('Stripe API unreachable', 502);
      }
    }

    // ── Stripe Webhook (must be before generic auth + body parsing) ──
    if (p === '/webhooks/stripe' && m === 'POST') {
      const rawBody = await req.text();
      const sigHeader = req.headers.get('Stripe-Signature') || '';
      if (env.STRIPE_WEBHOOK_SECRET) {
        if (!sigHeader) {
          log('warn', 'Stripe webhook missing signature header', { ip: ip(req) });
          return jsonErr('Missing Stripe-Signature header', 401);
        }
        const valid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
        if (!valid) {
          log('warn', 'Stripe webhook signature verification failed', { ip: ip(req) });
          return jsonErr('Invalid webhook signature', 401);
        }
      }
      let event: Record<string, unknown>;
      try { event = JSON.parse(rawBody) as Record<string, unknown>; } catch { return jsonErr('Invalid JSON', 400); }
      const eventType = String(event.type || 'unknown');
      const eventId = String(event.id || '');
      log('info', 'Stripe webhook received', { event_type: eventType, event_id: eventId, ip: ip(req) });
      const db = env.DB;
      await db.prepare('INSERT INTO webhook_events (org_id,event_type,payload) VALUES (?,?,?)').bind(
        0, `stripe.${eventType}`, rawBody
      ).run();

      // Process important Stripe events
      const data = event.data as Record<string, unknown> | undefined;
      const obj = data?.object as Record<string, unknown> | undefined;
      if (obj) {
        try {
          if (eventType === 'checkout.session.completed') {
            const customerEmail = String(obj.customer_email || obj.customer_details && (obj.customer_details as Record<string, unknown>).email || '');
            const stripeCustomerId = String(obj.customer || '');
            const metadata = obj.metadata as Record<string, string> | undefined;
            const serviceId = metadata?.service_id || '';
            const tierName = metadata?.tier || '';
            const amountTotal = Number(obj.amount_total || 0) / 100;
            const paymentStatus = String(obj.payment_status || '');

            log('info', 'Checkout completed', { email: customerEmail, service: serviceId, tier: tierName, amount: amountTotal, payment_status: paymentStatus });

            if (customerEmail && paymentStatus === 'paid') {
              // Find or create customer in D1
              let customer = await db.prepare('SELECT * FROM customers WHERE email=? LIMIT 1').bind(customerEmail).first();
              if (!customer) {
                const custName = metadata?.customer_name || customerEmail.split('@')[0];
                await db.prepare('INSERT INTO customers (org_id,email,name,payment_method,payment_token,metadata) VALUES (?,?,?,?,?,?)').bind(
                  1, customerEmail, custName, 'stripe', stripeCustomerId, JSON.stringify({ stripe_customer_id: stripeCustomerId, service_id: serviceId, tier: tierName })
                ).run();
                customer = await db.prepare('SELECT * FROM customers WHERE email=? LIMIT 1').bind(customerEmail).first();
              } else if (stripeCustomerId) {
                await db.prepare('UPDATE customers SET payment_method=?,payment_token=?,updated_at=? WHERE id=?').bind('stripe', stripeCustomerId, now(), customer.id).run();
              }

              // Find matching plan or create a default one
              if (customer && serviceId) {
                let plan = await db.prepare('SELECT * FROM plans WHERE slug=? AND org_id=1 LIMIT 1').bind(`${serviceId}-${tierName}`).first();
                if (!plan) {
                  await db.prepare('INSERT INTO plans (org_id,name,slug,price,interval,is_public) VALUES (?,?,?,?,?,?)').bind(
                    1, `${serviceId} ${tierName}`, `${serviceId}-${tierName}`, amountTotal, 'monthly', 1
                  ).run();
                  plan = await db.prepare('SELECT * FROM plans WHERE slug=? AND org_id=1 LIMIT 1').bind(`${serviceId}-${tierName}`).first();
                }
                if (plan) {
                  const periodEnd = calcPeriodEnd(now(), 'monthly', 1);
                  await db.prepare('INSERT INTO subscriptions (org_id,customer_id,plan_id,quantity,status,current_period_start,current_period_end) VALUES (?,?,?,?,?,?,?)').bind(
                    1, customer.id, plan.id, 1, 'active', now(), periodEnd
                  ).run();
                  await db.prepare('UPDATE customers SET mrr=mrr+?,lifetime_value=lifetime_value+?,updated_at=? WHERE id=?').bind(amountTotal, amountTotal, now(), customer.id).run();
                  await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(
                    1, 'stripe', 'subscription.activated', `customer:${customer.id}`, `plan:${serviceId}-${tierName} amount:${amountTotal} stripe_session:${eventId}`
                  ).run();
                }
              }
            }
          } else if (eventType === 'invoice.paid') {
            const customerEmail = String(obj.customer_email || '');
            const amountPaid = Number(obj.amount_paid || 0) / 100;
            if (customerEmail && amountPaid > 0) {
              await db.prepare('UPDATE customers SET lifetime_value=lifetime_value+?,updated_at=? WHERE email=?').bind(amountPaid, now(), customerEmail).run();
              log('info', 'Invoice paid via Stripe', { email: customerEmail, amount: amountPaid });
            }
          } else if (eventType === 'customer.subscription.deleted') {
            const stripeCustomerId = String(obj.customer || '');
            if (stripeCustomerId) {
              const customer = await db.prepare("SELECT * FROM customers WHERE payment_token=? AND payment_method='stripe' LIMIT 1").bind(stripeCustomerId).first();
              if (customer) {
                await db.prepare("UPDATE subscriptions SET status='canceled',canceled_at=?,cancel_reason=?,updated_at=? WHERE customer_id=? AND status='active'").bind(now(), 'stripe_webhook_cancellation', now(), customer.id).run();
                log('info', 'Subscription canceled via Stripe webhook', { customer_id: customer.id, stripe_customer: stripeCustomerId });
              }
            }
          }
        } catch (processErr) {
          log('error', 'Webhook event processing failed', { event_type: eventType, error: String(processErr) });
        }
      }

      return jsonOk({ ok: true, received: true, event_type: eventType });
    }

    // Rate limit + auth for writes
    if (m !== 'GET') {
      if (!authOk(req, env)) {
        log('warn', 'Auth failure', { path: p, method: m, ip: ip(req) });
        return jsonErr('Unauthorized', 401);
      }
      if (!(await rateLimit(env.SB_CACHE, `rl:w:${ip(req)}`, 30, 60000))) {
        log('warn', 'Rate limited (write)', { path: p, method: m, ip: ip(req) });
        return jsonErr('Rate limited', 429);
      }
    }

    const db = env.DB;
    let body: Record<string, unknown> = {};
    if (m === 'POST' || m === 'PUT') { try { body = await req.json() as Record<string, unknown>; } catch { log('warn', 'Invalid JSON body', { path: p, method: m, ip: ip(req) }); return jsonErr('Invalid JSON'); } }

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
      // Apply coupon (atomic redemption to prevent over-redemption race)
      let discount = 0; let couponCode: string | null = null;
      if (body.coupon_code) {
        const coupon = await db.prepare('SELECT * FROM coupons WHERE code=? AND org_id=? AND status=?').bind(String(body.coupon_code).toUpperCase(), Number(org_id), 'active').first();
        if (coupon) {
          // Atomically increment redemptions only if under max_redemptions limit
          const redeemResult = await db.prepare(
            'UPDATE coupons SET redemptions=redemptions+1 WHERE id=? AND (max_redemptions IS NULL OR redemptions < max_redemptions)'
          ).bind(coupon.id).run();
          if (redeemResult.meta.changes) {
            couponCode = coupon.code as string;
            if (coupon.discount_type === 'percent') discount = Number(coupon.discount_value);
          }
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
      } catch (err) {
        log('error', 'Churn prediction AI call failed', { org_id: orgId, error: String(err) });
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
      } catch (err) {
        log('error', 'Revenue forecast AI call failed', { org_id: orgId, error: String(err) });
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

    log('warn', 'Route not found', { path: p, method: m, ip: ip(req) });
    return jsonErr('Not found', 404);
  },

  async scheduled(event: ScheduledEvent, env: Env) {
    log('info', 'Scheduled cron started', { cron: event.cron });
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

    log('info', 'Renewals processed', { count: dueRenewals.results.length });

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

    // 4b. Trial expiration reminder — 2 days before trial ends
    const twoDaysFromNow = new Date(Date.now() + 2 * 86400000).toISOString().slice(0, 19).replace('T', ' ');
    const expiringTrials = await db.prepare(
      "SELECT s.id,s.customer_id,s.trial_end,s.plan_id,c.email,c.name,c.metadata FROM subscriptions s JOIN customers c ON s.customer_id=c.id WHERE s.status='trialing' AND s.trial_end<=? AND s.trial_end>? AND NOT EXISTS (SELECT 1 FROM activity_log WHERE action='trial.reminder_sent' AND target='subscription:'||s.id)"
    ).bind(twoDaysFromNow, n).all();
    for (const trial of expiringTrials.results as Record<string, unknown>[]) {
      const email = trial.email as string;
      const name = trial.name as string;
      const trialEnd = trial.trial_end as string;
      let serviceId = '';
      let tierName = '';
      try { const meta = JSON.parse(trial.metadata as string || '{}'); serviceId = meta.service_id || ''; tierName = meta.tier || ''; } catch {}
      const serviceName = serviceId.replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
      try {
        const expiryDate = new Date(trialEnd.replace(' ', 'T') + 'Z').toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
        const productSlug = serviceId.replace(/^echo-/, '');
        await env.EMAIL_SENDER.fetch('https://echo-email-sender.bmcii1976.workers.dev/send', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: email,
            subject: `Your ${serviceName} trial ends in 2 days — upgrade to keep your data`,
            html: `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;margin-top:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,#dc2626 0%,#ef4444 100%);padding:32px 24px;text-align:center">
    <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:700">Your Trial Ends in 2 Days</h1>
    <p style="color:rgba(255,255,255,0.9);margin:8px 0 0;font-size:15px">${serviceName}${tierName ? ' — ' + tierName.charAt(0).toUpperCase() + tierName.slice(1) : ''}</p>
  </div>
  <div style="padding:32px 24px">
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 16px">Hi ${name || 'there'},</p>
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 24px">Your free trial of <strong>${serviceName}</strong> expires on <strong>${expiryDate}</strong>. Upgrade now to keep full access to all features and your data.</p>
    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin:0 0 24px">
      <p style="margin:0;color:#991b1b;font-size:14px"><strong>What happens if you don't upgrade:</strong></p>
      <ul style="margin:8px 0 0;padding-left:20px;color:#991b1b;font-size:14px"><li>Your account will be paused</li><li>Data is saved for 30 days</li><li>You can reactivate anytime</li></ul>
    </div>
    <div style="text-align:center;margin:0 0 24px">
      <a href="https://echo-ept.com/pricing" style="display:inline-block;background:#0d7377;color:#ffffff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px">Upgrade Now</a>
    </div>
    <p style="color:#64748b;font-size:14px;line-height:1.6;margin:0">Questions? Reply to this email or visit <a href="https://echo-ept.com/support" style="color:#0d7377">echo-ept.com/support</a></p>
  </div>
  <div style="background:#f8fafc;padding:20px 24px;border-top:1px solid #e2e8f0;text-align:center">
    <p style="color:#94a3b8;font-size:12px;margin:0">Echo Prime Technologies — Midland, TX</p>
  </div>
</div></body></html>`,
          }),
        });
        await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(
          1, 'system', 'trial.reminder_sent', `subscription:${trial.id}`, `email:${email} trial_end:${trialEnd}`
        ).run();
        log('info', 'Trial reminder email sent', { email, trial_end: trialEnd, subscription_id: trial.id });
      } catch (emailErr) {
        log('warn', 'Trial reminder email failed', { email, error: String(emailErr) });
      }
    }

    // 4c. Day-1 activation nudge — sent 24h after trial start to drive first use
    const oneDayAgo = new Date(Date.now() - 86400000).toISOString().slice(0, 19).replace('T', ' ');
    const twoDaysAgo = new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 19).replace('T', ' ');
    const inactiveTrials = await db.prepare(
      "SELECT s.id,s.customer_id,s.trial_start,s.trial_end,s.plan_id,c.email,c.name,c.metadata FROM subscriptions s JOIN customers c ON s.customer_id=c.id WHERE s.status='trialing' AND s.trial_start<=? AND s.trial_start>=? AND NOT EXISTS (SELECT 1 FROM activity_log WHERE action='trial.day1_sent' AND target='subscription:'||s.id)"
    ).bind(oneDayAgo, twoDaysAgo).all();
    for (const trial of inactiveTrials.results as Record<string, unknown>[]) {
      const email = trial.email as string;
      const trialName = trial.name as string;
      let svcId = ''; let tName = '';
      try { const meta = JSON.parse(trial.metadata as string || '{}'); svcId = meta.service_id || ''; tName = meta.tier || ''; } catch {}
      const productName = svcId.replace(/^echo-/, '').replace(/-/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
      const productSlug = svcId.replace(/^echo-/, '');
      try {
        await env.EMAIL_SENDER.fetch('https://echo-email-sender.bmcii1976.workers.dev/send', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            to: email,
            subject: `Getting started with ${productName} — 3 things to try today`,
            html: `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">
<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;margin-top:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
  <div style="background:linear-gradient(135deg,#0d7377 0%,#14b8a6 100%);padding:32px 24px;text-align:center">
    <h1 style="color:#ffffff;margin:0;font-size:22px;font-weight:700">Day 1: Let's Get You Started</h1>
    <p style="color:rgba(255,255,255,0.9);margin:8px 0 0;font-size:15px">${productName}</p>
  </div>
  <div style="padding:32px 24px">
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 16px">Hi ${trialName || 'there'},</p>
    <p style="color:#334155;font-size:16px;line-height:1.6;margin:0 0 24px">You signed up for ${productName} yesterday. Here are 3 quick wins to get the most from your trial:</p>
    <div style="background:#f0fdfa;border-left:4px solid #14b8a6;padding:16px;margin:0 0 12px;border-radius:0 8px 8px 0">
      <p style="margin:0;color:#0f766e;font-size:14px"><strong>1. Explore the API</strong> — Your endpoint is live at <code style="background:#e2e8f0;padding:2px 6px;border-radius:4px;font-size:13px">${svcId}.bmcii1976.workers.dev</code></p>
    </div>
    <div style="background:#f0fdfa;border-left:4px solid #14b8a6;padding:16px;margin:0 0 12px;border-radius:0 8px 8px 0">
      <p style="margin:0;color:#0f766e;font-size:14px"><strong>2. Read the docs</strong> — Step-by-step guides at <a href="https://echo-ept.com/docs/${productSlug}" style="color:#0d7377">echo-ept.com/docs/${productSlug}</a></p>
    </div>
    <div style="background:#f0fdfa;border-left:4px solid #14b8a6;padding:16px;margin:0 0 24px;border-radius:0 8px 8px 0">
      <p style="margin:0;color:#0f766e;font-size:14px"><strong>3. Test from the dashboard</strong> — <a href="https://echo-ept.com/dashboard" style="color:#0d7377">echo-ept.com/dashboard</a></p>
    </div>
    <div style="text-align:center;margin:0 0 24px">
      <a href="https://echo-ept.com/${productSlug}" style="display:inline-block;background:#0d7377;color:#ffffff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:16px">Open ${productName}</a>
    </div>
    <p style="color:#64748b;font-size:14px;margin:0">Need help? Reply to this email — we respond within hours.</p>
  </div>
  <div style="background:#f8fafc;padding:20px 24px;border-top:1px solid #e2e8f0;text-align:center">
    <p style="color:#94a3b8;font-size:12px;margin:0">Echo Prime Technologies — Midland, TX</p>
  </div>
</div></body></html>`,
          }),
        });
        await db.prepare('INSERT INTO activity_log (org_id,actor,action,target,details) VALUES (?,?,?,?,?)').bind(
          1, 'system', 'trial.day1_sent', `subscription:${trial.id}`, `email:${email}`
        ).run();
        log('info', 'Day-1 activation email sent', { email, subscription_id: trial.id });
      } catch (emailErr) {
        log('warn', 'Day-1 activation email failed', { email, error: String(emailErr) });
      }
    }

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
    log('info', 'Scheduled cron completed', { orgs_processed: orgs.results.length, renewals: dueRenewals.results.length, dunning: pastDue.results.length });
  }
};
