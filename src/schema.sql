-- Echo Subscription v1.0.0 — AI-Powered Subscription Billing
-- D1 Schema

CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  currency TEXT DEFAULT 'USD',
  tax_rate REAL DEFAULT 0,
  dunning_attempts INTEGER DEFAULT 3,
  dunning_interval_days INTEGER DEFAULT 3,
  grace_period_days INTEGER DEFAULT 7,
  webhook_url TEXT,
  webhook_secret TEXT,
  settings JSON DEFAULT '{}',
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  currency TEXT DEFAULT 'USD',
  interval TEXT DEFAULT 'monthly',
  interval_count INTEGER DEFAULT 1,
  trial_days INTEGER DEFAULT 0,
  setup_fee REAL DEFAULT 0,
  features JSON DEFAULT '[]',
  metadata JSON DEFAULT '{}',
  is_public INTEGER DEFAULT 1,
  sort_order INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS addons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  billing_type TEXT DEFAULT 'flat',
  unit_name TEXT DEFAULT 'unit',
  included_units INTEGER DEFAULT 0,
  overage_price REAL DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  email TEXT NOT NULL,
  name TEXT,
  company TEXT,
  phone TEXT,
  address JSON DEFAULT '{}',
  payment_method TEXT,
  payment_token TEXT,
  tax_id TEXT,
  metadata JSON DEFAULT '{}',
  mrr REAL DEFAULT 0,
  lifetime_value REAL DEFAULT 0,
  churn_risk REAL DEFAULT 0,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, email)
);
CREATE INDEX IF NOT EXISTS idx_customers_org ON customers(org_id);
CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(org_id, status);

CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  customer_id INTEGER NOT NULL,
  plan_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  price_override REAL,
  discount_percent REAL DEFAULT 0,
  coupon_code TEXT,
  trial_start TEXT,
  trial_end TEXT,
  current_period_start TEXT NOT NULL,
  current_period_end TEXT NOT NULL,
  canceled_at TEXT,
  cancel_reason TEXT,
  pause_start TEXT,
  pause_end TEXT,
  dunning_count INTEGER DEFAULT 0,
  last_dunning_at TEXT,
  metadata JSON DEFAULT '{}',
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_subs_customer ON subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS idx_subs_plan ON subscriptions(plan_id);
CREATE INDEX IF NOT EXISTS idx_subs_status ON subscriptions(org_id, status);
CREATE INDEX IF NOT EXISTS idx_subs_period ON subscriptions(current_period_end);

CREATE TABLE IF NOT EXISTS subscription_addons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscription_id INTEGER NOT NULL,
  addon_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(subscription_id, addon_id)
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  customer_id INTEGER NOT NULL,
  subscription_id INTEGER,
  invoice_number TEXT NOT NULL,
  subtotal REAL NOT NULL DEFAULT 0,
  tax REAL DEFAULT 0,
  discount REAL DEFAULT 0,
  total REAL NOT NULL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  period_start TEXT,
  period_end TEXT,
  due_date TEXT,
  paid_at TEXT,
  payment_method TEXT,
  payment_ref TEXT,
  notes TEXT,
  status TEXT DEFAULT 'draft',
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_invoices_customer ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(org_id, status);

CREATE TABLE IF NOT EXISTS invoice_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER NOT NULL,
  description TEXT NOT NULL,
  quantity REAL DEFAULT 1,
  unit_price REAL NOT NULL,
  amount REAL NOT NULL,
  item_type TEXT DEFAULT 'subscription',
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS usage_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  subscription_id INTEGER NOT NULL,
  addon_id INTEGER NOT NULL,
  quantity REAL NOT NULL,
  recorded_at TEXT DEFAULT (datetime('now')),
  period TEXT NOT NULL,
  metadata JSON DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_usage_sub ON usage_records(subscription_id, addon_id, period);

CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  payload JSON NOT NULL,
  delivered INTEGER DEFAULT 0,
  attempts INTEGER DEFAULT 0,
  last_attempt TEXT,
  response_code INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS coupons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  code TEXT NOT NULL,
  name TEXT,
  discount_type TEXT DEFAULT 'percent',
  discount_value REAL NOT NULL,
  duration TEXT DEFAULT 'once',
  duration_months INTEGER,
  max_redemptions INTEGER,
  redemptions INTEGER DEFAULT 0,
  applies_to JSON DEFAULT '[]',
  valid_from TEXT,
  valid_until TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(org_id, code)
);

CREATE TABLE IF NOT EXISTS revenue_daily (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  mrr REAL DEFAULT 0,
  arr REAL DEFAULT 0,
  new_mrr REAL DEFAULT 0,
  churned_mrr REAL DEFAULT 0,
  expansion_mrr REAL DEFAULT 0,
  active_subscriptions INTEGER DEFAULT 0,
  new_subscriptions INTEGER DEFAULT 0,
  churned_subscriptions INTEGER DEFAULT 0,
  trial_subscriptions INTEGER DEFAULT 0,
  invoices_paid REAL DEFAULT 0,
  invoices_outstanding REAL DEFAULT 0,
  UNIQUE(org_id, date)
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
