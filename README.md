# Echo Subscription

> Recurring-billing & subscription management for ECHO Prime. Plans, add-ons,
> coupons, customers, invoices, and Stripe checkout/portal — multi-tenant. A
> Cloudflare Worker.

Private to Echo Prime Technologies.

## What it does

Define **plans** (with **add-ons** and **coupons**), enroll **customers** under an
**org**, bill them on a recurring cycle, and surface **invoices** and **metrics**
(MRR, churn). Checkout and self-service billing run through **Stripe**.

## API (auth: `X-Echo-API-Key`)

| Route | Resource |
|---|---|
| `/orgs` | Organizations (tenants) |
| `/customers` | Subscribers |
| `/plans` | Subscription plans |
| `/addons` | Plan add-ons |
| `/coupons` | Discount coupons |
| `/invoices` | Invoices |
| `/metrics` | Billing metrics (MRR, churn, …) |
| `/stripe/checkout-session` | Create a Stripe Checkout session |
| `/stripe/portal-session` | Create a Stripe customer-portal session |
| `/health` | Liveness |

`GET` lists/reads, `POST` creates, `PUT`/`DELETE` on `/:id` where applicable.

## Develop

```bash
npm install
npx wrangler dev       # local Worker
npx wrangler deploy    # deploy
```

Stripe keys and the D1 binding live in `wrangler.toml` / the Cloudflare dashboard.
`.gitignore` excludes `node_modules`. Never commit secrets.

## License

Proprietary — © Echo Prime Technologies. All rights reserved.
