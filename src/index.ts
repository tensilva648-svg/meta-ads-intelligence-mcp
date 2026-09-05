import "dotenv/config";
import express from "express";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "0.0.0.0";
const MCP_BEARER_TOKEN = process.env.MCP_BEARER_TOKEN || "";
const META_TOKEN = process.env.META_ACCESS_TOKEN || "";
const META_ACCOUNT = process.env.META_AD_ACCOUNT_ID || "";
const META_VERSION = process.env.META_API_VERSION || "";
const AD_LIBRARY_COUNTRY = process.env.META_AD_LIBRARY_COUNTRY || "BR";
const ALLOW_MUTATIONS = process.env.ALLOW_MUTATIONS === "true";
const MAX_BULK_MUTATIONS = Number(process.env.MAX_BULK_MUTATIONS || 50);

if (!MCP_BEARER_TOKEN) throw new Error("MCP_BEARER_TOKEN is required");

function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function auth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ") || !safeEqual(header.slice(7), MCP_BEARER_TOKEN)) {
    const base = `${req.protocol}://${req.get("host")}`;
    res.setHeader(
      "WWW-Authenticate",
      `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`
    );
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// --- Minimal OAuth 2.1 + PKCE + Dynamic Client Registration shim ---
// Claude's remote-connector UI requires an OAuth login flow before it will
// call /mcp. This server only has a single static MCP_BEARER_TOKEN, so this
// shim implements just enough OAuth to satisfy that flow: it auto-approves
// the authorization request and hands back the existing MCP_BEARER_TOKEN as
// the access_token. It does not add a second secret to protect — the real
// protection is still the bearer token itself.

type AuthCodeEntry = {
  code_challenge: string;
  code_challenge_method: string;
  redirect_uri: string;
  expires: number;
};

const AUTH_CODES = new Map<string, AuthCodeEntry>();
const REGISTERED_CLIENTS = new Map<string, { redirect_uris: string[] }>();

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function cleanupExpiredCodes() {
  const now = Date.now();
  for (const [code, entry] of AUTH_CODES) {
    if (entry.expires < now) AUTH_CODES.delete(code);
  }
}

function metaConfigured() {
  return Boolean(META_TOKEN && META_ACCOUNT && META_VERSION);
}

async function metaRequest(
  method: "GET" | "POST",
  path: string,
  params: Record<string, string> = {}
) {
  if (!metaConfigured()) {
    throw new Error("Configure META_ACCESS_TOKEN, META_AD_ACCOUNT_ID and META_API_VERSION");
  }

  const url = new URL(`https://graph.facebook.com/${META_VERSION}/${path.replace(/^\/+/, "")}`);
  const body = new URLSearchParams();

  if (method === "GET") {
    url.searchParams.set("access_token", META_TOKEN);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  } else {
    body.set("access_token", META_TOKEN);
    for (const [k, v] of Object.entries(params)) body.set(k, v);
  }

  const response = await fetch(url, {
    method,
    headers: method === "POST" ? { "content-type": "application/x-www-form-urlencoded" } : undefined,
    body: method === "POST" ? body : undefined
  });

  const json = await response.json();
  if (!response.ok) throw new Error(`Meta API ${response.status}: ${JSON.stringify(json)}`);
  return json;
}

function result(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function buildServer() {
  const server = new McpServer(
    { name: "meta-ads-intelligence", version: "0.2.0" },
    {
      capabilities: { tools: {} },
      instructions:
        "Meta Ads Intelligence. Prefer read-only analysis. For mutations, use dry-run tools first and require explicit confirmation. Never claim a copy is guaranteed to pass Meta review. Optimize for truthful, policy-compliant advertising; never disguise prohibited offers or bypass enforcement."
    }
  );

  server.tool(
    "meta_account_health",
    "Basic connectivity check for the configured Meta ad account.",
    {},
    async () => {
      const account = await metaRequest("GET", META_ACCOUNT, {
        fields: "id,name,account_status,currency,timezone_name"
      });
      return result(account);
    }
  );

  server.tool(
    "meta_list_campaigns",
    "List campaigns from the configured Meta ad account.",
    {
      limit: z.number().int().min(1).max(100).default(50),
      fields: z.string().default("id,name,status,effective_status,objective,daily_budget,lifetime_budget")
    },
    async ({ limit, fields }) =>
      result(await metaRequest("GET", `${META_ACCOUNT}/campaigns`, {
        fields,
        limit: String(limit)
      }))
  );

  server.tool(
    "meta_list_adsets",
    "List ad sets, optionally filtered to a campaign_id. Returns targeting, budget, optimization goal, billing event, bid strategy and schedule — read-only, no changes made.",
    {
      campaign_id: z.string().optional(),
      limit: z.number().int().min(1).max(100).default(50),
      fields: z.string().default(
        "id,name,campaign_id,status,effective_status,daily_budget,lifetime_budget,billing_event,optimization_goal,bid_strategy,targeting,start_time,end_time"
      )
    },
    async ({ campaign_id, limit, fields }) => {
      const params: Record<string, string> = { fields, limit: String(limit) };
      const path = campaign_id ? `${campaign_id}/adsets` : `${META_ACCOUNT}/adsets`;
      return result(await metaRequest("GET", path, params));
    }
  );

  server.tool(
    "meta_list_ads",
    "List ads, optionally restricted to an effective status.",
    {
      limit: z.number().int().min(1).max(100).default(50),
      effective_status: z.string().optional(),
      fields: z.string().default("id,name,status,effective_status,adset_id,campaign_id,creative{id,name,object_story_spec}")
    },
    async ({ limit, effective_status, fields }) => {
      const params: Record<string,string> = { fields, limit: String(limit) };
      if (effective_status) params.effective_status = effective_status;
      return result(await metaRequest("GET", `${META_ACCOUNT}/ads`, params));
    }
  );

  server.tool(
    "meta_insights",
    "Read performance insights at account, campaign, adset, or ad level.",
    {
      level: z.enum(["account","campaign","adset","ad"]).default("campaign"),
      date_preset: z.string().default("last_7d"),
      limit: z.number().int().min(1).max(100).default(100),
      fields: z.string().default("campaign_name,adset_name,ad_name,impressions,reach,spend,clicks,ctr,cpc,cpm,conversions,actions")
    },
    async ({ level, date_preset, limit, fields }) =>
      result(await metaRequest("GET", `${META_ACCOUNT}/insights`, {
        level, date_preset, limit: String(limit), fields
      }))
  );

  server.tool(
    "meta_ad_library_search",
    "Search eligible Meta Ad Library API results. Coverage depends on Meta's API rules, ad category and country. This tool does not scrape the public site.",
    {
      search_terms: z.string().min(1).max(100),
      country: z.string().default(AD_LIBRARY_COUNTRY),
      ad_type: z.string().default("ALL"),
      active_status: z.enum(["ACTIVE","ALL","INACTIVE"]).default("ACTIVE"),
      media_type: z.enum(["ALL","IMAGE","MEME","VIDEO","NONE"]).default("ALL"),
      limit: z.number().int().min(1).max(100).default(25)
    },
    async ({ search_terms, country, ad_type, active_status, media_type, limit }) =>
      result(await metaRequest("GET", "ads_archive", {
        search_terms,
        ad_reached_countries: JSON.stringify([country.toUpperCase()]),
        ad_type,
        ad_active_status: active_status,
        media_type,
        limit: String(limit),
        fields:
          "id,ad_archive_id,page_id,page_name,ad_creation_time,ad_delivery_start_time,ad_delivery_stop_time,ad_creative_bodies,ad_creative_link_captions,ad_creative_link_titles,ad_snapshot_url,publisher_platforms"
      }))
  );

  server.tool(
    "audit_copy_for_policy_risk",
    "Flags potentially risky wording patterns for review. This is a review aid, not a guarantee of Meta approval and not an evasion mechanism.",
    {
      ads: z.array(z.object({
        id: z.string().optional(),
        body: z.string().optional(),
        title: z.string().optional(),
        caption: z.string().optional()
      })).min(1).max(200)
    },
    async ({ ads }) => {
      const patterns = [
        { label: "illegal_or_unauthorized_claim", re: /\b(pirata|pirataria|sem licença|desbloqueado ilegal|acesso ilegal)\b/i },
        { label: "guaranteed_claim", re: /\b(garantido|100% garantido|sem risco)\b/i },
        { label: "extreme_urgency", re: /\b(última chance|agora ou nunca|imperdível|só hoje)\b/i },
        { label: "misleading_free_claim", re: /\b(grátis|gratuito)\b/i }
      ];

      const analyzed = ads.map(ad => {
        const text = [ad.body, ad.title, ad.caption].filter(Boolean).join(" ");
        const flags = patterns.filter(p => p.re.test(text)).map(p => p.label);
        return {
          id: ad.id ?? null,
          flags,
          risk: flags.length >= 2 ? "high" : flags.length === 1 ? "review" : "low",
          recommendation:
            flags.length
              ? "Revisar a veracidade, a oferta e a conformidade com as políticas da Meta antes de publicar."
              : "Nenhum padrão configurado foi detectado; isso não significa aprovação."
        };
      });

      return result({ count: analyzed.length, analyzed });
    }
  );

  server.tool(
    "prepare_bulk_ad_status_change",
    "Read-only dry run. Select ads and prepare a batch status change without modifying Meta.",
    {
      target_status: z.enum(["ACTIVE","PAUSED"]),
      effective_status: z.string().default("ACTIVE"),
      limit: z.number().int().min(1).max(500).default(200)
    },
    async ({ target_status, effective_status, limit }) => {
      const data = await metaRequest("GET", `${META_ACCOUNT}/ads`, {
        fields: "id,name,status,effective_status,campaign_id,adset_id",
        effective_status,
        limit: String(limit)
      });
      const ads = Array.isArray(data?.data) ? data.data : [];
      if (ads.length > MAX_BULK_MUTATIONS) {
        return result({
          dry_run: true,
          blocked: true,
          reason: `Batch contains ${ads.length} ads; configured maximum is ${MAX_BULK_MUTATIONS}.`
        });
      }
      return result({
        dry_run: true,
        target_status,
        count: ads.length,
        ads,
        confirmation_required: true
      });
    }
  );

  server.tool(
    "set_ad_status",
    "Pause or activate one ad. Mutations are disabled unless ALLOW_MUTATIONS=true.",
    {
      ad_id: z.string().min(1),
      status: z.enum(["ACTIVE","PAUSED"]),
      confirmed: z.boolean().default(false)
    },
    async ({ ad_id, status, confirmed }) => {
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing." });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", ad_id, status });
      }
      return result(await metaRequest("POST", ad_id, { status }));
    }
  );

  server.tool(
    "plan_competitor_report",
    "Create a structured research plan for comparing competitors using only public/authorized data.",
    {
      market: z.string().min(2),
      competitors: z.array(z.string()).min(1).max(20),
      country: z.string().default("BR")
    },
    async ({ market, competitors, country }) =>
      result({
        market,
        country,
        competitors,
        collect: [
          "active public ads available through Meta Ad Library/API",
          "recurring offers and positioning",
          "copy themes and calls to action",
          "creative formats and recurring visual patterns",
          "landing-page claims supplied by the user or obtained from authorized/public sources"
        ],
        do_not_infer: [
          "private competitor spend",
          "private conversion rates",
          "private audience lists",
          "private account data"
        ],
        output: "comparison matrix + opportunities + compliance review"
      })
  );

  // --- Creation tools ---
  // Safety design: every object created by these tools is FORCED to status
  // "PAUSED" in code, regardless of what the caller passes in. There is no
  // parameter that can make these tools publish something live. Combined
  // with the existing ALLOW_MUTATIONS + confirmed=true gate, this means a
  // new campaign/adset/ad can only ever be created paused, for manual
  // review — never activated by this pathway.

  server.tool(
    "create_campaign",
    "Create a new campaign. Always created with status PAUSED, regardless of input — this tool cannot launch a live campaign. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      name: z.string().min(1),
      objective: z.string().min(1),
      daily_budget_cents: z.number().int().positive().optional(),
      lifetime_budget_cents: z.number().int().positive().optional(),
      special_ad_categories: z.array(z.string()).default([]),
      confirmed: z.boolean().default(false)
    },
    async ({ name, objective, daily_budget_cents, lifetime_budget_cents, special_ad_categories, confirmed }) => {
      const preview = {
        name, objective, daily_budget_cents, lifetime_budget_cents,
        special_ad_categories, status: "PAUSED" as const
      };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      const params: Record<string, string> = {
        name,
        objective,
        status: "PAUSED",
        special_ad_categories: JSON.stringify(special_ad_categories)
      };
      if (daily_budget_cents) params.daily_budget = String(daily_budget_cents);
      if (lifetime_budget_cents) params.lifetime_budget = String(lifetime_budget_cents);
      return result(await metaRequest("POST", `${META_ACCOUNT}/campaigns`, params));
    }
  );

  server.tool(
    "create_adset",
    "Create a new ad set inside an existing campaign. Always created with status PAUSED, regardless of input. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      campaign_id: z.string().min(1),
      name: z.string().min(1),
      daily_budget_cents: z.number().int().positive().optional(),
      lifetime_budget_cents: z.number().int().positive().optional(),
      billing_event: z.string().default("IMPRESSIONS"),
      optimization_goal: z.string().min(1),
      targeting: z.record(z.any()),
      promoted_object: z.record(z.any()).optional(),
      attribution_spec: z.array(z.record(z.any())).optional(),
      start_time: z.string().optional(),
      end_time: z.string().optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ campaign_id, name, daily_budget_cents, lifetime_budget_cents, billing_event, optimization_goal, targeting, promoted_object, attribution_spec, start_time, end_time, confirmed }) => {
      const preview = {
        campaign_id, name, daily_budget_cents, lifetime_budget_cents,
        billing_event, optimization_goal, targeting, promoted_object, attribution_spec, start_time, end_time,
        status: "PAUSED" as const
      };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      const params: Record<string, string> = {
        campaign_id,
        name,
        status: "PAUSED",
        billing_event,
        optimization_goal,
        targeting: JSON.stringify(targeting)
      };
      if (daily_budget_cents) params.daily_budget = String(daily_budget_cents);
      if (lifetime_budget_cents) params.lifetime_budget = String(lifetime_budget_cents);
      if (promoted_object) params.promoted_object = JSON.stringify(promoted_object);
      if (attribution_spec) params.attribution_spec = JSON.stringify(attribution_spec);
      if (start_time) params.start_time = start_time;
      if (end_time) params.end_time = end_time;
      return result(await metaRequest("POST", `${META_ACCOUNT}/adsets`, params));
    }
  );

  server.tool(
    "create_ad",
    "Create a new ad inside an existing ad set, reusing an existing creative by id (e.g. to duplicate a proven creative under a new ad/copy test) or a full object_story_spec. Always created with status PAUSED, regardless of input. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      adset_id: z.string().min(1),
      name: z.string().min(1),
      creative_id: z.string().optional(),
      object_story_spec: z.record(z.any()).optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ adset_id, name, creative_id, object_story_spec, confirmed }) => {
      const preview = { adset_id, name, creative_id, object_story_spec, status: "PAUSED" as const };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      if (!creative_id && !object_story_spec) {
        return result({ executed: false, reason: "Provide either creative_id (reuse an existing creative) or object_story_spec (new creative)." });
      }
      let creativeId = creative_id;
      if (!creativeId && object_story_spec) {
        const creative = await metaRequest("POST", `${META_ACCOUNT}/adcreatives`, {
          name: `${name} - creative`,
          object_story_spec: JSON.stringify(object_story_spec)
        });
        creativeId = creative.id;
      }
      const params: Record<string, string> = {
        adset_id,
        name,
        status: "PAUSED",
        creative: JSON.stringify({ creative_id: creativeId })
      };
      return result(await metaRequest("POST", `${META_ACCOUNT}/ads`, params));
    }
  );

  // --- Update tools (for managing existing, already-live objects) ---
  // Unlike the create_* tools above, these do NOT force a status — that's
  // the point of them (pausing/reactivating/rebudgeting an existing
  // campaign is a legitimate, requested action). They stay behind the same
  // ALLOW_MUTATIONS + confirmed=true gate as set_ad_status, so nothing
  // executes without an explicit, per-call confirmation.

  server.tool(
    "update_campaign",
    "Update an existing campaign: name, budget, bid strategy, and/or status (ACTIVE/PAUSED). Only fields you pass are changed. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      campaign_id: z.string().min(1),
      name: z.string().optional(),
      daily_budget_cents: z.number().int().positive().optional(),
      lifetime_budget_cents: z.number().int().positive().optional(),
      bid_strategy: z.string().optional(),
      status: z.enum(["ACTIVE", "PAUSED"]).optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ campaign_id, name, daily_budget_cents, lifetime_budget_cents, bid_strategy, status, confirmed }) => {
      const preview = { campaign_id, name, daily_budget_cents, lifetime_budget_cents, bid_strategy, status };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      const params: Record<string, string> = {};
      if (name) params.name = name;
      if (daily_budget_cents) params.daily_budget = String(daily_budget_cents);
      if (lifetime_budget_cents) params.lifetime_budget = String(lifetime_budget_cents);
      if (bid_strategy) params.bid_strategy = bid_strategy;
      if (status) params.status = status;
      if (Object.keys(params).length === 0) {
        return result({ executed: false, reason: "No fields provided to update." });
      }
      return result(await metaRequest("POST", campaign_id, params));
    }
  );

  server.tool(
    "update_adset",
    "Update an existing ad set: name, budget, targeting, optimization goal, and/or status (ACTIVE/PAUSED). Only fields you pass are changed. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      adset_id: z.string().min(1),
      name: z.string().optional(),
      daily_budget_cents: z.number().int().positive().optional(),
      lifetime_budget_cents: z.number().int().positive().optional(),
      targeting: z.record(z.any()).optional(),
      optimization_goal: z.string().optional(),
      status: z.enum(["ACTIVE", "PAUSED"]).optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ adset_id, name, daily_budget_cents, lifetime_budget_cents, targeting, optimization_goal, status, confirmed }) => {
      const preview = { adset_id, name, daily_budget_cents, lifetime_budget_cents, targeting, optimization_goal, status };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      const params: Record<string, string> = {};
      if (name) params.name = name;
      if (daily_budget_cents) params.daily_budget = String(daily_budget_cents);
      if (lifetime_budget_cents) params.lifetime_budget = String(lifetime_budget_cents);
      if (targeting) params.targeting = JSON.stringify(targeting);
      if (optimization_goal) params.optimization_goal = optimization_goal;
      if (status) params.status = status;
      if (Object.keys(params).length === 0) {
        return result({ executed: false, reason: "No fields provided to update." });
      }
      return result(await metaRequest("POST", adset_id, params));
    }
  );

  server.tool(
    "update_ad",
    "Update an existing ad: name, status (ACTIVE/PAUSED), and/or swap its creative (pass creative_id to reuse/replace with a different creative). Only fields you pass are changed. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      ad_id: z.string().min(1),
      name: z.string().optional(),
      creative_id: z.string().optional(),
      status: z.enum(["ACTIVE", "PAUSED"]).optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ ad_id, name, creative_id, status, confirmed }) => {
      const preview = { ad_id, name, creative_id, status };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      const params: Record<string, string> = {};
      if (name) params.name = name;
      if (creative_id) params.creative = JSON.stringify({ creative_id });
      if (status) params.status = status;
      if (Object.keys(params).length === 0) {
        return result({ executed: false, reason: "No fields provided to update." });
      }
      return result(await metaRequest("POST", ad_id, params));
    }
  );

  server.tool(
    "create_adcreative",
    "Create a new ad creative (new copy/CTA/link, reusing an existing image_hash or video_id) that can then be passed as creative_id to create_ad or update_ad to swap a creative. Requires ALLOW_MUTATIONS=true and confirmed=true.",
    {
      name: z.string().min(1),
      page_id: z.string().min(1),
      message: z.string().optional(),
      link: z.string().optional(),
      link_title: z.string().optional(),
      call_to_action_type: z.string().optional(),
      image_hash: z.string().optional(),
      video_id: z.string().optional(),
      confirmed: z.boolean().default(false)
    },
    async ({ name, page_id, message, link, link_title, call_to_action_type, image_hash, video_id, confirmed }) => {
      const preview = { name, page_id, message, link, link_title, call_to_action_type, image_hash, video_id };
      if (!ALLOW_MUTATIONS) {
        return result({ executed: false, reason: "Mutations are disabled. Set ALLOW_MUTATIONS=true on the server after testing.", preview });
      }
      if (!confirmed) {
        return result({ executed: false, reason: "Explicit confirmation is required.", preview });
      }
      if (!image_hash && !video_id) {
        return result({ executed: false, reason: "Provide image_hash or video_id from an existing, already-uploaded asset." });
      }
      const link_data: Record<string, unknown> = { link: link || "" };
      if (message) link_data.message = message;
      if (link_title) link_data.name = link_title;
      if (image_hash) link_data.image_hash = image_hash;
      if (call_to_action_type) link_data.call_to_action = { type: call_to_action_type, value: { link } };

      const object_story_spec: Record<string, unknown> = video_id
        ? {
            page_id,
            video_data: {
              video_id,
              message,
              image_hash,
              call_to_action: call_to_action_type ? { type: call_to_action_type, value: { link } } : undefined
            }
          }
        : { page_id, link_data };

      return result(await metaRequest("POST", `${META_ACCOUNT}/adcreatives`, {
        name,
        object_story_spec: JSON.stringify(object_story_spec)
      }));
    }
  );

  return server;
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use((req, _res, next) => {
  console.error(`[req] ${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "meta-ads-intelligence-mcp", version: "0.2.0" });
});

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  res.json({
    resource: `${base}/mcp`,
    authorization_servers: [base]
  });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    registration_endpoint: `${base}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256", "plain"],
    token_endpoint_auth_methods_supported: ["none"]
  });
});

app.post("/register", (req, res) => {
  const client_id = randomToken(16);
  const redirect_uris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris : [];
  REGISTERED_CLIENTS.set(client_id, { redirect_uris });
  res.status(201).json({
    client_id,
    redirect_uris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"]
  });
});

app.get("/authorize", (req, res) => {
  cleanupExpiredCodes();
  const redirect_uri = String(req.query.redirect_uri || "");
  const state = req.query.state ? String(req.query.state) : "";
  const code_challenge = req.query.code_challenge ? String(req.query.code_challenge) : "";
  const code_challenge_method = req.query.code_challenge_method
    ? String(req.query.code_challenge_method)
    : "plain";

  if (!redirect_uri) return res.status(400).send("Missing redirect_uri");

  const code = randomToken(24);
  AUTH_CODES.set(code, {
    code_challenge,
    code_challenge_method,
    redirect_uri,
    expires: Date.now() + 5 * 60 * 1000
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
});

app.post(
  "/token",
  express.urlencoded({ extended: true }),
  (req, res) => {
    cleanupExpiredCodes();
    const grant_type = req.body?.grant_type;
    const code = req.body?.code;
    const code_verifier = req.body?.code_verifier;

    if (grant_type !== "authorization_code") {
      return res.status(400).json({ error: "unsupported_grant_type" });
    }

    const entry = code ? AUTH_CODES.get(code) : undefined;
    if (!entry || entry.expires < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    AUTH_CODES.delete(code);

    if (entry.code_challenge) {
      if (!code_verifier) {
        return res.status(400).json({ error: "invalid_grant", error_description: "missing code_verifier" });
      }
      let check = String(code_verifier);
      if (entry.code_challenge_method === "S256") {
        check = crypto.createHash("sha256").update(check).digest("base64url");
      }
      if (check !== entry.code_challenge) {
        return res.status(400).json({ error: "invalid_grant", error_description: "PKCE mismatch" });
      }
    }

    res.json({
      access_token: MCP_BEARER_TOKEN,
      token_type: "Bearer",
      expires_in: 31536000
    });
  }
);

app.all("/mcp", auth, async (req, res) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined
    });
    res.on("close", () => {
      transport.close();
    });

    const server = buildServer();
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error);
    if (!res.headersSent) res.status(500).json({ error: "MCP server error" });
  }
});

app.listen(PORT, HOST, () => {
  console.error(`Meta Ads Intelligence MCP listening on http://${HOST}:${PORT}/mcp`);
});
