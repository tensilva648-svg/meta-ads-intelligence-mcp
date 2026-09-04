import "dotenv/config";
import express from "express";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
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

const sessions = new Map<string, StreamableHTTPServerTransport>();

function safeEqual(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function auth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const header = String(req.headers.authorization || "");
  if (!header.startsWith("Bearer ") || !safeEqual(header.slice(7), MCP_BEARER_TOKEN)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
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

  return server;
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "meta-ads-intelligence-mcp", version: "0.2.0" });
});

app.all("/mcp", auth, async (req, res) => {
  try {
    const sessionId = String(req.headers["mcp-session-id"] || "");
    let transport = sessionId ? sessions.get(sessionId) : undefined;

    if (!transport && req.method === "POST" && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: (id) => {
          sessions.set(id, transport!);
        }
      });

      transport.onclose = () => {
        const id = transport?.sessionId;
        if (id) sessions.delete(id);
      };

      const server = buildServer();
      await server.connect(transport);
    }

    if (!transport) {
      return res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Invalid or missing MCP session" },
        id: null
      });
    }

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) res.status(500).json({ error: "MCP server error" });
  }
});

app.listen(PORT, HOST, () => {
  console.error(`Meta Ads Intelligence MCP listening on http://${HOST}:${PORT}/mcp`);
});
