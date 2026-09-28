import { MongoClient } from "npm:mongodb@6.19.0";

const MONGO_URI = Deno.env.get("MONGO_URI") ?? "";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") ?? "";

const client = new MongoClient(MONGO_URI);
let dbPromise: Promise<any> | null = null;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, x-admin-pass",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Cache-Control": "no-store",
};

const FAILURE = {
  active: false,
  message: "❌ Activation unavailable. Please contact us on WhatsApp at +91 95296 36044 to purchase an AI Assistant key.",
  success: false,
  variant: "elite",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });
}

async function db() {
  if (!dbPromise) {
    if (!MONGO_URI) throw new Error("MONGO_URI is not configured");
    dbPromise = client.connect().then(() => client.db("ai_assistant"));
  }
  return dbPromise;
}

function adminOK(req: Request) {
  const supplied = req.headers.get("x-admin-pass") ?? "";
  return !!ADMIN_PASSWORD && supplied === ADMIN_PASSWORD;
}

function clean(d: any) {
  return {
    key: d.key ?? "",
    active: !!d.active,
    device_id: d.device_id ?? null,
    variant: d.variant ?? "elite",
    expires_at: d.expires_at ?? null,
    claimed_at: d.claimed_at ?? null,
    created_at: d.created_at ?? null,
    remarks: d.remarks ?? "",
    notes: d.notes ?? "",
  };
}

async function verifyLicense(body: any) {
  const key = String(body?.access_key ?? "").trim();
  const device = String(body?.deviceId ?? "").trim();
  if (!key || !device) return FAILURE;

  const database = await db();
  const keys = database.collection("api_keys");
  const audit = database.collection("audit_logs");

  const doc = await keys.findOne({ key });
  if (!doc || !doc.active) return FAILURE;

  const variant = String(doc.variant ?? "elite");
  const expiry = doc.expires_at ? new Date(doc.expires_at) : null;
  if (expiry && !Number.isNaN(expiry.getTime()) && expiry <= new Date()) {
    return { ...FAILURE, variant };
  }

  const owner = doc.device_id ?? null;
  if (owner === device) {
    await audit.insertOne({ key, action: "verify_allowed", device_id: device, details: "Existing device verified", timestamp: new Date() });
    return { active: true, message: "Key activated successfully.", success: true, variant };
  }

  if (owner) {
    await audit.insertOne({ key, action: "verify_denied", device_id: device, details: "Key belongs to another device", timestamp: new Date() });
    return { ...FAILURE, variant };
  }

  const other = await keys.findOne({ device_id: device, key: { $ne: key } });
  if (other) {
    await audit.insertOne({ key, action: "verify_denied", device_id: device, details: `Device already owns ${other.key}`, timestamp: new Date() });
    return { ...FAILURE, variant };
  }

  const claimed = await keys.findOneAndUpdate(
    { key, active: true, $or: [{ device_id: null }, { device_id: "" }] },
    { $set: { device_id: device, claimed_at: new Date() } },
    { returnDocument: "after" },
  );

  if (claimed) {
    await audit.insertOne({ key, action: "claimed", device_id: device, details: "License activated", timestamp: new Date() });
    return { active: true, message: "Key activated successfully.", success: true, variant: String(claimed.variant ?? "elite") };
  }

  const current = await keys.findOne({ key });
  if (current?.device_id === device) {
    return { active: true, message: "Key activated successfully.", success: true, variant: String(current.variant ?? "elite") };
  }

  return { ...FAILURE, variant };
}

function segment() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = new Uint8Array(4);
  crypto.getRandomValues(b);
  return Array.from(b, x => chars[x % chars.length]).join("");
}

function makeKey(variant: string) {
  return `MJ-${variant.toUpperCase()}-${segment()}-${segment()}`;
}

async function adminAction(action: string, req: Request) {
  const database = await db();
  const keys = database.collection("api_keys");
  const audit = database.collection("audit_logs");

  if (action === "stats") {
    const [total, active, available, claimed, expired] = await Promise.all([
      keys.countDocuments({}),
      keys.countDocuments({ active: true }),
      keys.countDocuments({ device_id: null }),
      keys.countDocuments({ device_id: { $type: "string", $ne: "" } }),
      keys.countDocuments({ expires_at: { $ne: null, $lte: new Date() } }),
    ]);
    return { total, active, available, claimed, expired };
  }

  if (action === "keys") {
    const url = new URL(req.url);
  const action = url.searchParams.get("action");
  const accept = req.headers.get("accept") ?? "";
  const secFetchDest = (req.headers.get("sec-fetch-dest") ?? "").toLowerCase();
  const isDocumentRequest = secFetchDest === "document" || (!secFetchDest && accept.includes("text/html"));

  if (url.searchParams.get("panel") === "1" || (!action && isDocumentRequest)) {
    return new Response(PANEL, { headers: { ...CORS, "Content-Type": "text/html; charset=utf-8" } });
  }

  if (!action) {
    const panelUrl = url.origin + url.pathname + "?panel=1";
    const loader = (() => {
      const panelUrlJson = JSON.stringify(panelUrl);
      return `(() => {
        if (document.getElementById("gogo-keys-panel-frame")) return;
        const f = document.createElement("iframe");
        f.id = "gogo-keys-panel-frame";
        f.src = ${panelUrlJson};
        f.title = "GOGO AI License Control";
        f.style.cssText = "position:fixed;inset:0;width:100%;height:100%;border:0;z-index:2147483647;background:#070a11";
        document.documentElement.style.background = "#070a11";
        document.body.style.margin = "0";
        document.body.appendChild(f);
      })()`;
    })();
    return new Response(loader, { headers: { ...CORS, "Content-Type": "application/javascript; charset=utf-8" } });
  }

  if (action === "verify") {
    try { return json(await verifyLicense(await req.json())); }
    catch { return json(FAILURE); }
  }

  if (!adminOK(req)) return json({ error: "Unauthorized" }, 401);

  try { return json(await adminAction(action, req)); }
  catch (e) { return json({ error: e instanceof Error ? e.message : "Server error" }, 500); }
});