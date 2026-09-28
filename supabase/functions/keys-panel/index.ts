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
    const q = (url.searchParams.get("q") ?? "").trim();
    const filter = q ? { $or: [
      { key: { $regex: q, $options: "i" } },
      { device_id: { $regex: q, $options: "i" } },
      { remarks: { $regex: q, $options: "i" } },
      { notes: { $regex: q, $options: "i" } },
    ] } : {};
    const rows = await keys.find(filter).sort({ created_at: -1 }).limit(1000).toArray();
    return { keys: rows.map(clean) };
  }

  if (action === "audit") {
    const rows = await audit.find({}).sort({ timestamp: -1 }).limit(300).toArray();
    return { logs: rows.map((x: any) => ({
      key: x.key ?? "", action: x.action ?? "", device_id: x.device_id ?? null,
      details: x.details ?? "", timestamp: x.timestamp ?? null,
    })) };
  }

  const body = await req.json();

  if (action === "generate") {
    const count = Math.min(Math.max(Number(body?.count) || 1, 1), 1000);
    const variant = String(body?.variant || "elite").toLowerCase();
    const remarks = String(body?.remarks || "");
    const notes = String(body?.notes || "");
    const rows: any[] = [];
    for (let i = 0; i < count; i++) {
      let key = makeKey(variant);
      while (await keys.findOne({ key })) key = makeKey(variant);
      rows.push({
        key, active: true, device_id: null, variant, expires_at: null,
        claimed_at: null, created_at: new Date(), remarks, notes,
      });
    }
    await keys.insertMany(rows);
    await audit.insertOne({ action: "bulk_generated", details: `Generated ${count} ${variant} key(s)`, timestamp: new Date() });
    return { keys: rows.map(clean) };
  }

  if (action === "add") {
    const key = String(body?.key || "").trim().toUpperCase();
    if (!key) throw new Error("key required");
    const row = {
      key, active: body?.active !== false, device_id: body?.device_id || null,
      variant: String(body?.variant || "elite").toLowerCase(),
      expires_at: body?.expires_at ? new Date(body.expires_at) : null,
      claimed_at: body?.device_id ? new Date() : null,
      created_at: new Date(), remarks: String(body?.remarks || ""),
      notes: String(body?.notes || ""),
    };
    await keys.insertOne(row);
    await audit.insertOne({ key, action: "created", details: "Key added", timestamp: new Date() });
    return { key: clean(row) };
  }

  if (action === "update") {
    const key = String(body?.key || "").trim();
    if (!key) throw new Error("key required");
    const set: any = {};
    for (const field of ["active", "device_id", "variant", "remarks", "notes"]) {
      if (field in body) set[field] = body[field];
    }
    if ("expires_at" in body) set.expires_at = body.expires_at ? new Date(body.expires_at) : null;
    const updated = await keys.findOneAndUpdate({ key }, { $set: set }, { returnDocument: "after" });
    if (!updated) return json({ error: "Key not found" }, 404);
    await audit.insertOne({ key, action: "updated", details: Object.keys(set).join(", "), timestamp: new Date() });
    return { key: clean(updated) };
  }

  if (action === "toggle") {
    const key = String(body?.key || "").trim();
    const current = await keys.findOne({ key });
    if (!current) return json({ error: "Key not found" }, 404);
    const updated = await keys.findOneAndUpdate({ key }, { $set: { active: !current.active } }, { returnDocument: "after" });
    await audit.insertOne({ key, action: updated.active ? "enabled" : "disabled", details: updated.active ? "Key enabled" : "Key disabled", timestamp: new Date() });
    return { key: clean(updated) };
  }

  if (action === "delete") {
    const key = String(body?.key || "").trim();
    const result = await keys.deleteOne({ key });
    if (!result.deletedCount) return json({ error: "Key not found" }, 404);
    await audit.insertOne({ key, action: "deleted", details: "Key deleted", timestamp: new Date() });
    return { ok: true };
  }

  return json({ error: "Unknown action" }, 400);
}

const PANEL = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GOGO AI License Control</title><style>
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:#070a11;color:#eef3ff;font-family:Inter,system-ui,sans-serif}body{min-height:100vh}
.app{min-height:100vh;display:grid;grid-template-columns:240px 1fr;background:radial-gradient(circle at 80% 0,#203a6a55,transparent 35%),radial-gradient(circle at 5% 100%,#0d615344,transparent 32%),#070a11}
.side{padding:26px 16px;background:#0b1019eb;border-right:1px solid #ffffff10}.brand{display:flex;gap:11px;align-items:center;padding:4px 9px 30px}.logo{width:39px;height:39px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#6f80ff,#59dfc1);color:#071016;font-weight:900}.brand b{font-size:15px}.brand small{display:block;color:#78849b;margin-top:2px}.nav{display:grid;gap:6px}.nav button{border:0;background:transparent;color:#99a4b8;padding:12px 14px;border-radius:11px;text-align:left;cursor:pointer}.nav button.active,.nav button:hover{background:#ffffff09;color:#fff}
.main{padding:29px 34px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.top h1{margin:0;font-size:29px}.sub{color:#7f8ba0;font-size:12px;margin-top:6px}.online{color:#76e8bf;font-size:12px}.online:before{content:"";display:inline-block;width:7px;height:7px;background:#63e0b4;border-radius:50%;margin-right:7px;box-shadow:0 0 13px #63e0b4}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:18px}.stat{padding:18px;border-radius:17px;background:#111725bc;border:1px solid #ffffff09}.stat span{display:block;color:#758199;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.stat strong{display:block;font-size:25px;margin-top:6px}.toolbar{display:flex;justify-content:space-between;gap:12px;margin:15px 0}.search{width:min(570px,100%)}input,select,textarea{font:inherit;background:#0b1019;color:#fff;border:1px solid #ffffff12;border-radius:11px;padding:12px 13px;outline:none;width:100%}.btn{border:1px solid #ffffff10;background:#151c29;color:#d9e1f1;border-radius:10px;padding:10px 13px;cursor:pointer}.btn:hover{background:#1b2434}.primary{border:0;background:linear-gradient(135deg,#6f81ff,#58dcbd);color:#071016;font-weight:850}.table{overflow:auto;background:#0d121db8;border:1px solid #ffffff09;border-radius:17px}.table table{width:100%;min-width:960px;border-collapse:collapse}.table th{padding:14px 15px;text-align:left;color:#727e94;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.table td{padding:14px 15px;border-top:1px solid #ffffff08;font-size:12px;vertical-align:top}.muted{color:#7a869b}.badge{padding:5px 8px;border-radius:999px;font-size:10px;font-weight:800}.ok{color:#7ce9c0;background:#45dfad19}.off{color:#ff99a7;background:#ff657a19}.note{max-width:260px;white-space:pre-wrap;color:#98a3b6}.actions{display:flex;gap:5px;flex-wrap:wrap}.modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:#000b;backdrop-filter:blur(8px);padding:20px}.modal.show{display:flex}.dialog{width:min(760px,100%);max-height:90vh;overflow:auto;background:#0d131e;border:1px solid #ffffff10;border-radius:21px;padding:24px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-top:13px}.field label{display:block;color:#8994a7;font-size:10px;text-transform:uppercase;margin-bottom:6px}.field textarea{min-height:125px;resize:vertical}.foot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}.login{position:fixed;inset:0;display:grid;place-items:center;background:#070a11;z-index:10}.loginbox{width:min(410px,92vw);padding:29px;border-radius:21px;background:#0d131e;border:1px solid #ffffff10}.loginbox p{color:#7f8ba0;font-size:12px}.hidden{display:none!important}@media(max-width:1000px){.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:780px){.app{grid-template-columns:1fr}.side{border-right:0;border-bottom:1px solid #ffffff10}.main{padding:22px}.toolbar{flex-direction:column}.grid{grid-template-columns:1fr}}
</style></head><body>
<div class="login" id="login"><div class="loginbox"><div class="logo">G</div><h2>GOGO AI License Control</h2><p>MongoDB-backed administration. Nothing is stored as a local database.</p><input id="pass" type="password" placeholder="Admin password" autocomplete="off"><button class="btn primary" id="loginBtn" style="width:100%;margin-top:10px">Sign in</button><div id="error"></div></div></div>
<div class="app hidden" id="app"><aside class="side"><div class="brand"><div class="logo">G</div><div><b>GOGO AI</b><small>License Control</small></div></div><div class="nav"><button class="active" id="keysNav">🔑 Licenses</button><button id="auditNav">◷ Audit log</button></div></aside>
<main class="main"><div class="top"><div><h1 id="title">Licenses</h1><div class="sub">All persistent data is stored in MongoDB</div></div><div class="online">API ONLINE</div></div>
<div class="stats"><div class="stat"><span>Total</span><strong id="s0">—</strong></div><div class="stat"><span>Active</span><strong id="s1">—</strong></div><div class="stat"><span>Available</span><strong id="s2">—</strong></div><div class="stat"><span>Claimed</span><strong id="s3">—</strong></div><div class="stat"><span>Expired</span><strong id="s4">—</strong></div></div>
<section id="keys"><div class="toolbar"><input class="search" id="q" placeholder="Search key, device, remarks or notes"><div class="actions"><button class="btn" id="add">+ Add key</button><button class="btn primary" id="generate">Generate keys</button></div></div>
<div class="table"><table><thead><tr><th>Key</th><th>Status</th><th>Device ID</th><th>Variant</th><th>Expires</th><th>Remarks / Notes</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<section id="aud" class="hidden"><div class="table"><table><thead><tr><th>Time</th><th>Key</th><th>Action</th><th>Device</th><th>Details</th></tr></thead><tbody id="auditRows"></tbody></table></div></section>
</main></div>
<div class="modal" id="modal"><div class="dialog"><h2 id="mt">Edit license</h2><div class="sub" id="mk"></div><div class="grid"><div class="field"><label>Variant</label><select id="variant"><option value="elite">Elite</option></select></div><div class="field"><label>Expiry</label><input id="expiry" type="datetime-local"></div></div><div class="field"><label>Device ID</label><input id="device"></div><div class="field"><label>Remarks</label><input id="remarks" placeholder="Example: Given to Rahul"></div><div class="field"><label>Notes</label><textarea id="notes" placeholder="Payment, plan, date, customer details..."></textarea></div><div class="foot"><button class="btn" id="cancel">Cancel</button><button class="btn primary" id="save">Save to MongoDB</button></div></div></div>
<script>
(()=>{const API="https://rzhtesfikvykdnmrqwjs.supabase.co/functions/v1/keys",$=id=>document.getElementById(id);let pass="",items=[];
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
async function call(action,method="GET",body=null){const opt={method,headers:{"x-admin-pass":pass}};if(body!==null){opt.headers["Content-Type"]="application/json";opt.body=JSON.stringify(body)}const r=await fetch(API+"?action="+encodeURIComponent(action)+(action==="keys"?"&q="+encodeURIComponent($("q").value):""),opt);const d=await r.json();if(!r.ok)throw Error(d.error||"Request failed");return d}
async function refresh(){const [s,k]=await Promise.all([call("stats"),call("keys")]);$("s0").textContent=s.total;$("s1").textContent=s.active;$("s2").textContent=s.available;$("s3").textContent=s.claimed;$("s4").textContent=s.expired;items=k.keys||[];draw()}
function draw(){$("rows").innerHTML=items.length?items.map(k=>\`<tr><td><b>\${esc(k.key)}</b><div class="muted">\${esc(k.remarks)}</div></td><td><span class="badge \${k.active?"ok":"off"}">\${k.active?"ACTIVE":"DISABLED"}</span></td><td>\${esc(k.device_id||"Available")}</td><td>\${esc(k.variant)}</td><td>\${k.expires_at?esc(new Date(k.expires_at).toLocaleString()):"Never"}</td><td class="note">\${esc(k.notes)}</td><td><div class="actions"><button class="btn" data-a="copy" data-k="\${esc(k.key)}">Copy</button><button class="btn" data-a="edit" data-k="\${esc(k.key)}">Edit</button><button class="btn" data-a="toggle" data-k="\${esc(k.key)}">\${k.active?"Disable":"Enable"}</button><button class="btn" data-a="delete" data-k="\${esc(k.key)}">Delete</button></div></td></tr>\`).join(""):'<tr><td colspan="7" style="padding:40px;text-align:center" class="muted">No licenses found</td></tr>'}
function openEditor(k){$("mt").textContent=k?"Edit license":"Add license";$("mk").textContent=k?k.key:"New license";$("modal").dataset.key=k?.key||"";$("variant").value=k?.variant||"elite";$("device").value=k?.device_id||"";$("remarks").value=k?.remarks||"";$("notes").value=k?.notes||"";$("expiry").value=k?.expires_at?new Date(k.expires_at).toISOString().slice(0,16):"";$("modal").classList.add("show")}
$("loginBtn").onclick=async()=>{pass=$("pass").value;try{await call("stats");$("login").classList.add("hidden");$("app").classList.remove("hidden");await refresh()}catch{$("error").innerHTML='<span style="color:#ff8998;font-size:12px">Invalid administrator password.</span>'}};
$("pass").onkeydown=e=>{if(e.key==="Enter")$("loginBtn").click()};$("q").oninput=()=>refresh().catch(()=>{});$("add").onclick=()=>openEditor(null);$("cancel").onclick=()=>$("modal").classList.remove("show");
$("generate").onclick=async()=>{const n=Number(prompt("How many keys? (1–1000)","10")||0);if(n>0){await call("generate","POST",{count:Math.min(1000,n),variant:"elite"});await refresh()}};
$("save").onclick=async()=>{let key=$("modal").dataset.key;if(!key)key=prompt("Enter key","MJ-ELITE-XXXX-XXXX");if(!key)return;await call($("modal").dataset.key?"update":"add","POST",{key,variant:$("variant").value,device_id:$("device").value.trim()||null,remarks:$("remarks").value,notes:$("notes").value,expires_at:$("expiry").value?new Date($("expiry").value).toISOString():null});$("modal").classList.remove("show");await refresh()};
$("rows").onclick=async e=>{const b=e.target.closest("button");if(!b)return;const k=b.dataset.k,item=items.find(x=>x.key===k),a=b.dataset.a;if(a==="copy"){await navigator.clipboard.writeText(k);return}if(a==="edit"){openEditor(item);return}if(a==="toggle"){await call("toggle","POST",{key:k});await refresh();return}if(a==="delete"&&confirm("Delete "+k+" permanently?")){await call("delete","POST",{key:k});await refresh()}};
$("auditNav").onclick=async()=>{$("keys").classList.add("hidden");$("aud").classList.remove("hidden");$("auditNav").classList.add("active");$("keysNav").classList.remove("active");$("title").textContent="Audit log";const d=await call("audit");$("auditRows").innerHTML=(d.logs||[]).map(x=>\`<tr><td>\${esc(x.timestamp?new Date(x.timestamp).toLocaleString():"")}</td><td><b>\${esc(x.key||"—")}</b></td><td>\${esc(x.action)}</td><td>\${esc(x.device_id||"—")}</td><td>\${esc(x.details||"")}</td></tr>\`).join("")};
$("keysNav").onclick=()=>{$("aud").classList.add("hidden");$("keys").classList.remove("hidden");$("auditNav").classList.remove("active");$("keysNav").classList.add("active");$("title").textContent="Licenses"};
})();</script></body></html>`;

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  const url = new URL(req.url);
  const action = url.searchParams.get("action");
  const accept = req.headers.get("accept") ?? "";
  const secFetchDest = (req.headers.get("sec-fetch-dest") ?? "").toLowerCase();
  const isBrowserNavigation = secFetchDest === "document" || (!secFetchDest && accept.includes("text/html"));

  if (url.searchParams.get("panel") === "1" || (!action && isBrowserNavigation)) {
    return new Response(PANEL, {
      headers: { ...CORS, "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (!action) {
    const loader = "document.open();document.write(" + JSON.stringify(PANEL) + ");document.close();";
    return new Response(loader, {
      headers: { ...CORS, "Content-Type": "application/javascript; charset=utf-8" },
    });
  }

  if (action === "verify") {
    try {
      return json(await verifyLicense(await req.json()));
    } catch {
      return json(FAILURE);
    }
  }

  if (!adminOK(req)) return json({ error: "Unauthorized" }, 401);

  try {
    return json(await adminAction(action, req));
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : "Server error" }, 500);
  }
});
