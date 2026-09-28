import { MongoClient } from "npm:mongodb@6.19.0";

const MONGO_URI = Deno.env.get("MONGO_URI") ?? "";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") ?? "";

const client = new MongoClient(MONGO_URI);
let databasePromise: Promise<any> | null = null;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, x-admin-pass",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Cache-Control": "no-store",
};

const failResponse = {
  active: false,
  message:
    "❌ Activation unavailable. Please contact us on WhatsApp at +91 95296 36044 to purchase an AI Assistant key.",
  success: false,
  variant: "elite",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

function connectDb() {
  if (!databasePromise) {
    if (!MONGO_URI) throw new Error("MONGO_URI is not configured");
    databasePromise = client.connect().then(() => client.db("ai_assistant"));
  }
  return databasePromise;
}

function isAdmin(req: Request) {
  const supplied = req.headers.get("x-admin-pass") ?? "";
  return !!ADMIN_PASSWORD && supplied === ADMIN_PASSWORD;
}

function sanitizeKey(doc: any) {
  return {
    key: doc.key,
    active: !!doc.active,
    device_id: doc.device_id ?? null,
    variant: doc.variant ?? "elite",
    expires_at: doc.expires_at ?? null,
    claimed_at: doc.claimed_at ?? null,
    created_at: doc.created_at ?? null,
    remarks: doc.remarks ?? "",
    notes: doc.notes ?? "",
  };
}

async function verifyLicense(body: any) {
  const accessKey = String(body?.access_key ?? "").trim();
  const deviceId = String(body?.deviceId ?? "").trim();

  if (!accessKey || !deviceId) return failResponse;

  const db = await connectDb();
  const keys = db.collection("api_keys");

  const doc = await keys.findOne({ key: accessKey });
  if (!doc || !doc.active) return failResponse;

  const expiresAt = doc.expires_at ? new Date(doc.expires_at) : null;
  if (expiresAt && !Number.isNaN(expiresAt.getTime()) && expiresAt <= new Date()) {
    return { ...failResponse, variant: doc.variant ?? "elite" };
  }

  const variant = doc.variant ?? "elite";
  const owner = doc.device_id ?? null;

  if (owner === deviceId) {
    return {
      active: true,
      message: "Key activated successfully.",
      success: true,
      variant,
    };
  }

  if (owner) return { ...failResponse, variant };

  const other = await keys.findOne({
    device_id: deviceId,
    key: { $ne: accessKey },
  });

  if (other) return { ...failResponse, variant };

  const claimed = await keys.findOneAndUpdate(
    {
      key: accessKey,
      active: true,
      $or: [{ device_id: null }, { device_id: "" }],
    },
    {
      $set: {
        device_id: deviceId,
        claimed_at: new Date(),
      },
    },
    { returnDocument: "after" },
  );

  if (claimed) {
    await db.collection("audit_logs").insertOne({
      key: accessKey,
      action: "claimed",
      device_id: deviceId,
      details: "License activated",
      timestamp: new Date(),
    });

    return {
      active: true,
      message: "Key activated successfully.",
      success: true,
      variant: claimed.variant ?? "elite",
    };
  }

  const current = await keys.findOne({ key: accessKey });
  if (current?.device_id === deviceId) {
    return {
      active: true,
      message: "Key activated successfully.",
      success: true,
      variant: current.variant ?? "elite",
    };
  }

  return { ...failResponse, variant };
}

function randomSegment() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  for (let i = 0; i < 4; i++) {
    value += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return value;
}

function newKey(variant: string) {
  return `MJ-${variant.toUpperCase()}-${randomSegment()}-${randomSegment()}`;
}

async function adminAction(action: string, body: any) {
  const db = await connectDb();
  const keys = db.collection("api_keys");
  const audit = db.collection("audit_logs");

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
    const q = String(body?.q ?? "").trim();
    const filter = q
      ? {
          $or: [
            { key: { $regex: q, $options: "i" } },
            { device_id: { $regex: q, $options: "i" } },
            { remarks: { $regex: q, $options: "i" } },
            { notes: { $regex: q, $options: "i" } },
          ],
        }
      : {};

    const rows = await keys.find(filter)
      .sort({ created_at: -1 })
      .limit(1000)
      .toArray();

    return { keys: rows.map(sanitizeKey) };
  }

  if (action === "audit") {
    const rows = await audit.find({})
      .sort({ timestamp: -1 })
      .limit(250)
      .toArray();

    return {
      logs: rows.map((x: any) => ({
        key: x.key ?? "",
        action: x.action ?? "",
        device_id: x.device_id ?? null,
        details: x.details ?? "",
        timestamp: x.timestamp ?? null,
      })),
    };
  }

  if (action === "generate") {
    const count = Math.min(Math.max(Number(body?.count) || 1, 1), 1000);
    const variant = String(body?.variant || "elite").toLowerCase();
    const remarks = String(body?.remarks || "");
    const notes = String(body?.notes || "");
    const now = new Date();

    const rows = Array.from({ length: count }, () => ({
      key: newKey(variant),
      active: true,
      device_id: null,
      variant,
      expires_at: null,
      claimed_at: null,
      created_at: now,
      remarks,
      notes,
    }));

    await keys.insertMany(rows);
    await audit.insertOne({
      action: "bulk_generated",
      details: `Generated ${count} ${variant} key(s)`,
      timestamp: new Date(),
    });

    return { keys: rows.map(sanitizeKey) };
  }

  if (action === "add") {
    const key = String(body?.key || "").trim().toUpperCase();
    if (!key) throw new Error("key required");

    const row = {
      key,
      active: body?.active !== false,
      device_id: body?.device_id || null,
      variant: String(body?.variant || "elite").toLowerCase(),
      expires_at: body?.expires_at ? new Date(body.expires_at) : null,
      claimed_at: body?.device_id ? new Date() : null,
      created_at: new Date(),
      remarks: String(body?.remarks || ""),
      notes: String(body?.notes || ""),
    };

    await keys.insertOne(row);
    await audit.insertOne({
      key,
      action: "created",
      details: "Key added",
      timestamp: new Date(),
    });

    return { key: sanitizeKey(row) };
  }

  if (action === "update") {
    const key = String(body?.key || "").trim();
    if (!key) throw new Error("key required");

    const set: any = {};
    for (const field of ["active", "device_id", "variant", "remarks", "notes"]) {
      if (field in body) set[field] = body[field];
    }
    if ("expires_at" in body) {
      set.expires_at = body.expires_at ? new Date(body.expires_at) : null;
    }

    const result = await keys.findOneAndUpdate(
      { key },
      { $set: set },
      { returnDocument: "after" },
    );

    if (!result) return json({ error: "Key not found" }, 404);

    await audit.insertOne({
      key,
      action: "updated",
      details: Object.keys(set).join(", "),
      timestamp: new Date(),
    });

    return { key: sanitizeKey(result) };
  }

  if (action === "toggle") {
    const key = String(body?.key || "").trim();
    const current = await keys.findOne({ key });
    if (!current) return json({ error: "Key not found" }, 404);

    const result = await keys.findOneAndUpdate(
      { key },
      { $set: { active: !current.active } },
      { returnDocument: "after" },
    );

    await audit.insertOne({
      key,
      action: result.active ? "enabled" : "disabled",
      details: result.active ? "Key enabled" : "Key disabled",
      timestamp: new Date(),
    });

    return { key: sanitizeKey(result) };
  }

  if (action === "delete") {
    const key = String(body?.key || "").trim();
    const result = await keys.deleteOne({ key });
    if (!result.deletedCount) return json({ error: "Key not found" }, 404);

    await audit.insertOne({
      key,
      action: "deleted",
      details: "Key deleted",
      timestamp: new Date(),
    });

    return { ok: true };
  }

  return json({ error: "Unknown action" }, 400);
}

const uiScript = `(()=>{const root="gogo-license-panel";if(document.getElementById(root))return;
const s=document.createElement("style");s.textContent=`
*{box-sizing:border-box}html,body{margin:0;background:#070a11;color:#eef3ff;font-family:Inter,system-ui,sans-serif}body{min-height:100vh}
#gogo-license-panel{min-height:100vh;background:radial-gradient(circle at 80% 0,#19325866,transparent 36%),radial-gradient(circle at 10% 100%,#0b5c5140,transparent 30%),#070a11}
.gp{min-height:100vh;display:grid;grid-template-columns:238px 1fr}.gs{padding:26px 16px;background:#0b1019e8;border-right:1px solid #fff1;position:sticky;top:0;height:100vh}.brand{display:flex;gap:10px;align-items:center;padding:5px 10px 30px}.logo{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#6e7fff,#5de0bf);color:#071016;font-weight:900}.brand b{font-size:15px}.brand small{display:block;color:#7f8ba3}.nav{display:grid;gap:6px}.nav button{border:0;background:transparent;color:#9ba6ba;text-align:left;padding:12px 14px;border-radius:11px;cursor:pointer}.nav button.active,.nav button:hover{background:#fff0a;color:#fff}.gm{padding:28px 34px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:25px}.top h1{margin:0;font-size:28px}.muted{color:#8490a5}.online{color:#75e9c0;font-size:12px}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:13px;margin-bottom:18px}.stat{padding:18px;border-radius:17px;background:#111725b8;border:1px solid #fff0a}.stat span{display:block;font-size:10px;color:#78849b;text-transform:uppercase;letter-spacing:.08em}.stat b{display:block;font-size:25px;margin-top:6px}.bar{display:flex;gap:10px;justify-content:space-between;margin:15px 0}.search{flex:1;max-width:550px}.inp,.field input,.field textarea,.field select{width:100%;background:#0b1019;color:#fff;border:1px solid #fff1;border-radius:11px;padding:12px;outline:none}.btn{border:1px solid #fff1;background:#151c2a;color:#dce4f4;border-radius:10px;padding:11px 14px;cursor:pointer}.primary{border:0;background:linear-gradient(135deg,#6e7fff,#5de0bf);color:#071016;font-weight:800}.table{background:#0d121dbd;border:1px solid #fff1;border-radius:17px;overflow:auto}.table table{width:100%;border-collapse:collapse;min-width:940px}.table th,.table td{padding:14px 15px;text-align:left;border-bottom:1px solid #fff0d;font-size:12px}.table th{font-size:10px;color:#737f95;text-transform:uppercase}.badge{padding:5px 8px;border-radius:999px;font-weight:800;font-size:10px}.ok{color:#7de8be;background:#4ce2ac1b}.off{color:#ff9cab;background:#ff61781b}.actions{display:flex;gap:5px;flex-wrap:wrap}.modal{position:fixed;inset:0;background:#000b;display:none;align-items:center;justify-content:center;padding:20px;z-index:20}.modal.show{display:flex}.dialog{width:min(740px,100%);background:#0d131e;border:1px solid #fff1;border-radius:20px;padding:23px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-top:12px}.field label{display:block;color:#8c97aa;font-size:10px;margin-bottom:6px;text-transform:uppercase}.field textarea{min-height:120px}.foot{display:flex;justify-content:flex-end;gap:9px;margin-top:18px}.login{position:fixed;inset:0;background:#070a11;display:grid;place-items:center;z-index:30}.loginbox{width:min(390px,90vw);padding:28px;border-radius:20px;background:#0d131e;border:1px solid #fff1}.hidden{display:none!important}@media(max-width:950px){.stats{grid-template-columns:repeat(2,1fr)}.gp{grid-template-columns:1fr}.gs{position:relative;height:auto}.gm{padding:20px}}`;
document.head.appendChild(s);document.body.innerHTML=`<div id="${root}"><div class="login" id="gl"><div class="loginbox"><div class="logo">G</div><h2>GOGO License Control</h2><p class="muted">MongoDB-backed administration.</p><input class="inp" id="gp" type="password" placeholder="Admin password"><button class="btn primary" style="width:100%;margin-top:10px" id="gb">Sign in</button><p id="ge"></p></div></div><div class="gp hidden" id="ga"><aside class="gs"><div class="brand"><div class="logo">G</div><div><b>GOGO AI</b><small>License Control</small></div></div><div class="nav"><button class="active" id="nk">🔑 Licenses</button><button id="na">◷ Audit log</button></div></aside><main class="gm"><div class="top"><div><h1 id="gt">Licenses</h1><div class="muted">Everything persistent is stored in MongoDB</div></div><div class="online">● API ONLINE</div></div><div class="stats"><div class="stat"><span>Total</span><b id="s0">—</b></div><div class="stat"><span>Active</span><b id="s1">—</b></div><div class="stat"><span>Available</span><b id="s2">—</b></div><div class="stat"><span>Claimed</span><b id="s3">—</b></div><div class="stat"><span>Expired</span><b id="s4">—</b></div></div><section id="ks"><div class="bar"><input class="inp search" id="q" placeholder="Search key, device, remarks or notes"><div class="actions"><button class="btn" id="add">+ Add key</button><button class="btn primary" id="gen">Generate</button></div></div><div class="table"><table><thead><tr><th>Key</th><th>Status</th><th>Device</th><th>Variant</th><th>Expires</th><th>Notes</th><th>Actions</th></tr></thead><tbody id="rows"></tbody></table></div></section><section id="as" class="hidden"><div class="table"><table><thead><tr><th>Time</th><th>Key</th><th>Action</th><th>Device</th><th>Details</th></tr></thead><tbody id="audit"></tbody></table></div></section></main></div><div class="modal" id="modal"><div class="dialog"><h2 id="mt">Edit license</h2><div class="muted" id="mk"></div><div class="grid"><div class="field"><label>Variant</label><select id="fv"><option value="elite">Elite</option></select></div><div class="field"><label>Expiry</label><input id="fe" type="datetime-local"></div></div><div class="field"><label>Device ID</label><input id="fd"></div><div class="field"><label>Remarks</label><input id="fr"></div><div class="field"><label>Notes</label><textarea id="fn"></textarea></div><div class="foot"><button class="btn" id="mc">Cancel</button><button class="btn primary" id="ms">Save to MongoDB</button></div></div></div></div></div>`;
const $=x=>document.getElementById(x);let pass="",rows=[];
async function call(action,body){const m=["stats","keys","audit"].includes(action)?"GET":"POST";const r=await fetch(location.href.split("?")[0]+"?action="+encodeURIComponent(action),{method:m,headers:{"Content-Type":"application/json","x-admin-pass":pass},body:m==="POST"?JSON.stringify(body||{}):undefined});const d=await r.json();if(!r.ok)throw Error(d.error||"Request failed");return d}
function draw(){rows=rows||[];$("rows").innerHTML=rows.map(k=>`<tr><td><b>${k.key}</b><div class="muted">${k.remarks||""}</div></td><td><span class="badge ${k.active?"ok":"off"}">${k.active?"ACTIVE":"DISABLED"}</span></td><td>${k.device_id||"Available"}</td><td>${k.variant}</td><td>${k.expires_at?new Date(k.expires_at).toLocaleString():"Never"}</td><td>${(k.notes||"").slice(0,140)}</td><td><div class="actions"><button class="btn" data-a="copy" data-k="${k.key}">Copy</button><button class="btn" data-a="edit" data-k="${k.key}">Edit</button><button class="btn" data-a="toggle" data-k="${k.key}">${k.active?"Disable":"Enable"}</button><button class="btn" data-a="delete" data-k="${k.key}">Delete</button></div></td></tr>`).join("")||'<tr><td colspan="7" style="padding:35px;text-align:center" class="muted">No licenses</td></tr>'}
async function refresh(){const q=$("q").value.trim();const [s,k]=await Promise.all([call("stats"),fetch(location.href.split("?")[0]+"?action=keys",{headers:{"Content-Type":"application/json","x-admin-pass":pass},method:"POST",body:JSON.stringify({q,limit:1000})}).then(r=>r.json())]);$("s0").textContent=s.total;$("s1").textContent=s.active;$("s2").textContent=s.available;$("s3").textContent=s.claimed;$("s4").textContent=s.expired;rows=k.keys||[];draw()}
$("gb").onclick=async()=>{pass=$("gp").value;try{await call("stats");sessionStorage.setItem("gogo_admin_pass",pass);$("gl").classList.add("hidden");$("ga").classList.remove("hidden");await refresh()}catch{$("ge").textContent="Invalid password"}};
$("gp").onkeydown=e=>{if(e.key==="Enter")$("gb").click()};$("q").oninput=()=>refresh().catch(()=>{});
$("gen").onclick=async()=>{const n=Number(prompt("Generate how many keys?","10")||0);if(n>0){await call("generate",{count:Math.min(1000,n),variant:"elite"});await refresh()}};
function open(k){$("mt").textContent=k?"Edit license":"Add license";$("mk").textContent=k?k.key:"";$("modal").dataset.key=k?.key||"";$("fv").value=k?.variant||"elite";$("fd").value=k?.device_id||"";$("fr").value=k?.remarks||"";$("fn").value=k?.notes||"";$("fe").value=k?.expires_at?new Date(k.expires_at).toISOString().slice(0,16):"";$("modal").classList.add("show")}
$("add").onclick=()=>open(null);$("mc").onclick=()=>$("modal").classList.remove("show");
$("ms").onclick=async()=>{const key=$("modal").dataset.key||prompt("Enter key","MJ-ELITE-XXXX-XXXX");if(!key)return;await call($("modal").dataset.key?"update":"add",{key,variant:$("fv").value,device_id:$("fd").value||null,remarks:$("fr").value,notes:$("fn").value,expires_at:$("fe").value?new Date($("fe").value).toISOString():null});$("modal").classList.remove("show");await refresh()};
$("rows").onclick=async e=>{const b=e.target.closest("button");if(!b)return;const key=b.dataset.k,k=rows.find(x=>x.key===key);if(b.dataset.a==="copy")return navigator.clipboard.writeText(key);if(b.dataset.a==="edit")return open(k);if(b.dataset.a==="toggle"){await call("toggle",{key});return refresh()}if(b.dataset.a==="delete"&&confirm("Delete "+key+" permanently?")){await call("delete",{key});await refresh()}};
$("na").onclick=async()=>{ $("ks").classList.add("hidden");$("as").classList.remove("hidden");$("nk").classList.remove("active");$("na").classList.add("active");$("gt").textContent="Audit log";const d=await call("audit");$("audit").innerHTML=(d.logs||[]).map(x=>`<tr><td>${new Date(x.timestamp).toLocaleString()}</td><td><b>${x.key||"—"}</b></td><td>${x.action}</td><td>${x.device_id||"—"}</td><td>${x.details||""}</td></tr>`).join("")};
$("nk").onclick=()=>{$("as").classList.add("hidden");$("ks").classList.remove("hidden");$("na").classList.remove("active");$("nk").classList.add("active");$("gt").textContent="Licenses"};
const saved=sessionStorage.getItem("gogo_admin_pass");if(saved){$("gp").value=saved;$("gb").click()}
})();`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

  const url = new URL(req.url);
  const action = url.searchParams.get("action");

  if (!action) {
    return new Response(uiScript, {
      headers: { ...corsHeaders, "Content-Type": "application/javascript; charset=utf-8" },
    });
  }

  if (action === "verify") {
    try {
      return json(await verifyLicense(await req.json()));
    } catch {
      return json(failResponse);
    }
  }

  if (!isAdmin(req)) return json({ error: "Unauthorized" }, 401);

  try {
    const body = req.method === "POST" ? await req.json() : {};
    return json(await adminAction(action, body));
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Server error" }, 500);
  }
});