/* Africa University student portal.
   Security model is unchanged: every read/write goes through Supabase Row Level Security, the browser only
   uses the publishable key, and Records/Admin decisions (verification, finance, request status) can only be
   made by accounts whose server-side app_metadata role is "records" or "admin" (see backend/migrations/0008). */
const navItems = [
  ["overview", "Overview"], ["projects", "My Projects"], ["skills", "My Skills"],
  ["academics", "Academics & Certificates"], ["results", "Official Results"],
  ["finance", "Finance"], ["references", "Recommendations"], ["clubs", "Clubs & Activities"],
  ["professional", "Professional Profile"], ["security", "Account Security"]
];
const pages = {
  overview: ["Overview", "Your Africa University student profile", "Your digital student ID and details in one place."],
  projects: ["My Projects", "Showcase the work you have completed", "Add projects to your profile and request verification from an authorized university verifier."],
  skills: ["My Skills", "Highlight your knowledge and strengths", "Add the skills that describe your experience and remove the ones you no longer want listed."],
  academics: ["Academics & Certificates", "Your academic history and achievements", "Keep your qualifications, achievements and certificates together."],
  results: ["Official Results", "View official course results", "Results are supplied and maintained by the Records Office. Students can view them but cannot enter or change grades."],
  finance: ["Finance", "Fees and payments", "Your tuition balance, pending items and payment plan requests."],
  references: ["Recommendations", "Request a recommendation", "Ask a lecturer or supervisor for a recommendation. The request goes to the Records Office, who coordinate it with your referee."],
  clubs: ["Clubs & Activities", "Share your university community involvement", "Add clubs, associations and activities, with pictures."],
  professional: ["Professional Profile", "Prepare your professional profile and CV", "Link your GitHub and LinkedIn, and keep your CV ready to download."],
  security: ["Account Security", "Manage your account and profile backup", "Keep your account secure and export a backup of your profile."],
  admin: ["Student accounts", "Administration", "Administrator console."],
  "admin-profile": ["Administrator profile", "Administration", "Administrator profile access requires the protected server functions."],
  staff: ["Records Office", "Account and student record requests", "Records Office console."],
  reference: ["Reference request", "Africa University", "This secure one-time reference link requires the original protected server functions."],
  "staff-login": ["Staff sign in", "Secure account access", "Sign in"],
  "admin-login": ["Administrator sign in", "Secure account access", "Sign in"]
};
const key = document.body.dataset.page || "home";
const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const safe = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const config = window.MY_AU_CONFIG || {};
const studentKeys = new Set(navItems.map(([id]) => id));
const money = n => new Intl.NumberFormat("en-US", { style: "currency", currency: config.currency || "USD" }).format(Number(n) || 0);
const fmtDate = v => { const d = new Date(v); return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }); };
const httpsOnly = u => /^https:\/\//i.test(String(u || "")) ? String(u) : "";
const tableMissing = e => !!e && (["42P01", "PGRST205", "PGRST200"].includes(e.code) || /does not exist|schema cache/i.test(e.message || ""));
const IDLE_MS = 30 * 60 * 1000;

let supabasePromise;
let student;
let profileData;
let saveInProgress = false;
let verifications = [];
let verificationsReady = true;
let officialResults = [];
let officialResultsReady = true;
let financeRows = [], planRows = [], financeReady = true;
let recRows = [], recReady = true;
let shareRows = [], sharingReady = true;
let shareCandidates = [];
let changeRequests = [], achievementHistory = [], historyReady = true;
let pageNote = "";
let globalsBound = false;
let mfaLibraryPromise;
const urlCache = new Map();

function getSupabase() {
  if (!supabasePromise) {
    if (!config.supabaseUrl || !config.supabasePublishableKey) {
      throw new Error("Supabase URL and publishable key are required in js/config.js.");
    }
    supabasePromise = import("https://esm.sh/@supabase/supabase-js@2")
      .then(({ createClient }) => createClient(config.supabaseUrl, config.supabasePublishableKey));
  }
  return supabasePromise;
}

function loadMfaLibrary() {
  if (window.AUMfa) return Promise.resolve(window.AUMfa);
  if (!mfaLibraryPromise) {
    mfaLibraryPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = new URL("../js/mfa.js", location.href).href;
      script.onload = () => window.AUMfa
        ? resolve(window.AUMfa)
        : reject(new Error("The authenticator security module did not initialize."));
      script.onerror = () => reject(new Error("The authenticator security module could not be loaded."));
      document.head.appendChild(script);
    });
  }
  return mfaLibraryPromise;
}

/* ---------- small UI helpers ---------- */
function toast(message, isError) {
  $$(".toast").forEach(t => t.remove());
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " err" : "");
  el.setAttribute("role", isError ? "alert" : "status");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}
function setStatus(message) { const s = $("[data-status]"); if (s) s.textContent = message; }
function setupNotice(what) {
  return `<div class="notice warn"><strong>This feature needs a database update</strong><p>The ${safe(what)} tables are not installed yet. Ask your administrator to apply <code>backend/migrations/0008_records_verification_finance.sql</code> in Supabase.</p></div>`;
}

/* ---------- storage (private bucket, owner folder) ---------- */
const MIME_EXT = {
  "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "application/pdf": "pdf",
  "application/msword": "doc", "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx"
};
const IMAGE_OR_PDF = ["image/jpeg", "image/png", "image/webp", "application/pdf"];
const IMAGES_ONLY = ["image/jpeg", "image/png", "image/webp"];
const DOCS = ["application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"];

async function signedUrl(ref, options) {
  if (typeof ref !== "string" || !ref.startsWith("storage://")) return "";
  const path = ref.slice(10);
  const hit = urlCache.get(path);
  if (!options && hit && hit.exp > Date.now()) return hit.url;
  const client = await getSupabase();
  const { data, error } = await client.storage.from("student-content").createSignedUrl(path, 3600, options);
  if (error || !data) return "";
  if (!options) urlCache.set(path, { url: data.signedUrl, exp: Date.now() + 50 * 60 * 1000 });
  return data.signedUrl;
}

function resizeImage(file, max) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      const k = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.max(1, Math.round(img.width * k));
      c.height = Math.max(1, Math.round(img.height * k));
      c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);   // re-encoding also strips EXIF/GPS data
      c.toBlob(b => b ? resolve(b) : reject(new Error("The image could not be processed.")), "image/jpeg", 0.85);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error(`${file.name} could not be read as an image.`)); };
    img.src = url;
  });
}

async function uploadStudentFile(file, { allow = IMAGE_OR_PDF, maxMB = 8, shrinkImage = 0 } = {}) {
  let blob = file;
  if (shrinkImage && file.type.startsWith("image/")) blob = await resizeImage(file, shrinkImage);
  const type = blob.type || file.type;
  if (!allow.includes(type)) throw new Error(`${file.name}: this file type is not allowed.`);
  if (blob.size > maxMB * 1024 * 1024) throw new Error(`${file.name}: files must be ${maxMB} MB or smaller.`);
  const path = `${student.id}/${crypto.randomUUID()}.${MIME_EXT[type]}`;
  const client = await getSupabase();
  const { error } = await client.storage.from("student-content").upload(path, blob, { contentType: type, upsert: false });
  if (error) throw new Error(`Upload failed: ${error.message}`);
  return `storage://${path}`;
}

async function removeStoredFiles(refs) {          // best effort; never blocks the UI
  const paths = refs.filter(r => typeof r === "string" && r.startsWith(`storage://${student.id}/`)).map(r => r.slice(10));
  if (!paths.length) return;
  try { (await getSupabase()).storage.from("student-content").remove(paths); } catch { /* ignore */ }
}

/* ---------- profile data (unchanged behaviour) ---------- */
function emptyProfileData(user) {
  return {
    profile: {
      name: String(user.user_metadata?.name || ""),
      studentId: String(user.user_metadata?.student_id || ""),
      programme: "", faculty: "", year: "", email: user.email || "", phone: "",
      address: "", dob: "", nationality: "", languages: "", photo: "", bio: "",
      github: "", linkedin: "", cvFile: "", cvFileName: "", cgpa: "", graduated: false
    },
    skills: [], projects: [], certificates: [], academic: [], achievements: [], clubs: [], results: []
  };
}

function mergeProfileData(raw, user) {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("The saved profile has an unsupported format. It was not changed.");
  }
  const defaults = emptyProfileData(user);
  if (raw.profile != null && (typeof raw.profile !== "object" || Array.isArray(raw.profile))) {
    throw new Error("The saved profile details have an unsupported format. They were not changed.");
  }
  const merged = {
    ...defaults,
    ...raw,
    profile: { ...defaults.profile, ...(raw.profile || {}) }
  };
  for (const field of ["skills", "projects", "certificates", "academic", "achievements", "clubs", "results"]) {
    if (raw[field] != null && !Array.isArray(raw[field])) {
      throw new Error(`The saved ${field} data has an unsupported format. It was not changed.`);
    }
    merged[field] = raw[field] || [];
  }
  return merged;
}

async function loadStudentProfile() {
  const client = await getSupabase();
  const { data: auth, error: authError } = await client.auth.getUser();
  if (authError || !auth.user) {
    window.location.replace(`auth.html?next=${encodeURIComponent(`${key}.html`)}`);
    return false;
  }
  student = auth.user;

  const { data: row, error } = await client.from("profiles")
    .select("data").eq("id", student.id).maybeSingle();
  if (error) {
    const code = error.code ? ` (${error.code})` : "";
    throw new Error(`Could not load your cloud profile${code}: ${error.message}`);
  }
  if (row) {
    profileData = mergeProfileData(row.data, student);
  } else {
    const initialData = emptyProfileData(student);
    const { error: insertError } = await client.from("profiles").upsert(
      { id: student.id, data: initialData },
      { onConflict: "id", ignoreDuplicates: true }
    );
    if (insertError) {
      const code = insertError.code ? ` (${insertError.code})` : "";
      const migrationHint = insertError.code === "42501"
        ? " Apply backend/migrations/0007_allow_authenticated_profiles.sql in the Supabase SQL Editor, then retry."
        : "";
      throw new Error(`Could not create your cloud profile${code}: ${insertError.message}.${migrationHint}`);
    }

    const { data: created, error: reloadError } = await client.from("profiles")
      .select("data").eq("id", student.id).maybeSingle();
    if (reloadError) {
      const code = reloadError.code ? ` (${reloadError.code})` : "";
      throw new Error(`Profile creation succeeded, but the cloud profile could not be reloaded${code}: ${reloadError.message}`);
    }
    if (!created) {
      throw new Error("Profile creation did not return a readable profile. Apply backend/migrations/0007_allow_authenticated_profiles.sql in Supabase and verify that the owner-scoped profiles RLS policies are installed.");
    }
    profileData = mergeProfileData(created.data, student);
  }
  if (student.email) profileData.profile.email = student.email;

  client.auth.onAuthStateChange((event, session) => {
    if (studentKeys.has(key) &&
      (event === "SIGNED_OUT" || (event === "SIGNED_IN" && session?.user.id !== student.id))) {
      window.location.replace("auth.html");
    }
  });
  return true;
}

async function persistProfile(next) {
  const client = await getSupabase();
  const { data, error } = await client.from("profiles").update({ data: next, updated_at: new Date().toISOString() })
    .eq("id", student.id).select("id").maybeSingle();
  if (error) throw new Error(`Cloud profile save failed: ${error.message}`);
  if (!data) throw new Error("Cloud profile was not updated. Account access may have changed; reload and retry.");
  profileData = next;
  setStatus("Your profile is synced with Supabase.");
}

/* ---------- page-specific data (each load is non-fatal) ---------- */
async function loadVerifications() {
  const client = await getSupabase();
  const { data, error } = await client.from("verifications").select("*")
    .eq("student_id", student.id).order("created_at", { ascending: false });
  if (error) {
    if (tableMissing(error)) { verificationsReady = false; verifications = []; return; }
    throw error;
  }
  verifications = data || [];
}
async function loadFinance() {
  const client = await getSupabase();
  const [l, p] = await Promise.all([
    client.from("finance_ledger").select("*").eq("student_id", student.id).order("created_at", { ascending: false }),
    client.from("payment_plan_requests").select("*").eq("student_id", student.id).order("created_at", { ascending: false })
  ]);
  for (const r of [l, p]) if (r.error) { if (tableMissing(r.error)) { financeReady = false; return; } throw r.error; }
  financeRows = l.data || []; planRows = p.data || [];
}
async function loadRecommendations() {
  const client = await getSupabase();
  const { data, error } = await client.from("recommendation_requests").select("*")
    .eq("student_id", student.id).order("created_at", { ascending: false });
  if (error) { if (tableMissing(error)) { recReady = false; return; } throw error; }
  recRows = data || [];
  const { data: shares, error: shareError } = await client.from("achievement_shares")
    .select("id,request_id,expires_at,revoked_at,created_at").eq("student_id", student.id)
    .order("created_at", { ascending: false });
  if (shareError) {
    if (tableMissing(shareError)) { sharingReady = false; shareRows = []; return; }
    throw shareError;
  }
  const activeShares = shares || [];
  const { data: views, error: viewsError } = activeShares.length
    ? await client.from("share_access_log").select("share_id,lecturer_email,viewed_at")
      .in("share_id", activeShares.map(s => s.id)).order("viewed_at", { ascending: false }).limit(100)
    : { data: [], error: null };
  if (viewsError) throw viewsError;
  shareRows = activeShares.map(s => ({
    ...s,
    views: (views || []).filter(v => v.share_id === s.id).sort((a, b) => b.viewed_at.localeCompare(a.viewed_at))
  }));
}
async function loadShareCandidates() {
  shareCandidates = [];
  for (const [collection, type] of [["projects", "project"], ["achievements", "achievement"], ["clubs", "club"]]) {
    const cfg = COLLECTIONS[collection];
    for (const item of profileData[cfg.store] || []) {
      const info = await verificationInfo(cfg, item);
      if (info?.state === "verified") {
        shareCandidates.push({
          verificationId: info.row.id,
          title: cfg.title(item),
          type
        });
      }
    }
  }
}
async function loadAchievementHistory() {
  const client = await getSupabase();
  const [requests, history] = await Promise.all([
    client.from("achievement_change_requests").select("id,collection_name,item_id,action,reason,status,records_note,created_at,handled_at")
      .eq("student_id", student.id).order("created_at", { ascending: false }).limit(50),
    client.from("achievement_history").select("id,collection_name,item_id,action,old_data,new_data,created_at")
      .eq("student_id", student.id).order("created_at", { ascending: false }).limit(100)
  ]);
  for (const result of [requests, history]) {
    if (result.error) {
      if (tableMissing(result.error)) { historyReady = false; changeRequests = []; achievementHistory = []; return; }
      throw result.error;
    }
  }
  changeRequests = requests.data || [];
  achievementHistory = history.data || [];
}
async function loadOfficialResults() {
  const client = await getSupabase();
  const { data, error } = await client.from("official_results")
    .select("id,course_code,course,grade,semester,updated_at")
    .order("semester", { ascending: false }).order("course_code");
  if (error) {
    if (tableMissing(error)) {
      officialResultsReady = false;
      officialResults = [];
      return;
    }
    throw error;
  }
  officialResultsReady = true;
  officialResults = data || [];
}
async function loadPageData() {
  try {
    if (["projects", "academics", "clubs", "professional", "references"].includes(key)) await loadVerifications();
    if (key === "finance") await loadFinance();
    if (key === "results") await loadOfficialResults();
    if (key === "references") {
      await Promise.all([loadRecommendations(), loadShareCandidates()]);
    }
    if (["projects", "academics", "clubs"].includes(key)) await loadAchievementHistory();
  } catch (error) {
    pageNote = error instanceof Error ? error.message : "Some information could not be loaded.";
  }
}

function computeBalance(rows) {
  const sum = (kind, status) => rows.filter(r => r.kind === kind && r.status === status).reduce((a, r) => a + Number(r.amount || 0), 0);
  const billed = sum("charge", "posted"), paid = sum("payment", "posted"), credits = sum("credit", "posted");
  const pendingPayments = sum("payment", "pending"), pendingCredits = sum("credit", "pending"), pendingCharges = sum("charge", "pending");
  const balance = billed - paid - credits;
  return { billed, paid, credits, balance, pendingPayments, pendingCredits, pendingCharges,
    projected: balance + pendingCharges - pendingPayments - pendingCredits };
}

/* ---------- record collections ---------- */
const LEVELS = ["Beginner", "Intermediate", "Advanced"];
const COLLECTIONS = {
  projects: {
    store: "projects", verify: "project", empty: "No projects yet. Add your first project above.",
    fields: [["title", "Project name", "text", { required: true, max: 120 }],
      ["description", "Description", "textarea", { max: 1000 }],
      ["tech", "Technologies", "text", { max: 200 }],
      ["github", "Project link (must start with https://)", "url", { https: true, max: 300 }]],
    show: [["description"], ["tech", "Technologies"], ["github", "Link"]],
    hash: ["title", "description", "tech", "github"], title: r => r.title
  },
  skills: {
    store: "skills", pills: true, empty: "No skills yet. Add one above.",
    fields: [["name", "Skill", "text", { required: true, max: 80 }], ["level", "Level", "select", { options: LEVELS }]],
    title: r => r.name
  },
  academic: {
    store: "academic", empty: "No academic records yet.",
    fields: [["qualification", "Qualification", "text", { required: true, max: 160 }],
      ["institution", "Institution", "text", { max: 160 }], ["years", "Year", "text", { max: 40 }], ["result", "Result", "text", { max: 80 }]],
    show: [["institution", "Institution"], ["years", "Year"], ["result", "Result"]], title: r => r.qualification
  },
  achievements: {
    store: "achievements", verify: "achievement", empty: "No achievements yet.",
    fields: [["title", "Achievement", "text", { required: true, max: 160 }],
      ["category", "Category", "select", { options: ["Other", "Academic", "Leadership", "Research", "Community Service", "Sports", "Arts & Culture"] }],
      ["date", "Date", "date"],
      ["issuer", "Awarded by", "text", { max: 160 }], ["description", "Details", "textarea", { max: 800 }],
      ["file", "Supporting picture or PDF (optional, helps Records verify it)", "file", { accept: "image/*,.pdf" }]],
    show: [["category", "Category"], ["issuer", "Awarded by"], ["date", "Date"], ["description"]],
    hash: ["title", "category", "date", "issuer", "description"],
    legacyHash: ["title", "date", "issuer", "description"], title: r => r.title, hasFile: true
  },
  certificates: {
    store: "certificates", empty: "No certificates yet.",
    fields: [["title", "Certificate", "text", { required: true, max: 160 }], ["issuer", "Issued by", "text", { max: 160 }],
      ["date", "Date issued", "date"], ["file", "Certificate file (picture or PDF)", "file", { accept: "image/*,.pdf" }]],
    show: [["issuer", "Issued by"], ["date", "Date"]], title: r => r.title, hasFile: true
  },
  clubs: {
    store: "clubs", verify: "club", empty: "No clubs, associations or activities yet.",
    fields: [["name", "Club, association or activity", "text", { required: true, max: 120 }],
      ["type", "Type", "select", { options: ["Club", "Association", "Activity"] }],
      ["role", "Your role", "text", { max: 80 }],
      ["photos", "Pictures (up to 6 images)", "files", { accept: "image/*" }]],
    show: [["type", "Type"], ["role", "Role"]], hash: ["name", "type", "role"], title: r => r.name, hasPhotos: true
  }
};
const PAGE_COLLECTIONS = {
  projects: ["projects"], skills: ["skills"], clubs: ["clubs"],
  academics: ["academic", "achievements", "certificates"]
};
const ACADEMIC_TABS = [["academic", "Academic history"], ["achievements", "Achievements"], ["certificates", "Certificates"]];
const FIELD_LABELS = { title: "Title", name: "Name", description: "Description", tech: "Technologies", github: "Link", date: "Date", category: "Category", issuer: "Awarded by", type: "Type", role: "Role" };

function field([name, label, type, opt = {}], value = "") {
  const req = opt.required ? " required" : "";
  const max = opt.max ? ` maxlength="${opt.max}"` : "";
  let control;
  if (type === "textarea") control = `<textarea name="${name}" rows="${opt.rows || 3}"${req}${max} data-count>${safe(value)}</textarea>`;
  else if (type === "select") control = `<select name="${name}"${req}>${opt.options.map(o => `<option value="${safe(o)}"${o === value ? " selected" : ""}>${safe(o)}</option>`).join("")}</select>`;
  else if (type === "file" || type === "files") control = `<input name="${name}" type="file" accept="${safe(opt.accept || "")}"${type === "files" ? " multiple" : ""}>`;
  else if (type === "checkbox") return `<label class="check full"><input name="${name}" type="checkbox"${req}><span>${label}</span></label>`;
  else control = `<input name="${name}" type="${type}" value="${safe(value)}"${req}${max}${opt.min ? ` min="${opt.min}"` : ""}${opt.step ? ` step="${opt.step}"` : ""}${opt.autocomplete ? ` autocomplete="${opt.autocomplete}"` : ""}>`;
  return `<label${opt.full || type === "textarea" ? ' class="full"' : ""}>${safe(label)}${control}${opt.hint ? `<small class="hint">${safe(opt.hint)}</small>` : ""}</label>`;
}

function collectionSection(name, heading) {
  const cfg = COLLECTIONS[name];
  const form = `<form class="data-form" data-add="${name}"><h2 class="section-title full" style="margin:0">${safe(heading)}</h2>${cfg.fields.map(f => field(f)).join("")}<button class="button" type="submit">Add</button><p class="form-message" aria-live="polite"></p></form>`;
  return `${form}<div class="saved-items"><h2>Saved information</h2><div data-items="${name}"></div></div>`;
}

function officialResultsContent() {
  if (!officialResultsReady) {
    return `<div class="notice warn"><strong>Official results are not available yet</strong><p>Ask the Records Office to apply <code>backend/migrations/0012_official_results_scoped_verifiers_alumni.sql</code>.</p></div>`;
  }
  if (!officialResults.length) {
    return `<div class="empty">No official results are available on your account yet. Contact the Records Office if you think results should be listed here.</div>`;
  }
  const semesters = new Map();
  for (const result of officialResults) {
    if (!semesters.has(result.semester)) semesters.set(result.semester, []);
    semesters.get(result.semester).push(result);
  }
  return `<p class="muted">These are official results supplied by the Records Office. Contact Records if you believe an entry is incorrect.</p>
    ${[...semesters].map(([semester, rows]) => `<section class="saved-items"><h2>${safe(semester)}</h2>
      <div class="table-wrap"><table class="data stack"><thead><tr><th>Course code</th><th>Course</th><th>Grade</th></tr></thead><tbody>
      ${rows.map(row => `<tr><td data-label="Course code">${safe(row.course_code)}</td><td data-label="Course">${safe(row.course)}</td><td data-label="Grade"><strong>${safe(row.grade)}</strong></td></tr>`).join("")}
      </tbody></table></div></section>`).join("")}`;
}

/* ---------- verification (Records Office) ---------- */
async function itemHash(cfg, rec) {
  const text = JSON.stringify([cfg.verify, ...cfg.hash.map(f => String(rec[f] ?? ""))]);
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function verificationInfo(cfg, rec) {
  const hash = await itemHash(cfg, rec);
  const rows = verifications.filter(v => v.item_type === cfg.verify && v.item_id === rec.id);
  const hashes = new Set([hash]);
  if (cfg.legacyHash) hashes.add(await itemHash({ ...cfg, hash: cfg.legacyHash }, rec));
  const same = rows.filter(v => hashes.has(v.item_hash));
  const verified = same.find(v => v.status === "verified");
  if (verified) return { state: "verified", row: verified };
  const pending = same.find(v => v.status === "pending");
  if (pending) return { state: "pending", row: pending };
  const rejected = same.find(v => v.status === "rejected");
  if (rejected) return { state: "rejected", row: rejected };
  if (rows.some(v => v.status === "verified")) return { state: "changed" };
  return { state: "none" };
}
function verifyBadge(info) {
  switch (info?.state) {
    case "verified": return `<span class="badge ok">✓ Verified${info.row.reviewed_at ? " · " + safe(fmtDate(info.row.reviewed_at)) : ""}</span>`;
    case "pending": return `<span class="badge warn">Awaiting verifier review</span>`;
    case "rejected": return `<span class="badge bad">Could not be verified</span>${info.row.reviewer_note ? `<span>${safe(info.row.reviewer_note)}</span>` : ""}`;
    case "changed": return `<span class="badge bad">Changed since it was verified</span>`;
    default: return `<span class="badge">Not verified</span>`;
  }
}

async function requestVerification(name, id, { refresh = true } = {}) {
  const cfg = COLLECTIONS[name];
  const rec = profileData[cfg.store].find(r => r.id === id);
  const p = profileData.profile;
  if (!rec) throw new Error("This item could not be found in your saved profile. Reload and try again.");
  if (!p.name || !p.studentId) throw new Error("Add your full name and student ID on the Overview page first, so Records can find you.");
  const snapshot = {};
  for (const f of cfg.hash) snapshot[f] = rec[f] ?? "";
  const evidence = [rec.file, ...(rec.photos || [])].filter(Boolean);
  const client = await getSupabase();
  const { error } = await client.from("verifications").insert({
    student_id: student.id, student_name: p.name, student_number: p.studentId,
    item_type: cfg.verify, item_id: rec.id, item_title: cfg.title(rec).slice(0, 200),
    item_snapshot: snapshot, item_hash: await itemHash(cfg, rec), evidence, status: "pending"
  });
  if (error) {
    if (tableMissing(error)) throw new Error(cfg.verify === "result"
      ? "Course result verification is not set up. Ask your administrator to apply migrations 0008 and 0009."
      : "Verification is not set up yet. Ask your administrator to apply migration 0008.");
    if (cfg.verify === "result" && error.code === "23514") {
      throw new Error("Course result verification needs migration 0009. Ask your administrator to apply backend/migrations/0009_result_verification.sql.");
    }
    if (error.code === "23505") {
      if (refresh) await loadVerifications();
      return false;
    }
    throw new Error(`Could not send the verification request: ${error.message}`);
  }
  if (refresh) await loadVerifications();
  return true;
}

/* ---------- collection rendering ---------- */
function linkTo(url) { const u = httpsOnly(url); return u ? `<a href="${safe(u)}" target="_blank" rel="noopener noreferrer">${safe(u)}</a>` : safe(url); }

function itemCard(cfg, name, row, info) {
  const lines = (cfg.show || []).map(([f, label]) => {
    if (!row[f]) return "";
    const value = f === "github" ? linkTo(row[f]) : safe(row[f]);
    return `<p>${label ? `<strong>${safe(label)}:</strong> ` : ""}${value}</p>`;
  }).join("");
  const photos = cfg.hasPhotos && row.photos?.length ? `<div class="thumbs">${row.photos.map(r => `<img class="thumb" data-ref="${safe(r)}" alt="Picture for ${safe(cfg.title(row))}" loading="lazy">`).join("")}</div>` : "";
  const file = cfg.hasFile && row.file ? `<p><a data-file-ref="${safe(row.file)}" href="#" target="_blank" rel="noopener noreferrer">View uploaded file</a></p>` : "";
  let verifyUi = "";
  if (cfg.verify && verificationsReady) {
    const canAsk = ["none", "rejected", "changed"].includes(info?.state);
    verifyUi = `<div class="verify-line">${verifyBadge(info)}</div>${canAsk && cfg.requestMode !== "batch" ? `<button class="text-button" type="button" data-verify="${name}:${safe(row.id)}">Request verification</button>` : ""}`;
  }
  const pendingChange = changeRequests.find(r => r.collection_name === name && r.item_id === row.id && r.status === "pending");
  let changeControl = "";
  if (info?.state === "verified" && ["projects", "achievements", "clubs"].includes(name) && historyReady) {
    if (pendingChange) {
      changeControl = `<p class="notice warn">A ${safe(pendingChange.action)} request is awaiting Records Office review.</p>`;
    } else {
      const editableFields = (cfg.fields || [])
        .filter(([, , type]) => type !== "file" && type !== "files" && type !== "checkbox")
        .map(([f, label, type, opt = {}]) => field([f, label, type, { ...opt, required: false }], row[f] || "")).join("");
      changeControl = `<button class="text-button" type="button" data-change-toggle="${name}:${safe(row.id)}">Request a correction or removal</button>
        <form class="data-form" data-change-form="${name}:${safe(row.id)}" hidden>
          <label>Request type<select name="action"><option value="correct">Correct this achievement</option><option value="delete">Request deletion</option></select></label>
          <fieldset class="full"><legend>Proposed details</legend>${editableFields}</fieldset>
          <label class="full">Why should this be changed? (at least 10 characters)<textarea name="reason" rows="3" maxlength="1000" required></textarea></label>
          <button class="button" type="submit">Send to Records Office</button><button class="button ghost" type="button" data-change-cancel>Cancel</button><p class="form-message" aria-live="polite"></p>
        </form>`;
    }
  } else if (info?.state === "verified" && name === "results") {
    changeControl = `<p class="muted">Verified results are managed by the Records Office. Contact them to request a correction.</p>`;
  }
  const remove = info?.state === "verified"
    ? ""
    : `<button class="text-button danger" type="button" data-remove="${name}:${safe(row.id)}">Remove</button>`;
  return `<article class="saved-card"><h3>${safe(cfg.title(row))}</h3>${lines}${photos}${file}${verifyUi}${changeControl}<div class="card-actions">${remove}</div></article>`;
}

async function renderItems(name) {
  const box = $(`[data-items="${name}"]`);
  if (!box || !profileData) return;
  const cfg = COLLECTIONS[name];
  const rows = profileData[cfg.store] || [];
  if (!rows.length) { box.innerHTML = `<p class="muted">${safe(cfg.empty)}</p>`; return; }
  if (cfg.pills) {
    box.innerHTML = `<div class="pills">${rows.map(r => `<span class="pill l-${safe(r.level)}"><span>${safe(r.name)} <small>${safe(r.level)}</small></span><button type="button" aria-label="Remove ${safe(r.name)}" data-remove="${name}:${safe(r.id)}">×</button></span>`).join("")}</div>`;
    return;
  }
  const infos = cfg.verify && verificationsReady ? await Promise.all(rows.map(r => verificationInfo(cfg, r))) : [];
  box.innerHTML = `<div class="card-grid">${rows.map((r, i) => itemCard(cfg, name, r, infos[i])).join("")}</div>`;
  hydrateFiles(box);
}

function hydrateFiles(root) {
  $$("img[data-ref]", root).forEach(img => signedUrl(img.dataset.ref).then(u => { if (u) img.src = u; }));
  $$("a[data-file-ref]", root).forEach(a => signedUrl(a.dataset.fileRef).then(u => { if (u) a.href = u; else a.textContent = "File unavailable"; }));
}

async function addRecord(name, form) {
  const cfg = COLLECTIONS[name];
  const fd = new FormData(form);
  const rec = { id: crypto.randomUUID() };
  for (const [f, label, type, opt = {}] of cfg.fields) {
    if (type === "file") {
      const file = fd.get(f);
      if (file instanceof File && file.size) rec[f] = await uploadStudentFile(file, { shrinkImage: 1800 });
    } else if (type === "files") {
      const files = fd.getAll(f).filter(x => x instanceof File && x.size);
      if (files.length > 6) throw new Error("Choose at most 6 pictures at a time.");
      rec[f] = [];
      for (const file of files) {
        if (!file.type.startsWith("image/")) throw new Error(`${file.name} is not an image.`);
        rec[f].push(await uploadStudentFile(file, { allow: IMAGES_ONLY, shrinkImage: 1600 }));
      }
    } else {
      const v = valueForForm(f, fd);
      if (opt.required && !v) throw new Error(`${label} is required.`);
      if (opt.https && v && !/^https:\/\//i.test(v)) throw new Error("Links must start with https://.");
      rec[f] = v.slice(0, opt.max || 300);
    }
  }
  if (name === "skills" && profileData.skills.some(s => s.name.toLowerCase() === rec.name.toLowerCase())) {
    throw new Error("You already have that skill listed.");
  }
  await persistProfile({ ...profileData, [cfg.store]: [rec, ...profileData[cfg.store]] });
}

async function removeRecord(name, id) {
  const cfg = COLLECTIONS[name];
  const row = profileData[cfg.store].find(r => r.id === id);
  if (!row || !confirm(`Remove "${cfg.title(row)}"? This cannot be undone.`)) return;
  try {
    if (cfg.verify && (await verificationInfo(cfg, row))?.state === "verified") {
      throw new Error(name === "results"
        ? "Verified results are managed by the Records Office. Contact them to request a correction."
        : "Verified achievements cannot be removed directly. Send a deletion request to the Records Office.");
    }
    await persistProfile({ ...profileData, [cfg.store]: profileData[cfg.store].filter(r => r.id !== id) });
    removeStoredFiles([row.file, ...(row.photos || [])]);
    await renderItems(name);
    toast("Removed.");
  } catch (error) {
    toast(error instanceof Error ? error.message : "Could not remove the item.", true);
  }
}

async function submitAchievementChange(form) {
  const [collection, id] = form.dataset.changeForm.split(":");
  const cfg = COLLECTIONS[collection];
  const row = profileData[cfg.store].find(item => item.id === id);
  if (!row) throw new Error("This achievement is no longer in your profile.");
  const fd = new FormData(form);
  const action = String(fd.get("action"));
  const reason = valueForForm("reason", fd);
  if (reason.length < 10) throw new Error("Explain the requested change in at least 10 characters.");
  const proposed = {};
  if (action === "correct") {
    for (const [name, label, type, options = {}] of cfg.fields) {
      if (type === "file" || type === "files" || type === "checkbox") continue;
      const value = valueForForm(name, fd);
      if (options.required && !value) throw new Error(`${label} is required.`);
      if (options.https && value && !/^https:\/\//i.test(value)) throw new Error("Links must start with https://.");
      if (value !== String(row[name] ?? "")) proposed[name] = value.slice(0, options.max || 300);
    }
    if (!Object.keys(proposed).length) throw new Error("Change at least one field before sending a correction request.");
  }
  const client = await getSupabase();
  const { error } = await client.from("achievement_change_requests").insert({
    student_id: student.id, collection_name: collection, item_id: id,
    action, proposed_data: proposed, reason
  });
  if (error) throw new Error(`Could not send the change request: ${error.message}`);
  await loadAchievementHistory();
}

function achievementHistoryContent() {
  if (!historyReady) return `<div class="notice warn"><strong>Achievement history is not available yet</strong><p>Ask an administrator to apply <code>backend/migrations/0011_lecturer_sharing_and_achievement_history.sql</code>.</p></div>`;
  const requests = changeRequests.length
    ? `<div class="card-grid">${changeRequests.map(r => {
      const currentItem = (profileData[r.collection_name] || []).find(item => item.id === r.item_id);
      const title = currentItem?.title || currentItem?.name || r.item_id;
      return `<article class="saved-card">
        <div class="verify-line">${statusBadge({ pending: ["Awaiting review", "warn"], approved: ["Approved", "ok"], rejected: ["Not approved", "bad"] }, r.status)}<span>${safe(fmtDate(r.created_at))}</span></div>
        <h3>${safe(r.action === "delete" ? "Deletion request" : "Correction request")}: ${safe(title)}</h3>
        <p>${safe(r.reason)}</p>${r.records_note ? `<p class="notice">${safe(r.records_note)}</p>` : ""}
      </article>`;
    }).join("")}</div>`
    : '<p class="muted">No correction or deletion requests yet.</p>';
  const history = achievementHistory.length
    ? `<div class="table-wrap"><table class="data stack"><thead><tr><th>Date</th><th>Achievement</th><th>Action</th><th>Details</th></tr></thead><tbody>${achievementHistory.map(h => {
      const title = h.new_data?.title || h.new_data?.name || h.old_data?.title || h.old_data?.name || h.item_id;
      const detail = h.action === "updated" || h.action.includes("approved")
        ? `${h.old_data ? JSON.stringify(h.old_data) : ""}${h.new_data ? ` → ${JSON.stringify(h.new_data)}` : ""}`
        : "";
      return `<tr><td data-label="Date">${safe(fmtDate(h.created_at))}</td><td data-label="Achievement">${safe(title)}</td><td data-label="Action">${safe(h.action.replaceAll("_", " "))}</td><td data-label="Details">${safe(detail)}</td></tr>`;
    }).join("")}</tbody></table></div>`
    : '<p class="muted">Changes to your projects, achievements and activities will appear here.</p>';
  return `<section class="saved-items"><h2>Correction requests</h2>${requests}<h2 class="section-title">Achievement history</h2>${history}</section>`;
}

/* The student ID is encoded locally; it is not sent to a QR service. */
async function hydrateQrCode(root) {
  const box = $("[data-qr-value]", root);
  if (!box || !box.dataset.qrValue) return;
  try {
    const { toDataURL } = await import("https://esm.sh/qrcode@1.5.4?bundle");
    const image = await toDataURL(box.dataset.qrValue, {
      errorCorrectionLevel: "M", margin: 1, width: 144,
      color: { dark: "#0B0B0B", light: "#F5F2ED" }
    });
    if (box.isConnected) box.innerHTML = `<img src="${image}" alt="QR code for student ID ${safe(box.dataset.qrValue)}"><span>${safe(box.dataset.qrValue.toUpperCase())}</span>`;
  } catch (error) {
    console.error("Could not generate the digital ID QR code.", error);
    if (box.isConnected) box.textContent = "QR code unavailable. Check your connection and reload.";
  }
}

/* ---------- Overview: digital ID + details ---------- */
function initials(name) { return String(name || "?").trim().split(/\s+/).slice(0, 2).map(p => p[0]).join("").toUpperCase() || "?"; }

function overviewContent() {
  const p = profileData.profile;
  const complete = p.name && p.studentId && p.programme && p.faculty && p.year;
  const photo = p.photo ? `<img data-ref="${safe(p.photo)}" alt="Photo of ${safe(p.name)}">` : safe(initials(p.name));
  const card = `<section class="id-card" aria-label="Digital student identification card">
    <div class="id-top"><span class="brand-mark">AU</span><div><strong>Africa University</strong><small>Student identification</small></div></div>
    <div class="id-main"><div class="id-photo">${photo}</div><dl class="id-details">
      <div><dt>Name</dt><dd class="name">${safe(p.name || "Add your name")}</dd></div>
      <div><dt>Student ID</dt><dd>${safe(p.studentId || "Not set")}</dd></div>
      <div><dt>Programme</dt><dd>${safe(p.programme || "Not set")}</dd></div>
      <div><dt>Faculty · Year</dt><dd>${safe(p.faculty || "Not set")}${p.year ? " · Year " + safe(p.year) : ""}</dd></div>
    </dl></div>
    <div class="id-code"${p.studentId ? ` data-qr-value="${safe(p.studentId)}"` : ""}>${p.studentId ? '<span role="status">Generating QR code…</span>' : '<span>Add your student ID to show a QR code</span>'}</div>
    <div class="id-foot"><span>Mutare · Zimbabwe</span><span>${p.graduated ? "Graduate" : "Student"}</span></div></section>`;
  const details = [["Full name", p.name], ["Student ID", p.studentId], ["Programme", p.programme], ["Faculty", p.faculty],
    ["Year of study", p.year], ["Email", p.email || student.email], ["Phone", p.phone], ["About me", p.bio]];
  const rows = details.map(([k, v]) => `<dt>${k}</dt><dd>${v ? safe(v) : '<span class="muted">Not added</span>'}</dd>`).join("");
  const counts = [["Projects", profileData.projects.length], ["Skills", profileData.skills.length],
    ["Achievements", profileData.achievements.length], ["Certificates", profileData.certificates.length], ["Clubs", profileData.clubs.length]];
  const form = `<form class="data-form wide" data-profile-form="overview" style="max-width:760px">
    ${[["name", "Full name", "text", { required: true, max: 120, autocomplete: "name" }], ["studentId", "Student ID", "text", { required: true, max: 40 }],
      ["programme", "Programme", "text", { max: 160 }], ["faculty", "Faculty", "text", { max: 160 }],
      ["year", "Year of study", "select", { options: ["", "1", "2", "3", "4", "5", "6"] }],
      ["email", "Email", "email", { max: 200, autocomplete: "email" }], ["phone", "Phone", "tel", { max: 40, autocomplete: "tel" }],
      ["photo", "ID photo (JPG, PNG or WebP)", "file", { accept: "image/*" }], ["bio", "About me", "textarea", { max: 600 }]]
      .map(f => field(f, f[2] === "file" ? "" : p[f[0]] || "")).join("")}
    <button class="button" type="submit">Save profile</button><p class="form-message" aria-live="polite"></p></form>`;
  return `<div class="overview-grid"><div>${card}<div class="id-actions"><button class="button small" type="button" data-print-id>Print ID card</button></div></div>
    <div class="details-card"><h2>Student details</h2>${complete ? "" : '<p class="notice warn" style="margin:0 0 14px">Complete your name, student ID, programme, faculty and year so your ID card is complete.</p>'}<dl class="kv">${rows}</dl></div></div>
    <div class="stat-grid">${counts.map(([k, v]) => `<div class="stat"><span>${k}</span><strong>${v}</strong></div>`).join("")}</div>
    <h2 class="section-title">Edit your details</h2>${form}`;
}

/* ---------- Professional profile ---------- */
function professionalContent() {
  const p = profileData.profile;
  const gh = httpsOnly(p.github), li = httpsOnly(p.linkedin);
  const form = `<form class="data-form wide" data-profile-form="professional" style="max-width:760px">
    ${field(["linkedin", "LinkedIn profile", "url", { max: 300, hint: "e.g. https://www.linkedin.com/in/your-name" }], p.linkedin || "")}
    ${field(["github", "GitHub profile", "url", { max: 300, hint: "e.g. https://github.com/your-username" }], p.github || "")}
    ${field(["cvFile", "Upload CV (PDF, DOC or DOCX, up to 10 MB)", "file", { accept: ".pdf,.doc,.docx", full: true }])}
    <button class="button" type="submit">Save professional details</button><p class="form-message" aria-live="polite"></p></form>`;
  const links = `<div class="details-card"><h2>Your links and CV</h2><div class="id-actions" style="margin:0 0 6px">
    ${gh ? `<a class="button small" href="${safe(gh)}" target="_blank" rel="noopener noreferrer">Open GitHub</a>` : ""}
    ${li ? `<a class="button small" href="${safe(li)}" target="_blank" rel="noopener noreferrer">Open LinkedIn</a>` : ""}
    ${p.cvFile ? `<a class="button small" data-cv-download href="#">Download my CV${p.cvFileName ? " (" + safe(p.cvFileName) + ")" : ""}</a><button class="button small ghost" type="button" data-cv-remove>Remove CV</button>` : ""}
    <button class="button small ghost" type="button" data-cv-generate>Create a CV from my profile</button></div>
    ${!gh && !li && !p.cvFile ? '<p class="muted">Add your links and upload a CV below.</p>' : ""}
    <p class="muted" style="margin-bottom:0">The generated CV opens in a new tab. Use your browser’s Print option and choose “Save as PDF”. Items verified by the Records Office are marked.</p></div>`;
  return `${links}<h2 class="section-title">Edit professional details</h2>${form}`;
}

async function generateCv() {
  const p = profileData.profile;
  const w = window.open("", "_blank");
  if (!w) { toast("Allow pop-ups for this site to open the CV.", true); return; }
  const verified = (type, id) => verifications.some(v => v.item_type === type && v.item_id === id && v.status === "verified") ? " ✓ verified" : "";
  const ul = (title, items) => items.length ? `<h2>${title}</h2><ul>${items.map(i => `<li>${i}</li>`).join("")}</ul>` : "";
  const d = profileData;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${safe(p.name || "CV")} – CV</title>
  <style>body{font:14px/1.55 Arial,sans-serif;max-width:780px;margin:30px auto;padding:0 18px;color:#0B0B0B;background:#F5F2ED}h1{color:#8B0D1A;margin:0}h2{color:#8B0D1A;border-bottom:2px solid #8B0D1A;padding-bottom:3px;margin-top:24px;font-size:16px}ul{padding-left:20px}.sub{color:#514b48}@media print{button{display:none}}</style></head><body>
  <button onclick="print()" style="float:right">Print / Save as PDF</button>
  <h1>${safe(p.name || "Student")}</h1><p class="sub">${safe([p.programme, p.faculty, "Africa University"].filter(Boolean).join(" · "))}<br>${safe([p.email, p.phone].filter(Boolean).join(" · "))}<br>${safe([httpsOnly(p.linkedin), httpsOnly(p.github)].filter(Boolean).join(" · "))}</p>
  ${p.bio ? `<h2>Profile</h2><p>${safe(p.bio)}</p>` : ""}
  ${ul("Education", d.academic.map(a => `<b>${safe(a.qualification)}</b>${a.institution ? ", " + safe(a.institution) : ""}${a.years ? " (" + safe(a.years) + ")" : ""}${a.result ? " – " + safe(a.result) : ""}`))}
  ${ul("Skills", d.skills.map(s => `${safe(s.name)} (${safe(s.level)})`))}
  ${ul("Projects", d.projects.map(x => `<b>${safe(x.title)}</b>${x.tech ? " – " + safe(x.tech) : ""}${x.description ? ": " + safe(x.description) : ""}${verified("project", x.id)}`))}
  ${ul("Achievements", d.achievements.map(a => `<b>${safe(a.title)}</b>${a.issuer ? ", " + safe(a.issuer) : ""}${a.date ? " (" + safe(a.date) + ")" : ""}${verified("achievement", a.id)}`))}
  ${ul("Certificates", d.certificates.map(c => `<b>${safe(c.title)}</b>${c.issuer ? ", " + safe(c.issuer) : ""}${c.date ? " (" + safe(c.date) + ")" : ""}`))}
  ${ul("Clubs, associations and activities", d.clubs.map(c => `<b>${safe(c.name)}</b>${c.role ? " – " + safe(c.role) : ""}${verified("club", c.id)}`))}
  </body></html>`;
  w.document.open(); w.document.write(html); w.document.close();
}

/* ---------- Recommendation requests ---------- */
const REC_STATUS = { submitted: ["Submitted", "info"], in_review: ["In review", "warn"], forwarded: ["Sent to referee", "warn"], completed: ["Completed", "ok"], declined: ["Declined", "bad"] };
const LECTURER_STATUS = { in_review: ["Lecturer reviewing", "warn"], completed: ["Lecturer summary ready", "ok"], declined: ["Lecturer declined", "bad"] };
const PLAN_STATUS = { submitted: ["Submitted", "info"], in_review: ["In review", "warn"], approved: ["Approved", "ok"], declined: ["Declined", "bad"] };
const statusBadge = (map, s) => { const [label, cls] = map[s] || [s, ""]; return `<span class="badge ${cls}">${safe(label)}</span>`; };
const todayIso = () => new Date().toISOString().slice(0, 10);

function referencesContent() {
  if (!recReady) return setupNotice("recommendation");
  const p = profileData.profile;
  const f = (...a) => field(...a);
  const form = `<form class="data-form wide" data-rec-form>
    <fieldset><legend>Your details</legend>
      ${f(["student_name", "Full name", "text", { required: true, max: 120 }], p.name)}${f(["student_number", "Student ID", "text", { required: true, max: 40 }], p.studentId)}
      ${f(["programme", "Programme", "text", { max: 160 }], p.programme)}${f(["student_email", "Your email", "email", { required: true, max: 200 }], p.email || student.email)}
      ${f(["student_phone", "Phone", "tel", { max: 40 }], p.phone)}</fieldset>
    <fieldset><legend>Referee (lecturer or staff member)</legend>
      ${f(["staff_name", "Full name", "text", { required: true, max: 120 }])}${f(["staff_email", "Email address", "email", { required: true, max: 200 }])}
      ${f(["staff_title", "Title / position", "text", { max: 120, hint: "e.g. Senior Lecturer" }])}${f(["staff_department", "Department or faculty", "text", { max: 160 }])}
      ${f(["relationship", "Relationship to you", "select", { options: ["Lecturer", "Project supervisor", "Head of department", "Academic advisor", "Employer / internship supervisor", "Other"] }])}
      ${f(["course_or_context", "Course or context", "text", { max: 200, hint: "e.g. CIS2103, final-year project" }])}</fieldset>
    <fieldset><legend>What the recommendation is for</legend>
      ${f(["purpose", "Purpose", "select", { options: ["Scholarship", "Job application", "Postgraduate admission", "Internship", "Exchange programme", "Other"] }])}
      ${f(["recipient_org", "Organisation or institution", "text", { required: true, max: 200 }])}
      ${f(["recipient_contact", "Where it must be sent (email, portal link or address)", "text", { max: 300, full: true }])}
      ${f(["deadline", "Deadline", "date", { required: true, min: todayIso() }])}</fieldset>
    <fieldset><legend>Personal statement</legend>
      ${f(["personal_statement", "Tell your referee about your goals and what you would like them to mention (50–3000 characters)", "textarea", { required: true, max: 3000, rows: 7, full: true }])}</fieldset>
    <fieldset><legend>Share verified achievements (optional)</legend>
      <p class="muted">Choose only the verified items relevant to this request. The named lecturer must sign in with the referee email above. Access expires no later than 90 days and can be revoked at any time.</p>
      ${!sharingReady ? `<p class="notice warn">Lecturer sharing needs migration 0011. You can still submit a recommendation request without sharing achievements.</p>` : shareCandidates.length ? `<div class="check-list">${shareCandidates.map(c => `<label class="check"><input type="checkbox" name="share_verification_ids" value="${safe(c.verificationId)}"><span>${safe(c.title)} <small>· ${safe(c.type)}</small></span></label>`).join("")}</div>
        ${f(["share_expiry_days", "Access duration", "select", { options: ["7", "14", "30", "60", "90"] }], "30")}
        ${f(["share_consent", "I approve sharing only the selected verified items with the lecturer named above.", "checkbox"])}` 
        : '<p class="muted">You do not currently have verified projects, achievements or activities to share.</p>'}
    </fieldset>
    ${f(["consent", "I confirm these details are correct and I agree the Records Office may share my request with the named referee.", "checkbox", { required: true }])}
    <button class="button" type="submit">Send request to the Records Office</button><p class="form-message" aria-live="polite"></p></form>`;
  const list = recRows.length ? `<div class="card-grid">${recRows.map(r => {
    const share = shareRows.find(s => s.request_id === r.id);
    return `<article class="saved-card"><div class="verify-line">${statusBadge(REC_STATUS, r.status)}${r.lecturer_status ? statusBadge(LECTURER_STATUS, r.lecturer_status) : ""}<span>${safe(fmtDate(r.created_at))}</span></div>
    <h3>${safe(r.purpose)} · ${safe(r.recipient_org)}</h3><p><strong>Referee:</strong> ${safe(r.staff_name)} (${safe(r.staff_email)})</p><p><strong>Deadline:</strong> ${safe(fmtDate(r.deadline))}</p>
    ${r.lecturer_summary ? `<div class="notice"><strong>Lecturer’s letter summary:</strong><p>${safe(r.lecturer_summary)}</p></div>` : ""}
    ${share ? `<div class="notice"><strong>Verified achievement access</strong><p>${share.revoked_at ? "Revoked" : new Date(share.expires_at) <= new Date() ? "Expired" : `Expires ${safe(fmtDate(share.expires_at))}`}. ${share.views.length ? `${share.views.length} recent view${share.views.length === 1 ? "" : "s"} shown below.` : "No views recorded yet."}</p>
      ${share.views.length ? `<details><summary>View history</summary><ul>${share.views.map(view => `<li>${safe(new Date(view.viewed_at).toLocaleString())} · ${safe(view.lecturer_email)}</li>`).join("")}</ul></details>` : ""}
      ${!share.revoked_at && new Date(share.expires_at) > new Date() ? `<button class="text-button danger" type="button" data-revoke-share="${safe(share.id)}">Revoke lecturer access</button>` : ""}</div>` : ""}
    <p><button class="text-button" type="button" data-send-lecturer-link="${safe(r.staff_email)}">Send secure lecturer sign-in link</button>
      <span class="muted">The link is emailed to the referee and opens the workspace after one click.</span></p>
    ${r.records_assessment ? `<div class="notice" style="margin:6px 0 0"><strong>Records Office assessment:</strong><p>${safe(r.records_assessment)}</p></div>` : ""}
    ${r.records_note ? `<p class="notice" style="margin:6px 0 0"><strong>Records Office:</strong> ${safe(r.records_note)}</p>` : ""}
    ${r.letter_file ? `<p><button class="text-button" type="button" data-download-letter="${safe(r.letter_file)}">Download referee’s signed letter (PDF)</button></p>` : ""}</article>`;
  }).join("")}</div>` : '<p class="muted">You have not requested any recommendations yet.</p>';
  return `<h2 class="section-title">New request</h2>${form}<div class="saved-items"><h2>My requests</h2>${list}</div>`;
}

async function submitRecommendation(form) {
  const fd = new FormData(form);
  const v = n => valueForForm(n, fd);
  const statement = v("personal_statement");
  if (statement.length < 50) throw new Error("Your personal statement needs at least 50 characters.");
  if (v("deadline") < todayIso()) throw new Error("The deadline must be today or later.");
  const row = {
    student_id: student.id, student_name: v("student_name"), student_number: v("student_number"), student_email: v("student_email"),
    student_phone: v("student_phone") || null, programme: v("programme") || null,
    staff_name: v("staff_name"), staff_email: v("staff_email").toLowerCase(), staff_title: v("staff_title") || null,
    staff_department: v("staff_department") || null, relationship: v("relationship"), course_or_context: v("course_or_context") || null,
    purpose: v("purpose"), recipient_org: v("recipient_org"), recipient_contact: v("recipient_contact") || null,
    deadline: v("deadline"), personal_statement: statement, status: "submitted"
  };
  const selectedIds = fd.getAll("share_verification_ids").map(String);
  if (selectedIds.length > 25) throw new Error("Share no more than 25 verified achievements with one request.");
  if (selectedIds.length && !fd.get("share_consent")) throw new Error("Confirm consent before sharing selected achievements.");
  if (selectedIds.length && !sharingReady) throw new Error("Lecturer sharing is not set up yet. Apply migration 0011 or submit without selecting achievements.");
  const client = await getSupabase();
  const { data: created, error } = await client.from("recommendation_requests").insert(row).select("id").single();
  if (error) throw new Error(tableMissing(error) ? "Recommendation requests are not set up yet. Ask your administrator to apply migration 0008." : `Could not send the request: ${error.message}`);
  let sharingSucceeded = true;
  if (selectedIds.length) {
    const expiryDays = Number(v("share_expiry_days")) || 30;
    const expiresAt = new Date(Date.now() + expiryDays * 86400000).toISOString();
    const { error: shareError } = await client.rpc("au_create_recommendation_share", {
      p_request_id: created.id,
      p_verification_ids: selectedIds,
      p_expires_at: expiresAt
    });
    if (shareError) {
      console.error("Recommendation request was saved, but lecturer access could not be created.", shareError);
      sharingSucceeded = false;
    }
  }
  await loadRecommendations();
  return sharingSucceeded;
}

/* ---------- Finance ---------- */
function financeContent() {
  if (!financeReady) return setupNotice("finance");
  const b = computeBalance(financeRows);
  const owing = b.balance > 0;
  const stats = `<div class="stat-grid">
    <div class="stat primary"><span>Tuition balance</span><strong>${money(Math.abs(b.balance))}</strong><small>${owing ? "Outstanding" : b.balance < 0 ? "Overpaid / credit" : "Fully paid"}</small></div>
    <div class="stat"><span>Pending payments</span><strong>${money(b.pendingPayments + b.pendingCredits)}</strong><small>Awaiting confirmation</small></div>
    <div class="stat"><span>Pending charges</span><strong>${money(b.pendingCharges)}</strong><small>Not yet posted</small></div>
    <div class="stat"><span>Balance after pending</span><strong>${money(b.projected)}</strong><small>If all pending items clear</small></div></div>
    <p class="muted">Billed ${money(b.billed)} · Paid ${money(b.paid)}${b.credits ? ` · Credits ${money(b.credits)}` : ""}. Figures are entered by the Finance and Records offices.</p>`;
  const terms = [...new Set(financeRows.map(r => r.term))];
  const termRows = terms.map(t => { const x = computeBalance(financeRows.filter(r => r.term === t));
    return `<tr><td data-label="Term">${safe(t)}</td><td class="num" data-label="Billed">${money(x.billed)}</td><td class="num" data-label="Paid">${money(x.paid + x.credits)}</td><td class="num" data-label="Pending">${money(x.pendingPayments + x.pendingCredits + x.pendingCharges)}</td><td class="num" data-label="Balance"><strong>${money(x.balance)}</strong></td></tr>`; }).join("");
  const byTerm = terms.length ? `<h2 class="section-title">Balance by term</h2><div class="table-wrap"><table class="data stack"><thead><tr><th>Term</th><th class="num">Billed</th><th class="num">Paid</th><th class="num">Pending</th><th class="num">Balance</th></tr></thead><tbody>${termRows}</tbody></table></div>` : "";
  const ledger = financeRows.length ? `<h2 class="section-title">Statement</h2><div class="table-wrap"><table class="data stack"><thead><tr><th>Date</th><th>Term</th><th>Description</th><th>Type</th><th>Status</th><th class="num">Amount</th></tr></thead><tbody>${financeRows.map(r => `<tr><td data-label="Date">${safe(fmtDate(r.created_at))}</td><td data-label="Term">${safe(r.term)}</td><td data-label="Description">${safe(r.description)}${r.reference ? ` <small class="muted">(${safe(r.reference)})</small>` : ""}</td><td data-label="Type">${safe(r.kind)}</td><td data-label="Status"><span class="badge ${r.status === "posted" ? "ok" : "warn"}">${safe(r.status)}</span></td><td class="num ${r.kind === "charge" ? "" : "neg"}" data-label="Amount">${r.kind === "charge" ? "" : "−"}${money(r.amount)}</td></tr>`).join("")}</tbody></table></div>`
    : '<div class="empty">No fee records have been posted to your account yet.</div>';

  const open = planRows.find(r => ["submitted", "in_review"].includes(r.status));
  let plan;
  if (open) plan = `<div class="notice warn"><strong>You have a payment plan request in progress</strong><p>Submitted ${safe(fmtDate(open.created_at))} for ${money(open.amount_requested)} over ${open.instalments} instalments. You can send another once the Records Office has responded.</p></div>`;
  else if (b.balance <= 0) plan = '<div class="notice ok"><strong>No outstanding balance</strong><p>A payment plan is only needed when you owe tuition.</p></div>';
  else plan = `<form class="data-form wide" data-plan-form style="max-width:760px">
    ${field(["amount_requested", "Amount to spread over a plan", "number", { required: true, min: "1", step: "0.01", hint: `Up to your outstanding balance of ${money(b.balance)}` }], b.balance.toFixed(2))}
    ${field(["instalments", "Number of instalments", "select", { options: ["2", "3", "4", "5", "6", "8", "10", "12"] }], "3")}
    ${field(["frequency", "Payment frequency", "select", { options: ["monthly", "fortnightly"] }])}
    ${field(["first_payment_date", "First payment date", "date", { required: true, min: todayIso() }])}
    ${field(["student_phone", "Contact phone", "tel", { max: 40 }], profileData.profile.phone)}
    ${field(["reason", "Why do you need a payment plan? (20–1500 characters)", "textarea", { required: true, max: 1500, rows: 5, full: true }])}
    ${field(["consent", "I understand the Records Office decides on this request and that my balance remains payable until a plan is approved.", "checkbox", { required: true }])}
    <button class="button" type="submit">Send request to the Records Office</button><p class="form-message" aria-live="polite"></p></form>`;
  const history = planRows.length ? `<div class="saved-items"><h2>My payment plan requests</h2><div class="card-grid">${planRows.map(r => `<article class="saved-card"><div class="verify-line">${statusBadge(PLAN_STATUS, r.status)}<span>${safe(fmtDate(r.created_at))}</span></div><h3>${money(r.amount_requested)} · ${r.instalments} ${safe(r.frequency)} instalments</h3><p><strong>First payment:</strong> ${safe(fmtDate(r.first_payment_date))}</p>${r.approved_instalments ? `<p><strong>Approved instalments:</strong> ${r.approved_instalments}</p>` : ""}${r.records_note ? `<p class="notice" style="margin:6px 0 0"><strong>Records Office:</strong> ${safe(r.records_note)}</p>` : ""}</article>`).join("")}</div></div>` : "";
  return `${stats}${byTerm}${ledger}<h2 class="section-title">Request a payment plan</h2><p class="muted">Your request goes straight to the Records Office.</p>${plan}${history}`;
}

async function submitPlan(form) {
  const fd = new FormData(form);
  const b = computeBalance(financeRows);
  const amount = Number(fd.get("amount_requested"));
  if (!(amount > 0)) throw new Error("Enter the amount you want to spread.");
  if (amount > b.balance + 0.001) throw new Error(`The amount cannot be more than your outstanding balance of ${money(b.balance)}.`);
  const reason = valueForForm("reason", fd);
  if (reason.length < 20) throw new Error("Please explain your situation in at least 20 characters.");
  const date = valueForForm("first_payment_date", fd);
  if (date < todayIso()) throw new Error("The first payment date must be today or later.");
  const p = profileData.profile;
  if (!p.name || !p.studentId) throw new Error("Add your full name and student ID on the Overview page first.");
  const client = await getSupabase();
  const { error } = await client.from("payment_plan_requests").insert({
    student_id: student.id, student_name: p.name, student_number: p.studentId, student_email: p.email || student.email,
    student_phone: valueForForm("student_phone", fd) || null, amount_requested: amount,
    instalments: Number(fd.get("instalments")), frequency: String(fd.get("frequency")), first_payment_date: date, reason, status: "submitted"
  });
  if (error) {
    if (error.code === "23505") throw new Error("You already have a payment plan request in progress.");
    throw new Error(tableMissing(error) ? "Payment plans are not set up yet. Ask your administrator to apply migration 0008." : `Could not send the request: ${error.message}`);
  }
  await loadFinance();
}

/* ---------- Account security ---------- */
function securityContent() {
  const created = student.created_at ? fmtDate(student.created_at) : "";
  const last = student.last_sign_in_at ? new Date(student.last_sign_in_at).toLocaleString("en-GB") : "";
  return `<div class="details-card" style="max-width:640px"><h2>Your account</h2><dl class="kv"><dt>Email</dt><dd>${safe(student.email)}</dd>${created ? `<dt>Created</dt><dd>${safe(created)}</dd>` : ""}${last ? `<dt>Last sign-in</dt><dd>${safe(last)}</dd>` : ""}</dl></div>
  <h2 class="section-title">Change password</h2>
  <form class="data-form" data-password-form>
    <label class="full">Current password<input name="current" type="password" autocomplete="current-password" required></label>
    <label class="full">New password<input name="password" type="password" autocomplete="new-password" minlength="8" required><div class="meter" aria-hidden="true"><i data-meter></i></div><small class="hint" data-meter-text>Use at least 8 characters. A longer phrase is stronger.</small></label>
    <label class="full">Confirm new password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="8" required></label>
    <button class="button" type="submit">Update password</button><p class="form-message" aria-live="polite"></p></form>
  <h2 class="section-title">Sessions and backup</h2>
  <div class="security-list">
    <div class="saved-card"><div><h3>Sign out other devices</h3><p>Ends every session except this one. Use it if you signed in on a shared computer.</p></div><button class="button ghost small" type="button" data-signout-others>Sign out others</button></div>
    <div class="saved-card"><div><h3>Export profile backup</h3><p>Download a JSON copy of everything in your profile.</p></div><button class="button ghost small" type="button" data-export>Export backup</button></div>
    <div class="saved-card"><div><h3>Automatic sign-out</h3><p>For your protection you are signed out after 30 minutes without activity.</p></div></div>
  </div>`;
}
function passwordStrength(v) {
  let s = 0;
  if (v.length >= 8) s++; if (v.length >= 12) s++;
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++; if (/\d/.test(v)) s++; if (/[^A-Za-z0-9]/.test(v)) s++;
  return Math.min(4, s);
}

/* ---------- shell and page content ---------- */
function drawShell() {
  const isStudent = studentKeys.has(key);
  const links = navItems.map(([id, label]) => `<a class="nav-link ${id === key ? "active" : ""}" ${id === key ? 'aria-current="page"' : ""} href="${id}.html">${label}</a>`).join("");
  return `<header class="portal-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span><span>MyAU<small>Africa University · Student Portal</small></span></a><button class="menu-button" aria-expanded="false" aria-controls="student-nav" aria-label="Open navigation">☰</button><button class="header-action" type="button" data-signout>${isStudent ? "Sign out" : "Home"}</button></header>
  ${isStudent ? `<div class="portal-layout"><aside class="sidebar" id="student-nav" aria-label="Student navigation">${links}</aside><div class="nav-scrim"></div><main class="portal-main"><div class="status-row"><span data-status>Loading your cloud profile…</span><button class="text-button" data-export>Export profile</button></div>${pageContent()}</main></div>` : `<main class="portal-main single">${pageContent()}</main>`}`;
}

function pageContent() {
  const info = pages[key];
  if (!info) return homeContent();
  const head = `<p class="eyebrow">${safe(info[1])}</p><h1>${safe(info[0])}</h1><p class="lead">${safe(info[2])}</p>`;
  const warn = pageNote ? `<p class="notice warn" role="alert">${safe(pageNote)}</p>` : "";
  let body = "";
  if (key === "overview") body = overviewContent();
  else if (key === "results") body = officialResultsContent();
  else if (key === "professional") body = professionalContent();
  else if (key === "security") body = securityContent();
  else if (key === "finance") body = financeContent();
  else if (key === "references") body = referencesContent();
  else if (key === "academics") {
    body = `<div class="tabs" role="tablist" aria-label="Academic sections">${ACADEMIC_TABS.map(([id, label], i) => `<button type="button" role="tab" id="tab-${id}" aria-controls="panel-${id}" aria-selected="${i === 0}" data-tab="${id}">${label}</button>`).join("")}</div>`
      + ACADEMIC_TABS.map(([id, label], i) => `<section role="tabpanel" id="panel-${id}" aria-labelledby="tab-${id}" ${i ? "hidden" : ""}>${collectionSection(id, "Add " + label.toLowerCase().replace("academic history", "an academic record"))}</section>`).join("");
  } else if (PAGE_COLLECTIONS[key]) {
    body = PAGE_COLLECTIONS[key].map(n => collectionSection(n, { projects: "Add a project", skills: "Add a skill", clubs: "Add a club, association or activity" }[n])).join("");
  } else if (["admin", "staff", "reference", "admin-profile", "staff-login", "admin-login"].includes(key)) {
    body = `<div class="notice"><strong>Protected area</strong><p>${safe(info[2])}</p><p>The Records Office and Administrator console needs <code>js/staff.js</code> on this page. Do not perform these actions from browser code.</p></div>`;
  }
  if (["projects", "academics", "clubs"].includes(key)) body += achievementHistoryContent();
  return `${head}${warn}${body}`;
}

function homeContent() {
  return `<a class="skip-link" href="#main-content">Skip to content</a>
    <header class="public-header">
      <a class="brand dark" href="index.html"><span class="brand-mark">AU</span><span>MyAU<small>Africa University portal</small></span></a>
      <nav class="home-nav" aria-label="Main navigation">
        <a href="#solution">How it works</a><a href="#value">Who it serves</a><a href="#engagement">What's next</a>
      </nav>
      <a class="button home-signin" href="pages/auth.html">Sign in</a>
    </header>
    <main id="main-content">
      <section class="hero">
        <img src="assets/images/au_3.jpg" alt="Africa University campus">
        <div class="hero-shade"></div>
        <div class="hero-copy">
          <p class="eyebrow light">Africa University · Mutare, Zimbabwe</p>
          <h1>Your journey.<br>Your verified story.</h1>
          <p>MyAU brings student achievements, official records and trusted recommendations into one secure university profile.</p>
          <div class="hero-actions">
            <a class="button" href="pages/auth.html">Enter student portal <span aria-hidden="true">↗</span></a>
            <a class="button button-outline" href="#solution">Discover MyAU</a>
          </div>
          <p class="hero-note">A connected profile for students and the people who support their next step.</p>
        </div>
      </section>

      <section class="home-section" id="solution">
        <div class="home-heading">
          <p class="eyebrow">The solution</p>
          <h2>One trusted profile, from record to reference.</h2>
          <p>MyAU connects the everyday work of building a profile with the university checks that make it useful.</p>
        </div>
        <div class="home-steps">
          <article class="home-step"><span class="step-index">01</span><h3>Build your story</h3><p>Students keep projects, skills, achievements, activities and professional details together.</p></article>
          <article class="home-step"><span class="step-index">02</span><h3>Verify with the university</h3><p>Records maintains official results; authorized staff review submitted profile evidence.</p></article>
          <article class="home-step"><span class="step-index">03</span><h3>Share with purpose</h3><p>Students can share selected verified items with a referee and manage access to that recommendation request.</p></article>
        </div>
      </section>

      <section class="home-section home-section-soft" id="features">
        <div class="home-heading">
          <p class="eyebrow">Key features</p>
          <h2>More than a digital CV.</h2>
          <p>A student profile linked to real university workflows.</p>
        </div>
        <div class="home-grid home-grid-four">
          <article class="home-card"><span class="home-card-icon" aria-hidden="true">01</span><h3>Verified achievements</h3><p>Projects, achievements and campus activities can be submitted for authorized university review, with a record of reviewed changes.</p></article>
          <article class="home-card"><span class="home-card-icon" aria-hidden="true">02</span><h3>Official results</h3><p>Students can view official course results supplied by Records, separately from editable profile information.</p></article>
          <article class="home-card"><span class="home-card-icon" aria-hidden="true">03</span><h3>Trusted recommendations</h3><p>Students choose which verified items to share with a referee; access is time-limited and can be revoked.</p></article>
          <article class="home-card"><span class="home-card-icon" aria-hidden="true">04</span><h3>Career-ready profile</h3><p>Keep a CV, professional links, university activities and a digital student ID in one place.</p></article>
        </div>
      </section>

      <section class="home-section home-security" id="security">
        <div class="security-copy">
          <p class="eyebrow light">Privacy by design</p>
          <h2>Student data stays in the right hands.</h2>
          <p>Access is tied to authenticated accounts and enforced at the database, not just hidden in the interface.</p>
          <a class="security-link" href="pages/auth.html">Sign in to your account <span aria-hidden="true">↗</span></a>
        </div>
        <ul class="security-points">
          <li><strong>Role-based access</strong><span>Students, verifiers, Records and administrators have distinct permissions.</span></li>
          <li><strong>Protected records</strong><span>Row-level policies scope student data and official results to authorized users.</span></li>
          <li><strong>Controlled sharing</strong><span>Recommendation sharing is limited to selected verified items and can be revoked.</span></li>
          <li><strong>Private documents</strong><span>CVs, certificates and signed letters use private file storage.</span></li>
        </ul>
      </section>

      <section class="home-section" id="value">
        <div class="home-heading">
          <p class="eyebrow">Business value</p>
          <h2>A shared view of student progress.</h2>
          <p>MyAU gives each stakeholder a clearer way to contribute to student growth.</p>
        </div>
        <div class="home-grid home-grid-three">
          <article class="home-card"><h3>Students</h3><p>Build a portfolio over time and share trusted evidence for academic and career opportunities.</p></article>
          <article class="home-card"><h3>Career Advising &amp; HODs</h3><p>Support students using a richer view of their skills, academic progress and involvement.</p></article>
          <article class="home-card"><h3>Supervisors &amp; lecturers</h3><p>Review selected evidence when responding to recommendation requests.</p></article>
          <article class="home-card"><h3>Records Office</h3><p>Maintain official results and coordinate verification and record-access requests.</p></article>
          <article class="home-card home-card-plan"><p class="eyebrow">Sustainability path</p><h3>Adopt, measure, sustain.</h3><p>Start with a university pilot, estimate hosting and maintenance needs, then assess an institution-funded model as adoption grows.</p></article>
        </div>
      </section>

      <section class="home-section home-section-soft" id="difference">
        <div class="home-heading">
          <p class="eyebrow">Comparative evaluation</p>
          <h2>Purpose-built for a university journey.</h2>
          <p>MyAU complements familiar tools by connecting profile-building to university-owned records and review.</p>
        </div>
        <div class="comparison-wrap">
          <table class="comparison-table">
            <thead><tr><th scope="col">Capability</th><th scope="col">CV or portfolio</th><th scope="col">Shared spreadsheet</th><th scope="col">Generic social profile</th><th scope="col">MyAU</th></tr></thead>
            <tbody>
              <tr><th scope="row">Official results</th><td>Added manually</td><td>Separate file</td><td>Not university-managed</td><td>Records-supplied results</td></tr>
              <tr><th scope="row">Achievement review</th><td>Self-reported</td><td>Manual coordination</td><td>Self-reported</td><td>University verification workflow</td></tr>
              <tr><th scope="row">Recommendation evidence</th><td>Shared as a document</td><td>Broad access risk</td><td>General profile sharing</td><td>Selected, revocable sharing</td></tr>
              <tr><th scope="row">Built for AU stakeholders</th><td>Usually individual</td><td>Hard to maintain</td><td>Broad audience</td><td>Student and university roles</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="home-section" id="engagement">
        <div class="home-heading">
          <p class="eyebrow">Sustained engagement</p>
          <h2>Useful after the profile is complete.</h2>
          <p>MyAU already supports ongoing profile updates, verification history, recommendation tracking and overdue-request flags in the lecturer workspace.</p>
        </div>
        <div class="engagement-layout">
          <article class="engagement-live">
            <span class="status-label"><span aria-hidden="true"></span> Available now</span>
            <h3>Keep work moving</h3>
            <p>Students can follow recommendation requests and reviewed profile changes. Lecturers can see request status and overdue requests in their workspace.</p>
            <a href="pages/auth.html">Open the student portal <span aria-hidden="true">↗</span></a>
          </article>
          <div class="engagement-roadmap">
            <p class="eyebrow">Possible next steps</p>
            <ul>
              <li>Upcoming deadlines and reminders</li>
              <li>Internship and opportunity postings</li>
              <li>A university resource library</li>
              <li>Staff insights for student support</li>
            </ul>
            <p class="roadmap-note">These are future enhancements, not currently available services.</p>
          </div>
        </div>
      </section>

      <section class="home-access">
        <div class="home-heading">
          <p class="eyebrow">Choose your workspace</p>
          <h2>One university community.</h2>
        </div>
        <div class="audiences">
          <article><span>01</span><h3>Student</h3><a href="pages/auth.html">Enter portal <span aria-hidden="true">↗</span></a></article>
          <article><span>02</span><h3>Records Office</h3><a href="pages/staff-login.html">Sign in <span aria-hidden="true">↗</span></a></article>
          <article><span>03</span><h3>Admin</h3><a href="pages/admin-login.html">Sign in <span aria-hidden="true">↗</span></a></article>
          <article><span>04</span><h3>Staff</h3><a href="pages/staff-login.html">Verifier workspace <span aria-hidden="true">↗</span></a></article>
        </div>
      </section>
    </main>
    <footer class="public-footer"><span>MyAU · Africa University portal</span><a href="#main-content">Back to top ↑</a><span>Mutare · Zimbabwe</span></footer>`;
}

/* ---------- authentication pages ---------- */
function renderAuth() {
  const box = $("[data-auth]");
  if (!box) return;
  const mode = document.body.dataset.page;
  const map = { auth: ["Sign in", "Use your password and authenticator app to access your student account.", "Login"], signup: ["Create your account", "Join the student portal", "Register"], "forgot-password": ["Reset your password", "We will email you a secure reset link", "Recover"], "reset-password": ["Choose a new password", "Update your account password", "Update"] };
  const [heading, sub, action] = map[mode];
  box.innerHTML = `<p class="eyebrow">Secure account access</p><h1>${heading}</h1><p class="lead">${sub}</p><form class="auth-form"><label>Email address<input name="email" type="email" autocomplete="email" required></label>${mode === "signup" ? '<label>Full name<input name="name" required></label><label>Student ID<input name="studentId" required></label>' : ""}${mode === "reset-password" ? '<label>New password<input name="password" type="password" autocomplete="new-password" minlength="8" required></label>' : mode !== "forgot-password" ? '<label>Password<input name="password" type="password" autocomplete="current-password" required></label>' : ""}<button class="button" type="submit">${action}</button><p class="form-message" aria-live="polite"></p></form>${mode === "auth" ? '<a class="alumni-login-link" href="alumni-access.html"><span>Graduated?</span> Request access with your personal email <span aria-hidden="true">→</span></a>' : ""}<nav class="auth-links">${mode === "auth" ? '<a href="signup.html">Create an account</a><a href="forgot-password.html">Forgot password?</a>' : ""}${mode === "signup" ? '<a href="auth.html">Already registered? Sign in</a>' : ""}${mode === "forgot-password" ? '<a href="auth.html">Return to sign in</a>' : ""}</nav>`;
  if (new URLSearchParams(location.search).get("expired")) $(".form-message", box).textContent = "You were signed out after 30 minutes of inactivity. Please sign in again.";
  box.querySelector("form").addEventListener("submit", authSubmit);
}

function nextStudentPage() {
  const requested = new URLSearchParams(location.search).get("next");
  return studentKeys.has(requested?.replace(/\.html$/, "")) ? requested.replace(/\.html$/, "") + ".html" : "overview.html";
}

async function authSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const msg = $(".form-message", form);
  const data = Object.fromEntries(new FormData(form));
  if (typeof data.email === "string") data.email = data.email.trim();
  msg.textContent = "";
  try {
    const client = await getSupabase();
    let result;
    if (key === "auth") {
      const { error: signOutError } = await client.auth.signOut({ scope: "local" });
      if (signOutError) throw signOutError;
      result = await client.auth.signInWithPassword({ email: data.email, password: data.password });
      if (result.error) throw result.error;
      await loadMfaLibrary();
      const verified = await window.AUMfa.require(client, $("#app"), {
        title: "Student account",
        returnTo: "auth.html",
        onVerified: () => window.location.assign(nextStudentPage()),
      });
      if (verified) window.location.assign(nextStudentPage());
      return;
    } else if (key === "signup") {
      result = await client.auth.signUp({ email: data.email, password: data.password, options: { data: { name: data.name, student_id: data.studentId }, emailRedirectTo: new URL("auth.html", location.href).href } });
    } else if (key === "forgot-password") {
      result = await client.auth.resetPasswordForEmail(data.email, { redirectTo: new URL("reset-password.html", location.href).href });
    } else {
      result = await client.auth.updateUser({ password: data.password });
    }
    if (result.error) throw result.error;
    msg.textContent = key === "signup"
      ? `Registration submitted for ${data.email}. If email confirmation is enabled, check this inbox (including spam) for the confirmation message.`
      : key === "forgot-password" ? "If the address is registered, a password reset email has been sent." : "Password updated. You can now sign in.";
  } catch (error) {
    msg.textContent = error instanceof Error ? error.message : "The request could not be completed.";
  }
}

/* ---------- saving forms ---------- */
function valueForForm(name, formData) {
  const value = formData.get(name);
  return typeof value === "string" ? value.trim() : "";
}
function hostOk(url, host) { try { const h = new URL(url).hostname.toLowerCase(); return h === host || h.endsWith("." + host); } catch { return false; } }

async function saveProfileForm(event) {
  event.preventDefault();
  if (saveInProgress) return;
  saveInProgress = true;
  const form = event.currentTarget;
  const message = $(".form-message", form);
  const button = $('button[type="submit"]', form);
  button.disabled = true;
  message.textContent = "";
  message.className = "form-message";
  try {
    const fd = new FormData(form);
    const next = { ...profileData, profile: { ...profileData.profile } };
    const oldFiles = [];
    if (key === "overview") {
      for (const f of ["name", "studentId", "programme", "faculty", "year", "email", "phone", "bio"]) next.profile[f] = valueForForm(f, fd);
      if (!next.profile.name) throw new Error("Your full name is required.");
      const photo = fd.get("photo");
      if (photo instanceof File && photo.size) {
        next.profile.photo = await uploadStudentFile(photo, { allow: IMAGES_ONLY, maxMB: 10, shrinkImage: 480 });
        oldFiles.push(profileData.profile.photo);
      }
    } else if (key === "professional") {
      next.profile.linkedin = valueForForm("linkedin", fd);
      next.profile.github = valueForForm("github", fd);
      for (const f of ["linkedin", "github"]) {
        if (next.profile[f] && !/^https:\/\//i.test(next.profile[f])) throw new Error("Profile links must start with https://.");
      }
      if (next.profile.linkedin && !hostOk(next.profile.linkedin, "linkedin.com")) throw new Error("The LinkedIn link must be on linkedin.com.");
      if (next.profile.github && !hostOk(next.profile.github, "github.com")) throw new Error("The GitHub link must be on github.com.");
      const file = fd.get("cvFile");
      if (file instanceof File && file.size) {
        if (!DOCS.includes(file.type)) throw new Error("Choose a PDF, DOC or DOCX file.");
        next.profile.cvFile = await uploadStudentFile(file, { allow: DOCS, maxMB: 10 });
        next.profile.cvFileName = file.name;
        oldFiles.push(profileData.profile.cvFile);
      }
    }
    await persistProfile(next);
    removeStoredFiles(oldFiles);
    toast(key === "overview" ? "Profile saved." : "Professional details saved.");
    drawStudentContent();
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : "The profile could not be saved.";
    message.classList.add("err");
    button.disabled = false;
  } finally {
    saveInProgress = false;
  }
}

async function withForm(form, task, success) {
  const message = $(".form-message", form);
  const button = $('button[type="submit"]', form);
  button.disabled = true;
  message.className = "form-message";
  message.textContent = "";
  try {
    const result = await task();
    toast(typeof success === "function" ? success(result) : success);
    return true;
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : "That could not be completed.";
    message.classList.add("err");
    return false;
  } finally {
    button.disabled = false;
  }
}

function exportProfile() {
  if (!profileData) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify({ version: 1, data: profileData }, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "au-profile-backup.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------- wiring ---------- */
function bindGlobals() {
  if (globalsBound) return;
  globalsBound = true;
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") { $(".sidebar")?.classList.remove("open"); $(".nav-scrim")?.classList.remove("open"); $(".menu-button")?.setAttribute("aria-expanded", "false"); }
  });
  let timer;
  const reset = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try { await (await getSupabase()).auth.signOut(); } catch { /* ignore */ }
      window.location.replace("auth.html?expired=1");
    }, IDLE_MS);
  };
  ["click", "keydown", "touchstart", "scroll"].forEach(ev => addEventListener(ev, reset, { passive: true }));
  reset();
}

function lightbox(src) {
  let d = $("dialog.lightbox");
  if (!d) {
    d = document.createElement("dialog");
    d.className = "lightbox";
    d.innerHTML = '<button type="button" aria-label="Close">×</button><img alt="">';
    d.addEventListener("click", e => { if (e.target === d || e.target.tagName === "BUTTON") d.close(); });
    document.body.appendChild(d);
  }
  $("img", d).src = src;
  d.showModal();
}

function drawStudentContent() {
  const app = $("#app");
  app.innerHTML = drawShell();
  document.title = `${pages[key]?.[0] || "Portal"} | MyAU`;
  setStatus("Your profile is synced with Supabase.");
  bindGlobals();

  /* navigation drawer */
  const menu = $(".menu-button"), side = $(".sidebar"), scrim = $(".nav-scrim");
  const setNav = open => { side.classList.toggle("open", open); scrim.classList.toggle("open", open); menu.setAttribute("aria-expanded", String(open)); };
  if (menu) {
    menu.addEventListener("click", () => setNav(!side.classList.contains("open")));
    scrim.addEventListener("click", () => setNav(false));
    side.addEventListener("click", e => { if (e.target.closest("a")) setNav(false); });
  }

  /* profile forms */
  $$("[data-profile-form]").forEach(form => form.addEventListener("submit", saveProfileForm));
  $$("[data-print-id]").forEach(b => b.addEventListener("click", () => window.print()));
  hydrateFiles(app);
  hydrateQrCode(app);

  /* collection forms and lists */
  $$("[data-add]").forEach(form => form.addEventListener("submit", async event => {
    event.preventDefault();
    const name = form.dataset.add;
    if (await withForm(form, () => addRecord(name, form), name === "projects" ? "Project added." : "Added.")) {
      form.reset();
      await renderItems(name);
      if (name === "projects") {
        try {
          const submitted = await requestVerification("projects", profileData.projects[0].id);
          await renderItems(name);
          toast(submitted ? "Project sent to the Records Office for verification." : "Project saved; its verification is already in the Records queue.");
        } catch (error) {
          toast(`Project saved, but its verification request could not be sent: ${error instanceof Error ? error.message : "Please try again."}`, true);
        }
      }
    }
  }));
  $$("[data-items]").forEach(box => {
    renderItems(box.dataset.items);
    box.addEventListener("click", async event => {
      const rm = event.target.closest("[data-remove]");
      const vf = event.target.closest("[data-verify]");
      const changeToggle = event.target.closest("[data-change-toggle]");
      const changeCancel = event.target.closest("[data-change-cancel]");
      const img = event.target.closest("img.thumb");
      if (rm) { const [n, id] = rm.dataset.remove.split(":"); removeRecord(n, id); }
      else if (changeToggle) {
        const form = $(`[data-change-form="${changeToggle.dataset.changeToggle}"]`, box);
        if (form) form.hidden = !form.hidden;
      } else if (changeCancel) {
        const form = changeCancel.closest("[data-change-form]");
        if (form) form.hidden = true;
      }
      else if (vf) {
        const [n, id] = vf.dataset.verify.split(":");
        vf.disabled = true;
        try {
          const submitted = await requestVerification(n, id);
          await renderItems(n);
          toast(submitted ? "Sent to the Records Office for verification." : "This item is already in the Records queue.");
        }
        catch (error) { toast(error instanceof Error ? error.message : "Could not send the request.", true); vf.disabled = false; }
      } else if (img && img.src) lightbox(img.src);
    });
    box.addEventListener("change", event => {
      const select = event.target.closest('select[name="action"]');
      if (!select) return;
      const fields = select.closest("form").querySelector("fieldset");
      if (fields) fields.disabled = select.value === "delete";
    });
    box.addEventListener("submit", async event => {
      const form = event.target.closest("[data-change-form]");
      if (!form) return;
      event.preventDefault();
      const ok = await withForm(form, () => submitAchievementChange(form), "Change request sent to the Records Office.");
      if (ok) drawStudentContent();
    });
  });

  /* tabs (academics) */
  const tabs = $$("[data-tab]");
  if (tabs.length) {
    const show = id => tabs.forEach(t => {
      const on = t.dataset.tab === id;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      $(`#panel-${t.dataset.tab}`).hidden = !on;
    });
    tabs.forEach(t => {
      t.addEventListener("click", () => { show(t.dataset.tab); history.replaceState(null, "", `#${t.dataset.tab}`); });
      t.addEventListener("keydown", e => {
        const i = tabs.indexOf(t), n = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : null;
        if (n === null) return;
        const target = tabs[(n + tabs.length) % tabs.length];
        target.click(); target.focus();
      });
    });
    const start = location.hash.slice(1);
    show(tabs.some(t => t.dataset.tab === start) ? start : tabs[0].dataset.tab);
  }

  /* textarea counters */
  $$("textarea[data-count]").forEach(t => {
    const max = t.maxLength;
    if (!(max > 0)) return;
    const c = document.createElement("small");
    c.className = "counter";
    const upd = () => { c.textContent = `${t.value.length}/${max}`; };
    t.insertAdjacentElement("afterend", c);
    t.addEventListener("input", upd);
    upd();
  });

  /* recommendations and finance */
  $$("[data-rec-form]").forEach(form => form.addEventListener("submit", async event => {
    event.preventDefault();
    if (await withForm(form, () => submitRecommendation(form), shared =>
      shared ? "Request sent. Use the secure-link button below to invite the lecturer." : "Request sent, but verified-item sharing failed. Contact the Records Office before relying on lecturer access."
    )) drawStudentContent();
  }));
  $$("[data-send-lecturer-link]").forEach(button => button.addEventListener("click", async () => {
    button.disabled = true;
    const originalText = button.textContent;
    button.textContent = "Sending secure link…";
    try {
      const client = await getSupabase();
      const redirectTo = new URL("lecturer.html", location.href).href;
      const { error } = await client.auth.signInWithOtp({
        email: button.dataset.sendLecturerLink,
        options: { emailRedirectTo: redirectTo, shouldCreateUser: true }
      });
      if (error) throw error;
      toast("Secure sign-in link sent to the referee’s email. After one click, it opens the lecturer workspace.");
    } catch (error) {
      toast(error instanceof Error ? error.message : "Could not send the lecturer sign-in link.", true);
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  }));
  $$("[data-download-letter]").forEach(button => button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const url = await signedUrl(button.dataset.downloadLetter, { download: "recommendation-letter.pdf" });
      if (!url) throw new Error("The referee’s letter could not be opened. Please try again or contact the Records Office.");
      window.location.assign(url);
    } catch (error) {
      toast(error instanceof Error ? error.message : "The letter could not be downloaded.", true);
      button.disabled = false;
    }
  }));
  $$("[data-revoke-share]").forEach(button => button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      const client = await getSupabase();
      const { error } = await client.rpc("au_revoke_recommendation_share", { p_share_id: button.dataset.revokeShare });
      if (error) throw error;
      toast("Lecturer access revoked.");
      drawStudentContent();
    } catch (error) {
      toast(error instanceof Error ? error.message : "Could not revoke lecturer access.", true);
      button.disabled = false;
    }
  }));
  $$("[data-plan-form]").forEach(form => form.addEventListener("submit", async event => {
    event.preventDefault();
    if (await withForm(form, () => submitPlan(form), "Payment plan request sent to the Records Office.")) drawStudentContent();
  }));

  /* professional profile */
  const dl = $("[data-cv-download]");
  if (dl) dl.addEventListener("click", async event => {
    event.preventDefault();
    const url = await signedUrl(profileData.profile.cvFile, { download: profileData.profile.cvFileName || "cv" });
    if (url) window.location.assign(url); else toast("Your CV could not be opened. Try again.", true);
  });
  const rmCv = $("[data-cv-remove]");
  if (rmCv) rmCv.addEventListener("click", async () => {
    if (!confirm("Remove your uploaded CV?")) return;
    try {
      const old = profileData.profile.cvFile;
      await persistProfile({ ...profileData, profile: { ...profileData.profile, cvFile: "", cvFileName: "" } });
      removeStoredFiles([old]);
      toast("CV removed.");
      drawStudentContent();
    } catch (error) { toast(error instanceof Error ? error.message : "Could not remove the CV.", true); }
  });
  const gen = $("[data-cv-generate]");
  if (gen) gen.addEventListener("click", generateCv);

  /* security */
  $$("[data-password-form]").forEach(form => {
    const pw = $('input[name="password"]', form), bar = $("[data-meter]", form), txt = $("[data-meter-text]", form);
    pw.addEventListener("input", () => {
      const s = passwordStrength(pw.value);
      bar.style.width = `${s * 25}%`;
      bar.style.background = ["#a12622", "#a12622", "#b9770e", "#6f9a2a", "#1f7a4d"][s];
      txt.textContent = pw.value ? ["Very weak", "Weak", "Fair", "Good", "Strong"][s] : "Use at least 8 characters. A longer phrase is stronger.";
    });
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const fd = new FormData(form);
      const ok = await withForm(form, async () => {
        if (fd.get("password") !== fd.get("confirmPassword")) throw new Error("The passwords do not match.");
        if (fd.get("password") === fd.get("current")) throw new Error("Choose a password you have not used on this account.");
        const client = await getSupabase();
        const check = await client.auth.signInWithPassword({ email: student.email, password: String(fd.get("current")) });
        if (check.error) throw new Error("Your current password is not correct.");
        const { error } = await client.auth.updateUser({ password: String(fd.get("password")) });
        if (error) throw error;
      }, "Password updated.");
      if (ok) { form.reset(); bar.style.width = "0"; txt.textContent = "Use at least 8 characters. A longer phrase is stronger."; }
    });
  });
  const others = $("[data-signout-others]");
  if (others) others.addEventListener("click", async () => {
    others.disabled = true;
    try {
      const { error } = await (await getSupabase()).auth.signOut({ scope: "others" });
      if (error) throw error;
      toast("Other devices have been signed out.");
    } catch (error) { toast(error instanceof Error ? error.message : "Could not sign out other devices.", true); }
    others.disabled = false;
  });

  /* sign out and export */
  const signout = $("[data-signout]");
  if (signout) signout.addEventListener("click", async () => {
    signout.disabled = true;
    try {
      const client = await getSupabase();
      const { error } = await client.auth.signOut();
      if (error) throw error;
      window.location.replace("../index.html");
    } catch (error) {
      signout.disabled = false;
      setStatus(error instanceof Error ? `Sign out failed: ${error.message}` : "Sign out failed.");
    }
  });
  $$("[data-export]").forEach(b => b.addEventListener("click", exportProfile));
}

async function start() {
  const root = $("#app");
  if (key === "home") {
    document.title = "MyAU | Africa University Portal";
    root.innerHTML = homeContent();
    return;
  }
  if (["auth", "signup", "forgot-password", "reset-password"].includes(key)) {
    document.title = `${pages[key]?.[0] || "Secure account"} | MyAU`;
    root.innerHTML = `<header class="auth-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span>MyAU</a></header><main class="auth-wrap"><section class="auth-card" data-auth></section></main><footer class="auth-footer">MyAU · Africa University secure account access</footer>`;
    renderAuth();
    return;
  }
  if (studentKeys.has(key)) {
    root.innerHTML = '<main class="portal-main single"><p role="status">Checking your account and loading your cloud profile…</p></main>';
    try {
      const client = await getSupabase();
      await loadMfaLibrary();
      const verified = await window.AUMfa.require(client, root, {
        title: "Student account",
        returnTo: "auth.html",
      });
      if (!verified) return;
      const loaded = await loadStudentProfile();
      if (!loaded) return;
      await loadPageData();
      drawStudentContent();
    } catch (error) {
      root.innerHTML = `<main class="portal-main single"><h1>Student profile unavailable</h1><p class="notice" role="alert">${safe(error instanceof Error ? error.message : "Could not load your profile.")}</p><button class="button" type="button" data-retry>Retry</button> <a class="button" href="auth.html">Sign in</a></main>`;
      $("[data-retry]", root).addEventListener("click", start);
    }
    return;
  }
  if (["admin", "staff", "staff-login", "admin-login"].includes(key) && window.AUStaff) {
    try {
      await loadMfaLibrary();
      await window.AUStaff.start(key);
    }
    catch (error) { root.innerHTML = `<main class="portal-main single"><h1>Unavailable</h1><p class="notice" role="alert">${safe(error instanceof Error ? error.message : "This page could not be loaded.")}</p></main>`; }
    return;
  }
  root.innerHTML = drawShell();
}

window.AU = { getSupabase, loadMfaLibrary, safe, $, $$, money, fmtDate, signedUrl, computeBalance, tableMissing, toast, config };
document.addEventListener("DOMContentLoaded", start);
