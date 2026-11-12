/* Records Office and Administrator sign-in and console.
   Access is decided by the server-side role in the user's token (app_metadata.role = "records" | "admin"),
   which a user cannot change from the browser. Every query below is additionally enforced by Row Level Security
   (see backend/migrations/0008_records_verification_finance.sql), so hiding a tab here is convenience, not security. */
(function () {
  "use strict";
  const AU = window.AU;
  const { safe, $, $$, money, fmtDate, tableMissing, toast } = AU;
  const ROLE_LABEL = { records: "Records Office", admin: "Administrator", lecturer: "Lecturer verifier", department_staff: "Department verifier", supervisor: "Supervisor verifier" };
  const REC_STATUS = { submitted: "Submitted", in_review: "In review", forwarded: "Sent to referee", completed: "Completed", declined: "Declined" };
  const PLAN_STATUS = { submitted: "Submitted", in_review: "In review", approved: "Approved", declined: "Declined" };
  const FIELD_LABELS = { title: "Title", name: "Name", description: "Description", tech: "Technologies", github: "Link", date: "Date", category: "Category", issuer: "Awarded by", type: "Type", role: "Role", course: "Course", grade: "Result", semester: "Semester" };
  const TYPE_LABEL = { project: "Project", achievement: "Achievement", club: "Club / activity", result: "Course result" };
  let client, user, role, consoleKey, verifierAssignment;

  const roleOf = u => String(u?.app_metadata?.role || "");
  const badge = (text, cls = "") => `<span class="badge ${cls}">${safe(text)}</span>`;
  const select = (name, map, value) => `<select name="${name}">${Object.entries(map).map(([k, v]) => `<option value="${k}"${k === value ? " selected" : ""}>${safe(v)}</option>`).join("")}</select>`;
  const errorBox = e => tableMissing(e) || e?.code === "PGRST202"
    ? /official_results|student_registry|verifier_assignments|alumni_access|au_import_official_results|au_save_verifier_assignment/i.test(e?.message || "")
      ? `<div class="notice warn"><strong>Official results and access setup needed</strong><p>Apply <code>backend/migrations/0012_official_results_scoped_verifiers_alumni.sql</code> after migrations 0008 and 0011, then reload.</p></div>`
      : /achievement_change_requests|achievement_history|au_review_achievement_change/i.test(e?.message || "")
      ? `<div class="notice warn"><strong>Achievement review setup needed</strong><p>Apply <code>backend/migrations/0011_lecturer_sharing_and_achievement_history.sql</code> after migrations 0008 and 0010, then reload.</p></div>`
      : `<div class="notice warn"><strong>Records database setup needed</strong><p>Your Records role is recognized, but the console tables are missing or not yet visible. This is separate from granting the role.</p><ol><li>In Supabase SQL Editor, run the entire <code>backend/migrations/0008_records_verification_finance.sql</code> file.</li><li>Reload this page after it completes.</li></ol><p>If you already ran the migration successfully, refresh the Supabase API schema cache in SQL Editor with <code>NOTIFY pgrst, 'reload schema';</code>, wait briefly, and reload this page.</p></div>`
    : `<div class="notice bad" role="alert"><strong>Something went wrong</strong><p>${safe(e?.message || "Please try again.")}</p></div>`;

  async function functionErrorMessage(error) {
    const response = error?.context;
    if (response && typeof response.clone === "function") {
      try {
        const body = await response.clone().json();
        if (typeof body?.error === "string" && body.error) return body.error;
      } catch {
        // The function may return a non-JSON error response.
      }
    }
    return error?.message || "The server request failed.";
  }

  async function updateRow(table, id, patch) {
    const { data, error } = await client.from(table).update(patch).eq("id", id).select("id").maybeSingle();
    if (error) throw error;
    if (!data) throw new Error("The change was not applied. Your access may have changed; reload and try again.");
  }

  async function uploadRecommendationLetter(request, file) {
    if (file.type !== "application/pdf") throw new Error("The referee’s letter must be a PDF.");
    if (file.size > 10 * 1024 * 1024) throw new Error("The referee’s letter must be 10 MB or smaller.");
    const signature = new TextDecoder().decode(await file.slice(0, 5).arrayBuffer());
    if (signature !== "%PDF-") throw new Error("This file does not appear to be a valid PDF.");
    const path = `${request.student_id}/recommendation-letters/${request.id}.pdf`;
    const { error } = await client.storage.from("student-content").upload(path, file, {
      contentType: "application/pdf", upsert: true
    });
    if (error) throw new Error(`Letter upload failed: ${error.message}`);
    return `storage://${path}`;
  }

  function parseResultsCsv(text) {
    const records = [];
    let record = [], field = "", quoted = false;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (char === '"') {
        if (quoted && text[i + 1] === '"') { field += '"'; i++; }
        else quoted = !quoted;
      } else if (char === "," && !quoted) {
        record.push(field); field = "";
      } else if ((char === "\n" || char === "\r") && !quoted) {
        if (char === "\r" && text[i + 1] === "\n") i++;
        record.push(field); records.push(record); record = []; field = "";
      } else {
        field += char;
      }
    }
    if (quoted) throw new Error("The CSV has an unclosed quoted field.");
    if (field || record.length) { record.push(field); records.push(record); }
    const nonempty = records.filter(row => row.some(value => value.trim()));
    if (!nonempty.length) throw new Error("The CSV file is empty.");
    const headers = nonempty.shift().map((value, index) => value.replace(/^\uFEFF/, "").trim().toLowerCase());
    const required = ["student_id", "course_code", "course", "grade", "semester"];
    if (required.some(name => !headers.includes(name))) {
      throw new Error(`CSV headers must include: ${required.join(", ")}.`);
    }
    if (new Set(headers).size !== headers.length) throw new Error("The CSV contains duplicate column names.");
    const rows = nonempty.map((values, index) => {
      if (values.length !== headers.length) throw new Error(`CSV row ${index + 2} has a different number of values than the header.`);
      const row = Object.fromEntries(headers.map((name, position) => [name, values[position].trim()]));
      for (const name of required) if (!row[name]) throw new Error(`CSV row ${index + 2} is missing ${name}.`);
      return Object.fromEntries(required.map(name => [name, row[name]]));
    });
    if (rows.length > 1000) throw new Error("Import no more than 1,000 results at a time.");
    if (!rows.length) throw new Error("The CSV contains a header but no result rows.");
    return rows;
  }

  async function importOfficialResults(rows) {
    const { data, error } = await client.rpc("au_import_official_results", { p_rows: rows });
    if (error) {
      if (error.code === "PGRST202" || /au_import_official_results|schema cache/i.test(error.message || "")) {
        throw new Error("Official results import is not installed yet. Ask an administrator to apply migration 0012_official_results_scoped_verifiers_alumni.sql.");
      }
      throw error;
    }
    return Number(data) || rows.length;
  }

  /* ------------------------------------------------------------ entry */
  async function start(key) {
    const root = $("#app");
    const pageTitle = key === "staff-login" ? "Staff sign in"
      : key === "admin-login" ? "Administrator sign in"
        : key === "admin" ? "Administrator console" : "Records Office console";
    document.title = `${pageTitle} | MyAU`;
    client = await AU.getSupabase();
    if (key === "staff-login" || key === "admin-login") return renderLogin(root, key);
    consoleKey = key;
    const loginPage = key === "admin" ? "admin-login.html" : "staff-login.html";
    const mfaReady = await window.AUMfa.require(client, root, {
      title: key === "admin" ? "Administrator account" : "Staff account",
      returnTo: loginPage,
      onVerified: () => start(key),
    });
    if (!mfaReady) return;
    const { data, error } = await client.auth.getUser();
    user = data?.user;
    if (error || !user) { location.replace(loginPage); return; }
    role = roleOf(user);
    verifierAssignment = null;
    if (key === "admin" && role !== "admin") {
      await client.auth.signOut();
      location.replace(`${loginPage}?denied=1`);
      return;
    }
    if (key !== "admin" && !["records", "admin"].includes(role)) {
      const { data: assignment, error: assignmentError } = await client.from("verifier_assignments")
        .select("id,user_id,verifier_role,allowed_student_ids,allowed_item_types")
        .eq("user_id", user.id).maybeSingle();
      if (assignmentError) {
        if (tableMissing(assignmentError)) throw new Error("Scoped verifier access is not installed yet. Ask an administrator to apply migration 0012_official_results_scoped_verifiers_alumni.sql.");
        throw assignmentError;
      }
      if (!assignment) {
        await client.auth.signOut();
        location.replace(`${loginPage}?denied=1`);
        return;
      }
      verifierAssignment = assignment;
      role = assignment.verifier_role;
    }
    renderConsole(root);
  }

  /* ------------------------------------------------------------ login pages */
  function renderLogin(root, key) {
    const admin = key === "admin-login";
    const params = new URLSearchParams(location.search);
    const notice = params.get("denied") ? "That account is not authorised for this area." : params.get("expired") ? "You were signed out after a period of inactivity." : "";
    root.innerHTML = `<header class="auth-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span>MyAU</a></header>
    <main class="auth-wrap"><section class="auth-card">
      <p class="eyebrow">${admin ? "Administration" : "Staff and Records"} · Secure account access</p>
      <h1>${admin ? "Administrator sign in" : "Staff sign in"}</h1>
      <p class="lead">${admin ? "For authorised university administrators only. Use your password and authenticator app." : "For Records Office staff and verifiers with an administrator assignment. Use your password and authenticator app."}</p>
      <form class="auth-form"><label>Work email address<input name="email" type="email" autocomplete="username" required></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
        <button class="button" type="submit">Sign in</button><p class="form-message" aria-live="polite" role="status">${safe(notice)}</p></form>
      <nav class="auth-links"><a href="forgot-password.html">Forgot password?</a><a href="auth.html">Student sign in</a>${admin ? '<a href="staff-login.html">Staff sign in</a>' : '<a href="admin-login.html">Administrator sign in</a>'}</nav>
    </section></main><footer class="auth-footer">MyAU · Africa University secure account access</footer>`;
    $("form", root).addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget, msg = $(".form-message", form), btn = $("button", form);
      const fd = new FormData(form);
      btn.disabled = true; msg.textContent = "";
      try {
        const { error: signOutError } = await client.auth.signOut({ scope: "local" });
        if (signOutError) throw signOutError;
        const { data, error } = await client.auth.signInWithPassword({
          email: String(fd.get("email")).trim(),
          password: String(fd.get("password")),
        });
        if (error) throw error;
        const verified = await window.AUMfa.require(client, root, {
          title: admin ? "Administrator account" : "Staff account",
          returnTo: key === "admin-login" ? "admin-login.html" : "staff-login.html",
          onVerified: () => finishStaffSignIn(data.user, admin),
        });
        if (verified) await finishStaffSignIn(data.user, admin);
      } catch (error) {
        msg.textContent = error instanceof Error ? error.message : "Sign in failed.";
        btn.disabled = false;
      }
    });
  }

  async function finishStaffSignIn(signedInUser, admin) {
    const { data: refreshed, error: refreshError } = await client.auth.refreshSession();
    if (refreshError) throw new Error(`Authenticator verified, but the staff session could not be refreshed: ${refreshError.message}`);
    const user = refreshed.user || signedInUser;
    if (!user) throw new Error("Your verified account could not be loaded. Sign in again.");
    const r = roleOf(user);
    let assignedVerifier = false;
    if (!admin && !["records", "admin"].includes(r)) {
      const { data: assignment, error: assignmentError } = await client.from("verifier_assignments")
        .select("id").eq("user_id", user.id).maybeSingle();
      if (assignmentError) throw assignmentError;
      assignedVerifier = Boolean(assignment);
    }
    const ok = admin ? r === "admin" : ["records", "admin"].includes(r) || assignedVerifier;
    if (!ok) {
      await client.auth.signOut();
      throw new Error(admin
        ? "This account is not assigned the Administrator role. Ask an administrator to check its access."
        : "This account has no Records/Admin role or active verifier assignment. Ask an administrator to check its access.");
    }
    location.assign(r === "admin" ? "admin.html" : "staff.html");
  }

  /* ------------------------------------------------------------ console shell */
  function renderConsole(root) {
    const isAdmin = role === "admin";
    const isRecordsStaff = ["records", "admin"].includes(role);
    const tabs = isRecordsStaff
      ? [...(isAdmin && consoleKey === "admin" ? [["overview", "Overview"]] : []),
        ["verify", "Verifications"], ["changes", "Achievement changes"], ["recs", "Recommendations"],
        ["plans", "Payment plans"], ["finance", "Student finance"], ["official-results", "Official results"],
        ["alumni", "Alumni access"], ...(isAdmin ? [["verifiers", "Verifier access"]] : [])]
      : [["verify", "Assigned verifications"]];
    const consoleTitle = isAdmin ? "Administrator console" : isRecordsStaff ? "Records Office console" : "Verifier workspace";
    const consoleSection = isAdmin ? "Administration" : isRecordsStaff ? "Records Office" : "Verification";
    root.innerHTML = `<header class="portal-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span><span>MyAU<small>${ROLE_LABEL[role]} · Console</small></span></a><button class="header-action" type="button" data-signout>Sign out</button></header>
    <main class="console"><div class="console-head"><div><p class="eyebrow">${consoleSection}</p><h1>${consoleTitle}</h1></div><p class="muted">Signed in as ${safe(user.email)}</p></div>
    <div class="tabs" role="tablist">${tabs.map(([id, label]) => `<button type="button" role="tab" data-ctab="${id}" aria-selected="false">${label}</button>`).join("")}</div>
    <section id="console-body" tabindex="-1" aria-live="polite"></section></main>`;
    const body = $("#console-body");
    const TABS = {
      overview: tabOverview, verify: tabVerify, changes: tabChanges, recs: tabRecs, plans: tabPlans,
      finance: tabFinance, "official-results": tabOfficialResults, alumni: tabAlumni,
      verifiers: tabVerifiers
    };
    const open = async id => {
      $$("[data-ctab]").forEach(b => b.setAttribute("aria-selected", String(b.dataset.ctab === id)));
      history.replaceState(null, "", `#${id}`);
      body.innerHTML = '<p class="muted" role="status">Loading…</p>';
      try { await TABS[id](body); } catch (e) { body.innerHTML = errorBox(e); }
    };
    $$("[data-ctab]").forEach(b => b.addEventListener("click", () => open(b.dataset.ctab)));
    $("[data-signout]").addEventListener("click", async () => {
      await client.auth.signOut();
      location.replace(consoleKey === "admin" ? "admin-login.html" : "staff-login.html");
    });
    client.auth.onAuthStateChange(event => { if (event === "SIGNED_OUT") location.replace(consoleKey === "admin" ? "admin-login.html" : "staff-login.html"); });
    const wanted = location.hash.slice(1);
    open(tabs.some(t => t[0] === wanted) ? wanted : tabs[0][0]);

    let idle;
    const reset = () => { clearTimeout(idle); idle = setTimeout(async () => { await client.auth.signOut(); location.replace((consoleKey === "admin" ? "admin-login.html" : "staff-login.html") + "?expired=1"); }, 20 * 60 * 1000); };
    ["click", "keydown", "touchstart", "scroll"].forEach(e => addEventListener(e, reset, { passive: true }));
    reset();
  }

  /* ------------------------------------------------------------ overview (admin) */
  async function count(table, filter) {
    let q = client.from(table).select("id", { count: "exact", head: true });
    if (filter) q = filter(q);
    const { count: c, error } = await q;
    if (error) throw error;
    return c || 0;
  }
  async function tabOverview(body) {
    const [students, pv, rec, plan, pend] = await Promise.all([
      count("profiles"), count("verifications", q => q.eq("status", "pending")),
      count("recommendation_requests", q => q.in("status", ["submitted", "in_review", "forwarded"])),
      count("payment_plan_requests", q => q.in("status", ["submitted", "in_review"])),
      count("finance_ledger", q => q.eq("status", "pending"))]);
    const stat = (l, v) => `<div class="stat"><span>${l}</span><strong>${v}</strong></div>`;
    body.innerHTML = `<div class="stat-grid">${stat("Student profiles", students)}${stat("Verifications waiting", pv)}${stat("Open recommendations", rec)}${stat("Open payment plans", plan)}${stat("Pending ledger entries", pend)}</div>
    `;
  }

  async function tabOfficialResults(body) {
    const [resultsResult, registryResult] = await Promise.all([
      client.from("official_results").select("id,student_number,course_code,course,grade,semester,updated_at")
        .order("updated_at", { ascending: false }).limit(200),
      client.from("student_registry").select("student_id,student_number,verification_note,updated_at")
        .order("student_number").limit(500),
    ]);
    if (resultsResult.error) throw resultsResult.error;
    if (registryResult.error) throw registryResult.error;
    const rows = resultsResult.data || [];
    const registry = registryResult.data || [];
    body.innerHTML = `<p class="muted">Only Records Office staff can supply or change grades. Student accounts have read-only access. Re-importing a matching student, course code, and semester updates that result; edits are recorded in history.</p>
      <section class="details-card"><h2>Verified student number links</h2>
        <p>Student profile numbers can be edited by students and are not used for official data. First match an Auth user UUID to the student's official number after checking university records. This verified registry is used by result imports, verifier assignments, and alumni requests.</p>
        <form class="inline-form" data-student-registry><label>Student Auth user UUID<input name="user_id" required maxlength="36" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>
          <label>Official student number<input name="student_number" required maxlength="40"></label>
          <label class="full">Official record checked (at least 5 characters)<input name="verification_note" required maxlength="1000" placeholder="e.g. Registrar's student master record"></label>
          <button class="button" type="submit">Save verified link</button></form>
        <div class="table-wrap"><table class="data stack"><thead><tr><th>Official student number</th><th>Auth user UUID</th><th>Verification record</th></tr></thead><tbody>
          ${registry.map(row => `<tr><td data-label="Official student number">${safe(row.student_number)}</td><td data-label="Auth user UUID">${safe(row.student_id)}</td><td data-label="Verification record">${safe(row.verification_note)}</td></tr>`).join("") || '<tr><td colspan="3">No student identities have been linked.</td></tr>'}
        </tbody></table></div>
      </section>
      <section class="details-card"><h2>Import results from CSV</h2>
        <p>Use UTF-8 CSV with these required headers: <code>student_id,course_code,course,grade,semester</code>. Each student ID must match exactly one MyAU profile. Maximum 1,000 rows and 5 MB per file.</p>
        <form class="inline-form" data-results-csv><label>CSV file<input name="file" type="file" accept=".csv,text/csv" required></label><button class="button" type="submit">Import CSV</button></form>
      </section>
      <section class="details-card"><h2>Add one official result</h2>
        <form class="inline-form" data-result-manual><label>Student number<input name="student_id" required maxlength="40"></label>
          <label>Course code<input name="course_code" required maxlength="40"></label><label>Course title<input name="course" required maxlength="160"></label>
          <label>Grade / result<input name="grade" required maxlength="40"></label><label>Semester<input name="semester" required maxlength="60" placeholder="2026 Semester 1"></label>
          <button class="button" type="submit">Save official result</button></form>
      </section>
      <h2 class="section-title">Recent official results</h2>
      <div class="queue">${rows.length ? rows.map(result => `<article class="queue-card" data-result-id="${safe(result.id)}">
        <p class="sub">${safe(result.student_number)} · ${safe(result.course_code)} · ${safe(result.semester)} · updated ${safe(fmtDate(result.updated_at))}</p>
        <form class="inline-form" data-result-edit><label>Course title<input name="course" required maxlength="160" value="${safe(result.course)}"></label>
          <label>Grade / result<input name="grade" required maxlength="40" value="${safe(result.grade)}"></label>
          <label>Semester<input name="semester" required maxlength="60" value="${safe(result.semester)}"></label>
          <button class="button small" type="submit">Save correction</button></form></article>`).join("") : '<div class="empty">No official results have been added.</div>'}</div>`;

    $("[data-student-registry]", body).addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget, button = $("button", form);
      const values = Object.fromEntries(new FormData(form));
      button.disabled = true;
      try {
        const { error: linkError } = await client.rpc("au_link_student_identity", {
          p_student_number: String(values.student_number).trim(),
          p_user_id: String(values.user_id).trim(),
          p_verification_note: String(values.verification_note).trim(),
        });
        if (linkError) throw linkError;
        toast("Official student identity linked.");
        await tabOfficialResults(body);
      } catch (e) { toast(e.message || "Could not link the student identity.", true); button.disabled = false; }
    });
    $("[data-results-csv]", body).addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget, button = $("button", form);
      button.disabled = true;
      try {
        const file = new FormData(form).get("file");
        if (!(file instanceof File) || !file.size) throw new Error("Choose a CSV file.");
        if (file.size > 5 * 1024 * 1024) throw new Error("The CSV file must be 5 MB or smaller.");
        const imported = await importOfficialResults(parseResultsCsv(await file.text()));
        toast(`${imported} official result row${imported === 1 ? "" : "s"} imported or updated.`);
        await tabOfficialResults(body);
      } catch (e) { toast(e.message || "Could not import the results.", true); button.disabled = false; }
    });
    $("[data-result-manual]", body).addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget, button = $("button", form), values = Object.fromEntries(new FormData(form));
      button.disabled = true;
      try {
        const imported = await importOfficialResults([values]);
        toast(`${imported} official result saved.`);
        await tabOfficialResults(body);
      } catch (e) { toast(e.message || "Could not save the official result.", true); button.disabled = false; }
    });
    $$("[data-result-edit]", body).forEach(form => form.addEventListener("submit", async event => {
      event.preventDefault();
      const card = form.closest("[data-result-id]");
      const button = $("button", form), values = Object.fromEntries(new FormData(form));
      button.disabled = true;
      try {
        const { data: updated, error: updateError } = await client.from("official_results")
          .update({ course: String(values.course).trim(), grade: String(values.grade).trim(), semester: String(values.semester).trim() })
          .eq("id", card.dataset.resultId).select("id").maybeSingle();
        if (updateError) throw updateError;
        if (!updated) throw new Error("The result was not updated. Reload and try again.");
        toast("Official result corrected; the previous values were added to its history.");
        await tabOfficialResults(body);
      } catch (e) { toast(e.message || "Could not correct the result.", true); button.disabled = false; }
    }));
  }

  async function tabVerifiers(body) {
    const { data, error } = await client.from("verifier_assignments")
      .select("id,user_id,verifier_role,allowed_item_types,allowed_student_ids,updated_at")
      .order("updated_at", { ascending: false }).limit(200);
    if (error) throw error;
    const assignments = data || [];
    const categoryOptions = [["project", "Projects"], ["achievement", "Achievements"], ["club", "Clubs / activities"]];
    body.innerHTML = `<p class="muted">Assignments are enforced by database row-level security. Each verifier sees only the selected students and categories. Get the verifier’s Auth user UUID from Supabase; enter student numbers as a comma- or line-separated list.</p>
      <form class="data-form" data-verifier-form><label class="full">Verifier Auth user UUID<input name="user_id" required maxlength="36" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>
        <label>Verifier role<select name="verifier_role"><option value="lecturer">Lecturer</option><option value="department_staff">Department staff</option><option value="supervisor">Supervisor</option></select></label>
        <label class="full">Assigned student numbers<textarea name="student_numbers" rows="4" required placeholder="One student number per line or separated by commas"></textarea></label>
        <fieldset class="full"><legend>Allowed categories</legend><div class="check-list">${categoryOptions.map(([value, label]) => `<label class="check"><input type="checkbox" name="item_types" value="${value}"><span>${label}</span></label>`).join("")}</div></fieldset>
        <button class="button" type="submit">Save verifier assignment</button><p class="form-message" aria-live="polite"></p></form>
      <h2 class="section-title">Current assignments</h2><div class="queue">${assignments.length ? assignments.map(a => `<article class="queue-card" data-assignment-id="${safe(a.id)}">
        <p><strong>${safe(ROLE_LABEL[a.verifier_role])}</strong> · ${safe(a.user_id)}</p>
        <p><strong>Categories:</strong> ${safe(a.allowed_item_types.join(", "))}</p>
        <p><strong>Assigned student account IDs:</strong> ${safe(a.allowed_student_ids.join(", "))}</p>
        <button class="text-button danger" type="button" data-remove-assignment>Revoke assignment</button></article>`).join("") : '<div class="empty">No verifier assignments yet.</div>'}</div>`;
    const form = $("[data-verifier-form]", body);
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const message = $(".form-message", form), button = $("button[type=submit]", form);
      const values = new FormData(form);
      const studentNumbers = String(values.get("student_numbers")).split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
      const itemTypes = values.getAll("item_types").map(String);
      message.textContent = "";
      if (!itemTypes.length) { message.textContent = "Select at least one category."; message.classList.add("err"); return; }
      button.disabled = true;
      try {
        const { error: saveError } = await client.rpc("au_save_verifier_assignment", {
          p_user_id: String(values.get("user_id")).trim(),
          p_verifier_role: String(values.get("verifier_role")),
          p_student_numbers: studentNumbers,
          p_item_types: itemTypes,
        });
        if (saveError) throw saveError;
        toast("Verifier assignment saved.");
        await tabVerifiers(body);
      } catch (e) { message.textContent = e.message || "Could not save the verifier assignment."; message.classList.add("err"); button.disabled = false; }
    });
    $$("[data-remove-assignment]", body).forEach(button => button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const { error: deleteError } = await client.from("verifier_assignments").delete()
          .eq("id", button.closest("[data-assignment-id]").dataset.assignmentId);
        if (deleteError) throw deleteError;
        toast("Verifier assignment revoked.");
        await tabVerifiers(body);
      } catch (e) { toast(e.message || "Could not revoke the assignment.", true); button.disabled = false; }
    }));
  }

  async function tabAlumni(body) {
    const { data, error } = await client.from("alumni_access_requests").select("*")
      .order("created_at", { ascending: false }).limit(100);
    if (error) throw error;
    const requests = data || [];
    body.innerHTML = `<p class="muted">Requests appear in this queue; the system does not send Records an email alert. Requests are queued even when the student account has not yet been linked. Check the student number and university email against official university records. For an unlinked request, first create the verified student-number link in Official results using the exact university email shown here, then return to approve. Do not approve based only on the request. Approval changes the Auth email to the personal address; the alumnus can then request a password reset. This workflow does not collect identity documents.</p>
      <div class="queue">${requests.length ? requests.map(request => `<article class="queue-card" data-alumni-id="${safe(request.id)}">
        <header>${badge({ pending: "Awaiting review", awaiting_confirmation: "Awaiting email confirmation", approved: "Approved", rejected: "Declined" }[request.status] || request.status, request.status === "pending" || request.status === "awaiting_confirmation" ? "warn" : request.status === "approved" ? "ok" : "bad")}
          <h3>${safe(request.student_number)}</h3><p class="sub">Requested ${safe(fmtDate(request.created_at))}</p></header>
        <dl class="kv"><dt>University email</dt><dd>${safe(request.university_email)}</dd><dt>Personal email</dt><dd>${safe(request.personal_email)}</dd></dl>
        ${request.records_note ? `<p class="notice">${safe(request.records_note)}</p>` : ""}
        ${request.status === "pending" ? `<label class="full">Records identity-check note (required)<textarea data-records-note rows="2" maxlength="1000" placeholder="Record the university record checked"></textarea></label>
          <label class="check"><input type="checkbox" data-identity-confirm><span>I checked the student number and university email against official university records.</span></label>
          <div class="actions"><button class="button" type="button" data-alumni-action="approve">Approve and change email</button><button class="button ghost" type="button" data-alumni-action="reject">Decline request</button></div>` : ""}</article>`).join("") : '<div class="empty">No alumni access requests are awaiting review.</div>'}</div>`;
    $$("[data-alumni-action]", body).forEach(button => button.addEventListener("click", async () => {
      const card = button.closest("[data-alumni-id]");
      const action = button.dataset.alumniAction;
      const recordsNote = $("[data-records-note]", card).value.trim();
      const identityChecked = $("[data-identity-confirm]", card).checked;
      if (!recordsNote) { toast("Add a note describing the identity check.", true); return; }
      if (action === "approve" && !identityChecked) { toast("Confirm the Records Office identity check before approving.", true); return; }
      button.disabled = true;
      try {
        const { data: result, error: invokeError } = await client.functions.invoke("alumni-access", {
          body: { action, request_id: card.dataset.alumniId, identity_checked: identityChecked, records_note: recordsNote },
        });
        if (invokeError) throw invokeError;
        toast(result?.message || `Alumni request ${action === "approve" ? "approved" : "declined"}.`);
        await tabAlumni(body);
      } catch (e) { toast(await functionErrorMessage(e), true); button.disabled = false; }
    }));
  }

  /* ------------------------------------------------------------ verifications */
  async function tabVerify(body, filter = "pending") {
    let q = client.from("verifications").select("*").in("item_type", ["project", "achievement", "club"]).order("created_at", { ascending: false }).limit(100);
    if (filter !== "all") q = q.eq("status", filter);
    if (verifierAssignment) {
      q = q.in("item_type", verifierAssignment.allowed_item_types)
        .in("student_id", verifierAssignment.allowed_student_ids);
    }
    const { data, error } = await q;
    if (error) throw error;
    const rows = data || [];
    body.innerHTML = `<div class="toolbar"><label>Show<select data-filter>${["pending", "verified", "rejected", "all"].map(f => `<option value="${f}"${f === filter ? " selected" : ""}>${f === "rejected" ? "Not verified" : f[0].toUpperCase() + f.slice(1)}</option>`).join("")}</select></label><button class="button ghost small" type="button" data-refresh>Refresh</button></div>
    <p class="muted">${verifierAssignment
      ? `You can review only your assigned students (${verifierAssignment.allowed_student_ids.length}) and categories (${safe(verifierAssignment.allowed_item_types.join(", "))}).`
      : "Check each item against the evidence, then confirm it is true or mark it as not verified. Students see your decision on their profile."}</p>
    <div class="queue">${rows.length ? rows.map(verifyCard).join("") : '<div class="empty">Nothing to show here.</div>'}</div>`;
    $("[data-filter]", body).addEventListener("change", e => tabVerify(body, e.target.value).catch(err => body.innerHTML = errorBox(err)));
    $("[data-refresh]", body).addEventListener("click", () => tabVerify(body, filter).catch(err => body.innerHTML = errorBox(err)));
    $$("a[data-ref]", body).forEach(a => AU.signedUrl(a.dataset.ref).then(u => { if (u) a.href = u; else { a.textContent = "File unavailable"; a.removeAttribute("href"); } }));
    $$("[data-decide]", body).forEach(btn => btn.addEventListener("click", async () => {
      const card = btn.closest("[data-id]");
      const status = btn.dataset.decide;
      const note = $("textarea", card).value.trim();
      if (status === "rejected" && !note) { toast("Add a short note so the student knows why.", true); return; }
      $$("button", card).forEach(b => b.disabled = true);
      try { await updateRow("verifications", card.dataset.id, { status, reviewer_note: note || null }); toast(status === "verified" ? "Marked as verified." : "Marked as not verified."); tabVerify(body, filter); }
      catch (e) { toast(e.message, true); $$("button", card).forEach(b => b.disabled = false); }
    }));
  }
  function verifyCard(v) {
    const snap = Object.entries(v.item_snapshot || {}).filter(([, val]) => val).map(([k, val]) => `<dt>${safe(FIELD_LABELS[k] || k)}</dt><dd>${safe(val)}</dd>`).join("");
    const ev = (v.evidence || []).map((r, i) => `<a data-ref="${safe(r)}" href="#" target="_blank" rel="noopener noreferrer">Evidence ${i + 1}</a>`).join("");
    const state = { pending: ["Pending", "warn"], verified: ["Verified", "ok"], rejected: ["Not verified", "bad"] }[v.status];
    return `<article class="queue-card" data-id="${safe(v.id)}"><header>${badge(TYPE_LABEL[v.item_type] || v.item_type, "info")}<h3>${safe(v.item_title)}</h3>${badge(state[0], state[1])}
      <p class="sub">${safe(v.student_name)} · ${safe(v.student_number)} · requested ${safe(fmtDate(v.created_at))}</p></header>
      <dl class="kv">${snap}</dl>${ev ? `<div class="evidence">${ev}</div>` : '<p class="muted">No evidence file attached.</p>'}
      ${v.status === "pending"
        ? `<div class="actions"><label>Note to student (required if not verified)<textarea rows="2" maxlength="1000"></textarea></label><button class="button" type="button" data-decide="verified">Verify as true</button><button class="button ghost" type="button" data-decide="rejected">Cannot verify</button></div>`
        : `<p class="muted">${v.reviewed_at ? "Decided " + safe(fmtDate(v.reviewed_at)) + "." : ""} ${v.reviewer_note ? "Note: " + safe(v.reviewer_note) : ""}</p>`}</article>`;
  }

  async function tabChanges(body) {
    const { data, error } = await client.from("achievement_change_requests").select("*")
      .order("created_at", { ascending: false }).limit(100);
    if (error) throw error;
    const requests = data || [];
    const studentIds = [...new Set(requests.map(r => r.student_id))];
    const profilesResult = studentIds.length
      ? await client.from("profiles").select("id,data").in("id", studentIds)
      : { data: [], error: null };
    if (profilesResult.error) throw profilesResult.error;
    const profiles = new Map((profilesResult.data || []).map(p => [p.id, p.data]));
    const titleFor = r => {
      const current = (profiles.get(r.student_id)?.[r.collection_name] || []).find(item => item.id === r.item_id);
      return current?.title || current?.name || r.item_id;
    };
    const studentLabel = r => {
      const profile = profiles.get(r.student_id)?.profile || {};
      return profile.name ? `${profile.name} (${profile.studentId || r.student_id})` : r.student_id;
    };
    const open = requests.filter(r => r.status === "pending");
    body.innerHTML = `<p class="muted">Students cannot directly change or remove verified items. Review the reason and proposed changes before applying a correction or deletion.</p>
      <div class="queue">${requests.length ? requests.map(r => `<article class="queue-card" data-change-id="${safe(r.id)}">
        <header>${badge(r.status === "pending" ? "Awaiting review" : r.status, r.status === "pending" ? "warn" : r.status === "approved" ? "ok" : "bad")}
          <h3>${safe(titleFor(r))}</h3><p class="sub">${safe(r.collection_name)} · ${safe(studentLabel(r))} · ${safe(fmtDate(r.created_at))}</p></header>
        <p><strong>${r.action === "delete" ? "Deletion requested" : "Correction requested"}:</strong> ${safe(r.reason)}</p>
        ${r.action === "correct" ? `<dl class="kv">${Object.entries(r.proposed_data || {}).map(([k, v]) => `<dt>${safe(FIELD_LABELS[k] || k)}</dt><dd>${safe(v)}</dd>`).join("")}</dl>` : ""}
        ${r.records_note ? `<p class="notice">${safe(r.records_note)}</p>` : ""}
        ${r.status === "pending" ? `<label>Note to student<textarea name="review-note" rows="2" maxlength="1000"></textarea></label>
          <div class="actions"><button class="button" type="button" data-change-decision="approve">Approve request</button>
          <button class="button ghost" type="button" data-change-decision="reject">Decline request</button></div>` : ""}
      </article>`).join("") : '<div class="empty">No achievement change requests.</div>'}</div>
      <p class="muted">${open.length} request${open.length === 1 ? "" : "s"} awaiting review.</p>`;
    $$("[data-change-decision]", body).forEach(button => button.addEventListener("click", async () => {
      const card = button.closest("[data-change-id]");
      const approve = button.dataset.changeDecision === "approve";
      const note = $('textarea[name="review-note"]', card).value.trim();
      if (!approve && note.length < 5) { toast("Add a short reason before declining.", true); return; }
      if (approve && !confirm("Apply this change to the student's profile? The existing verification will be superseded.")) return;
      $$("button", card).forEach(b => b.disabled = true);
      try {
        const { error: reviewError } = await client.rpc("au_review_achievement_change", {
          p_request_id: card.dataset.changeId,
          p_approve: approve,
          p_note: note || null
        });
        if (reviewError) throw reviewError;
        toast(approve ? "Change request approved and applied." : "Change request declined.");
        await tabChanges(body);
      } catch (reviewError) {
        toast(reviewError.message || "The change request could not be reviewed.", true);
        $$("button", card).forEach(b => b.disabled = false);
      }
    }));
  }

  /* ------------------------------------------------------------ recommendations */
  async function tabRecs(body, filter = "open") {
    let q = client.from("recommendation_requests").select("*").order("created_at", { ascending: false }).limit(100);
    if (filter === "open") q = q.in("status", ["submitted", "in_review", "forwarded"]);
    else if (filter !== "all") q = q.eq("status", filter);
    const { data, error } = await q;
    if (error) throw error;
    const rows = data || [];
    const filters = { open: "Open", completed: "Completed", declined: "Declined", all: "All" };
    body.innerHTML = `<div class="toolbar"><label>Show${select("filter", filters, filter).replace("<select", "<select data-filter")}</label><button class="button ghost small" type="button" data-refresh>Refresh</button></div>
    <p class="muted">Contact the referee using the details provided, then update the status. Students see the status and your note.</p>
    <div class="queue">${rows.length ? rows.map(recCard).join("") : '<div class="empty">No requests to show.</div>'}</div>`;
    $("[data-filter]", body).addEventListener("change", e => tabRecs(body, e.target.value).catch(err => body.innerHTML = errorBox(err)));
    $("[data-refresh]", body).addEventListener("click", () => tabRecs(body, filter).catch(err => body.innerHTML = errorBox(err)));
    $$("[data-save]", body).forEach(btn => btn.addEventListener("click", async () => {
      const card = btn.closest("[data-id]");
      btn.disabled = true;
      try {
        const request = rows.find(row => row.id === card.dataset.id);
        if (!request) throw new Error("This recommendation request is no longer available. Refresh and try again.");
        const status = $("select[name=status]", card).value;
        const file = $('input[name="letter"]', card).files[0];
        if (status === "completed" && !file && !request.letter_file) {
          throw new Error("Upload the referee’s signed PDF letter before marking this request completed.");
        }
        const letterFile = file ? await uploadRecommendationLetter(request, file) : request.letter_file;
        await updateRow("recommendation_requests", card.dataset.id, {
          status,
          records_note: $('textarea[name="records_note"]', card).value.trim() || null,
          records_assessment: $('textarea[name="records_assessment"]', card).value.trim() || null,
          letter_file: letterFile || null
        });
        toast("Request updated."); tabRecs(body, filter);
      } catch (e) {
        const message = /records_assessment|letter_file/i.test(e?.message || "")
          ? "Recommendation letters are not set up yet. Ask an administrator to apply migration 0010_recommendation_letters.sql."
          : e.message || "The request could not be updated.";
        toast(message, true); btn.disabled = false;
      }
    }));
  }
  function recCard(r) {
    return `<article class="queue-card" data-id="${safe(r.id)}"><header>${badge(REC_STATUS[r.status] || r.status, r.status === "completed" ? "ok" : r.status === "declined" ? "bad" : "warn")}<h3>${safe(r.purpose)} · ${safe(r.recipient_org)}</h3>
      <p class="sub">Requested ${safe(fmtDate(r.created_at))} · deadline ${safe(fmtDate(r.deadline))}</p></header>
      <dl class="kv"><dt>Student</dt><dd>${safe(r.student_name)} (${safe(r.student_number)})${r.programme ? ", " + safe(r.programme) : ""}</dd>
      <dt>Student contact</dt><dd>${safe(r.student_email)}${r.student_phone ? " · " + safe(r.student_phone) : ""}</dd>
      <dt>Referee</dt><dd>${safe(r.staff_name)}${r.staff_title ? ", " + safe(r.staff_title) : ""}${r.staff_department ? " – " + safe(r.staff_department) : ""}</dd>
      <dt>Referee email</dt><dd><a href="mailto:${safe(r.staff_email)}">${safe(r.staff_email)}</a></dd>
      <dt>Relationship</dt><dd>${safe(r.relationship || "")}${r.course_or_context ? " · " + safe(r.course_or_context) : ""}</dd>
      ${r.recipient_contact ? `<dt>Send to</dt><dd>${safe(r.recipient_contact)}</dd>` : ""}</dl>
      <p class="muted" style="margin:10px 0 0">Personal statement</p><div class="statement">${safe(r.personal_statement)}</div>
      ${r.lecturer_status ? `<p class="sub">Lecturer status: ${badge(REC_STATUS[r.lecturer_status] || r.lecturer_status, r.lecturer_status === "completed" ? "ok" : r.lecturer_status === "declined" ? "bad" : "warn")}</p>` : ""}
      ${r.lecturer_summary ? `<p class="muted" style="margin:10px 0 0">Lecturer summary</p><div class="statement">${safe(r.lecturer_summary)}</div>` : ""}
      ${r.letter_file ? `<p><a data-ref="${safe(r.letter_file)}" href="#" target="_blank" rel="noopener noreferrer">Open current referee letter</a></p>` : ""}
      <div class="actions"><label>Status${select("status", REC_STATUS, r.status)}</label>
      <label>Records Office assessment (shared with student)<textarea name="records_assessment" rows="4" maxlength="3000">${safe(r.records_assessment || "")}</textarea></label>
      <label>Note to student<textarea name="records_note" rows="2" maxlength="1000">${safe(r.records_note || "")}</textarea></label>
      <label>Referee’s signed letter (PDF, up to 10 MB)<input name="letter" type="file" accept="application/pdf"></label>
      <button class="button" type="button" data-save>Save</button></div></article>`;
  }

  /* ------------------------------------------------------------ payment plans */
  async function ledgerFor(ids) {
    if (!ids.length) return {};
    const { data, error } = await client.from("finance_ledger").select("student_id,kind,status,amount").in("student_id", ids);
    if (error) throw error;
    const by = {};
    (data || []).forEach(r => (by[r.student_id] ||= []).push(r));
    return by;
  }
  async function tabPlans(body, filter = "open") {
    let q = client.from("payment_plan_requests").select("*").order("created_at", { ascending: false }).limit(100);
    if (filter === "open") q = q.in("status", ["submitted", "in_review"]);
    else if (filter !== "all") q = q.eq("status", filter);
    const { data, error } = await q;
    if (error) throw error;
    const rows = data || [];
    const ledgers = await ledgerFor([...new Set(rows.map(r => r.student_id))]);
    const filters = { open: "Open", approved: "Approved", declined: "Declined", all: "All" };
    body.innerHTML = `<div class="toolbar"><label>Show${select("filter", filters, filter).replace("<select", "<select data-filter")}</label><button class="button ghost small" type="button" data-refresh>Refresh</button></div>
    <p class="muted">The balance shown comes from the finance ledger, not from what the student typed.</p>
    <div class="queue">${rows.length ? rows.map(r => planCard(r, AU.computeBalance(ledgers[r.student_id] || []))).join("") : '<div class="empty">No payment plan requests to show.</div>'}</div>`;
    $("[data-filter]", body).addEventListener("change", e => tabPlans(body, e.target.value).catch(err => body.innerHTML = errorBox(err)));
    $("[data-refresh]", body).addEventListener("click", () => tabPlans(body, filter).catch(err => body.innerHTML = errorBox(err)));
    $$("[data-save]", body).forEach(btn => btn.addEventListener("click", async () => {
      const card = btn.closest("[data-id]");
      const status = $("select", card).value;
      const inst = Number($('input[name="approved"]', card).value) || null;
      if (status === "approved" && !inst) { toast("Enter the number of approved instalments.", true); return; }
      btn.disabled = true;
      try {
        await updateRow("payment_plan_requests", card.dataset.id, { status, approved_instalments: status === "approved" ? inst : null, records_note: $("textarea", card).value.trim() || null });
        toast("Request updated."); tabPlans(body, filter);
      } catch (e) { toast(e.message, true); btn.disabled = false; }
    }));
  }
  function planCard(r, bal) {
    return `<article class="queue-card" data-id="${safe(r.id)}"><header>${badge(PLAN_STATUS[r.status] || r.status, r.status === "approved" ? "ok" : r.status === "declined" ? "bad" : "warn")}<h3>${money(r.amount_requested)} · ${r.instalments} ${safe(r.frequency)} instalments</h3>
      <p class="sub">${safe(r.student_name)} · ${safe(r.student_number)} · requested ${safe(fmtDate(r.created_at))}</p></header>
      <dl class="kv"><dt>Ledger balance</dt><dd><strong>${money(bal.balance)}</strong> outstanding · ${money(bal.pendingPayments + bal.pendingCredits)} pending payments</dd>
      <dt>First payment</dt><dd>${safe(fmtDate(r.first_payment_date))}</dd><dt>Contact</dt><dd>${safe(r.student_email)}${r.student_phone ? " · " + safe(r.student_phone) : ""}</dd><dt>Reason</dt><dd>${safe(r.reason)}</dd></dl>
      <div class="actions"><label>Decision${select("status", PLAN_STATUS, r.status)}</label><label>Approved instalments<input name="approved" type="number" min="1" max="12" value="${r.approved_instalments || r.instalments}"></label>
      <label>Note to student<textarea rows="2" maxlength="1000">${safe(r.records_note || "")}</textarea></label><button class="button" type="button" data-save>Save</button></div></article>`;
  }

  /* ------------------------------------------------------------ student finance */
  async function tabFinance(body) {
    body.innerHTML = `<form class="inline-form" data-search><label>Student ID number<input name="q" required maxlength="40" placeholder="e.g. 202301234"></label><button class="button" type="submit">Find student</button></form><div data-result></div>`;
    $("[data-search]", body).addEventListener("submit", async e => {
      e.preventDefault();
      const term = String(new FormData(e.currentTarget).get("q")).trim().replace(/[%_,()]/g, "");
      if (term) lookup(term, $("[data-result]", body));
    });
  }
  async function lookup(term, box) {
    box.innerHTML = '<p class="muted" role="status">Searching…</p>';
    try {
      const { data, error } = await client.from("profiles").select("id,data").ilike("data->profile->>studentId", term).limit(5);
      if (error) throw error;
      if (!data?.length) { box.innerHTML = '<div class="empty">No student found with that ID number.</div>'; return; }
      if (data.length > 1) { box.innerHTML = `<div class="notice warn">More than one profile uses that ID number. Check the records before posting anything.</div>`; }
      await showStudent(data[0], box, data.length > 1);
    } catch (err) { box.innerHTML = errorBox(err); }
  }
  async function showStudent(row, box, keepNotice) {
    const p = row.data?.profile || {};
    const { data: ledger, error } = await client.from("finance_ledger").select("*").eq("student_id", row.id).order("created_at", { ascending: false });
    if (error) throw error;
    const rows = ledger || [];
    const b = AU.computeBalance(rows);
    const notice = keepNotice ? box.innerHTML : "";
    box.innerHTML = `${notice}<div class="details-card" style="margin-bottom:16px"><h2>${safe(p.name || "Unnamed student")}</h2><dl class="kv"><dt>Student ID</dt><dd>${safe(p.studentId)}</dd><dt>Programme</dt><dd>${safe(p.programme || "—")}</dd><dt>Email</dt><dd>${safe(p.email || "—")}</dd></dl></div>
    <div class="stat-grid"><div class="stat primary"><span>Outstanding balance</span><strong>${money(b.balance)}</strong></div><div class="stat"><span>Billed</span><strong>${money(b.billed)}</strong></div><div class="stat"><span>Paid</span><strong>${money(b.paid + b.credits)}</strong></div><div class="stat"><span>Pending</span><strong>${money(b.pendingPayments + b.pendingCredits + b.pendingCharges)}</strong></div></div>
    <form class="inline-form" data-entry><label>Term<input name="term" required maxlength="80" placeholder="2026 Semester 1"></label><label>Description<input name="description" required maxlength="200" placeholder="Tuition fees"></label>
      <label>Type<select name="kind"><option value="charge">Charge (adds to balance)</option><option value="payment">Payment</option><option value="credit">Credit / scholarship</option></select></label>
      <label>Amount<input name="amount" type="number" min="0.01" step="0.01" required></label><label>Status<select name="status"><option value="posted">Posted</option><option value="pending">Pending</option></select></label>
      <label>Reference / receipt no.<input name="reference" maxlength="80"></label><button class="button" type="submit">Add entry</button></form>
    <p class="muted">Entries cannot be deleted. To correct a mistake, add an offsetting entry so there is a clear audit trail.</p>
    ${rows.length ? `<div class="table-wrap"><table class="data stack"><thead><tr><th>Date</th><th>Term</th><th>Description</th><th>Type</th><th>Status</th><th class="num">Amount</th><th></th></tr></thead><tbody>${rows.map(r => `<tr><td data-label="Date">${safe(fmtDate(r.created_at))}</td><td data-label="Term">${safe(r.term)}</td><td data-label="Description">${safe(r.description)}${r.reference ? ` <small class="muted">(${safe(r.reference)})</small>` : ""}</td><td data-label="Type">${safe(r.kind)}</td><td data-label="Status">${badge(r.status, r.status === "posted" ? "ok" : "warn")}</td><td class="num" data-label="Amount">${r.kind === "charge" ? "" : "−"}${money(r.amount)}</td><td data-label="">${r.status === "pending" ? `<button class="text-button" type="button" data-post="${safe(r.id)}">Mark posted</button>` : ""}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty">No ledger entries yet.</div>'}`;
    const refresh = () => showStudent(row, box, false).catch(e => box.innerHTML = errorBox(e));
    $("[data-entry]", box).addEventListener("submit", async e => {
      e.preventDefault();
      const fd = new FormData(e.currentTarget), btn = $("button", e.currentTarget);
      btn.disabled = true;
      try {
        const { error: err } = await client.from("finance_ledger").insert({
          student_id: row.id, term: String(fd.get("term")).trim(), description: String(fd.get("description")).trim(), kind: fd.get("kind"),
          amount: Number(fd.get("amount")), status: fd.get("status"), reference: String(fd.get("reference")).trim() || null });
        if (err) throw err;
        toast("Entry added."); refresh();
      } catch (er) { toast(er.message, true); btn.disabled = false; }
    });
    $$("[data-post]", box).forEach(b => b.addEventListener("click", async () => {
      b.disabled = true;
      try { await updateRow("finance_ledger", b.dataset.post, { status: "posted" }); toast("Entry posted."); refresh(); }
      catch (er) { toast(er.message, true); b.disabled = false; }
    }));
  }

  window.AUStaff = { start };
})();
