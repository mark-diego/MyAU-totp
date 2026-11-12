/* Lecturer access is limited to recommendation requests addressed to the
   authenticated email and student-approved, unexpired achievement shares. */
(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const safe = value => String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
  const REC_STATUS = {
    in_review: "In review",
    completed: "Summary completed",
    declined: "Declined"
  };
  const FIELD_LABELS = {
    title: "Title", description: "Description", tech: "Technologies", github: "Project link",
    date: "Date", issuer: "Awarded by", name: "Activity", type: "Type", role: "Role"
  };
  const config = window.MY_AU_CONFIG || {};
  let client;

  async function loadMfaLibrary() {
    if (window.AUMfa) return window.AUMfa;
    await new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = new URL("../js/mfa.js", location.href).href;
      script.onload = () => window.AUMfa
        ? resolve()
        : reject(new Error("The authenticator security module did not initialize."));
      script.onerror = () => reject(new Error("The authenticator security module could not be loaded."));
      document.head.appendChild(script);
    });
    return window.AUMfa;
  }

  function showError(message) {
    const root = $("#app");
    root.innerHTML = `<main class="console"><div class="notice bad" role="alert">${safe(message)}</div></main>`;
  }

  async function getClient() {
    if (!config.supabaseUrl || !config.supabasePublishableKey) {
      throw new Error("Supabase URL and publishable key are required in js/config.js.");
    }
    const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
    return createClient(config.supabaseUrl, config.supabasePublishableKey);
  }

  function renderLogin(root, notice = "") {
    root.innerHTML = `<header class="auth-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span>MyAU</a></header>
      <main class="auth-wrap"><section class="auth-card">
        <p class="eyebrow">Lecturer access · Secure email sign-in</p><h1>Lecturer workspace</h1>
        <p class="lead">Enter the exact email address a student used for your recommendation request. MyAU will email you a secure sign-in link.</p>
        <form class="auth-form"><label>Invited email address<input name="email" type="email" autocomplete="email" required></label>
          <button class="button" type="submit">Email me a sign-in link</button>
          <p class="form-message" aria-live="polite" role="status">${safe(notice)}</p></form>
        <nav class="auth-links"><a href="../index.html">Return to MyAU</a></nav>
      </section></main><footer class="auth-footer">MyAU · Africa University</footer>`;
    $("form", root).addEventListener("submit", async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = $("button", form);
      const message = $(".form-message", form);
      button.disabled = true;
      message.textContent = "";
      try {
        const email = String(new FormData(form).get("email")).trim().toLowerCase();
        const redirectTo = new URL("lecturer.html", location.href).href;
        const { error } = await client.auth.signInWithOtp({
          email,
          options: { emailRedirectTo: redirectTo, shouldCreateUser: true }
        });
        if (error) throw error;
        message.textContent = "If the email can receive MyAU sign-in links, check its inbox and spam folder. Open the link on this device to continue.";
        form.reset();
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : "The sign-in email could not be sent.";
      } finally {
        button.disabled = false;
      }
    });
  }

  function suggestedSummary(request, share) {
    if (!share?.items?.length) return "";
    const items = share.items.map(item => {
      const details = Object.entries(item.details || {})
        .filter(([, value]) => value)
        .map(([key, value]) => `${FIELD_LABELS[key] || key}: ${value}`)
        .join("; ");
      return `- ${item.title}${details ? ` (${details})` : ""} [verified ${item.verified_at ? new Date(item.verified_at).toLocaleDateString() : ""}]`;
    });
    return `Recommendation summary for ${request.student_name}\nPurpose: ${request.purpose} — ${request.recipient_org}\n\nVerified achievements shared with consent:\n${items.join("\n")}\n\nLecturer's comments:\n`;
  }

  function renderWorkspace(root, user, workspace) {
    const shares = workspace.shares || [];
    const requests = workspace.requests || [];
    const sharesByRequest = new Map(shares.map(share => [share.request_id, share]));
    const today = new Date().toISOString().slice(0, 10);
    const overdue = requests.filter(r => r.deadline < today && !["completed", "declined"].includes(r.lecturer_status));
    const requestsHtml = requests.length ? requests.map(request => {
      const share = sharesByRequest.get(request.id);
      const summary = request.lecturer_summary || suggestedSummary(request, share);
      return `<article class="queue-card" data-request-id="${safe(request.id)}">
        <header><span class="badge ${request.lecturer_status === "completed" ? "ok" : request.lecturer_status === "declined" ? "bad" : "warn"}">${safe(REC_STATUS[request.lecturer_status] || "Awaiting review")}</span>
          <h2>${safe(request.student_name)} · ${safe(request.purpose)}</h2>
          <p class="sub">${safe(request.programme || "Africa University")} · ${safe(request.recipient_org)} · deadline ${safe(request.deadline)}</p></header>
        ${request.deadline < today && !["completed", "declined"].includes(request.lecturer_status) ? '<p class="notice warn" role="status"><strong>Overdue reminder:</strong> this request is past its deadline. Please update the student and Records Office.</p>' : ""}
        <p><strong>Student number:</strong> ${safe(request.student_number)}</p>
        <p><strong>Student's request:</strong></p><div class="statement">${safe(request.personal_statement)}</div>
        ${share ? `<section class="details-card"><h3>Verified achievements shared by the student</h3>${share.items.map(item => `<div class="saved-card">
          <p><span class="badge ok">Verified</span> ${safe(item.type)}</p><h4>${safe(item.title)}</h4>
          <dl class="kv">${Object.entries(item.details || {}).map(([key, value]) => `<dt>${safe(FIELD_LABELS[key] || key)}</dt><dd>${safe(value)}</dd>`).join("")}</dl>
        </div>`).join("")}<p class="muted">This selection was shared for this request only and expires ${safe(new Date(share.expires_at).toLocaleString())}.</p></section>`
          : '<p class="notice">The student did not share verified achievements with this request.</p>'}
        <form class="data-form" data-summary-form>
          <label class="full">Recommendation letter summary / draft<textarea name="summary" rows="8" maxlength="5000" required>${safe(summary)}</textarea>
            <small class="hint">A suggested summary is prefilled only from achievements the student selected. Review and edit it; you remain the letter’s author.</small></label>
          <label>Lecturer status<select name="status">${Object.entries(REC_STATUS).map(([value, label]) => `<option value="${value}"${(request.lecturer_status || "in_review") === value ? " selected" : ""}>${safe(label)}</option>`).join("")}</select></label>
          <button class="button" type="submit">Save summary and status</button><p class="form-message" aria-live="polite"></p>
        </form></article>`;
    }).join("") : '<div class="empty">No requests have been addressed to this email. Check that you signed in using the exact email the student entered.</div>';

    root.innerHTML = `<header class="portal-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span><span>MyAU<small>Lecturer workspace</small></span></a>
        <button class="header-action" type="button" data-signout>Sign out</button></header>
      <main class="console"><div class="console-head"><div><p class="eyebrow">Recommendation requests</p><h1>Lecturer workspace</h1></div><p class="muted">Signed in as ${safe(user.email)}</p></div>
        <p class="lead">You can see only requests addressed to this email and verified achievements each student explicitly chose to share.</p>
        ${overdue.length ? `<div class="notice warn" role="status"><strong>${overdue.length} overdue request${overdue.length === 1 ? "" : "s"}</strong><p>Review the request${overdue.length === 1 ? "" : "s"} below and update the student and Records Office.</p></div>` : ""}
        <div class="queue">${requestsHtml}</div>
        ${shares.length ? `<section class="saved-items"><h2>Shared profile access</h2>${shares.map(share => `<article class="saved-card"><p>${safe(share.student_name)} · ${safe(share.purpose)}</p><p>Access expires ${safe(new Date(share.expires_at).toLocaleString())}.</p><p class="muted">The student can revoke this access at any time. Access to these selected items is logged.</p></article>`).join("")}</section>` : ""}
      </main>`;

    $$("[data-summary-form]").forEach(form => form.addEventListener("submit", async event => {
      event.preventDefault();
      const card = form.closest("[data-request-id]");
      const button = $("button[type=submit]", form);
      const message = $(".form-message", form);
      button.disabled = true;
      message.textContent = "";
      try {
        const data = new FormData(form);
        const { error } = await client.rpc("au_lecturer_update_recommendation", {
          p_request_id: card.dataset.requestId,
          p_summary: String(data.get("summary")).trim(),
          p_status: String(data.get("status"))
        });
        if (error) throw error;
        message.textContent = "Your summary and status have been saved.";
        const refreshed = await client.rpc("au_lecturer_workspace");
        if (refreshed.error) throw refreshed.error;
        renderWorkspace(root, user, refreshed.data || {});
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : "The update could not be saved.";
      } finally {
        button.disabled = false;
      }
    }));
    $("[data-signout]").addEventListener("click", async event => {
      const button = event.currentTarget;
      button.disabled = true;
      const { error } = await client.auth.signOut();
      if (error) {
        button.disabled = false;
        showError(error.message);
      } else {
        renderLogin(root, "You have signed out.");
      }
    });
  }

  async function start() {
    const root = $("#app");
    try {
      client = await getClient();
      await loadMfaLibrary();
      const verified = await window.AUMfa.require(client, root, {
        title: "Lecturer account",
        returnTo: "lecturer.html",
        onCancel: () => renderLogin(root, "Signed out. Sign in again to continue."),
        onVerified: () => start(),
      });
      if (!verified) return;
      const { data, error } = await client.auth.getUser();
      if (error && !/auth session missing/i.test(error.message || "")) throw error;
      if (!data.user) {
        renderLogin(root);
        return;
      }
      const { data: workspace, error: workspaceError } = await client.rpc("au_lecturer_workspace");
      if (workspaceError) {
        if (/au_lecturer_workspace|schema cache/i.test(workspaceError.message || "")) {
          throw new Error("Lecturer access is not installed yet. Ask the administrator to apply migration 0011_lecturer_sharing_and_achievement_history.sql and add this page to Supabase's allowed redirect URLs.");
        }
        throw workspaceError;
      }
      renderWorkspace(root, data.user, workspace || {});
    } catch (error) {
      showError(error instanceof Error ? error.message : "The lecturer workspace could not be loaded.");
    }
  }

  start();
})();
