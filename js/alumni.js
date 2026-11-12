(() => {
  "use strict";
  const root = document.querySelector("#app");
  const config = window.MY_AU_CONFIG || {};
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
  async function start() {
    root.innerHTML = `<header class="auth-header alumni-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span><span>MyAU<small>Africa University</small></span></a><a class="alumni-home" href="auth.html">Student sign in</a></header>
      <main class="alumni-page">
        <section class="alumni-intro" aria-labelledby="alumni-title">
          <p class="eyebrow light">Africa University · Alumni services</p>
          <h1 id="alumni-title">Your MyAU journey continues.</h1>
          <p>Keep access to your university profile after graduation. Request a move to your personal email with a simple Records Office identity check.</p>
          <div class="alumni-steps" aria-label="How the process works">
            <div><span>01</span><p>Share your university account details</p></div>
            <div><span>02</span><p>Records checks your university record</p></div>
            <div><span>03</span><p>Confirm the link sent to your personal email</p></div>
          </div>
        </section>
        <section class="alumni-panel" aria-labelledby="request-title">
          <p class="eyebrow">Alumni account access</p>
          <h2 id="request-title">Request an email update</h2>
          <p class="muted">Your university email remains your sign-in until you confirm the email-change link.</p>
          <form class="auth-form">
            <label>Student number<input name="student_number" required maxlength="40" autocomplete="off"></label>
            <label>Current university email<input name="university_email" type="email" required maxlength="200" autocomplete="email"></label>
            <label>Personal email<input name="personal_email" type="email" required maxlength="200" autocomplete="email"></label>
            <button class="button" type="submit">Send request for review</button>
            <p class="form-message" aria-live="polite" role="status"></p>
          </form>
          <p class="alumni-privacy"><span>Privacy</span> Your information is reviewed by the Records Office. Do not send identity documents through this form.</p>
          <nav class="auth-links"><a href="auth.html">Return to student sign in</a></nav>
        </section>
      </main><footer class="auth-footer">MyAU · Africa University · Mutare, Zimbabwe</footer>`;
    $("form").addEventListener("submit", submit);
  }

  async function submit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector("button");
    const message = form.querySelector(".form-message");
    const values = Object.fromEntries(new FormData(form));
    if (String(values.university_email).trim().toLowerCase() === String(values.personal_email).trim().toLowerCase()) {
      message.textContent = "Enter a personal email address different from your university email.";
      message.classList.add("err");
      return;
    }
    button.disabled = true;
    message.textContent = "";
    message.className = "form-message";
    try {
      if (!config.supabaseUrl || !config.supabasePublishableKey) throw new Error("Supabase configuration is missing.");
      const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
      const client = createClient(config.supabaseUrl, config.supabasePublishableKey);
      const { data, error } = await client.functions.invoke("alumni-access", {
        body: { action: "request", ...values },
      });
      if (error) throw error;
      message.textContent = data?.message || "Your request has been sent for Records Office review. This does not grant access automatically.";
      form.reset();
    } catch (error) {
      message.textContent = await functionErrorMessage(error);
      message.classList.add("err");
    } finally {
      button.disabled = false;
    }
  }

  function $(selector) {
    return root.querySelector(selector);
  }

  start();
})();
