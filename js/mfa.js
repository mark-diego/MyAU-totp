(() => {
  "use strict";

  const safe = value => String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));

  function shell(root, title, description, body) {
    root.innerHTML = `<header class="auth-header"><a class="brand" href="../index.html"><span class="brand-mark">AU</span>MyAU</a></header>
      <main class="auth-wrap"><section class="auth-card">
        <p class="eyebrow">Authenticator-app security</p><h1>${safe(title)}</h1>
        <p class="lead">${safe(description)}</p>${body}
      </section></main><footer class="auth-footer">MyAU · Africa University secure account access</footer>`;
  }

  async function requireMfa(client, root, {
    title = "Secure your account", returnTo = "auth.html", onVerified, onCancel
  } = {}) {
    const { data: sessionData, error: sessionError } = await client.auth.getSession();
    if (sessionError) throw sessionError;
    if (!sessionData.session) return true;

    let assurance = await client.auth.mfa.getAuthenticatorAssuranceLevel();
    if (assurance.error) throw assurance.error;
    if (assurance.data.currentLevel === "aal2" && assurance.data.nextLevel === "aal2") return true;
    if (assurance.data.currentLevel === "aal2") {
      const { error } = await client.auth.refreshSession();
      if (error) throw error;
      assurance = await client.auth.mfa.getAuthenticatorAssuranceLevel();
      if (assurance.error) throw assurance.error;
      if (assurance.data.currentLevel === "aal2" && assurance.data.nextLevel === "aal2") return true;
    }

    const { data: factorData, error: factorsError } = await client.auth.mfa.listFactors();
    if (factorsError) throw factorsError;
    const factors = factorData.totp || [];
    const factor = factors.find(item => item.status === "verified");
    let enrollment = null;
    if (!factor) {
      for (const pending of factors.filter(item => item.status !== "verified")) {
        const { error } = await client.auth.mfa.unenroll({ factorId: pending.id });
        if (error) throw error;
      }
      const { data, error } = await client.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: `MyAU ${title}`,
      });
      if (error) throw error;
      enrollment = data;
    }

    const intro = factor
      ? "Enter the current 6-digit code from your authenticator app to continue."
      : "Scan this QR code with an authenticator app such as Google Authenticator, Microsoft Authenticator, or Authy. Then enter the 6-digit code shown in the app.";
    shell(root, factor ? "Verify your identity" : "Set up your authenticator", intro,
      `<form class="auth-form" data-totp-form>
        ${enrollment ? `<img class="totp-qr" src="${safe(enrollment.totp.qr_code)}" alt="QR code for setting up MyAU in your authenticator app">
          <p class="totp-secret-label">Can’t scan the QR code? Enter this setup key manually:</p>
          <code class="totp-secret">${safe(enrollment.totp.secret)}</code>` : ""}
        <label>Authenticator code<input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required></label>
        <button class="button" type="submit">${factor ? "Verify and continue" : "Verify and enable authenticator"}</button>
        <button class="text-button mfa-back" type="button">Cancel and return to sign in</button>
        <p class="form-message" aria-live="polite" role="status"></p>
      </form>`);

    const form = root.querySelector("[data-totp-form]");
    const code = form.querySelector('input[name="code"]');
    const message = form.querySelector(".form-message");
    const button = form.querySelector('button[type="submit"]');
    form.querySelector(".mfa-back").addEventListener("click", async () => {
      try {
        await client.auth.signOut({ scope: "local" });
        if (onCancel) await onCancel();
        else location.assign(returnTo);
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : "Could not return to sign in.";
        message.classList.add("err");
      }
    });
    code.focus();
    form.addEventListener("submit", async event => {
      event.preventDefault();
      button.disabled = true;
      message.textContent = "";
      message.classList.remove("err");
      try {
        const challenge = await client.auth.mfa.challenge({ factorId: (factor || enrollment).id });
        if (challenge.error) throw challenge.error;
        const verification = await client.auth.mfa.verify({
          factorId: (factor || enrollment).id,
          challengeId: challenge.data.id,
          code: code.value.trim(),
        });
        if (verification.error) throw verification.error;

        let current = await client.auth.mfa.getAuthenticatorAssuranceLevel();
        if (current.error) throw current.error;
        if (current.data.currentLevel !== "aal2") {
          const { error } = await client.auth.refreshSession();
          if (error) throw error;
          current = await client.auth.mfa.getAuthenticatorAssuranceLevel();
          if (current.error) throw current.error;
        }
        if (current.data.currentLevel !== "aal2" || current.data.nextLevel !== "aal2") {
          throw new Error("The authenticator code was accepted, but Supabase did not upgrade this session to AAL2. Check the project's MFA settings and try again.");
        }
        if (onVerified) await onVerified();
        else location.reload();
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : "The authenticator code could not be verified.";
        message.classList.add("err");
        button.disabled = false;
        code.select();
      }
    });

    return false;
  }

  window.AUMfa = { require: requireMfa };
})();
