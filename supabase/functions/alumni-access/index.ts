import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async request => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return respond(405, { error: "POST is required." });

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) return respond(500, { error: "Alumni access is not configured on the server." });

  let payload: Record<string, unknown>;
  try {
    payload = await request.json();
  } catch {
    return respond(400, { error: "A valid JSON request is required." });
  }

  if (payload.action === "request") {
    const studentNumber = String(payload.student_number ?? "").trim();
    const universityEmail = String(payload.university_email ?? "").trim();
    const personalEmail = String(payload.personal_email ?? "").trim();
    if (!studentNumber || !universityEmail || !personalEmail) {
      return respond(400, { error: "Enter the requested account details." });
    }
    const publicClient = createClient(url, anonKey, { auth: { persistSession: false } });
    const { error } = await publicClient.rpc("au_request_alumni_access", {
      p_student_number: studentNumber,
      p_university_email: universityEmail,
      p_personal_email: personalEmail,
    });
    if (error) return respond(400, { error: error.message });
    return respond(202, {
      message: "Your request has been sent for Records Office review. This does not grant access automatically.",
    });
  }

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return respond(401, { error: "Staff sign-in is required." });
  const callerClient = createClient(url, anonKey, {
    auth: { persistSession: false },
    global: { headers: { Authorization: authorization } },
  });
  const { data: callerData, error: callerError } = await callerClient.auth.getUser();
  if (callerError || !callerData.user) return respond(401, { error: "The staff session is invalid or expired." });
  const callerRole = String(callerData.user.app_metadata?.role ?? "");
  if (!["records", "admin"].includes(callerRole)) return respond(403, { error: "Only Records Office staff can review alumni access." });

  const requestId = String(payload.request_id ?? "");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId)) {
    return respond(400, { error: "A valid alumni request ID is required." });
  }
  const serviceClient = createClient(url, serviceKey, { auth: { persistSession: false } });
  const { data: alumniRequest, error: requestError } = await serviceClient
    .from("alumni_access_requests").select("*").eq("id", requestId).maybeSingle();
  if (requestError) return respond(500, { error: `Could not load the alumni request: ${requestError.message}` });
  if (!alumniRequest || alumniRequest.status !== "pending") return respond(409, { error: "This request is no longer awaiting review." });

  if (payload.action === "reject") {
    const note = String(payload.records_note ?? "").trim();
    if (!note) return respond(400, { error: "Add a reason before declining the request." });
    const { data: updated, error } = await serviceClient.from("alumni_access_requests").update({
      status: "rejected", records_note: note.slice(0, 1000),
      handled_by: callerData.user.id, handled_at: new Date().toISOString(),
    }).eq("id", requestId).eq("status", "pending").select("id").maybeSingle();
    if (error) return respond(500, { error: `Could not decline the request: ${error.message}` });
    if (!updated) return respond(409, { error: "This request was already handled by another staff member." });
    return respond(200, { message: "Alumni access request declined." });
  }

  if (payload.action !== "approve" || payload.identity_checked !== true) {
    return respond(400, { error: "Confirm the Records Office identity check before approving this request." });
  }
  const recordsNote = String(payload.records_note ?? "").trim();
  if (!recordsNote) return respond(400, { error: "Record how the identity was checked before approval." });

  let studentId = alumniRequest.student_id;
  if (!studentId) {
    const { data: resolvedStudentId, error: resolveError } = await callerClient.rpc(
      "au_resolve_alumni_request",
      { p_request_id: requestId },
    );
    if (resolveError) return respond(409, { error: resolveError.message });
    studentId = resolvedStudentId;
  }
  if (!studentId) return respond(409, { error: "Link this request to a verified student account before approving." });

  const { data: accountData, error: accountError } = await serviceClient.auth.admin.getUserById(studentId);
  if (accountError || !accountData.user) return respond(500, { error: `The student account could not be loaded${accountError ? `: ${accountError.message}` : "."}` });
  const currentEmail = String(accountData.user.email ?? "").toLowerCase();
  const oldEmail = String(alumniRequest.university_email).toLowerCase();
  const newEmail = String(alumniRequest.personal_email).toLowerCase();
  if (currentEmail !== oldEmail && currentEmail !== newEmail) {
    return respond(409, { error: "The account email changed since the request was submitted. Recheck the university record before proceeding." });
  }

  if (currentEmail !== newEmail) {
    const { error } = await serviceClient.auth.admin.updateUserById(studentId, {
      email: alumniRequest.personal_email,
    });
    if (error) return respond(500, { error: `The account email could not be updated: ${error.message}` });
  }

  const awaitingConfirmation = currentEmail !== newEmail;
  const { data: updatedRequest, error: finishError } = await serviceClient.from("alumni_access_requests").update({
    status: awaitingConfirmation ? "awaiting_confirmation" : "approved",
    records_note: recordsNote.slice(0, awaitingConfirmation ? 800 : 1000)
      + (awaitingConfirmation ? "\nPersonal email confirmation requested; access remains on the university email until confirmed." : ""),
    handled_by: callerData.user.id, handled_at: new Date().toISOString(),
  }).eq("id", requestId).eq("status", "pending").select("id").maybeSingle();
  if (finishError) {
    return respond(500, { error: `The email change was requested, but the review status could not be recorded: ${finishError.message}` });
  }
  if (!updatedRequest) return respond(409, { error: "This request was already handled by another staff member." });
  return respond(200, {
    message: awaitingConfirmation
      ? "Records approved the request and a confirmation email was sent to the personal address. The alumnus should keep using the university email until they click that confirmation link."
      : "The personal email is already confirmed on the account.",
  });
});
