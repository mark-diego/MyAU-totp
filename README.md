# MyAU – Africa University portal setup

1. In Supabase SQL Editor, run `backend/migrations/0007_allow_authenticated_profiles.sql` first, then
   `backend/migrations/0008_records_verification_finance.sql`,
   `backend/migrations/0009_result_verification.sql`, `backend/migrations/0010_recommendation_letters.sql`,
   `backend/migrations/0011_lecturer_sharing_and_achievement_history.sql`,
   `backend/migrations/0012_official_results_scoped_verifiers_alumni.sql`, and
   `backend/migrations/0013_queue_unmatched_alumni_requests.sql`, in that order. Migration 0008 assumes
   the owner-scoped `profiles` policies installed by 0007. For authenticator-app MFA, also apply
   `backend/migrations/0015_totp_mfa.sql`. If migration 0014 was already applied, 0015 removes the
   previous custom email-code challenge storage; if it was not applied, skip 0014.
2. The supplied images `assets/images/au_1.jpg` and `assets/images/au_3.jpg` are used for login backgrounds
   and the homepage hero, respectively.
3. Create Records/Admin roles in Supabase SQL Editor only; never expose a service-role key in browser code:
   ```sql
   update auth.users
      set raw_app_meta_data = coalesce(raw_app_meta_data,'{}'::jsonb) || '{"role":"records"}'
    where email = 'records.officer@example.com';   -- use "admin" for administrators
   ```
   The person signs out and in again afterwards.
4. Deploy `js/app.js`, `js/staff.js`, `js/lecturer.js`, `js/alumni.js`, the pages, Edge Functions, and migrations.
   `js/config.js` is unchanged. Optional: add `currency: "USD"` to `config.js`.
5. Storage: club pictures, ID photos and certificates use the existing private `student-content` bucket and
   the same `<user id>/…` folder rule used by CV uploads. Migration 0010 adds recommendation-letter policies.

Student, Staff, Records, Administrator and Lecturer accounts use Supabase TOTP authenticator MFA. After the
password or lecturer email-link sign-in, users scan a QR code with an authenticator app and confirm a code;
later sign-ins require a fresh 6-digit authenticator code. No Resend account or email-MFA Edge Function is
needed. Supabase Auth MFA is enabled by default.

Apply migration `0015_totp_mfa.sql` to enforce AAL2 on database and private-storage access and to update the
custom access-token hook for TOTP sessions. In the Supabase Dashboard, enable the Custom Access Token Hook
under Authentication → Hooks and select `public.custom_access_token_hook` (also declared in
`supabase/config.toml`). Unverified AAL1 sessions cannot read or change MyAU data; this is enforced by
restrictive RLS policies as well as by the application sign-in screens. Deploy the updated static site,
including `js/mfa.js`. If a user loses their authenticator device, an administrator must verify their identity
and remove that user's TOTP factor in Supabase Auth; the user will enroll a new authenticator on the next
sign-in.

Students can select verified projects, achievements, and clubs when requesting a recommendation. Only those
selected snapshots are shared with the exact referee email after email-link sign-in; access expires within 90
days and students can revoke it. From a saved request, students can send a Supabase secure sign-in link directly
to the referee. After one click, the link signs the lecturer in and opens the lecturer workspace. Add the deployed
`pages/lecturer.html` URL to Supabase Authentication's allowed redirect URLs and enable email-link sign-in. If
lecturers do not already have Auth accounts, allow email sign-up; otherwise pre-create their Auth accounts.
Lecturers can edit a summary based on the selected items and track their own status. Lecturer access is logged,
and overdue requests are flagged in the lecturer workspace. Scheduled email reminders require a separately
deployed, secured email/Edge Function; the static site does not send them.

Official course results are stored separately from student profiles. Students can only view results tied to
their own authenticated account. Before results or verifier access are assigned, Records must link each official
student number to an Auth user UUID in the protected student registry after checking university records and
recording the source checked; editable profile numbers are not trusted for these mappings. Get the Auth UUID
from the Supabase Auth users list. Records can add results manually or import a CSV with the
exact required headers `student_id,course_code,course,grade,semester`. Here `student_id` is the official number
in the verified registry. Imports accept up to 1,000 rows. Re-importing the same student, course code, and semester
updates the result and records the prior values in history. Existing student-entered grades are not copied into
the official table.

Administrators can assign verifier access from the Admin console. An assignment is bound to the verifier's
Supabase Auth user UUID and an explicit list of student numbers and item categories (projects, achievements,
clubs/activities). Database RLS enforces those limits even for direct API access. Remove the assignment to
revoke it. Verifiers use the Staff sign-in page but do not receive Records/Admin permissions.

Alumni can request an account email change from the sign-in page using their student number, current university
email, and personal email. The request does not reveal whether the account exists and does not grant access.
Records must check the university records and enter an identity-check note before approving; MyAU does not
collect identity documents. Approval requests an Auth email change and sends a confirmation message to the
personal address; the university email remains the login until that confirmation succeeds. Enable Supabase
email confirmations and configure the deployed site as its Auth Site URL so Supabase sends a verification link
to the new address. The student profile email is refreshed from the confirmed Auth email on their next sign-in.
Deploy the server function with the Supabase CLI:

```powershell
supabase functions deploy alumni-access --project-ref mrkgziygjbknujsesvta
```

The function uses server-side Supabase environment secrets. Never copy a service-role key into browser code or
the static site. Alumni requests appear in the Staff console's Alumni access tab; the current workflow does not
send email alerts to Records. Migration 0013 ensures requests still reach the Records queue when the student
number and university email have not yet been linked to an Auth account. Before approval, Records must add
that verified student-number link with the exact university email from the request.

Student achievements include the university-approved category (Academic, Leadership, Research, Community
Service, Sports, Arts & Culture, Other), date, issuer, and description. Existing achievements remain visible;
their old verification remains recognized until a Records-reviewed change or a new verification request.

The Records console includes a queue for verified-achievement correction/deletion requests. Direct edits and
removals of unchanged verified projects, achievements, and clubs are blocked. Approved changes supersede the
old verification and are recorded in the student's history.

Projects are sent to the Records verification queue when saved. The Results page only displays official data
supplied by Records; it does not issue an official transcript. The digital student ID QR code is generated in the browser and contains
only the student ID. Records can add an assessment and upload the referee's signed recommendation letter as a
PDF; only the request's student and Records staff can access that private letter.
