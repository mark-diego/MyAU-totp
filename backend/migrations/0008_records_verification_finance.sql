-- 0008_records_verification_finance.sql
-- Adds: item verification, recommendation requests, finance ledger, payment plan requests.
--
-- SECURITY MODEL
--  * Staff roles live in auth.users.raw_app_meta_data ("role": "records" | "admin").
--    app_metadata can only be changed server-side (SQL editor / service role), never by the user,
--    so the browser cannot grant itself Records or Admin access.
--  * Students can only read their own rows and only INSERT requests with a fixed starting status.
--  * Only Records/Admin can change a status, post finance entries, or mark anything verified.
--  * The existing owner-scoped policies on public.profiles are untouched; one extra read-only
--    policy lets Records/Admin look students up.
--
-- GRANT A ROLE (run in the Supabase SQL editor, never from the website):
--   update auth.users
--      set raw_app_meta_data = coalesce(raw_app_meta_data,'{}'::jsonb) || '{"role":"records"}'
--    where email = 'records.officer@example.com';       -- use "admin" for administrators
-- The person must sign out and in again for the new role to appear in their token.

-- ---------------------------------------------------------------- helpers
create or replace function public.au_role() returns text
language sql stable as $$
  select coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '')
$$;

create or replace function public.au_is_staff() returns boolean
language sql stable as $$
  select public.au_role() in ('records', 'admin')
$$;

-- ---------------------------------------------------------------- verifications
create table if not exists public.verifications (
  id             uuid primary key default gen_random_uuid(),
  student_id     uuid not null references auth.users(id) on delete cascade,
  student_name   text not null default '' check (char_length(student_name) <= 120),
  student_number text not null default '' check (char_length(student_number) <= 40),
  item_type      text not null check (item_type in ('project', 'achievement', 'club')),
  item_id        text not null check (char_length(item_id) <= 64),
  item_title     text not null default '' check (char_length(item_title) <= 200),
  item_snapshot  jsonb not null default '{}'::jsonb,
  item_hash      text not null check (char_length(item_hash) = 64),
  evidence       text[] not null default '{}',
  status         text not null default 'pending' check (status in ('pending', 'verified', 'rejected')),
  reviewer_note  text check (char_length(reviewer_note) <= 1000),
  reviewed_by    uuid references auth.users(id),
  reviewed_at    timestamptz,
  created_at     timestamptz not null default now()
);

create unique index if not exists verifications_open_uq
  on public.verifications (student_id, item_type, item_id, item_hash)
  where status in ('pending', 'verified');
create index if not exists verifications_status_idx on public.verifications (status, created_at desc);

alter table public.verifications enable row level security;

drop policy if exists verifications_student_select on public.verifications;
create policy verifications_student_select on public.verifications
  for select to authenticated using (student_id = auth.uid());

drop policy if exists verifications_student_insert on public.verifications;
create policy verifications_student_insert on public.verifications
  for insert to authenticated
  with check (student_id = auth.uid() and status = 'pending'
              and reviewed_by is null and reviewed_at is null and reviewer_note is null);

drop policy if exists verifications_staff_select on public.verifications;
create policy verifications_staff_select on public.verifications
  for select to authenticated using (public.au_is_staff());

drop policy if exists verifications_staff_update on public.verifications;
create policy verifications_staff_update on public.verifications
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create or replace function public.au_verifications_guard() returns trigger
language plpgsql as $$
begin
  -- staff may only change the decision; everything the student submitted is frozen
  new.student_id := old.student_id;   new.student_name := old.student_name;
  new.student_number := old.student_number; new.item_type := old.item_type;
  new.item_id := old.item_id;         new.item_title := old.item_title;
  new.item_snapshot := old.item_snapshot; new.item_hash := old.item_hash;
  new.evidence := old.evidence;       new.created_at := old.created_at;
  if new.status is distinct from old.status then
    new.reviewed_by := auth.uid();
    new.reviewed_at := now();
  end if;
  return new;
end $$;
drop trigger if exists au_verifications_guard on public.verifications;
create trigger au_verifications_guard before update on public.verifications
  for each row execute function public.au_verifications_guard();

-- ---------------------------------------------------------------- recommendation requests
create table if not exists public.recommendation_requests (
  id                 uuid primary key default gen_random_uuid(),
  student_id         uuid not null references auth.users(id) on delete cascade,
  student_name       text not null check (char_length(student_name) between 1 and 120),
  student_number     text not null check (char_length(student_number) between 1 and 40),
  student_email      text not null check (char_length(student_email) between 3 and 200),
  student_phone      text check (char_length(student_phone) <= 40),
  programme          text check (char_length(programme) <= 160),
  staff_name         text not null check (char_length(staff_name) between 1 and 120),
  staff_email        text not null check (char_length(staff_email) between 3 and 200),
  staff_title        text check (char_length(staff_title) <= 120),
  staff_department   text check (char_length(staff_department) <= 160),
  relationship       text check (char_length(relationship) <= 80),
  course_or_context  text check (char_length(course_or_context) <= 200),
  purpose            text not null check (char_length(purpose) <= 80),
  recipient_org      text not null check (char_length(recipient_org) between 1 and 200),
  recipient_contact  text check (char_length(recipient_contact) <= 300),
  deadline           date not null,
  personal_statement text not null check (char_length(personal_statement) between 50 and 3000),
  status             text not null default 'submitted'
                     check (status in ('submitted', 'in_review', 'forwarded', 'completed', 'declined')),
  records_note       text check (char_length(records_note) <= 1000),
  handled_by         uuid references auth.users(id),
  handled_at         timestamptz,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);
create index if not exists recommendation_requests_status_idx
  on public.recommendation_requests (status, created_at desc);

alter table public.recommendation_requests enable row level security;

drop policy if exists recs_student_select on public.recommendation_requests;
create policy recs_student_select on public.recommendation_requests
  for select to authenticated using (student_id = auth.uid());

drop policy if exists recs_student_insert on public.recommendation_requests;
create policy recs_student_insert on public.recommendation_requests
  for insert to authenticated
  with check (student_id = auth.uid() and status = 'submitted'
              and records_note is null and handled_by is null and handled_at is null);

drop policy if exists recs_staff_select on public.recommendation_requests;
create policy recs_staff_select on public.recommendation_requests
  for select to authenticated using (public.au_is_staff());

drop policy if exists recs_staff_update on public.recommendation_requests;
create policy recs_staff_update on public.recommendation_requests
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create or replace function public.au_recs_guard() returns trigger
language plpgsql as $$
declare k text;
begin
  -- staff may only change status and note
  new := jsonb_populate_record(old,
          to_jsonb(old) || jsonb_build_object('status', new.status, 'records_note', new.records_note));
  new.handled_by := auth.uid();
  new.handled_at := now();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists au_recs_guard on public.recommendation_requests;
create trigger au_recs_guard before update on public.recommendation_requests
  for each row execute function public.au_recs_guard();

-- ---------------------------------------------------------------- finance ledger (staff-written, student read-only)
create table if not exists public.finance_ledger (
  id          uuid primary key default gen_random_uuid(),
  student_id  uuid not null references auth.users(id) on delete cascade,
  term        text not null check (char_length(term) between 1 and 80),
  description text not null check (char_length(description) between 1 and 200),
  kind        text not null check (kind in ('charge', 'payment', 'credit')),
  amount      numeric(12, 2) not null check (amount > 0),
  status      text not null default 'posted' check (status in ('posted', 'pending')),
  reference   text check (char_length(reference) <= 80),
  created_by  uuid references auth.users(id) default auth.uid(),
  created_at  timestamptz not null default now()
);
create index if not exists finance_ledger_student_idx on public.finance_ledger (student_id, created_at desc);

alter table public.finance_ledger enable row level security;

drop policy if exists ledger_student_select on public.finance_ledger;
create policy ledger_student_select on public.finance_ledger
  for select to authenticated using (student_id = auth.uid());

drop policy if exists ledger_staff_select on public.finance_ledger;
create policy ledger_staff_select on public.finance_ledger
  for select to authenticated using (public.au_is_staff());

drop policy if exists ledger_staff_insert on public.finance_ledger;
create policy ledger_staff_insert on public.finance_ledger
  for insert to authenticated with check (public.au_is_staff());

drop policy if exists ledger_staff_update on public.finance_ledger;
create policy ledger_staff_update on public.finance_ledger
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());
-- No delete policy: corrections are made with an offsetting entry so there is always an audit trail.

-- ---------------------------------------------------------------- payment plan requests
create table if not exists public.payment_plan_requests (
  id                    uuid primary key default gen_random_uuid(),
  student_id            uuid not null references auth.users(id) on delete cascade,
  student_name          text not null check (char_length(student_name) between 1 and 120),
  student_number        text not null check (char_length(student_number) between 1 and 40),
  student_email         text not null check (char_length(student_email) between 3 and 200),
  student_phone         text check (char_length(student_phone) <= 40),
  amount_requested      numeric(12, 2) not null check (amount_requested > 0),
  instalments           int not null check (instalments between 2 and 12),
  frequency             text not null check (frequency in ('monthly', 'fortnightly')),
  first_payment_date    date not null,
  reason                text not null check (char_length(reason) between 20 and 1500),
  status                text not null default 'submitted'
                        check (status in ('submitted', 'in_review', 'approved', 'declined')),
  approved_instalments  int check (approved_instalments between 1 and 12),
  records_note          text check (char_length(records_note) <= 1000),
  handled_by            uuid references auth.users(id),
  handled_at            timestamptz,
  created_at            timestamptz not null default now()
);
-- one open request per student
create unique index if not exists payment_plan_one_open_uq
  on public.payment_plan_requests (student_id) where status in ('submitted', 'in_review');

alter table public.payment_plan_requests enable row level security;

drop policy if exists plans_student_select on public.payment_plan_requests;
create policy plans_student_select on public.payment_plan_requests
  for select to authenticated using (student_id = auth.uid());

drop policy if exists plans_student_insert on public.payment_plan_requests;
create policy plans_student_insert on public.payment_plan_requests
  for insert to authenticated
  with check (student_id = auth.uid() and status = 'submitted'
              and records_note is null and handled_by is null
              and handled_at is null and approved_instalments is null);

drop policy if exists plans_staff_select on public.payment_plan_requests;
create policy plans_staff_select on public.payment_plan_requests
  for select to authenticated using (public.au_is_staff());

drop policy if exists plans_staff_update on public.payment_plan_requests;
create policy plans_staff_update on public.payment_plan_requests
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create or replace function public.au_plans_guard() returns trigger
language plpgsql as $$
begin
  new := jsonb_populate_record(old,
          to_jsonb(old) || jsonb_build_object('status', new.status,
                                              'records_note', new.records_note,
                                              'approved_instalments', new.approved_instalments));
  new.handled_by := auth.uid();
  new.handled_at := now();
  return new;
end $$;
drop trigger if exists au_plans_guard on public.payment_plan_requests;
create trigger au_plans_guard before update on public.payment_plan_requests
  for each row execute function public.au_plans_guard();

-- ---------------------------------------------------------------- staff read access to existing data
-- Read-only; the existing owner-scoped policies on profiles stay exactly as they are.
drop policy if exists profiles_staff_read on public.profiles;
create policy profiles_staff_read on public.profiles
  for select to authenticated using (public.au_is_staff());

-- Lets Records open evidence files (club pictures, certificates) in the student's folder.
-- Students keep whatever owner-only policies the bucket already has.
drop policy if exists student_content_staff_read on storage.objects;
create policy student_content_staff_read on storage.objects
  for select to authenticated
  using (bucket_id = 'student-content' and public.au_is_staff());
