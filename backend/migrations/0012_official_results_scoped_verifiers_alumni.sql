-- Official Records-managed results, scoped achievement verifiers, and reviewed alumni email changes.
-- Requires migrations 0008 and 0011.

create table if not exists public.student_registry (
  student_id      uuid primary key references auth.users(id) on delete cascade,
  student_number  text not null unique check (char_length(student_number) between 1 and 40),
  verification_note text not null check (char_length(verification_note) between 5 and 1000),
  verified_by     uuid references auth.users(id),
  verified_at     timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
alter table public.student_registry enable row level security;
grant select, insert, update on public.student_registry to authenticated;
drop policy if exists student_registry_self_select on public.student_registry;
create policy student_registry_self_select on public.student_registry
  for select to authenticated using (student_id = auth.uid());
drop policy if exists student_registry_staff_select on public.student_registry;
create policy student_registry_staff_select on public.student_registry
  for select to authenticated using (public.au_is_staff());
drop policy if exists student_registry_staff_insert on public.student_registry;
create policy student_registry_staff_insert on public.student_registry
  for insert to authenticated with check (public.au_is_staff());
drop policy if exists student_registry_staff_update on public.student_registry;
create policy student_registry_staff_update on public.student_registry
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create table if not exists public.student_registry_history (
  id                    bigint generated always as identity primary key,
  student_id            uuid not null references auth.users(id) on delete cascade,
  old_student_number    text not null,
  new_student_number    text not null,
  old_verification_note text not null,
  new_verification_note text not null,
  actor_id              uuid references auth.users(id),
  created_at            timestamptz not null default now()
);
alter table public.student_registry_history enable row level security;
grant select on public.student_registry_history to authenticated;
drop policy if exists student_registry_history_staff_select on public.student_registry_history;
create policy student_registry_history_staff_select on public.student_registry_history
  for select to authenticated using (public.au_is_staff());

create or replace function public.au_guard_student_registry() returns trigger
language plpgsql as $$
begin
  if not public.au_is_staff() then raise exception 'Only Records Office staff can maintain the official student registry.'; end if;
  if tg_op = 'UPDATE' then
    new.student_id := old.student_id;
    new.verified_at := old.verified_at;
  end if;
  new.student_number := btrim(new.student_number);
  new.verification_note := btrim(new.verification_note);
  if char_length(new.student_number) not between 1 and 40 then
    raise exception 'Enter a valid official student number.';
  end if;
  if char_length(new.verification_note) not between 5 and 1000 then
    raise exception 'Record the official identity check in at least 5 characters.';
  end if;
  new.verified_by := auth.uid();
  new.verified_at := now();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists au_guard_student_registry on public.student_registry;
create trigger au_guard_student_registry before insert or update on public.student_registry
  for each row execute function public.au_guard_student_registry();

create or replace function public.au_log_student_registry_update() returns trigger
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if old.student_number is distinct from new.student_number
     or old.verification_note is distinct from new.verification_note then
    insert into public.student_registry_history(
      student_id, old_student_number, new_student_number,
      old_verification_note, new_verification_note, actor_id
    ) values (
      old.student_id, old.student_number, new.student_number,
      old.verification_note, new.verification_note, auth.uid()
    );
  end if;
  return new;
end $$;
drop trigger if exists au_log_student_registry_update on public.student_registry;
create trigger au_log_student_registry_update after update on public.student_registry
  for each row execute function public.au_log_student_registry_update();

create or replace function public.au_link_student_identity(
  p_student_number text,
  p_user_id uuid,
  p_verification_note text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if not public.au_is_staff() then raise exception 'Only Records Office staff can maintain the official student registry.'; end if;
  if p_user_id is null or not exists (select 1 from auth.users u where u.id = p_user_id) then
    raise exception 'The student account was not found.';
  end if;
  if btrim(coalesce(p_student_number, '')) = '' then
    raise exception 'Enter an official student number.';
  end if;
  if char_length(btrim(coalesce(p_verification_note, ''))) not between 5 and 1000 then
    raise exception 'Record the official identity check in at least 5 characters.';
  end if;
  insert into public.student_registry(student_id, student_number, verification_note)
  values (p_user_id, btrim(p_student_number), btrim(p_verification_note))
  on conflict (student_id) do update
    set student_number = excluded.student_number, verification_note = excluded.verification_note;
end $$;
revoke all on function public.au_link_student_identity(text, uuid, text) from public;
revoke all on function public.au_link_student_identity(text, uuid, text) from anon;
grant execute on function public.au_link_student_identity(text, uuid, text) to authenticated;

create table if not exists public.official_results (
  id              uuid primary key default gen_random_uuid(),
  student_id      uuid not null references auth.users(id) on delete cascade,
  student_number  text not null check (char_length(student_number) between 1 and 40),
  course_code     text not null check (char_length(course_code) between 1 and 40),
  course          text not null check (char_length(course) between 1 and 160),
  grade           text not null check (char_length(grade) between 1 and 40),
  semester        text not null check (char_length(semester) between 1 and 60),
  created_by      uuid references auth.users(id),
  updated_by      uuid references auth.users(id),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  unique (student_id, course_code, semester)
);

alter table public.official_results enable row level security;
grant select, insert, update on public.official_results to authenticated;
drop policy if exists official_results_student_select on public.official_results;
create policy official_results_student_select on public.official_results
  for select to authenticated using (student_id = auth.uid());
drop policy if exists official_results_staff_select on public.official_results;
create policy official_results_staff_select on public.official_results
  for select to authenticated using (public.au_is_staff());
drop policy if exists official_results_staff_insert on public.official_results;
create policy official_results_staff_insert on public.official_results
  for insert to authenticated with check (public.au_is_staff());
drop policy if exists official_results_staff_update on public.official_results;
create policy official_results_staff_update on public.official_results
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create table if not exists public.official_results_history (
  id          bigint generated always as identity primary key,
  result_id   uuid not null references public.official_results(id) on delete cascade,
  student_id  uuid not null references auth.users(id) on delete cascade,
  actor_id    uuid references auth.users(id),
  old_data    jsonb not null,
  new_data    jsonb not null,
  created_at  timestamptz not null default now()
);
alter table public.official_results_history enable row level security;
grant select on public.official_results_history to authenticated;
drop policy if exists official_results_history_student_select on public.official_results_history;
create policy official_results_history_student_select on public.official_results_history
  for select to authenticated using (student_id = auth.uid());
drop policy if exists official_results_history_staff_select on public.official_results_history;
create policy official_results_history_staff_select on public.official_results_history
  for select to authenticated using (public.au_is_staff());

create or replace function public.au_guard_official_result() returns trigger
language plpgsql as $$
declare
  official_number text;
begin
  if not public.au_is_staff() then raise exception 'Only Records Office staff can manage official results.'; end if;
  select r.student_number into official_number
    from public.student_registry r where r.student_id = new.student_id;
  if not found then raise exception 'Link this account to a verified official student number before adding results.'; end if;
  new.student_number := official_number;
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
  else
    new.id := old.id;
    new.student_id := old.student_id;
    new.student_number := old.student_number;
    new.course_code := old.course_code;
    new.created_by := old.created_by;
    new.created_at := old.created_at;
  end if;
  new.updated_by := auth.uid();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists au_guard_official_result on public.official_results;
create trigger au_guard_official_result before insert or update on public.official_results
  for each row execute function public.au_guard_official_result();

create or replace function public.au_log_official_result_update() returns trigger
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if old.course is distinct from new.course
     or old.grade is distinct from new.grade
     or old.semester is distinct from new.semester then
    insert into public.official_results_history(result_id, student_id, actor_id, old_data, new_data)
    values (
      old.id, old.student_id, auth.uid(),
      jsonb_build_object('course_code', old.course_code, 'course', old.course, 'grade', old.grade, 'semester', old.semester),
      jsonb_build_object('course_code', new.course_code, 'course', new.course, 'grade', new.grade, 'semester', new.semester)
    );
  end if;
  return new;
end $$;
drop trigger if exists au_log_official_result_update on public.official_results;
create trigger au_log_official_result_update after update on public.official_results
  for each row execute function public.au_log_official_result_update();

create or replace function public.au_import_official_results(p_rows jsonb) returns integer
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  row_data jsonb;
  matches integer;
  target_id uuid;
  total integer := 0;
  v_student_number text;
  course_code text;
  course_name text;
  grade_value text;
  semester_value text;
begin
  if not public.au_is_staff() then raise exception 'Only Records Office staff can import official results.'; end if;
  if p_rows is null or jsonb_typeof(p_rows) is distinct from 'array' then
    raise exception 'Provide a JSON array of official result rows.';
  end if;
  if jsonb_array_length(p_rows) not between 1 and 1000 then
    raise exception 'Import between 1 and 1,000 result rows at a time.';
  end if;

  for row_data in select value from jsonb_array_elements(p_rows)
  loop
    if jsonb_typeof(row_data) is distinct from 'object' then
      raise exception 'Every imported result must be an object with the required fields.';
    end if;
    v_student_number := btrim(coalesce(row_data ->> 'student_id', ''));
    course_code := btrim(coalesce(row_data ->> 'course_code', ''));
    course_name := btrim(coalesce(row_data ->> 'course', ''));
    grade_value := btrim(coalesce(row_data ->> 'grade', ''));
    semester_value := btrim(coalesce(row_data ->> 'semester', ''));
    if v_student_number = '' or course_code = '' or course_name = '' or grade_value = '' or semester_value = '' then
      raise exception 'Each row needs student_id, course_code, course, grade, and semester.';
    end if;

    select count(*), (array_agg(r.student_id))[1] into matches, target_id
      from public.student_registry r
     where r.student_number = v_student_number;
    if matches <> 1 then
      raise exception 'Student ID % matched % registry entries; every imported ID must match exactly one student.', v_student_number, matches;
    end if;

    insert into public.official_results(student_id, student_number, course_code, course, grade, semester)
    values (target_id, v_student_number, course_code, course_name, grade_value, semester_value)
    on conflict (student_id, course_code, semester)
    do update set course = excluded.course, grade = excluded.grade;
    total := total + 1;
  end loop;
  return total;
end $$;

revoke all on function public.au_import_official_results(jsonb) from public;
revoke all on function public.au_import_official_results(jsonb) from anon;
grant execute on function public.au_import_official_results(jsonb) to authenticated;

create or replace function public.au_guard_achievement_category() returns trigger
language plpgsql as $$
declare
  item jsonb;
  category text;
  allowed_categories text[] := array[
    'Academic', 'Leadership', 'Research', 'Community Service',
    'Sports', 'Arts & Culture', 'Other'
  ];
begin
  if new.data ? 'achievements' and new.data -> 'achievements' <> 'null'::jsonb then
    if jsonb_typeof(new.data -> 'achievements') is distinct from 'array' then
      raise exception 'Achievements must be stored as a list.';
    end if;
    for item in select value from jsonb_array_elements(new.data -> 'achievements')
    loop
      if jsonb_typeof(item) is distinct from 'object' then
        raise exception 'Each achievement must be a record.';
      end if;
      if item ? 'category' then
        if jsonb_typeof(item -> 'category') is distinct from 'string' then
          raise exception 'Achievement categories must be text.';
        end if;
        category := item ->> 'category';
        if not (category = any(allowed_categories)) then
          raise exception 'Choose a valid achievement category.';
        end if;
      end if;
    end loop;
  end if;
  return new;
end $$;
drop trigger if exists au_guard_achievement_category on public.profiles;
create trigger au_guard_achievement_category before insert or update of data on public.profiles
  for each row execute function public.au_guard_achievement_category();

create table if not exists public.verifier_assignments (
  id                  uuid primary key default gen_random_uuid(),
  user_id             uuid not null unique references auth.users(id) on delete cascade,
  verifier_role       text not null check (verifier_role in ('lecturer', 'department_staff', 'supervisor')),
  allowed_student_ids uuid[] not null check (cardinality(allowed_student_ids) between 1 and 500),
  allowed_item_types  text[] not null check (
    cardinality(allowed_item_types) between 1 and 3
    and allowed_item_types <@ array['project', 'achievement', 'club']::text[]
  ),
  assigned_by         uuid references auth.users(id),
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
alter table public.verifier_assignments enable row level security;
grant select, insert, update, delete on public.verifier_assignments to authenticated;
drop policy if exists verifier_assignment_self_select on public.verifier_assignments;
create policy verifier_assignment_self_select on public.verifier_assignments
  for select to authenticated using (user_id = auth.uid());
drop policy if exists verifier_assignment_admin_manage on public.verifier_assignments;
create policy verifier_assignment_admin_manage on public.verifier_assignments
  for all to authenticated using (public.au_role() = 'admin')
  with check (public.au_role() = 'admin');

create or replace function public.au_guard_verifier_assignment() returns trigger
language plpgsql as $$
begin
  if public.au_role() <> 'admin' then raise exception 'Only administrators can assign verifiers.'; end if;
  if tg_op = 'INSERT' then
    new.assigned_by := auth.uid();
  else
    new.id := old.id;
    new.user_id := old.user_id;
    new.created_at := old.created_at;
    new.assigned_by := auth.uid();
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists au_guard_verifier_assignment on public.verifier_assignments;
create trigger au_guard_verifier_assignment before insert or update on public.verifier_assignments
  for each row execute function public.au_guard_verifier_assignment();

create or replace function public.au_save_verifier_assignment(
  p_user_id uuid,
  p_verifier_role text,
  p_student_numbers text[],
  p_item_types text[]
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  v_student_number text;
  target_id uuid;
  match_count integer;
  target_ids uuid[] := '{}';
begin
  if public.au_role() <> 'admin' then raise exception 'Only administrators can assign verifiers.'; end if;
  if p_user_id is null or p_verifier_role is null
     or p_verifier_role not in ('lecturer', 'department_staff', 'supervisor') then
    raise exception 'Choose a verifier account and a valid verifier role.';
  end if;
  if p_student_numbers is null or cardinality(p_student_numbers) not between 1 and 500
     or p_item_types is null or cardinality(p_item_types) not between 1 and 3
     or not (p_item_types <@ array['project', 'achievement', 'club']::text[]) then
    raise exception 'Assign at least one student and one valid item category.';
  end if;
  if not exists (select 1 from auth.users u where u.id = p_user_id) then
    raise exception 'The verifier account was not found.';
  end if;
  foreach v_student_number in array p_student_numbers
  loop
    select count(*), (array_agg(r.student_id))[1] into match_count, target_id
      from public.student_registry r
     where r.student_number = btrim(v_student_number);
    if match_count <> 1 then
      raise exception 'Student ID % matched % registry entries; each assignment must match exactly one student.', v_student_number, match_count;
    end if;
    if target_id = any(target_ids) then raise exception 'Remove duplicate student IDs from the assignment.'; end if;
    target_ids := array_append(target_ids, target_id);
  end loop;

  insert into public.verifier_assignments(user_id, verifier_role, allowed_student_ids, allowed_item_types)
  values (p_user_id, p_verifier_role, target_ids, p_item_types)
  on conflict (user_id) do update
    set verifier_role = excluded.verifier_role,
        allowed_student_ids = excluded.allowed_student_ids,
        allowed_item_types = excluded.allowed_item_types;
end $$;
revoke all on function public.au_save_verifier_assignment(uuid, text, text[], text[]) from public;
revoke all on function public.au_save_verifier_assignment(uuid, text, text[], text[]) from anon;
grant execute on function public.au_save_verifier_assignment(uuid, text, text[], text[]) to authenticated;

create or replace function public.au_can_verify(p_student_id uuid, p_item_type text) returns boolean
language sql stable as $$
  select public.au_is_staff() or exists (
    select 1 from public.verifier_assignments a
     where a.user_id = auth.uid()
       and p_student_id = any(a.allowed_student_ids)
       and p_item_type = any(a.allowed_item_types)
  )
$$;
revoke all on function public.au_can_verify(uuid, text) from public;
grant execute on function public.au_can_verify(uuid, text) to authenticated;

drop policy if exists verifications_staff_select on public.verifications;
drop policy if exists verifications_staff_update on public.verifications;
drop policy if exists verifications_authorized_select on public.verifications;
create policy verifications_authorized_select on public.verifications
  for select to authenticated using (public.au_can_verify(student_id, item_type));
drop policy if exists verifications_authorized_update on public.verifications;
create policy verifications_authorized_update on public.verifications
  for update to authenticated
  using (public.au_can_verify(student_id, item_type))
  with check (public.au_can_verify(student_id, item_type));

create table if not exists public.alumni_access_requests (
  id                uuid primary key default gen_random_uuid(),
  student_id        uuid not null references auth.users(id) on delete cascade,
  student_number    text not null check (char_length(student_number) between 1 and 40),
  university_email  text not null check (char_length(university_email) between 3 and 200),
  personal_email    text not null check (char_length(personal_email) between 3 and 200),
  status            text not null default 'pending' check (status in ('pending', 'awaiting_confirmation', 'approved', 'rejected')),
  records_note      text check (records_note is null or char_length(records_note) <= 1000),
  handled_by        uuid references auth.users(id),
  handled_at        timestamptz,
  created_at        timestamptz not null default now()
);
create unique index if not exists alumni_access_one_pending_per_student
  on public.alumni_access_requests(student_id) where status in ('pending', 'awaiting_confirmation');
alter table public.alumni_access_requests enable row level security;
grant select, update on public.alumni_access_requests to authenticated;
drop policy if exists alumni_access_student_select on public.alumni_access_requests;
create policy alumni_access_student_select on public.alumni_access_requests
  for select to authenticated using (student_id = auth.uid());
drop policy if exists alumni_access_staff_select on public.alumni_access_requests;
create policy alumni_access_staff_select on public.alumni_access_requests
  for select to authenticated using (public.au_is_staff());
drop policy if exists alumni_access_staff_update on public.alumni_access_requests;
create policy alumni_access_staff_update on public.alumni_access_requests
  for update to authenticated using (public.au_is_staff()) with check (public.au_is_staff());

create or replace function public.au_request_alumni_access(
  p_student_number text,
  p_university_email text,
  p_personal_email text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  target_id uuid;
  match_count integer;
  v_student_number text := btrim(coalesce(p_student_number, ''));
  university_email text := lower(btrim(coalesce(p_university_email, '')));
  personal_email text := lower(btrim(coalesce(p_personal_email, '')));
begin
  if char_length(v_student_number) not between 1 and 40
     or char_length(university_email) not between 3 and 200
     or char_length(personal_email) not between 3 and 200
     or position('@' in university_email) < 2
     or position('@' in personal_email) < 2
     or university_email = personal_email then
    raise exception 'Enter your student number, current university email, and a different personal email.';
  end if;

  select count(*), (array_agg(r.student_id))[1] into match_count, target_id
    from public.student_registry r
    join auth.users u on u.id = r.student_id
   where r.student_number = v_student_number
     and lower(u.email) = university_email;
  if match_count <> 1 then return; end if;
  if exists (
    select 1 from public.alumni_access_requests r
     where r.student_id = target_id and r.status in ('pending', 'awaiting_confirmation')
  ) or exists (
    select 1 from public.alumni_access_requests r
     where r.student_id = target_id and r.created_at > now() - interval '24 hours'
  ) then
    return;
  end if;

  insert into public.alumni_access_requests(student_id, student_number, university_email, personal_email)
  values (target_id, v_student_number, university_email, personal_email);
exception when unique_violation then
  return;
end $$;
revoke all on function public.au_request_alumni_access(text, text, text) from public;
grant execute on function public.au_request_alumni_access(text, text, text) to anon, authenticated;

-- Category is a fixed university-approved reporting field and is part of the verified snapshot.
create or replace function public.au_guard_achievement_change_insert() returns trigger
language plpgsql as $$
declare
  item jsonb;
  verified boolean;
  allowed_keys text[];
  k text;
  max_length integer;
begin
  if new.student_id <> auth.uid() then raise exception 'You can only request changes to your own achievements.'; end if;
  if new.action = 'delete' and new.proposed_data <> '{}'::jsonb then
    raise exception 'A deletion request cannot include replacement fields.';
  end if;
  if new.action = 'correct' and new.proposed_data = '{}'::jsonb then
    raise exception 'Provide at least one proposed correction.';
  end if;

  select exists (
    select 1
      from public.verifications v
      join public.profiles p on p.id = v.student_id
      cross join lateral jsonb_array_elements(coalesce(p.data -> new.collection_name, '[]'::jsonb)) as arr(item)
     where v.student_id = new.student_id and v.status = 'verified'
       and v.item_id = new.item_id and arr.item ->> 'id' = v.item_id
       and v.item_type = case new.collection_name
         when 'projects' then 'project' when 'achievements' then 'achievement' else 'club' end
       and not exists (
         select 1 from jsonb_each(v.item_snapshot) as snapshot(field_name, expected)
          where (arr.item -> snapshot.field_name) is distinct from snapshot.expected
       )
  ) into verified;
  if not verified then raise exception 'Only verified achievements can be sent for review.'; end if;

  select arr.item into item
    from public.profiles p,
         jsonb_array_elements(coalesce(p.data -> new.collection_name, '[]'::jsonb)) as arr(item)
   where p.id = new.student_id and arr.item ->> 'id' = new.item_id limit 1;
  if item is null then raise exception 'The achievement is no longer in your profile.'; end if;

  allowed_keys := case new.collection_name
    when 'projects' then array['title', 'description', 'tech', 'github']
    when 'achievements' then array['title', 'date', 'category', 'issuer', 'description']
    else array['name', 'type', 'role']
  end;
  for k in select jsonb_object_keys(new.proposed_data)
  loop
    if not k = any(allowed_keys) then raise exception 'A proposed field is not editable.'; end if;
    if jsonb_typeof(new.proposed_data -> k) <> 'string' then
      raise exception 'Correction fields must be text.';
    end if;
    max_length := case k
      when 'title' then case new.collection_name when 'projects' then 120 else 160 end
      when 'name' then 120
      when 'description' then case new.collection_name when 'projects' then 1000 else 800 end
      when 'tech' then 200
      when 'github' then 300
      when 'date' then 10
      when 'category' then 40
      when 'issuer' then 160
      when 'type' then 20
      when 'role' then 80
      else 0
    end;
    if char_length(new.proposed_data ->> k) > max_length then
      raise exception 'A correction field exceeds its allowed length.';
    end if;
  end loop;
  if new.action = 'correct' then
    if new.collection_name = 'projects'
       and new.proposed_data ? 'github'
       and new.proposed_data ->> 'github' <> ''
       and new.proposed_data ->> 'github' !~* '^https://' then
      raise exception 'Project links must start with https://.';
    end if;
    if new.collection_name = 'clubs' and new.proposed_data ? 'type'
       and new.proposed_data ->> 'type' not in ('Club', 'Association', 'Activity') then
      raise exception 'Choose a valid club or activity type.';
    end if;
    if new.collection_name = 'achievements' and new.proposed_data ? 'category'
       and new.proposed_data ->> 'category' not in ('Academic', 'Leadership', 'Research', 'Community Service', 'Sports', 'Arts & Culture', 'Other') then
      raise exception 'Choose a valid achievement category.';
    end if;
    if (new.collection_name = 'projects' and new.proposed_data ? 'title' and btrim(new.proposed_data ->> 'title') = '')
       or (new.collection_name = 'achievements' and new.proposed_data ? 'title' and btrim(new.proposed_data ->> 'title') = '')
       or (new.collection_name = 'clubs' and new.proposed_data ? 'name' and btrim(new.proposed_data ->> 'name') = '') then
      raise exception 'Titles and names cannot be blank.';
    end if;
  end if;
  return new;
end $$;

create or replace function public.au_review_achievement_change(
  p_request_id uuid,
  p_approve boolean,
  p_note text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  req public.achievement_change_requests%rowtype;
  profile_row public.profiles%rowtype;
  current_item jsonb;
  updated_item jsonb;
  updated_array jsonb;
  allowed_keys text[];
  k text;
begin
  if not public.au_is_staff() then raise exception 'Records Office access is required.'; end if;
  if p_approve is null then raise exception 'Choose whether to approve or decline this request.'; end if;
  if p_note is not null and char_length(p_note) > 1000 then raise exception 'The review note is too long.'; end if;
  if not p_approve and char_length(btrim(coalesce(p_note, ''))) < 5 then
    raise exception 'Provide a short reason when declining a change request.';
  end if;
  select * into req from public.achievement_change_requests where id = p_request_id for update;
  if not found or req.status <> 'pending' then raise exception 'This change request is no longer pending.'; end if;

  if p_approve then
    select * into profile_row from public.profiles where id = req.student_id for update;
    if not found then raise exception 'Student profile not found.'; end if;
    select arr.item into current_item
      from jsonb_array_elements(coalesce(profile_row.data -> req.collection_name, '[]'::jsonb)) as arr(item)
     where arr.item ->> 'id' = req.item_id limit 1;
    if current_item is null then raise exception 'The achievement is no longer in the student profile.'; end if;

    update public.verifications
       set status = 'rejected', reviewer_note = 'Superseded by an approved student change request.'
     where student_id = req.student_id and item_id = req.item_id and status = 'verified'
       and item_type = case req.collection_name
         when 'projects' then 'project' when 'achievements' then 'achievement' else 'club' end;

    if req.action = 'delete' then
      select coalesce(jsonb_agg(arr.item order by arr.ordinality), '[]'::jsonb) into updated_array
        from jsonb_array_elements(coalesce(profile_row.data -> req.collection_name, '[]'::jsonb))
          with ordinality as arr(item, ordinality)
       where arr.item ->> 'id' <> req.item_id;
    else
      allowed_keys := case req.collection_name
        when 'projects' then array['title', 'description', 'tech', 'github']
        when 'achievements' then array['title', 'date', 'category', 'issuer', 'description']
        else array['name', 'type', 'role']
      end;
      if req.proposed_data = '{}'::jsonb then raise exception 'No proposed corrections were provided.'; end if;
      updated_item := current_item;
      for k in select jsonb_object_keys(req.proposed_data)
      loop
        if not k = any(allowed_keys) then raise exception 'A proposed field is not editable.'; end if;
        if req.collection_name = 'achievements' and k = 'category'
           and req.proposed_data ->> k not in ('Academic', 'Leadership', 'Research', 'Community Service', 'Sports', 'Arts & Culture', 'Other') then
          raise exception 'Choose a valid achievement category.';
        end if;
        updated_item := jsonb_set(updated_item, array[k], req.proposed_data -> k, true);
      end loop;
      select coalesce(jsonb_agg(
        case when arr.item ->> 'id' = req.item_id then updated_item else arr.item end
        order by arr.ordinality
      ), '[]'::jsonb)
        into updated_array
        from jsonb_array_elements(coalesce(profile_row.data -> req.collection_name, '[]'::jsonb))
          with ordinality as arr(item, ordinality);
    end if;

    perform set_config('myau.approved_achievement_change', 'on', true);
    update public.profiles
       set data = jsonb_set(coalesce(data, '{}'::jsonb), array[req.collection_name], updated_array, true),
           updated_at = now()
     where id = req.student_id;
    insert into public.achievement_history(
      student_id, collection_name, item_id, action, actor_id, request_id, old_data, new_data
    ) values (
      req.student_id, req.collection_name, req.item_id,
      case req.action when 'delete' then 'deletion_approved' else 'correction_approved' end,
      auth.uid(), req.id, current_item, case req.action when 'delete' then null else updated_item end
    );
  else
    insert into public.achievement_history(
      student_id, collection_name, item_id, action, actor_id, request_id, old_data
    ) values (
      req.student_id, req.collection_name, req.item_id, 'change_rejected',
      auth.uid(), req.id, req.proposed_data
    );
  end if;

  update public.achievement_change_requests
     set status = case when p_approve then 'approved' else 'rejected' end,
         records_note = nullif(btrim(p_note), ''),
         handled_by = auth.uid(), handled_at = now()
   where id = req.id;
end $$;

update public.verifications
   set status = 'rejected',
       reviewer_note = 'Student-submitted grades are no longer treated as official. Records Office results are displayed separately.'
 where item_type = 'result' and status in ('pending', 'verified');

drop policy if exists verifications_student_insert on public.verifications;
create policy verifications_student_insert on public.verifications
  for insert to authenticated
  with check (
    student_id = auth.uid()
    and item_type in ('project', 'achievement', 'club')
    and status = 'pending'
    and reviewed_by is null and reviewed_at is null and reviewer_note is null
  );
