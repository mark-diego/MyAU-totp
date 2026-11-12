-- Adds consent-based lecturer access, lecturer recommendation workspaces,
-- and staff-reviewed changes to verified achievements.
-- Requires migrations 0008 and 0010.

alter table public.recommendation_requests
  add column if not exists lecturer_summary text
    check (lecturer_summary is null or char_length(lecturer_summary) <= 5000),
  add column if not exists lecturer_status text
    check (lecturer_status is null or lecturer_status in ('in_review', 'completed', 'declined')),
  add column if not exists lecturer_updated_at timestamptz;

drop policy if exists recs_student_insert on public.recommendation_requests;
create policy recs_student_insert on public.recommendation_requests
  for insert to authenticated
  with check (student_id = auth.uid()
              and status = 'submitted'
              and records_note is null
              and records_assessment is null
              and letter_file is null
              and lecturer_summary is null
              and lecturer_status is null
              and lecturer_updated_at is null
              and handled_by is null
              and handled_at is null);

create table if not exists public.achievement_shares (
  id              uuid primary key default gen_random_uuid(),
  request_id      uuid not null references public.recommendation_requests(id) on delete cascade,
  student_id      uuid not null references auth.users(id) on delete cascade,
  student_name    text not null check (char_length(student_name) between 1 and 120),
  lecturer_email  text not null check (char_length(lecturer_email) between 3 and 200),
  purpose         text not null check (char_length(purpose) between 1 and 80),
  items           jsonb not null check (jsonb_typeof(items) = 'array' and jsonb_array_length(items) between 1 and 25),
  expires_at      timestamptz not null,
  revoked_at      timestamptz,
  created_at      timestamptz not null default now()
);
create unique index if not exists achievement_shares_one_active_request
  on public.achievement_shares(request_id) where revoked_at is null;
create index if not exists achievement_shares_lecturer_idx
  on public.achievement_shares(lower(lecturer_email), expires_at) where revoked_at is null;

alter table public.achievement_shares enable row level security;
drop policy if exists achievement_shares_student_select on public.achievement_shares;
create policy achievement_shares_student_select on public.achievement_shares
  for select to authenticated using (student_id = auth.uid());

create table if not exists public.share_access_log (
  id              bigint generated always as identity primary key,
  share_id        uuid not null references public.achievement_shares(id) on delete cascade,
  lecturer_id     uuid not null references auth.users(id) on delete cascade,
  lecturer_email  text not null,
  viewed_at       timestamptz not null default now()
);
create index if not exists share_access_log_share_idx on public.share_access_log(share_id, viewed_at desc);
alter table public.share_access_log enable row level security;
grant select on public.achievement_shares, public.share_access_log to authenticated;
drop policy if exists share_access_log_student_select on public.share_access_log;
create policy share_access_log_student_select on public.share_access_log
  for select to authenticated using (
    exists (select 1 from public.achievement_shares s
            where s.id = share_id and s.student_id = auth.uid())
  );

create table if not exists public.achievement_change_requests (
  id               uuid primary key default gen_random_uuid(),
  student_id       uuid not null references auth.users(id) on delete cascade,
  collection_name  text not null check (collection_name in ('projects', 'achievements', 'clubs')),
  item_id          text not null check (char_length(item_id) between 1 and 64),
  action           text not null check (action in ('correct', 'delete')),
  proposed_data    jsonb not null default '{}'::jsonb check (jsonb_typeof(proposed_data) = 'object'),
  reason           text not null check (char_length(reason) between 10 and 1000),
  status           text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  records_note     text check (records_note is null or char_length(records_note) <= 1000),
  handled_by       uuid references auth.users(id),
  handled_at       timestamptz,
  created_at       timestamptz not null default now()
);
create index if not exists achievement_change_requests_open_idx
  on public.achievement_change_requests(status, created_at desc);
create unique index if not exists achievement_change_one_pending_item
  on public.achievement_change_requests(student_id, collection_name, item_id)
  where status = 'pending';
alter table public.achievement_change_requests enable row level security;
grant select, insert on public.achievement_change_requests to authenticated;
drop policy if exists achievement_changes_student_select on public.achievement_change_requests;
create policy achievement_changes_student_select on public.achievement_change_requests
  for select to authenticated using (student_id = auth.uid());
drop policy if exists achievement_changes_student_insert on public.achievement_change_requests;
create policy achievement_changes_student_insert on public.achievement_change_requests
  for insert to authenticated with check (
    student_id = auth.uid() and status = 'pending' and records_note is null
    and handled_by is null and handled_at is null
  );
drop policy if exists achievement_changes_staff_select on public.achievement_change_requests;
create policy achievement_changes_staff_select on public.achievement_change_requests
  for select to authenticated using (public.au_is_staff());

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
    when 'achievements' then array['title', 'date', 'issuer', 'description']
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
    if (new.collection_name = 'projects' and new.proposed_data ? 'title' and btrim(new.proposed_data ->> 'title') = '')
       or (new.collection_name = 'achievements' and new.proposed_data ? 'title' and btrim(new.proposed_data ->> 'title') = '')
       or (new.collection_name = 'clubs' and new.proposed_data ? 'name' and btrim(new.proposed_data ->> 'name') = '') then
      raise exception 'Titles and names cannot be blank.';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists au_guard_achievement_change_insert on public.achievement_change_requests;
create trigger au_guard_achievement_change_insert before insert on public.achievement_change_requests
  for each row execute function public.au_guard_achievement_change_insert();

create table if not exists public.achievement_history (
  id               bigint generated always as identity primary key,
  student_id       uuid not null references auth.users(id) on delete cascade,
  collection_name  text not null,
  item_id          text not null,
  action           text not null,
  actor_id         uuid references auth.users(id),
  request_id       uuid references public.achievement_change_requests(id) on delete set null,
  old_data         jsonb,
  new_data         jsonb,
  created_at       timestamptz not null default now()
);
create index if not exists achievement_history_student_idx
  on public.achievement_history(student_id, created_at desc);
alter table public.achievement_history enable row level security;
grant select on public.achievement_history to authenticated;
drop policy if exists achievement_history_student_select on public.achievement_history;
create policy achievement_history_student_select on public.achievement_history
  for select to authenticated using (student_id = auth.uid());
drop policy if exists achievement_history_staff_select on public.achievement_history;
create policy achievement_history_staff_select on public.achievement_history
  for select to authenticated using (public.au_is_staff());

create or replace function public.au_guard_verified_profile_items() returns trigger
language plpgsql as $$
declare
  v record;
  old_item jsonb;
  new_item jsonb;
  collection_key text;
  item_key text;
  k text;
begin
  if current_setting('myau.approved_achievement_change', true) = 'on' then
    return new;
  end if;

  for v in
    select item_type, item_id, item_snapshot
      from public.verifications
     where student_id = old.id and status = 'verified'
       and item_type in ('project', 'achievement', 'club')
  loop
    collection_key := case v.item_type
      when 'project' then 'projects'
      when 'achievement' then 'achievements'
      else 'clubs'
    end;
    old_item := null;
    new_item := null;
    select arr.item into old_item
      from jsonb_array_elements(coalesce(old.data -> collection_key, '[]'::jsonb)) as arr(item)
     where arr.item ->> 'id' = v.item_id limit 1;
    if old_item is null then continue; end if;

    -- A verification applies only while its reviewed fields still match the saved item.
    item_key := null;
    for k in select jsonb_object_keys(v.item_snapshot)
    loop
      if (old_item -> k) is distinct from (v.item_snapshot -> k) then
        item_key := k;
        exit;
      end if;
    end loop;
    if item_key is not null then continue; end if;

    select arr.item into new_item
      from jsonb_array_elements(coalesce(new.data -> collection_key, '[]'::jsonb)) as arr(item)
     where arr.item ->> 'id' = v.item_id limit 1;
    if new_item is null or new_item is distinct from old_item then
      raise exception 'Verified achievements must be corrected or removed through a Records Office review request.';
    end if;
  end loop;
  return new;
end $$;
drop trigger if exists au_guard_verified_profile_items on public.profiles;
create trigger au_guard_verified_profile_items before update of data on public.profiles
  for each row execute function public.au_guard_verified_profile_items();

create or replace function public.au_log_achievement_history() returns trigger
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  collection_key text;
  before_item jsonb;
  after_item jsonb;
  item_key text;
  item_id_value text;
begin
  foreach collection_key in array array['projects', 'achievements', 'clubs']
  loop
    for after_item in
      select arr.item from jsonb_array_elements(coalesce(new.data -> collection_key, '[]'::jsonb)) as arr(item)
    loop
      item_id_value := after_item ->> 'id';
      if item_id_value is null then continue; end if;
      select arr.item into before_item
        from jsonb_array_elements(coalesce(old.data -> collection_key, '[]'::jsonb)) as arr(item)
       where arr.item ->> 'id' = item_id_value limit 1;
      if before_item is null then
        insert into public.achievement_history(student_id, collection_name, item_id, action, actor_id, new_data)
        values (new.id, collection_key, item_id_value, 'added', auth.uid(), after_item);
      elsif before_item is distinct from after_item then
        insert into public.achievement_history(student_id, collection_name, item_id, action, actor_id, old_data, new_data)
        values (new.id, collection_key, item_id_value, 'updated', auth.uid(), before_item, after_item);
      end if;
      before_item := null;
    end loop;

    for before_item in
      select arr.item from jsonb_array_elements(coalesce(old.data -> collection_key, '[]'::jsonb)) as arr(item)
    loop
      item_id_value := before_item ->> 'id';
      if item_id_value is null then continue; end if;
      if not exists (
        select 1 from jsonb_array_elements(coalesce(new.data -> collection_key, '[]'::jsonb)) as arr(item)
         where arr.item ->> 'id' = item_id_value
      ) then
        insert into public.achievement_history(student_id, collection_name, item_id, action, actor_id, old_data)
        values (new.id, collection_key, item_id_value, 'removed', auth.uid(), before_item);
      end if;
    end loop;
  end loop;
  return new;
end $$;
drop trigger if exists au_log_achievement_history on public.profiles;
create trigger au_log_achievement_history after update of data on public.profiles
  for each row when (old.data is distinct from new.data)
  execute function public.au_log_achievement_history();

create or replace function public.au_recs_guard() returns trigger
language plpgsql as $$
begin
  if lower(coalesce(auth.jwt() ->> 'email', '')) = lower(old.staff_email)
     and (new.lecturer_summary is distinct from old.lecturer_summary
          or new.lecturer_status is distinct from old.lecturer_status
          or new.lecturer_updated_at is distinct from old.lecturer_updated_at) then
    new := jsonb_populate_record(old,
      to_jsonb(old) || jsonb_build_object(
        'lecturer_summary', new.lecturer_summary,
        'lecturer_status', new.lecturer_status,
        'lecturer_updated_at', now()
      ));
    if new.lecturer_status not in ('in_review', 'completed', 'declined') then
      raise exception 'Choose in review, completed, or declined.';
    end if;
  elsif public.au_is_staff() then
    new := jsonb_populate_record(old,
      to_jsonb(old) || jsonb_build_object(
        'status', new.status,
        'records_note', new.records_note,
        'records_assessment', new.records_assessment,
        'letter_file', new.letter_file
      ));
    new.handled_by := auth.uid();
    new.handled_at := now();
  else
    raise exception 'You are not allowed to update this recommendation request.';
  end if;
  new.updated_at := now();
  return new;
end $$;

create or replace function public.au_create_recommendation_share(
  p_request_id uuid,
  p_verification_ids uuid[],
  p_expires_at timestamptz
) returns uuid
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  req public.recommendation_requests%rowtype;
  profile_row public.profiles%rowtype;
  v record;
  item jsonb;
  collection_key text;
  k text;
  item_count integer := 0;
  shared_items jsonb := '[]'::jsonb;
  share_id uuid;
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  if p_expires_at <= now() or p_expires_at > now() + interval '90 days' then
    raise exception 'Choose an expiry within the next 90 days.';
  end if;
  if coalesce(cardinality(p_verification_ids), 0) not between 1 and 25
     or cardinality(p_verification_ids) <> (
       select count(distinct ids.value) from unnest(p_verification_ids) as ids(value)
     ) then
    raise exception 'Select between 1 and 25 distinct verified achievements.';
  end if;

  select * into req from public.recommendation_requests
   where id = p_request_id and student_id = auth.uid() for update;
  if not found then raise exception 'Recommendation request not found.'; end if;
  select * into profile_row from public.profiles where id = auth.uid();
  if not found then raise exception 'Student profile not found.'; end if;

  update public.achievement_shares set revoked_at = now()
   where request_id = req.id and revoked_at is null and expires_at <= now();

  for v in
    select id, item_type, item_id, item_title, item_snapshot, reviewed_at
      from public.verifications
     where id = any(p_verification_ids) and student_id = auth.uid() and status = 'verified'
  loop
    collection_key := case v.item_type
      when 'project' then 'projects'
      when 'achievement' then 'achievements'
      when 'club' then 'clubs'
      else null
    end;
    if collection_key is null then raise exception 'Only verified projects, achievements, and clubs can be shared.'; end if;
    select arr.item into item
      from jsonb_array_elements(coalesce(profile_row.data -> collection_key, '[]'::jsonb)) as arr(item)
     where arr.item ->> 'id' = v.item_id limit 1;
    if item is null then raise exception 'A selected item is no longer in your profile.'; end if;
    for k in select jsonb_object_keys(v.item_snapshot)
    loop
      if (item -> k) is distinct from (v.item_snapshot -> k) then
        raise exception 'A selected item has changed since verification; refresh and review it before sharing.';
      end if;
    end loop;
    shared_items := shared_items || jsonb_build_array(jsonb_build_object(
      'type', v.item_type, 'title', v.item_title, 'verified_at', v.reviewed_at,
      'details', v.item_snapshot
    ));
    item_count := item_count + 1;
  end loop;
  if item_count <> cardinality(p_verification_ids) then
    raise exception 'One or more selected items are not verified or are no longer available.';
  end if;

  insert into public.achievement_shares(
    request_id, student_id, student_name, lecturer_email, purpose, items, expires_at
  ) values (
    req.id, auth.uid(), req.student_name, lower(req.staff_email), req.purpose, shared_items, p_expires_at
  ) returning id into share_id;
  return share_id;
end $$;

create or replace function public.au_revoke_recommendation_share(p_share_id uuid)
returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  update public.achievement_shares set revoked_at = now()
   where id = p_share_id and student_id = auth.uid() and revoked_at is null;
  if not found then raise exception 'This share is already revoked or is no longer available.'; end if;
end $$;

create or replace function public.au_lecturer_workspace()
returns jsonb
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  v_lecturer_email text := lower(coalesce(auth.jwt() ->> 'email', ''));
  shares_json jsonb;
  requests_json jsonb;
begin
  if auth.uid() is null or v_lecturer_email = '' then raise exception 'Sign in with your invited lecturer email.'; end if;

  with visible as (
    select s.* from public.achievement_shares s
     where lower(s.lecturer_email) = v_lecturer_email
       and s.revoked_at is null and s.expires_at > now()
  )
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', id, 'request_id', request_id, 'student_name', student_name,
    'purpose', purpose, 'items', items, 'expires_at', expires_at, 'created_at', created_at
  )), '[]'::jsonb) into shares_json from visible;

  insert into public.share_access_log(share_id, lecturer_id, lecturer_email)
    select id, auth.uid(), v_lecturer_email from public.achievement_shares
     where lower(achievement_shares.lecturer_email) = v_lecturer_email
       and revoked_at is null and expires_at > now();

  select coalesce(jsonb_agg(jsonb_build_object(
    'id', r.id, 'student_name', r.student_name, 'student_number', r.student_number,
    'programme', r.programme, 'purpose', r.purpose, 'recipient_org', r.recipient_org,
    'deadline', r.deadline, 'personal_statement', r.personal_statement, 'status', r.status,
    'lecturer_status', r.lecturer_status,
    'lecturer_summary', r.lecturer_summary, 'created_at', r.created_at
  ) order by r.deadline), '[]'::jsonb) into requests_json
    from public.recommendation_requests r
   where lower(r.staff_email) = v_lecturer_email;

  return jsonb_build_object('shares', shares_json, 'requests', requests_json);
end $$;

create or replace function public.au_lecturer_update_recommendation(
  p_request_id uuid,
  p_summary text,
  p_status text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  if p_summary is not null and char_length(p_summary) > 5000 then
    raise exception 'The letter summary must be 5,000 characters or fewer.';
  end if;
  if p_status not in ('in_review', 'completed', 'declined') then
    raise exception 'Choose a valid lecturer status.';
  end if;
  if p_status = 'completed' and nullif(btrim(p_summary), '') is null then
    raise exception 'Add the letter summary before marking the work complete.';
  end if;
  update public.recommendation_requests
     set lecturer_status = p_status, lecturer_summary = nullif(btrim(p_summary), ''),
         lecturer_updated_at = now()
   where id = p_request_id and lower(staff_email) = lower(auth.jwt() ->> 'email');
  if not found then raise exception 'This recommendation request is not assigned to your signed-in email.'; end if;
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
        when 'achievements' then array['title', 'date', 'issuer', 'description']
        else array['name', 'type', 'role']
      end;
      if req.proposed_data = '{}'::jsonb then raise exception 'No proposed corrections were provided.'; end if;
      updated_item := current_item;
      for k in select jsonb_object_keys(req.proposed_data)
      loop
        if not k = any(allowed_keys) then raise exception 'A proposed field is not editable.'; end if;
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

revoke all on function public.au_create_recommendation_share(uuid, uuid[], timestamptz) from public;
revoke all on function public.au_revoke_recommendation_share(uuid) from public;
revoke all on function public.au_lecturer_workspace() from public;
revoke all on function public.au_lecturer_update_recommendation(uuid, text, text) from public;
revoke all on function public.au_review_achievement_change(uuid, boolean, text) from public;
revoke all on function public.au_create_recommendation_share(uuid, uuid[], timestamptz) from anon;
revoke all on function public.au_revoke_recommendation_share(uuid) from anon;
revoke all on function public.au_lecturer_workspace() from anon;
revoke all on function public.au_lecturer_update_recommendation(uuid, text, text) from anon;
revoke all on function public.au_review_achievement_change(uuid, boolean, text) from anon;
revoke all on function public.au_guard_verified_profile_items() from public, anon, authenticated;
revoke all on function public.au_log_achievement_history() from public, anon, authenticated;
revoke all on function public.au_guard_achievement_change_insert() from public, anon, authenticated;
revoke all on function public.au_recs_guard() from public, anon, authenticated;
grant execute on function public.au_create_recommendation_share(uuid, uuid[], timestamptz) to authenticated;
grant execute on function public.au_revoke_recommendation_share(uuid) to authenticated;
grant execute on function public.au_lecturer_workspace() to authenticated;
grant execute on function public.au_lecturer_update_recommendation(uuid, text, text) to authenticated;
grant execute on function public.au_review_achievement_change(uuid, boolean, text) to authenticated;
