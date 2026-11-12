-- Replace the previous custom email-code gate with Supabase authenticator-app MFA (AAL2).
-- Apply after 0014 if it was already installed; also safe on projects that skipped 0014.

create or replace function public.au_mfa_verified() returns boolean
language sql stable as $$
  select coalesce(auth.jwt() ->> 'aal', '') = 'aal2'
$$;

create or replace function public.au_email_mfa_verified() returns boolean
language sql stable as $$
  select public.au_mfa_verified()
$$;

-- Admin policies and privileged routines also use au_role(), so gate it on AAL2.
create or replace function public.au_role() returns text
language sql stable as $$
  select case when public.au_mfa_verified()
    then coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '')
    else ''
  end
$$;

create or replace function public.au_is_staff() returns boolean
language sql stable as $$
  select public.au_mfa_verified()
     and coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '') in ('records', 'admin')
$$;

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  claims jsonb := event -> 'claims';
  verified boolean := false;
begin
  verified := coalesce(claims ->> 'aal', '') = 'aal2';
  claims := jsonb_set(coalesce(claims, '{}'::jsonb), '{email_mfa_verified}', to_jsonb(verified), true);
  claims := jsonb_set(claims, '{role}', to_jsonb(
    case when verified then coalesce(claims ->> 'role', 'authenticated') else 'anon' end
  ), true);
  return jsonb_build_object('claims', claims);
end;
$$;

grant usage on schema public to supabase_auth_admin;
revoke all on function public.custom_access_token_hook(jsonb) from public, anon, authenticated;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;

do $$
declare
  target record;
begin
  for target in
    select c.relname
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and c.relkind in ('r', 'p')
       and c.relrowsecurity
  loop
    execute format('drop policy if exists email_mfa_required on public.%I', target.relname);
    execute format('drop policy if exists mfa_required on public.%I', target.relname);
    execute format(
      'create policy mfa_required on public.%I as restrictive for all to public using (public.au_mfa_verified()) with check (public.au_mfa_verified())',
      target.relname
    );
    execute format('drop trigger if exists email_mfa_write_guard on public.%I', target.relname);
  end loop;
end;
$$;

drop policy if exists email_mfa_required on storage.objects;
drop policy if exists mfa_required on storage.objects;
create policy mfa_required on storage.objects as restrictive
  for all to public
  using (public.au_mfa_verified())
  with check (public.au_mfa_verified());

drop function if exists public.au_email_mfa_write_guard();
drop function if exists public.au_issue_email_mfa_challenge(uuid, uuid, text, text, text, text);
drop function if exists public.au_consume_email_mfa_challenge(uuid, text);
drop table if exists public.email_mfa_challenges;
drop table if exists public.email_mfa_sessions;

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
  if not public.au_mfa_verified() then raise exception 'Complete authenticator verification before sharing profile items.'; end if;
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
end;
$$;

create or replace function public.au_revoke_recommendation_share(p_share_id uuid)
returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if not public.au_mfa_verified() then raise exception 'Complete authenticator verification before changing shared access.'; end if;
  if auth.uid() is null then raise exception 'Sign in is required.'; end if;
  update public.achievement_shares set revoked_at = now()
   where id = p_share_id and student_id = auth.uid() and revoked_at is null;
  if not found then raise exception 'This share is already revoked or is no longer available.'; end if;
end;
$$;

create or replace function public.au_lecturer_update_recommendation(
  p_request_id uuid,
  p_summary text,
  p_status text
) returns void
language plpgsql security definer
set search_path = public, pg_temp
as $$
begin
  if not public.au_mfa_verified() then raise exception 'Complete authenticator verification before updating a recommendation.'; end if;
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
end;
$$;
