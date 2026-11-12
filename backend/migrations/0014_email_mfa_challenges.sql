-- Short-lived, server-only storage for password-verified email MFA challenges.
create table if not exists public.email_mfa_challenges (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references auth.users(id) on delete cascade,
  session_id    uuid not null,
  email         text not null,
  code_hash     text not null,
  access_token  text not null,
  refresh_token text not null,
  attempts      integer not null default 0 check (attempts between 0 and 5),
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  consumed_at   timestamptz
);

create table if not exists public.email_mfa_sessions (
  session_id  uuid primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  verified_at timestamptz not null default now(),
  expires_at  timestamptz not null
);

alter table public.email_mfa_challenges enable row level security;
alter table public.email_mfa_sessions enable row level security;
revoke all on public.email_mfa_challenges from public, anon, authenticated;
revoke all on public.email_mfa_sessions from public, anon, authenticated;
grant all on public.email_mfa_challenges to service_role;
grant all on public.email_mfa_sessions to service_role;

create index if not exists email_mfa_challenges_user_created_idx
  on public.email_mfa_challenges(user_id, created_at desc);

create or replace function public.au_issue_email_mfa_challenge(
  p_user_id uuid,
  p_session_id uuid,
  p_email text,
  p_code_hash text,
  p_access_token text,
  p_refresh_token text
)
returns table(challenge_id uuid, retry_after_seconds integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_recent_count integer;
  v_last_created timestamptz;
  v_retry integer;
  v_challenge_id uuid;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'service role required';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_user_id::text));
  delete from public.email_mfa_challenges
   where created_at < now() - interval '24 hours';
  delete from public.email_mfa_sessions where expires_at <= now();

  select count(*)::integer, max(c.created_at)
    into v_recent_count, v_last_created
    from public.email_mfa_challenges c
   where c.user_id = p_user_id
     and c.created_at > now() - interval '1 hour';

  if v_recent_count >= 5 then
    return query select null::uuid, 3600;
    return;
  end if;
  if v_last_created is not null and v_last_created > now() - interval '1 minute' then
    v_retry := greatest(1, ceil(extract(epoch from (v_last_created + interval '1 minute' - now())))::integer);
    return query select null::uuid, v_retry;
    return;
  end if;

  update public.email_mfa_challenges c
     set consumed_at = now(), access_token = '', refresh_token = ''
   where c.user_id = p_user_id and c.consumed_at is null;

  insert into public.email_mfa_challenges(user_id, session_id, email, code_hash, access_token, refresh_token, expires_at)
  values (p_user_id, p_session_id, p_email, p_code_hash, p_access_token, p_refresh_token, now() + interval '5 minutes')
  returning id into v_challenge_id;

  return query select v_challenge_id, 0;
end;
$$;

create or replace function public.au_consume_email_mfa_challenge(
  p_challenge_id uuid,
  p_code_hash text
)
returns table(verified boolean, access_token text, refresh_token text, attempts_remaining integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_challenge public.email_mfa_challenges%rowtype;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'service role required';
  end if;

  select c.* into v_challenge
    from public.email_mfa_challenges c
   where c.id = p_challenge_id
   for update;

  if not found or v_challenge.consumed_at is not null or v_challenge.expires_at <= now()
     or v_challenge.attempts >= 5 then
    return query select false, null::text, null::text, 0;
    return;
  end if;

  if v_challenge.code_hash <> p_code_hash then
    update public.email_mfa_challenges c
       set attempts = c.attempts + 1
     where c.id = p_challenge_id
     returning c.attempts into v_challenge.attempts;
    return query select false, null::text, null::text, greatest(0, 5 - v_challenge.attempts);
    return;
  end if;

  update public.email_mfa_challenges c
     set consumed_at = now(), code_hash = '', access_token = '', refresh_token = ''
   where c.id = p_challenge_id;

  insert into public.email_mfa_sessions(session_id, user_id, expires_at)
  values (v_challenge.session_id, v_challenge.user_id, now() + interval '12 hours')
  on conflict (session_id) do update
    set user_id = excluded.user_id, verified_at = now(), expires_at = excluded.expires_at;

  return query select true, v_challenge.access_token, v_challenge.refresh_token, 0;
end;
$$;

create or replace function public.au_email_mfa_verified() returns boolean
language sql stable as $$
  select coalesce(auth.jwt() ->> 'email_mfa_verified', 'false') = 'true'
$$;

create or replace function public.au_is_staff() returns boolean
language sql stable as $$
  select public.au_email_mfa_verified()
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
  session_uuid uuid;
  verified boolean := false;
begin
  if coalesce(claims ->> 'session_id', '') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     and coalesce(claims ->> 'sub', '') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
    session_uuid := (claims ->> 'session_id')::uuid;
    select exists (
      select 1 from public.email_mfa_sessions s
       where s.session_id = session_uuid
         and s.user_id = (claims ->> 'sub')::uuid
         and s.expires_at > now()
    ) into verified;
  end if;

  claims := jsonb_set(coalesce(claims, '{}'::jsonb), '{email_mfa_verified}', to_jsonb(verified), true);
  claims := jsonb_set(claims, '{role}', to_jsonb(case when verified then coalesce(claims ->> 'role', 'authenticated') else 'anon' end), true);
  return jsonb_build_object('claims', claims);
end;
$$;

grant usage on schema public to supabase_auth_admin;
revoke all on function public.custom_access_token_hook(jsonb) from public, anon, authenticated;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;

create or replace function public.au_email_mfa_write_guard()
returns trigger
language plpgsql
as $$
begin
  if coalesce(auth.role(), '') = 'authenticated' and not public.au_email_mfa_verified() then
    raise exception 'Complete email verification before accessing MyAU data.';
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end;
$$;

revoke all on function public.au_email_mfa_write_guard() from public, anon, authenticated;

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
    execute format(
      'create policy email_mfa_required on public.%I as restrictive for all to authenticated using (public.au_email_mfa_verified()) with check (public.au_email_mfa_verified())',
      target.relname
    );
    execute format('drop trigger if exists email_mfa_write_guard on public.%I', target.relname);
    execute format(
      'create trigger email_mfa_write_guard before insert or update or delete on public.%I for each row execute function public.au_email_mfa_write_guard()',
      target.relname
    );
  end loop;
end;
$$;

drop policy if exists email_mfa_required on storage.objects;
create policy email_mfa_required on storage.objects as restrictive
  for all to authenticated
  using (public.au_email_mfa_verified())
  with check (public.au_email_mfa_verified());

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
  if not public.au_email_mfa_verified() then raise exception 'Complete email verification before opening the lecturer workspace.'; end if;
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
end
$$;

revoke all on function public.au_issue_email_mfa_challenge(uuid, uuid, text, text, text, text) from public, anon, authenticated;
revoke all on function public.au_consume_email_mfa_challenge(uuid, text) from public, anon, authenticated;
grant execute on function public.au_issue_email_mfa_challenge(uuid, uuid, text, text, text, text) to service_role;
grant execute on function public.au_consume_email_mfa_challenge(uuid, text) to service_role;
