-- Keep valid alumni access requests visible to Records even before the
-- submitted student number and university email are linked to an Auth account.
-- Requires migration 0012.

alter table public.alumni_access_requests
  alter column student_id drop not null;

create unique index if not exists alumni_access_one_pending_unmatched
  on public.alumni_access_requests(student_number, university_email)
  where student_id is null and status in ('pending', 'awaiting_confirmation');

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
  if match_count <> 1 then target_id := null; end if;

  if exists (
    select 1 from public.alumni_access_requests r
     where r.created_at > now() - interval '24 hours'
       and lower(r.student_number) = lower(v_student_number)
       and lower(r.university_email) = university_email
  ) or (target_id is not null and exists (
    select 1 from public.alumni_access_requests r
     where r.student_id = target_id
       and r.status in ('pending', 'awaiting_confirmation')
  )) then
    return;
  end if;

  insert into public.alumni_access_requests(
    student_id, student_number, university_email, personal_email
  ) values (
    target_id, v_student_number, university_email, personal_email
  );
exception when unique_violation then
  return;
end $$;

create or replace function public.au_resolve_alumni_request(p_request_id uuid)
returns uuid
language plpgsql security definer
set search_path = public, pg_temp
as $$
declare
  req public.alumni_access_requests%rowtype;
  target_id uuid;
begin
  if not public.au_is_staff() then
    raise exception 'Only Records Office staff can resolve alumni access requests.';
  end if;

  select * into req
    from public.alumni_access_requests
   where id = p_request_id
   for update;
  if not found or req.status <> 'pending' then
    raise exception 'This request is no longer awaiting review.';
  end if;
  if req.student_id is not null then return req.student_id; end if;

  select r.student_id into target_id
    from public.student_registry r
    join auth.users u on u.id = r.student_id
   where r.student_number = req.student_number
     and lower(u.email) = lower(req.university_email);
  if target_id is null then
    raise exception 'First link this student number to the Auth account using the exact university email on the request, then retry approval.';
  end if;

  update public.alumni_access_requests
     set student_id = target_id
   where id = req.id;
  return target_id;
end $$;

revoke all on function public.au_resolve_alumni_request(uuid) from public;
revoke all on function public.au_resolve_alumni_request(uuid) from anon;
grant execute on function public.au_resolve_alumni_request(uuid) to authenticated;
