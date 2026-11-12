-- Add Records assessment notes and downloadable referee letters to recommendation requests.
-- Requires 0008_records_verification_finance.sql and the private student-content bucket.
alter table public.recommendation_requests
  add column if not exists records_assessment text
    check (records_assessment is null or char_length(records_assessment) <= 3000),
  add column if not exists letter_file text
    check (letter_file is null or letter_file =
      'storage://' || student_id::text || '/recommendation-letters/' || id::text || '.pdf');

create or replace function public.au_recs_guard() returns trigger
language plpgsql as $$
begin
  new := jsonb_populate_record(old,
          to_jsonb(old) || jsonb_build_object('status', new.status,
                                              'records_note', new.records_note,
                                              'records_assessment', new.records_assessment,
                                              'letter_file', new.letter_file));
  new.handled_by := auth.uid();
  new.handled_at := now();
  new.updated_at := now();
  return new;
end $$;

-- Students can submit a request, but cannot create staff assessments or attach a letter.
drop policy if exists recs_student_insert on public.recommendation_requests;
create policy recs_student_insert on public.recommendation_requests
  for insert to authenticated
  with check (student_id = auth.uid()
              and status = 'submitted'
              and records_note is null
              and records_assessment is null
              and letter_file is null
              and handled_by is null
              and handled_at is null);

-- Students can read only letters stored in their own recommendation-letters folder.
drop policy if exists recommendation_letter_student_read on storage.objects;
create policy recommendation_letter_student_read on storage.objects
  for select to authenticated
  using (bucket_id = 'student-content'
         and (storage.foldername(name))[1] = auth.uid()::text
         and (storage.foldername(name))[2] = 'recommendation-letters');

-- Records can only create or replace objects in the recommendation-letter folder.
drop policy if exists recommendation_letter_staff_insert on storage.objects;
create policy recommendation_letter_staff_insert on storage.objects
  for insert to authenticated
  with check (bucket_id = 'student-content'
              and (storage.foldername(name))[2] = 'recommendation-letters'
              and public.au_is_staff());

drop policy if exists recommendation_letter_staff_update on storage.objects;
create policy recommendation_letter_staff_update on storage.objects
  for update to authenticated
  using (bucket_id = 'student-content'
         and (storage.foldername(name))[2] = 'recommendation-letters'
         and public.au_is_staff())
  with check (bucket_id = 'student-content'
              and (storage.foldername(name))[2] = 'recommendation-letters'
              and public.au_is_staff());
