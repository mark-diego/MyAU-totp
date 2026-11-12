-- Allow student-entered course results to be submitted to the Records verification queue.
-- Requires 0008_records_verification_finance.sql.
alter table public.verifications
  drop constraint if exists verifications_item_type_check;

alter table public.verifications
  add constraint verifications_item_type_check
  check (item_type in ('project', 'achievement', 'club', 'result'));
