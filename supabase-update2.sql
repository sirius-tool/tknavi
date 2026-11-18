-- 「日程」（考査・模試のカウントダウン用）テーブルの追加（SQL Editor に貼って Run）
create table if not exists events (id text primary key, kind text, title text, date text, end_date text, note text, updated bigint);
alter table events enable row level security;
create policy "read" on events for select using (true);
create policy "admin" on events for all to authenticated using (true) with check (true);
grant select on events to anon, authenticated;
grant all on events to authenticated;
