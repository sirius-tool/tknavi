-- たちこくナビ用 Supabase セットアップ（SQL Editor に丸ごと貼って Run）

create table if not exists ranges  (id text primary key, exam text, title text, date text, note text, url text, fn text, updated bigint);
create table if not exists tasks   (id text primary key, subject text, title text, due text, detail text, url text, fn text, updated bigint);
create table if not exists news    (id text primary key, cat text, title text, date text, detail text, pin boolean default false, updated bigint);
create table if not exists comments(id text primary key, name text, text text, ts bigint, likes int default 0,
  constraint c_len check (char_length(text) <= 200 and char_length(name) <= 20));

alter table ranges   enable row level security;
alter table tasks    enable row level security;
alter table news     enable row level security;
alter table comments enable row level security;

-- 全員が読める
create policy "read" on ranges   for select using (true);
create policy "read" on tasks    for select using (true);
create policy "read" on news     for select using (true);
create policy "read" on comments for select using (true);

-- 書き込み・削除は管理者（ログイン済みユーザー）だけ
create policy "admin" on ranges   for all to authenticated using (true) with check (true);
create policy "admin" on tasks    for all to authenticated using (true) with check (true);
create policy "admin" on news     for all to authenticated using (true) with check (true);
create policy "admin" on comments for all to authenticated using (true) with check (true);

-- コメント投稿は誰でも可（👍は0から開始）
create policy "post" on comments for insert to anon with check (likes = 0);

-- 👍の増減（誰でも呼べるが、likes 以外は変更できない）
create or replace function like_comment(cid text, d int) returns void
language sql security definer set search_path = public as $$
  update comments set likes = greatest(0, likes + case when d > 0 then 1 else -1 end) where id = cid;
$$;
grant execute on function like_comment(text, int) to anon, authenticated;

-- PDF 置き場（公開読み取り・書き込みは管理者のみ）
insert into storage.buckets (id, name, public) values ('files', 'files', true) on conflict do nothing;
create policy "admin files" on storage.objects for all to authenticated
  using (bucket_id = 'files') with check (bucket_id = 'files');

-- API からテーブルを使うための権限（「Grant API access」がオフでも動くように）
grant usage on schema public to anon, authenticated;
grant select on ranges, tasks, news, comments to anon, authenticated;
grant insert on comments to anon;
grant all on ranges, tasks, news, comments to authenticated;
