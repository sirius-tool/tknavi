-- コメントの「固定」「IP非公開記録」「管理人の偽称対策」
-- 先に supabase-security.sql と supabase-secret.sql を実行済みであること
-- 「destructive」の警告が出ても実行して大丈夫です（ルールを作り直すだけで、コメントは消えません）

-- 1. コメントの固定
alter table comments add column if not exists pinned boolean not null default false;

-- 2. IPアドレスの非公開記録（コメントとは別の表。一般の人には見えない）
create table if not exists comment_ips (
  comment_id text primary key references comments(id) on delete cascade,
  ip text, t timestamptz default now());
create index if not exists comment_ips_ip on comment_ips (ip);
alter table comment_ips enable row level security;
revoke all on comment_ips from anon, authenticated;
grant select on comment_ips to authenticated;
drop policy if exists "admin read" on comment_ips;
create policy "admin read" on comment_ips for select to authenticated using (is_admin());

create or replace function comments_log_ip() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into comment_ips (comment_id, ip) values (new.id, client_ip()) on conflict do nothing;
  return null;
end $$;
create or replace trigger comments_log_ip_t after insert on comments for each row execute function comments_log_ip();

-- 3. 「管理人」などの名前を使えなくする（全角・空白・記号・ゼロ幅文字・部首の似た字でのすり抜けも対策）
create or replace function norm_name(n text) returns text language sql immutable as $$
  select regexp_replace(lower(normalize(coalesce(n, ''), NFKC)), '[^a-z0-9ぁ-んァ-ヶー一-龯々✅✔☑]', '', 'g')
$$;
create or replace function is_reserved_name(n text) returns boolean language sql immutable as $$
  select norm_name(n) ~ '管理人|管理者|運営|かんりにん|カンリニン|認証済|^(admin|administrator|moderator)$|[✅✔☑]'
$$;

drop policy if exists "post" on comments;
create policy "post" on comments for insert to anon
  with check (likes = 0 and admin is not true and pinned is not true and not is_reserved_name(name));

create or replace function comments_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then
    new.admin := false;
    new.pinned := false;
    if is_reserved_name(new.name) then raise exception 'name reserved'; end if;
    if exists (select 1 from site_flags where name = 'comments_off' and on_) then raise exception 'comments closed'; end if;
    perform rate_check('c_min', 3, interval '1 minute');
    perform rate_check('c_hour', 20, interval '1 hour');
    perform rate_check('c_day', 60, interval '1 day');
    perform rate_check('c_all', 200, interval '1 hour', false);
  end if;
  return new;
end $$;

-- 4. すでに投稿されている偽称コメントの確認（まずこれだけ実行して中身を見る）
select id, name, text, to_timestamp(ts / 1000.0) as 投稿日時 from comments
where not coalesce(admin, false) and is_reserved_name(name) order by ts desc;

-- 5. 偽称の名前を「名無しさん」に直す（4の結果を確認してから、下の2行を実行）
-- update comments set name = '名無しさん' where not coalesce(admin, false) and is_reserved_name(name);
