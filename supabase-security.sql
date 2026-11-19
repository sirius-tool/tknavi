-- 不正アクセス・スパム対策（SQL Editor に貼って Run）
-- 警告「destructive」が出ても大丈夫です（関数を上書きするだけで、データは消えません）

-- 1. 緊急停止スイッチ（Table Editor で site_flags の on_ を true にすると即停止）
create table if not exists site_flags (name text primary key, on_ boolean not null default false);
insert into site_flags (name, on_) values ('comments_off', false), ('likes_off', false) on conflict do nothing;

-- 2. アクセス記録（IPごとの回数制限用）
create table if not exists rate_log (id bigserial primary key, ip text, kind text, t timestamptz default now());
create index if not exists rate_log_idx on rate_log (kind, ip, t);
alter table site_flags enable row level security;
alter table rate_log   enable row level security;
revoke all on site_flags, rate_log from anon, authenticated;

create or replace function client_ip() returns text language sql stable as $$
  select coalesce(nullif(trim(split_part(coalesce(current_setting('request.headers', true)::json->>'x-forwarded-for', ''), ',', 1)), ''), 'unknown')
$$;

-- 3. 回数チェック（超えたらエラー）。per_ip=false なら全員合計
create or replace function rate_check(k text, lim int, win interval, per_ip boolean default true) returns void
language plpgsql security definer set search_path = public as $$
declare v_ip text := case when per_ip then client_ip() else 'ALL' end; n int;
begin
  if random() < 0.02 then delete from rate_log where t < now() - interval '2 days'; end if;
  select count(*) into n from rate_log where kind = k and rate_log.ip = v_ip and t > now() - win;
  if n >= lim then raise exception 'rate limit'; end if;
  insert into rate_log (ip, kind) values (v_ip, k);
end $$;
revoke execute on function rate_check(text, int, interval, boolean) from public, anon, authenticated;

-- 4. コメント投稿の制限（管理者ログイン中は対象外）
--    1人: 1分3件 / 1時間20件 / 1日60件、全員合計: 1時間200件
create or replace function comments_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if coalesce(auth.jwt()->>'role', 'anon') <> 'authenticated' then
    if exists (select 1 from site_flags where name = 'comments_off' and on_) then raise exception 'comments closed'; end if;
    perform rate_check('c_min', 3, interval '1 minute');
    perform rate_check('c_hour', 20, interval '1 hour');
    perform rate_check('c_day', 60, interval '1 day');
    perform rate_check('c_all', 200, interval '1 hour', false);
  end if;
  return new;
end $$;
create or replace trigger comments_guard_t before insert on comments for each row execute function comments_guard();

-- 5. 👍の制限（1人: 1分30回 / 1日500回）
create or replace function like_comment(cid text, d int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if exists (select 1 from site_flags where name = 'likes_off' and on_) then raise exception 'likes closed'; end if;
  perform rate_check('l_min', 30, interval '1 minute');
  perform rate_check('l_day', 500, interval '1 day');
  update comments set likes = greatest(0, likes + case when d > 0 then 1 else -1 end) where id = cid;
end $$;
grant execute on function like_comment(text, int) to anon, authenticated;
