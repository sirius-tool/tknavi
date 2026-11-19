-- 秘密の質問（4つ目の認証）＋ 管理者権限の厳格化
-- 先に supabase-security.sql を実行済みであること。「destructive」の警告が出ても実行して大丈夫です
-- （古い権限ルールを作り直すだけで、データは消えません）
-- ※ このファイルには答えが書いてあるので、GitHub などには絶対に公開しないでください

create extension if not exists pgcrypto with schema extensions;

create table if not exists admin_cfg    (email text primary key, ans_hash text not null);
create table if not exists admin_unlock (email text primary key, until_t timestamptz not null);
alter table admin_cfg    enable row level security;
alter table admin_unlock enable row level security;
revoke all on admin_cfg, admin_unlock from anon, authenticated;

-- ★ 管理者のメールを変えている場合は、下の1行目のメールを書き換えてから実行
insert into admin_cfg (email, ans_hash)
values ('admin@tachikoku-navi.example', extensions.crypt('調布病院', extensions.gen_salt('bf')))
on conflict (email) do update set ans_hash = excluded.ans_hash;

-- 秘密の質問に正解した管理者かどうか
create or replace function is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from admin_unlock where email = (auth.jwt()->>'email') and until_t > now())
$$;

-- 答え合わせ（1時間に6回まで）。正解すると55分間だけ管理者になる
create or replace function unlock_admin(ans text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare v_email text := auth.jwt()->>'email'; ok boolean;
begin
  if v_email is null then raise exception 'not logged in'; end if;
  perform rate_check('sq', 6, interval '1 hour');
  select (ans_hash = crypt(ans, ans_hash)) into ok from admin_cfg where email = v_email;
  if coalesce(ok, false) then
    insert into admin_unlock (email, until_t) values (v_email, now() + interval '55 minutes')
    on conflict (email) do update set until_t = excluded.until_t;
    return true;
  end if;
  return false;
end $$;
revoke execute on function unlock_admin(text) from public, anon;
grant  execute on function unlock_admin(text) to authenticated;

-- ログアウト時に管理者権限をすぐ解除
create or replace function lock_admin() returns void language sql security definer set search_path = public as $$
  delete from admin_unlock where email = auth.jwt()->>'email'
$$;
revoke execute on function lock_admin() from public, anon;
grant  execute on function lock_admin() to authenticated;

-- 書き込みは「秘密の質問に正解した管理者」だけに限定
do $$
declare t text;
begin
  foreach t in array array['ranges','tasks','news','events','comments'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop policy if exists "admin" on %I', t);
      execute format('create policy "admin" on %I for all to authenticated using (is_admin()) with check (is_admin())', t);
    end if;
  end loop;
end $$;

drop policy if exists "admin files" on storage.objects;
create policy "admin files" on storage.objects for all to authenticated
  using (bucket_id = 'files' and is_admin()) with check (bucket_id = 'files' and is_admin());

-- コメントの回数制限は、秘密の質問に正解した管理者だけ対象外にする
create or replace function comments_guard() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then
    if exists (select 1 from site_flags where name = 'comments_off' and on_) then raise exception 'comments closed'; end if;
    perform rate_check('c_min', 3, interval '1 minute');
    perform rate_check('c_hour', 20, interval '1 hour');
    perform rate_check('c_day', 60, interval '1 day');
    perform rate_check('c_all', 200, interval '1 hour', false);
  end if;
  return new;
end $$;
