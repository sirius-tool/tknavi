-- DDoS対策（同一IPからのアクセス回数の制限）＋ パスワード試行の抜け道ふさぎ
-- 先に supabase-security.sql と supabase-secret.sql を実行済みであること
-- 「destructive」の警告が出ても実行して大丈夫です（ルールを作り直すだけで、データは消えません）

-- 1. 閲覧（読み取り）の回数制限。1つのリクエストにつき1回だけ数える工夫をしています。
--    管理者ログイン中（秘密の質問まで正解した状態）は対象外です。
create or replace function read_guard() returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if is_admin() then return true; end if;
  if current_setting('app.rl_read_done', true) = '1' then return true; end if;
  perform set_config('app.rl_read_done', '1', true);
  perform rate_check('read_min', 300, interval '1 minute');
  perform rate_check('read_hour', 4000, interval '1 hour');
  return true;
end $$;

do $$
declare t text;
begin
  foreach t in array array['ranges','tasks','news','events','comments'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop policy if exists "read" on %I', t);
      execute format('create policy "read" on %I for select using (read_guard())', t);
    end if;
  end loop;
end $$;

-- 2. パスワード試行の回数制限（サーバー側。端末の記録を消したり書き換えたりしても効きます）
--    1つのIPにつき、15分で5回、1日で30回まで
create or replace function pw_attempt_guard() returns void
language plpgsql security definer set search_path = public as $$
begin
  perform rate_check('pw_min', 5, interval '15 minutes');
  perform rate_check('pw_day', 30, interval '1 day');
end $$;
revoke execute on function pw_attempt_guard() from public;
grant  execute on function pw_attempt_guard() to anon, authenticated;
