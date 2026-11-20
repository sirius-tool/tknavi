-- 「パスワードを忘れた場合」の本人確認（秘密の質問①②③）
-- 先に supabase-ddos.sql を実行済みであること
-- ★★★ このファイルには答えが書いてあります。GitHub などには絶対に上げないでください ★★★

create extension if not exists pgcrypto with schema extensions;

create table if not exists admin_recovery (
  id int primary key default 1,
  a1_hash text not null, a2_hash text not null, a3_hash text not null,
  constraint single_row check (id = 1)
);
alter table admin_recovery enable row level security;
revoke all on admin_recovery from anon, authenticated;

insert into admin_recovery (id, a1_hash, a2_hash, a3_hash) values (1,
  extensions.crypt('東立川幼稚園', extensions.gen_salt('bf')),
  extensions.crypt('秋田県', extensions.gen_salt('bf')),
  extensions.crypt('INFJ', extensions.gen_salt('bf'))
) on conflict (id) do update set a1_hash = excluded.a1_hash, a2_hash = excluded.a2_hash, a3_hash = excluded.a3_hash;

-- 1日に試せる回数（IPごとに5回まで）。3つとも正解したら、
-- ①この端末のロックは画面側で解除され、②このIPのパスワード試行の回数制限もリセットされます。
create or replace function recover_access(a1 text, a2 text, a3 text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare r admin_recovery; ok boolean;
begin
  perform rate_check('rec', 5, interval '1 day');
  select * into r from admin_recovery where id = 1;
  ok := (r.a1_hash = crypt(a1, r.a1_hash)) and (r.a2_hash = crypt(a2, r.a2_hash)) and (r.a3_hash = crypt(a3, r.a3_hash));
  if ok then
    delete from rate_log where kind in ('pw_min','pw_day') and ip = client_ip();
  end if;
  return coalesce(ok, false);
end $$;
revoke execute on function recover_access(text, text, text) from public;
grant  execute on function recover_access(text, text, text) to anon, authenticated;
