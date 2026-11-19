-- 期限が過ぎて3日たった課題の自動削除用
-- 「destructive」の警告が出ても実行して大丈夫です。作るのは関数だけで、いまあるデータは消えません
-- （この関数は、あとで「期限から3日たったPDFなしの課題」だけを削除します）

create or replace function purge_old_tasks() returns void
language sql security definer set search_path = public as $$
  delete from tasks
  where url is null
    and case when due ~ '^\d{4}-\d{2}-\d{2}$' then due::date end <= (now() at time zone 'Asia/Tokyo')::date - 3
$$;
revoke execute on function purge_old_tasks() from public;
grant  execute on function purge_old_tasks() to anon, authenticated;
