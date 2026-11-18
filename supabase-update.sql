-- コメントの「返信」と「管理人の認証マーク」用の更新（SQL Editor に貼って Run）
alter table comments add column if not exists admin boolean default false;
alter table comments add column if not exists parent_id text references comments(id) on delete cascade;
create index if not exists comments_parent_idx on comments(parent_id);

-- 誰でも投稿できるが、認証マーク(admin)を付けることと「管理人」を名乗ることはできない
drop policy if exists "post" on comments;
create policy "post" on comments for insert to anon
  with check (likes = 0 and admin is not true and regexp_replace(name, '[\s　]', '', 'g') not like '%管理人%');
