# tachikoku-navi
たちこくナビ

## v4.4.0 アップデート内容
- 日程に「時間割」（1日目・2日目…の教科）を登録できるようにしました（管理画面の「＋日程」「編集」）
- トップに、プロモーションビデオ（promo-navi.html / promo.html）へのバナーを追加
- フッターのバージョン表示を修正

## 時間割機能を使うための準備（Supabase・1回だけ）
SupabaseのSQL Editorで次を実行してください。実行するまでは、時間割**なし**の日程は今までどおり保存できます。

```sql
alter table public.events add column if not exists timetable jsonb;
```
