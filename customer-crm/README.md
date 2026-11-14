# TUTI CRM（GINIE風 顧客管理システム）

顧客・連絡先・案件パイプライン・活動履歴・タスクをひとつの画面で管理する、FastAPI + SQLite + Vanilla JS の顧客管理システムです。GINIEのような「顧客情報を見ながら、次の商談とタスクを進める」体験を、追加のフロントエンドビルドなしで動かせることを目指しています。

## 主な機能

- **ダッシュボード**: 顧客数、進行中案件、パイプライン、今月の受注、期限超過タスク、ステージ別パイプライン、最近の活動、今日のタスク
- **顧客管理**: 検索、業種・ランク・担当者フィルター、ページ送り、CSV出力、顧客詳細
- **連絡先管理**: 顧客に紐づく担当者、主担当フラグ、メール・電話、CSV出力は顧客単位
- **案件管理**: 6ステージのカンバン、ドラッグ＆ドロップでステージ更新、金額・確度・完了予定日、CSV出力
- **活動履歴**: 商談・電話・メール・訪問・メモのタイムライン、顧客・連絡先・案件への紐づけ
- **タスク**: 期限・優先度・完了状態、期限超過/今日/今後/完了のグルーピング、顧客・案件への紐づけ
- **セキュリティ**: 署名付きセッションCookie、CSRFトークン、ログイン試行制限、CSP、Referrer-Policy、SQLパラメータ化

## 起動方法

`customer-crm/.venv` を使います。Python 3.13 で作成済みです。

```powershell
cd "$env:USERPROFILE\Documents\API\customer-crm"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8766
```

仮想環境を作り直す場合:

```powershell
cd "$env:USERPROFILE\Documents\API\customer-crm"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

`Start-CustomerCrm.ps1` を使うと、ローカルデモ用の環境変数を設定して起動できます（`.venv` が無い場合は `business-ops/.venv` も探します）。

```powershell
.\Start-CustomerCrm.ps1
```

ブラウザで `http://127.0.0.1:8766/` を開いてください。

## デモログイン

`CRM_PASSWORD` を設定しない場合、ローカルデモとして以下のアカウントが有効になります。

- ユーザー名: `admin`
- パスワード: `demo`

**このデモ設定を本番環境で使わないでください。** 本番では `CRM_PASSWORD` と 32文字以上の `CRM_SESSION_KEY` を必ず設定してください。

## 環境変数

| 変数 | 既定値 | 内容 |
| --- | --- | --- |
| `CRM_DATA` | `customer-crm/data` | SQLite の保存ディレクトリ |
| `CRM_USER` | `admin` | ログインユーザー名 |
| `CRM_NAME` | `管理者` | 画面に表示する名前 |
| `CRM_PASSWORD` | 未設定時 `demo` | ログインパスワード |
| `CRM_SESSION_KEY` | 起動ごとに生成 | セッション署名鍵（32文字以上推奨） |
| `CRM_SECURE_COOKIES` | `0` | HTTPS運用時は `1` |
| `CRM_SEED` | `1` | 初回起動時のデモデータ投入。`0` で無効 |
| `TUTI_API_BASE` | `https://2415.jp` | TUTI BaaS API のベースURL |
| `TUTI_API_KEY` | 未設定 | テナントAPIキー（`baas_live_…` / `baas_sandbox_…`） |
| `TUTI_API_ENV` | 未設定（自動） | `sandbox` / `production` を明示する場合に設定 |

本番では HTTPS リバースプロキシの背後で動かし、`CRM_SECURE_COOKIES=1` を設定してください。SQLite ファイルと環境変数はGitへコミットしないでください。

## TUTI連携（契約・ライセンス・請求）

`TUTI連携` 画面は、TUTI の管理API（`/api/baas/v1/service.php`）から契約状況を読み取って表示します。CRMの手入力データとは別に、次の情報を同期します。

| 項目 | API | 用途 |
| --- | --- | --- |
| サービス状態 | `service.status` | テナントslug、製品数、ライセンス数 |
| 製品 | `products.list` | 契約中の製品一覧 |
| ライセンス | `licenses.list` | 発行済みライセンス、環境、端末上限、有効期限 |
| API利用料 | `usage.summary` | 当月の課金対象リクエストと料金 |
| 請求書 | `billing.invoices` | 発行済み・支払済みの請求書 |
| APIイベント | `audit.list` | 直近のAPI呼び出し履歴 |

設定手順:

```powershell
$env:TUTI_API_BASE='https://2415.jp'
$env:TUTI_API_KEY='baas_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
$env:TUTI_API_ENV='production'   # sandbox のキーなら sandbox
.\Start-CustomerCrm.ps1
```

- 認証は `X-Tenant-API-Key` ヘッダーです。キーは画面・ログ・DBに保存しません（表示は先頭13文字のみ）。
- 読み取り専用です。ライセンスの発行・停止・削除は行いません。書き込みが必要な場合は管理センターを使ってください。
- 取得結果は `tuti_cache` テーブルにキャッシュし、同期に失敗した項目は前回の内容を保持したままエラーを表示します。
- 「今すぐ同期」はログインセッションとCSRFトークンを要求します。
- キーが無い場合はセットアップ手順を画面に表示し、ダミーデータは作りません。

## データモデル

- `companies`: 顧客（会社）
- `contacts`: 連絡先（顧客に属する）
- `deals`: 案件（顧客に属する）
- `activities`: 活動履歴（顧客・連絡先・案件に紐づく）
- `tasks`: タスク（顧客・案件に紐づく）

顧客を削除すると、紐づく連絡先・案件・活動・タスクも削除されます。削除前に画面で確認します。

## APIの概要

すべてのAPIはログインセッションを要求します。書き込み系APIは `X-CSRF-Token` が必要です。

- `GET /api/dashboard`
- `GET|POST /api/companies`
- `GET|PUT|DELETE /api/companies/{id}`
- `GET|POST /api/contacts`
- `GET|PUT|DELETE /api/contacts/{id}`
- `GET|POST /api/deals`
- `GET|PUT|DELETE /api/deals/{id}`
- `PATCH /api/deals/{id}/stage`
- `GET|POST /api/activities`
- `DELETE /api/activities/{id}`
- `GET|POST /api/tasks`
- `GET|PUT|PATCH|DELETE /api/tasks/{id}`
- `GET /api/export/companies.csv`
- `GET /api/export/deals.csv`
- `GET /api/tuti/config`
- `GET /api/tuti/overview`
- `POST /api/tuti/sync`
- `GET /api/export/tuti-licenses.csv`

## 制限事項

このアプリは顧客管理のプロトタイプです。

- 単一管理者ログインです。ユーザーごとの権限管理は未実装です。
- OIDC / SSO 連携は未実装です。必要になった場合は `business-ops/main.py` のOIDC実装を参考に、セッション発行部分を差し替えてください。
- 複数テナント、監査ログ、メール送信は未実装です。外部連携は TUTI BaaS API の読み取り同期（TUTI連携画面）のみです。
- TUTI連携は読み取り専用で、ライセンス発行・停止・請求確定は行いません。
- SQLite は単一プロセス向けです。同時書き込みが多い本番では PostgreSQL などへの移行を検討してください。

## テスト

```powershell
cd "$env:USERPROFILE\Documents\API"
customer-crm\.venv\Scripts\python.exe -m unittest tests.test_customer_crm tests.test_tuti_api -v
```
```

外部依存を追加しないため、`PYTHONPATH` の設定は不要です。

画面のE2Eは、ヘッドレスEdge/Chromeが利用できる環境で手動またはCDPスクリプトから確認できます。
