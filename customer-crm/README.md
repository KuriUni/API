# TUTI CRM（管理者向け）

TUTI の管理者コンソールです。**管理者SSOで1回ログイン**すると、管理APIから全テナントの契約先・ライセンス・請求書を読み取ります。テナントAPIキーの登録はありません。

利用者は TUTI の管理者・運用担当者です。契約者（テナント）向けの画面ではありません。

## 画面

- **ダッシュボード**: 契約先数、有効ライセンス、期限切れ、未払い請求、契約先別サマリ、最近の請求書、接続状態
- **契約先**: TUTIのテナント一覧（状態・環境・ライセンス数・期限間近・未払い）、契約先ごとの詳細
- **ライセンス**: 全テナント横断の検索（ID・ラベル・契約先）、状態・契約先で絞り込み、CSV出力
- **請求**: 全テナントの請求書（下書き／発行済み／入金済み／無効）、検索・絞り込み、CSV出力
- **接続**: SSOログイン、接続解除、同期状態

## 認証とデータ取得

| 用途 | 呼び出し |
| --- | --- |
| 管理者ログイン | `admin_api.php?admin_sso_start=1&return_app=desktop`（ブラウザ + Passkey） |
| 契約先一覧 | `POST admin_api.php` `action=list_tenants` |
| ライセンス | `POST admin_api.php` `action=list_licenses` |
| 請求書 | `POST ha/api-billing-admin.php` `action=list` |

いずれも `X-HA-Session`（管理者セッション）で認証します。SSOの応答は `127.0.0.1` のループバックでのみ受け取り、state を照合したうえでセッションを保存します。

- セッションは AES-256-GCM で暗号化して SQLite に保存し、画面・ログ・APIレスポンスには出しません。
- 読み取り専用です。ライセンスの発行・停止、請求書の発行・入金は管理センターで操作してください。
- 管理セッションが失効すると同期がエラーになり、接続画面から再ログインできます。

## 起動方法

```powershell
cd "$env:USERPROFILE\Documents\API\customer-crm"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8766
```

`.\Start-CustomerCrm.ps1` でも起動できます。ブラウザで `http://127.0.0.1:8766/` を開き、アプリのログイン（`admin` / `demo`）後に「接続」画面で **SSOでログイン** を押します。

デモログインは `CRM_PASSWORD` 未設定時のみ有効です。本番では必ず設定してください。

## 環境変数

| 変数 | 既定値 | 内容 |
| --- | --- | --- |
| `CRM_DATA` | `customer-crm/data` | SQLite の保存ディレクトリ |
| `CRM_USER` | `admin` | アプリのログインユーザー名 |
| `CRM_NAME` | `管理者` | 画面に表示する名前 |
| `CRM_PASSWORD` | 未設定時 `demo` | アプリのログインパスワード |
| `CRM_SESSION_KEY` | 起動ごとに生成 | セッション署名鍵 |
| `CRM_SECRET` | `data/.secret` を自動生成 | セッション暗号化の元鍵。本番では必ず設定 |
| `CRM_SECURE_COOKIES` | `0` | HTTPS運用時は `1` |
| `TUTI_ADMIN_BASE` | `https://2415.jp` | 管理APIのベースURL |
| `TUTI_ADMIN_SESSION` | 未設定 | 管理者セッションを直接渡す開発・自動化用。設定時はSSOログイン無効 |

`CRM_SECRET` を変更すると保存済みセッションは復号できなくなります（再ログインが必要）。APIキーやトークンをCSV・チャットへ貼り付けないでください。

## データ

- `admin_auth`: 管理者セッション（暗号化）
- `tenants` / `licenses` / `invoices`: 管理APIから取得したスナップショット
- `sync_state`: 対象ごとの取得時刻とエラー

同期は「今すぐ同期」で全件を取り直します。取得に失敗した対象は前回の内容を残したままエラーを表示します。

## API

すべてアプリのログインセッションが必要です。書き込み系は `X-CSRF-Token` も必要です。

- `GET /api/connection` / `POST /api/connection/start` / `GET /api/connection/poll` / `POST /api/connection/disconnect`
- `POST /api/sync`
- `GET /api/dashboard`
- `GET /api/tenants` / `GET /api/tenants/{id}`
- `GET /api/licenses`（`q`, `state`, `tenant_id`, `page`, `limit`）
- `GET /api/invoices`（`q`, `status`, `tenant_id`, `page`, `limit`）
- `GET /api/export/licenses.csv` / `GET /api/export/invoices.csv`

## 制限事項

- 管理者SSOはブラウザとPasskeyが必要です。CLIだけでは完結しません。
- 管理セッションはサーバー側の有効期限（約30分）で失効します。失効後は再ログインしてください。
- 読み取り専用です。管理センターの書き込み操作は行いません。
- SQLite は単一プロセス向けです。

## テスト

```powershell
cd "$env:USERPROFILE\Documents\API"
customer-crm\.venv\Scripts\python.exe -m unittest tests.test_tuti_crm -v
```

管理APIはローカルの擬似サーバーに対して検証し、SSOはループバックのstate照合までを検証します（外部通信なし）。
