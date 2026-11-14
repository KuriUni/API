# TUTI CRM（TUTI API専用の顧客管理）

TUTI の管理APIだけを使う顧客管理です。1顧客 = 1TUTIテナントで、テナントAPIキーを登録すると、その契約先のライセンス・API利用料・請求書・監査イベントを読み取って表示します。

手入力の顧客台帳、連絡先、案件パイプライン、活動履歴、タスクは持ちません。営業CRMではなく、**テナント契約の管理画面**です。

## 機能

- **ダッシュボード**: 顧客数、ライセンス数（稼働中）、今月のAPI利用料、未払い請求、顧客別サマリ、最近のAPIイベント
- **顧客**: TUTIテナントの登録・編集・削除、個別/一括同期、APIキーの暗号化保存
- **ライセンス**: 全顧客横断の検索（顧客・ラベル・製品コード・ID）、環境・状態・顧客で絞り込み、CSV出力
- **請求**: 全顧客の請求書（対象月・状態で絞り込み、CSV出力）と顧客別の今月の利用料

## 使っているTUTI API

`/api/baas/v1/service.php` に `X-Tenant-API-Key` を付けて読み取ります。すべて読み取り専用です。

| 画面 | API | 内容 |
| --- | --- | --- |
| 顧客 | `service.status` | テナントslug、製品数・ライセンス数 |
| 顧客 | `products.list` | 契約中の製品 |
| ライセンス | `licenses.list` | 発行済みライセンス、環境、端末上限、有効期限 |
| 請求 | `usage.summary` | 当月の課金対象リクエストと利用料 |
| 請求 | `billing.invoices` | 請求書（issued / paid） |
| ダッシュボード | `audit.list` | 直近のAPI呼び出し |

ライセンスの発行・停止・削除、請求確定、テナント作成は行いません。これらは TUTI 管理センターで操作してください。必要なスコープは `tenant:read` です。

## 起動方法

`customer-crm/.venv`（Python 3.13）を使います。

```powershell
cd "$env:USERPROFILE\Documents\API\customer-crm"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8766
```

または:

```powershell
.\Start-CustomerCrm.ps1
```

ブラウザで `http://127.0.0.1:8766/` を開きます。デモログインは `admin` / `demo` です（`CRM_PASSWORD` 未設定時のみ）。

## 顧客の追加

1. 右上の「顧客を追加」を押します。
2. 顧客名・slug・環境を入力します。
3. TUTI の**テナントAPIキー**（`baas_live_…` / `baas_sandbox_…`）を入力します。
4. 保存すると自動で同期し、ライセンス・請求・利用料が表示されます。

APIキーは AES-256-GCM で暗号化して SQLite に保存します。画面には先頭と末尾4文字だけを表示し、復号したキーをAPIレスポンスへ返すことはありません。ベースURLは `https` のみ許可し、`http` は localhost の検証用に限ります。

## 環境変数

| 変数 | 既定値 | 内容 |
| --- | --- | --- |
| `CRM_DATA` | `customer-crm/data` | SQLite の保存ディレクトリ |
| `CRM_USER` | `admin` | ログインユーザー名 |
| `CRM_NAME` | `管理者` | 画面に表示する名前 |
| `CRM_PASSWORD` | 未設定時 `demo` | ログインパスワード |
| `CRM_SESSION_KEY` | 起動ごとに生成 | セッション署名鍵（32文字以上推奨） |
| `CRM_SECRET` | `data/.secret` を自動生成 | APIキー暗号化の元鍵。本番では必ず設定 |
| `CRM_SECURE_COOKIES` | `0` | HTTPS運用時は `1` |

`CRM_SECRET` を変更すると、保存済みAPIキーは復号できなくなります（顧客の再登録が必要）。本番では HTTPS リバースプロキシの背後で動かし、`CRM_SECURE_COOKIES=1` を設定してください。

## データモデル

- `customers`: 顧客（TUTIテナント）。名前、slug、ベースURL、環境、暗号化したAPIキー、メモ、有効フラグ
- `customer_cache`: 顧客 × APIスコープの最新スナップショット（最終同期時刻とエラーを保持）

同期に失敗した項目は前回の内容を保持し、画面にエラーを表示します。APIキーやトークンはログに出しません。

## APIの概要

すべてログインセッションが必要です。書き込み系は `X-CSRF-Token` も必要です。

- `GET /api/dashboard`
- `GET|POST /api/customers`
- `GET|PUT|DELETE /api/customers/{id}`
- `POST /api/customers/{id}/sync`
- `POST /api/sync-all`
- `GET /api/licenses?q=&environment=&status=&customer_id=`
- `GET /api/invoices?period=&status=&customer_id=`
- `GET /api/events?customer_id=&limit=`
- `GET /api/export/licenses.csv`
- `GET /api/export/invoices.csv`

## 制限事項

- 読み取り専用です。TUTI側のデータを変更する操作はありません。
- 単一管理者ログインです。ユーザーごとの権限管理は未実装です。
- SQLite は単一プロセス向けです。同時書き込みが多い本番では PostgreSQL などへの移行を検討してください。

## テスト

```powershell
cd "$env:USERPROFILE\Documents\API"
customer-crm\.venv\Scripts\python.exe -m unittest tests.test_tuti_crm -v
```

APIはローカルの擬似BaaSサーバーに対して検証します（外部通信なし）。
