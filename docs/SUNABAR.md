# Sunabar API エミュレーター

Sunabar は、本番環境や Sandbox API に接続せずに、API連携のリクエストと応答を試せる独立したエミュレーターです。発行されるライセンスとAPIキーはデモ専用で、実ソフトの認証には使えません。

## ブラウザーで試す

[Sunabar Playground](https://2415.jp/license/sunabar/) を開き、専用APIキーを発行します。画面の左側から操作を選び、必要に応じてJSONを編集して「APIを呼び出す」を押してください。

- 稼働確認はAPIキーなしで実行できます。
- キー発行後は、ライセンス発行→検証→端末認証→セッション確認・更新・終了の一連の流れを試せます。
- 発行したライセンスや端末トークンは、次の操作の入力欄に自動で引き継がれます。
- APIキーはタブの `sessionStorage` に保存され、トークンと発行ライセンスは画面を開いている間だけメモリー上で扱われます。
- リクエスト履歴を押すと、その時のJSONと応答を再表示できます。履歴を消すと画面上の履歴だけが消えます。

## APIエンドポイント

Core Server直結のベースURLは `https://suna.2415.jp/suna/api/v1/` です。2415.jpのPlaygroundは同一オリジン中継を利用します。

| 操作 | Core Server | 2415.jp中継 | メソッド |
| --- | --- | --- | --- |
| 稼働確認 | `healthz` | `health.php` | GET |
| 専用キー発行 | `key` | `key.php` | POST |
| 製品一覧 | `products` | `products.php` | GET |
| デモライセンス発行 | `licenses` | `licenses.php` | POST |
| ライセンス検証 | `verify` | `verify.php` | POST |
| ライセンス一覧 | `licenses/list` | `license-list.php` | GET |
| ライセンス失効 | `licenses/revoke` | `license-revoke.php` | POST |
| 端末認証 | `activate` | `activate.php` | POST |
| セッション確認 | `session/check` | `session-check.php` | POST |
| セッション更新 | `session/refresh` | `session-refresh.php` | POST |
| セッション終了 | `session/deactivate` | `session-deactivate.php` | POST |

2415.jp中継のベースURLは `https://2415.jp/license/api/sunabar/v1/` です。稼働確認以外は `X-Sunabar-API-Key: <専用キー>` を付けます。POSTには `Content-Type: application/json` を指定します。`Authorization: Bearer <専用キー>` も利用できます。

## 端末セッションの例

端末IDは1～128文字のASCII英数字、ドット、コロン、アンダースコア、ハイフンで指定します。

```json
{
  "license_key": "<demo-license-key>",
  "device_id": "demo-device-01"
}
```

`activate` の応答に含まれる `data.session.access_token` は `session/check` に、`refresh_token` は `session/refresh` と `session/deactivate` に渡します。更新に成功すると両トークンがローテーションされ、古いトークンは使えなくなります。終了操作は `refresh_token` と同じ `device_id` を受け取り、その端末のセッションを無効化します。

アクセストークンの有効期間は最大1時間、更新トークンは最大7日です。ライセンスと専用APIキーの期限を超えて有効になることはありません。セッション情報はDBにハッシュで保存されます。

## 主な応答エラー

- `401 invalid_api_key` / `expired_token`: 専用キーの期限切れまたは不正。Playgroundで新しいキーを発行してください。
- `401 license_unavailable`: ライセンスが存在しない、失効済み、または期限切れです。
- `401 invalid_session_token`: セッショントークンが古い、無効、または端末IDが一致していません。
- `409 device_limit_reached`: ライセンスの端末数上限に達しています。
- `422 invalid_device_id`: 端末IDの文字種または長さを確認してください。
- `503 sunabar_upstream_unavailable`: Core Serverへ一時的に接続できません。時間をおいて再試行してください。

## 分離と制限

専用キー・ライセンスはワークスペース単位で分離されます。レート制限とデモ専用DBを使用し、実BaaS、Sandbox、契約・請求情報にはアクセスしません。画面でリセットするとブラウザーに保持したキー、フォーム、応答、履歴を消去します。DBに作成されたデモ記録は画面リセットでは削除されず、失効操作でライセンスを無効化できます。
