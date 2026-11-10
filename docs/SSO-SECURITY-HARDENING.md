# SSO ID サービスのセキュリティ強化

`https://sso.2415.jp` の SSO Core（`sso-ftp-source-20261103-002438/server.py`）に対する強化内容と、運用時の確認項目をまとめます。OIDC Discovery は `https://sso.2415.jp/.well-known/openid-configuration` です。

## 今回の追加

| 対策 | 内容 |
| --- | --- |
| HSTS | `Strict-Transport-Security: max-age=31536000; includeSubDomains` を全レスポンスへ付与。HTTPで開かれても以後HTTPSへ固定 |
| タブ乗っ取り対策 | `Cross-Origin-Opener-Policy: same-origin-allow-popups`。外部ページから `window.opener` 経由でSSO画面を操作させない |
| 権限の明示 | `Permissions-Policy` に `payment=()` と `usb=()` を追加 |
| 認証面の全体レート制限 | 認証系POSTと `GET /authorize` に、IP単位の全体予算（240回/5分）を追加。エンドポイントを切り替える試行も抑制 |
| ログアウト時の消去 | `Clear-Site-Data: "cache", "cookies", "storage"` を返し、端末側の残存状態を消去 |

## 既存の主要対策（確認済み）

- パスキー（WebAuthn）を第一要素にし、`userVerification=required`、チャレンジは32バイト乱数、カウンタ巻き戻しを拒否
- TOTPは6桁・前後1ステップのみ許可し、`last_step` の原子的更新で**再生を拒否**
- 回復はメールOTP＋登録済みTOTPまたは未使用の復旧証明書が必須。成功時に**全パスキー・TOTP・セッション・認可コード・アクセストークンを失効**
- ログイン失敗はアカウント単位で5回/15分ロック。回復コード送信は3回/時、再送60秒間隔
- レート制限キーはIP・IDをHMAC化して保存（生のIP/メールを保存しない）
- 認証系POSTは `Origin` を `https://sso.2415.jp` に限定。ブラウザーセッションはCSRFハッシュで保護
- 未登録SSO IDでも応答形状・状態コードを揃え、存在有無を推測させない
- セッションは8時間の絶対期限と30分のアイドル期限。Cookieは `__Host-` 接頭辞・`Secure`・`HttpOnly`・`SameSite=Lax`
- 認可コードは90秒・単回使用、PKCE S256必須、リダイレクトURIは登録値と完全一致
- 管理系APIはBasic認証＋管理者セッション＋直近2分の再認証を要求
- CSPは `default-src 'none'`、スクリプトはnonce方式。全レスポンス `Cache-Control: no-store`

## 運用確認

```powershell
curl.exe -sI https://sso.2415.jp/healthz | Select-String "Strict-Transport-Security|Content-Security-Policy|Cross-Origin-Opener-Policy"
```

- HSTSはブラウザーに長期保存されるため、検証環境で有効化する場合はドメインを分けてください。
- レート制限の上限は `GLOBAL_AUTH_RATE_LIMIT` / `GLOBAL_AUTH_RATE_WINDOW` と `rate_policy` で調整します。NAT配下の同時ログインが多い場合は全体予算を上げてください。
- 強化後は `tests/test_sso_security.py` を実行します。

```powershell
python -m unittest tests.test_sso_security
```

## 配備時の注意

`server.py` はSSO Coreの本番コードです。配備は `operations/SSO/Deploy-SsoTenantInvite.ps1` など既存の手順で行い、配備後に `/healthz` とログイン・ログアウトを確認してください。秘密鍵、DB、メール鍵は公開領域へ置かないでください。

## 今後の候補

- 認証イベントの監査ログ（ログイン成功/失敗、回復、パスキー変更）をDBへ記録し、管理画面から確認できるようにする
- ユーザーごとの同時セッション上限と、不審セッションの一括失効
- 署名鍵のローテーション（`kid` 付きJWKSと旧鍵の並行公開）
