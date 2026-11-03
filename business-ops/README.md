# 業務記録 Web アプリ（試作）

このフォルダーは、個人の勤怠・業務記録を扱うPython/FastAPIのWebアプリ試作です。TUTI OperationsのWindows管理者デスクトップソフトとは別製品です。テナント、ライセンス、APIキー、契約者SSO招待を管理する機能はありません。また、このREADMEだけでは本番環境へのデプロイ済みであることを示しません。

## 現在の機能

- SSO CoreのOIDCログイン（Authorization Code + PKCE、state、nonce）
- 本人の勤務記録の登録・日別修正
- 勤務記録の月次集計と診断
- CSVダウンロード
- SQLiteへの保存

Google DriveへのPDF保管や複数人の承認など、元のExcel VBAにある機能はこの試作の範囲外です。

## SSOクライアント設定

SSO Core側に専用OIDCクライアントを登録し、登録されたClient ID、Client Secret、HTTPSのコールバックURLを環境変数で設定します。クライアント登録とSecret発行はSSO管理者が行います。

```text
BUSINESS_OPS_OIDC_ISSUER=https://sso.2415.jp
BUSINESS_OPS_OIDC_CLIENT_ID=<registered-client-id>
BUSINESS_OPS_OIDC_CLIENT_SECRET=<secret-from-SSO-Core>
BUSINESS_OPS_OIDC_REDIRECT_URI=https://<app-host>/auth/callback
BUSINESS_OPS_SESSION_KEY=<random-secret-at-least-32-characters>
BUSINESS_OPS_DATA=<persistent-directory-outside-web-root>
```

Secret、セッション鍵、SQLiteデータベースをソースや公開ディレクトリに置かないでください。HTTPSリバースプロキシの後ろで実行し、Uvicornをインターネットへ直接公開しないでください。CookieのSecure設定を使うため、ログイン確認にはHTTPSの登録済みホストが必要です。

## ローカルでの起動

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:BUSINESS_OPS_OIDC_CLIENT_ID = '<registered-client-id>'
$env:BUSINESS_OPS_OIDC_CLIENT_SECRET = '<secret>'
$env:BUSINESS_OPS_OIDC_REDIRECT_URI = 'https://<app-host>/auth/callback'
$env:BUSINESS_OPS_SESSION_KEY = '<random-secret-at-least-32-characters>'
py -m uvicorn main:app --host 127.0.0.1 --port 8765
```

認証設定がない状態ではログインを開始できません。実際のコールバックURLはSSO Coreに登録した値と完全一致させてください。
