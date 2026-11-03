# OpenID Connect Discoveryとログイン

SSO Coreは設定情報を `https://sso.2415.jp/.well-known/openid-configuration` で公開します。これはログイン画面ではなく、OIDCクライアントが接続先や対応方式を確認するためのJSONです。

## 主な項目

| 項目 | 用途 |
| --- | --- |
| `issuer` | IDトークンを発行するSSO Coreの識別子 |
| `authorization_endpoint` | ユーザー認証を開始する接続先 |
| `token_endpoint` | 認可コードをトークンへ交換する接続先 |
| `userinfo_endpoint` | 認証済みユーザーの情報を取得する接続先 |
| `jwks_uri` | IDトークン署名の検証鍵を取得する接続先 |
| `end_session_endpoint` | SSO Coreのログアウト接続先 |

現行実装はAuthorization Code Flow、PKCE `S256`、IDトークンの`RS256`署名を使用します。登録済みクライアントは`client_secret_basic`で認証します。Discovery JSONにClient Secretや秘密鍵は含まれません。クライアントSecretはサーバー側で保管し、ブラウザーへ渡さないでください。

## 管理者PCアプリ

TUTI OperationsはWindows上で動作する管理者向けデスクトップアプリです。SSO認証後にテナント、ライセンス、APIキー、監査ログ、契約者SSO招待を管理します。管理者IDで契約者ポータルを利用する設計ではありません。管理操作は[デスクトップ運用資料](../tools/TUTI-OPERATIONS-DESKTOP.md)を参照してください。

## 契約者SSO招待

管理者アプリから招待先メールアドレスとtenant IDを指定して招待を作成します。招待作成・メール送信の前にPasskeyによる管理者本人確認が必要です。招待の登録とtenant IDの関係は[契約者SSO招待資料](./SSO-CONTRACTOR-INVITE.md)を参照してください。

## ログアウト

アプリやポータルのログアウト操作は、まずアプリ側のセッションを終了してからSSO Coreのログアウトへ進みます。SSO Coreのログアウト後、同じブラウザーで再度認証が必要になる場合があります。登録済みのログアウト戻り先以外へリダイレクトしてはいけません。
