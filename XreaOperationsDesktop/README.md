# TUTI Operations デスクトップ管理ソフト

Windows向けの独立した管理者用PCアプリです。契約者向けポータルではありません。管理者SSO IDで認証し、XREA側の管理APIを通じてテナント、ライセンス、APIキー、監査ログ、契約者SSO招待を運用します。

## 起動

ビルド済みの場合は `bin/Release/net8.0-windows/win-x64/publish/TutiOperations.exe` を実行します。ファイルがない場合は、このディレクトリで.NET 8 SDKを使ってビルドします。

```powershell
dotnet publish .\XreaOperationsDesktop.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:EnableCompressionInSingleFile=true
```

## ログインと接続先

アプリの「SSO IDでログイン」から既定のブラウザーでSSO Coreにサインインします。デスクトップアプリの管理API URLは `https://2415.jp/license/admin_api.php`、ログイン開始URLは `https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop` です。サーバー側で管理者権限と操作ごとの権限を確認します。

コールバックはアプリが一時的に開く `127.0.0.1` のループバックアドレスに限定され、49152～65535番ポートと `/callback` を使います。認証トークンはアプリの実行中メモリーで扱い、ファイルには保存しません。ログアウトまたはアプリ終了後は再度SSO認証が必要です。

## 主な運用機能

- テナントの一覧、作成、名称・プラン変更、一時停止、再開
- sandboxライセンスの作成、ライセンス検索・発行・停止・再開
- テナントAPIキーの発行、ローテーション、失効
- 監査ログの検索と変更前後の確認
- 契約者向けSSO招待の作成。招待先メールアドレスとtenant IDを指定し、送信前のPasskey再認証を行う

実際に利用できる操作は、サーバー側の管理者ロール、権限、テナント状態によって制限されます。発行済みAPIキーなどの秘密値は安全な場所に保管してください。

## 関連資料

- [SSO Discoveryとログイン](../docs/OIDC-DISCOVERY.md)
- [契約者SSO招待とtenant ID](../docs/SSO-CONTRACTOR-INVITE.md)
- [V8プロダクトキー発行](../docs/PRODUCT-KEY-ISSUANCE-V8.md)
