# TUTI Operations デスクトップ管理ソフトの使い方

TUTI OperationsはWindows向けの管理者用PCソフトです。Webページではありません。ビルド済みの`TutiOperations.exe`を起動し、「SSO IDでログイン」を選びます。既定のブラウザーでSSO Coreの認証を行い、完了後にPCアプリへ戻ります。

## ログインとセキュリティ

認証情報はアプリの実行中メモリーで扱い、ファイルには保存しません。ログアウトまたはアプリ終了後はアプリから再利用できません。管理APIは `https://2415.jp/license/admin_api.php` に接続し、サーバー側でも管理者ロールと権限を確認します。

デスクトップ認証の開始URLは次のとおりです。

```text
https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop
```

認証コールバックはアプリが一時的に待ち受ける`127.0.0.1`上のループバック接続に限定されます。ポートは49152～65535、パスは`/callback`です。

## 管理できる情報

- tenant一覧、作成、名称・プラン変更、一時停止・再開
- sandboxライセンスの発行・検索・停止・再開
- tenant APIキーの発行、ローテーション、失効
- 監査ログの検索
- 契約者向けSSO ID招待。招待先メールとtenant IDを結び付け、送信前にPasskeyで再認証

実際に利用できる操作はサーバー側の権限で決まります。招待メールを送る前に、選択したtenant IDと宛先を確認してください。招待自体でTenant APIキーやポータル権限が発行されるわけではありません。

## ビルド

Windowsに.NET 8 SDKを用意して、この資料と同じ階層のプロジェクトディレクトリで実行します。

```powershell
dotnet publish .\XreaOperationsDesktop.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:EnableCompressionInSingleFile=true
```

実行ファイルは`bin/Release/net8.0-windows/win-x64/publish/`に出力されます。
