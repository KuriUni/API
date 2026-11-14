# TUTI Operations デスクトップ管理ソフトの使い方

TUTI OperationsはWindows向けの管理者用PCソフトです。現在の開発ベースはRust版で、Webブラウザー内ではなくPC上のネイティブウィンドウで動作します。`XreaOperationsDesktop\rust\target\x86_64-pc-windows-msvc\release\TutiOperations.exe`を起動し、「SSO IDでログイン」を選びます。既定のブラウザーでSSO Coreの認証を行い、完了後にPCアプリへ戻ります。

## ログインとセキュリティ

認証トークンはアプリの実行中メモリーで扱い、ファイルには保存しません。ログアウトまたはアプリ終了後はアプリから再利用できません。管理APIは `https://2415.jp/license/admin_api.php` に接続し、サーバー側でも管理者ロールと操作権限を確認します。

デスクトップ認証の開始URLは次のとおりです。

```text
https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop
```

認証コールバックはアプリが一時的に待ち受ける`127.0.0.1`上のループバック接続に限定されます。ランダムな空きポートと`/callback`パスを使い、state値を照合します。

## 管理できる情報

- tenant一覧、作成、名称・プラン変更、一時停止・再開、検証sandbox作成
- ライセンスの発行・検索・停止・再開、端末再認証、期限延長、削除・復元
- tenant APIキーの発行、ローテーション、失効
- 監査ログの検索
- 契約者向けSSO ID招待。招待先メールとtenant IDを結び付け、送信前にPasskeyで再認証
- 管理者一覧とPasskey再認証付きロール変更

実際に利用できる操作はサーバー側の権限で決まります。招待メールを送る前に、選択したtenant IDと宛先を確認してください。招待自体でTenant APIキーやポータル権限が自動発行されるわけではありません。

## Rust版のビルド

Rust 1.88以降とWindows MSVC Build Toolsを用意します。PowerShellから次を実行してください。

```powershell
cd "$env:USERPROFILE\Documents\API\XreaOperationsDesktop"
.\Build-Rust.ps1
```

実行ファイルは`rust\target\x86_64-pc-windows-msvc\release\TutiOperations.exe`に出力されます。画面表示にはWindowsの`yumin.ttf`日本語フォントを使います（アプリには同梱しません）。依存関係のコンパイル確認だけを行う場合は次を使います。

```powershell
cd "$env:USERPROFILE\Documents\API\XreaOperationsDesktop\rust"
cargo check
```

## 旧版

WinForms/C#ソースは移行確認用として同じプロジェクト内に保管しています。Rust版を本番運用へ切り替える際は、SSOログイン・権限・各操作を対象サーバーで確認してから旧版を整理してください。\n