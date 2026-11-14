# TUTI Operations デスクトップ管理ソフト

Windows向けの管理者用PCアプリです。Rust版を現在の開発ベースとして追加しました。管理APIや運用機能は既存サーバー側を使用し、アプリはXREAサーバー上の設定・データベースを直接変更しません。

## Rust版をビルド・起動

Rust 1.88以降とWindowsのC++ Build Tools（MSVC）を用意し、PowerShellから次を実行します。

```powershell
cd "$env:USERPROFILE\Documents\API\XreaOperationsDesktop\rust"
cargo run --release --target x86_64-pc-windows-msvc
```

配布用EXEは `rust\target\x86_64-pc-windows-msvc\release\TutiOperations.exe` に生成されます。単体実行ファイルとして配布するには、MSVCランタイムが必要な端末への同梱方法も含めて配布パッケージを準備してください。

画面の日本語表示にはWindows標準フォント（Yu Mincho）を使い、アプリにはフォントファイルを同梱しません。日本語フォントがないWindowsではOSに日本語フォントを追加してください。`Build-Rust.ps1` は現在起動中の旧EXEをロックしないよう、x64用ターゲットフォルダーへ出力します。

依存関係を含む型チェック:

```powershell
cargo check
```

## ログインと接続先

「SSO IDでログイン」から既定ブラウザーでSSO Coreにサインインします。アプリは `https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop` でログインを開始し、認証応答を一時的な `127.0.0.1` ループバックに受け取ります。API呼び出しは `https://2415.jp/license/admin_api.php` とテナント管理APIを使用します。

セッションはアプリ稼働中のメモリーだけに保持します。ローカルファイルには保存しません。管理権限、Passkey再認証、テナント状態の確認はサーバー側に委ねます。通信に失敗した場合は画面下部にAPIのエラーを表示します。

## 主な運用機能

- テナントの一覧、作成、名称・プラン変更、一時停止、再開、検証sandbox作成
- sandboxライセンスの作成、ライセンス検索・発行・停止・再開、端末再認証、期限延長、削除・復元
- テナントAPIクライアントの発行、ローテーション、失効
- 監査ログの検索
- 管理者一覧とPasskey再認証付きロール変更
- tenant IDを指定した契約者SSO招待

発行したプロダクトキーとAPIキーは画面に一度だけ表示します。必要な場合は表示中にコピーし、安全な保管先に保存してください。

## 旧版

従来のWinForms/C#版ソース（`Form1.cs`、`XreaOperationsDesktop.csproj`）は移行中の比較・切り戻し用に残しています。Rust版の運用確認が済むまでは削除しません。

## 関連資料

- [SSO Discoveryとログイン](../docs/OIDC-DISCOVERY.md)
- [契約者SSO招待とtenant ID](../docs/SSO-CONTRACTOR-INVITE.md)
- [V8プロダクトキー発行](../docs/PRODUCT-KEY-ISSUANCE-V8.md)\n\n