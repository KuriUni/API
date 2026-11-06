# PowerShell 運用スクリプト一覧

通常はプロジェクトルートの `Xrea-Operations.cmd` を起動し、カテゴリから操作を選びます。個別スクリプトは `operations` 以下に用途別で整理しています。起動時の作業フォルダーはプロジェクトルートに固定し、既存データ・資格情報の位置を保ちます。

## バックアップ保持数の設定

1. プロジェクトルートの `Xrea-Operations.cmd` を起動します。
2. 画面上部の「バックアップ保持」ボタンを押します。
3. 残す世代数を1～20から選び、「保存」を押します。既定値は3世代です。

設定はWindowsユーザーごとに `%LOCALAPPDATA%\TutiOperations\settings.json` へ保存されます。対象のデプロイスクリプトが正常に完了すると、バックアップ系列ごとに設定数を超えた古い世代を自動削除します。`deploy-backups` と `xrea-source` 内のMain siteバックアップが対象です。設定変更後に既存バックアップをすぐ整理する場合は、PowerShellで `operations\Prune-DeployBackups.ps1` を実行してください。

## サイト

| スクリプト | 用途 | 注意 |
| --- | --- | --- |
| `operations/Xrea/Download-Xrea.ps1` | Primaryから公開ソースを取得 | 既定保存先はプロジェクトルートの `xrea-source` |
| `operations/Xrea/Deploy-Xrea.ps1` | XREA Primary/Backupへ同期 | 初回にDPAPI資格情報を設定。既定は両方 |
| `operations/Xrea/Sync-XreaBackup.ps1` | Backupだけへ同期 | リモートのみのファイルは保持 |
| `operations/Xrea/Deploy-TUTI-Help.ps1` | ヘルプHTMLの配置 | 既存ページをローカルバックアップしてから更新 |
| `operations/Xrea/Upload-Xrea.ps1` | 任意のフォルダーを任意の公開パスへアップロード | 高影響の汎用ツール。接続先を確認して個別実行 |

## Sunabar

| スクリプト | 用途 |
| --- | --- |
| `operations/Sunabar/Deploy-SunaCore.ps1` | Core Serverへアプリを配置し、ヘルスチェック |
| `operations/Sunabar/Deploy-Sunabar.ps1` | 2415.jp側のSunabar中継を配置 |

## Main.2415.jp

| スクリプト | 用途 | 注意 |
| --- | --- | --- |
| `operations/MainSite/Deploy-Main2415.ps1` | `xrea-source` をCore Serverのmain.2415.jp公開ルートへ同期 | Explicit FTPS、証明書固定、リモート専用ファイルを保持。パスワードはWindows DPAPIで任意保存 |

### main.2415.jpへの同期手順

1. プロジェクトルートの `Xrea-Operations.cmd` を起動し、`Main.2415.jp` → `main.2415.jpへ同期` を選びます。
2. 接続先は `v2006.coreserver.jp`（Explicit FTPS、21番ポート）です。ローカルの送信元は `xrea-source`、転送先はFTPルート `/` です。
3. FTPユーザー名を確認します。初期表示は `main@sso.2415.jp` ですが、対象のFTPアカウント名に合わせて画面で修正できます。FTPアカウントが `main.2415.jp` の `public_html` に割り当てられていることを事前に確認してください。FTPルート `/` はアカウントの公開領域を指します。
4. パスワードを画面に入力します。保存済み資格情報を使う場合はチェックを確認してください。「このWindowsユーザーのDPAPIで保存」は初期状態でオンです。保存したくない場合はオフにします。DPAPI資格情報は保存したWindowsユーザーのアカウントでのみ復号できます。
5. 接続先・送信元を示す確認画面で内容を確認し、同期を実行します。接続・証明書の検証に失敗した場合は転送を止めます。

同期はローカルの新規・更新ファイルをサーバーへ送ります。サーバーにだけ存在するファイルは削除しません。`fastapi-runtime.json`、`__pycache__`、`.tuti-deploy-backup-*`、`.tuti-deploy-stage-*` は転送対象外です。完了ダイアログのアップロード数を確認してください。

保存済みパスワードで認証に失敗した場合、スクリプトはその資格情報ファイルを削除します。ランチャーから再実行し、現在有効なFTPパスワードを入力してください。資格情報だけを消して再設定する場合は、PowerShellから次のように起動できます。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\operations\MainSite\Deploy-Main2415.ps1" -ResetCredentials
```

この起動方法は保存済み資格情報を削除して入力画面を開き、その後は通常どおり同期を続けます。新しい認証情報での転送を避けたい場合は、入力画面でキャンセルしてください。転送前には確認ダイアログが表示されます。

## SSO

| スクリプト | 用途 | 状態 |
| --- | --- | --- |
| `operations/SSO/Inspect-SsoFtp.ps1` | Core ServerのFTP構成を確認 | 読み取り用途 |
| `operations/SSO/Deploy-SsoTenantInvite.ps1` | SSO Coreの `server.py` 単体配置 | 旧個別版。対象・文字コード・配置先を確認するまでランチャーから起動不可 |

## 運用・移行

| スクリプト | 用途 | 注意 |
| --- | --- | --- |
| `operations/Maintenance/Rotate-XreaHaToken.ps1` | Primary/BackupのHAトークン更新 | 両系で整合させる高影響操作 |
| `operations/Maintenance/Run-XreaV8Migration.ps1` | V8データベース移行 | DBバックアップと対象確認が必要 |

## 個別の起動ファイル

- `Deploy-Xrea.cmd` と `Deploy-Xrea-GUI.vbs` は整理後のXREAデプロイ先へ接続する互換ショートカットです。
- `Inspect-SsoFtp.cmd` は整理後のSSO FTP確認先へ接続する互換ショートカットです。
- `business-ops/Start-BusinessOps.ps1` と `Stop-BusinessOps.ps1` はローカルの業務運用アプリ用で、XREAデプロイとは別管理です。
- `XreaOperationsDesktop/Build-Rust.ps1` は管理ソフトのビルド用です。
- `xrea-source/downloads/mnsl-card-web-bridge.ps1` は公開サイトから利用者が取得するカード読取ブリッジで、管理用スクリプトではありません。

資格情報はチャットやログへ記録しないでください。各スクリプトのGUI入力と、DPAPIで保存する場合のWindowsユーザー範囲を確認してください。
