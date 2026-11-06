# PowerShell 運用スクリプト一覧

通常はプロジェクトルートの `Xrea-Operations.cmd` を起動し、カテゴリから操作を選びます。個別スクリプトは `operations` 以下に用途別で整理しています。起動時の作業フォルダーはプロジェクトルートに固定し、既存データ・資格情報の位置を保ちます。

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
