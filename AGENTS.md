# API プロジェクト（TUTI / SSO / XREA 運用リポジトリ）

このリポジトリは、TUTI 製品群のサーバー側コード、Windows 向け管理アプリ、XREA / Core Server への配備運用スクリプトをまとめたものです。リモートは `https://github.com/KuriUni/API.git`。

## 構成

| パス | 内容 |
| --- | --- |
| `xrea-source/` | 本番公開コード（FastAPI + PHP 管理 API、ライセンス V2〜V4、SSO/OIDC、BaaS）。`app.py` / `asgi.py` が起点、`db/` にスキーマとマイグレーション |
| `sso-ftp-source-20261103-002438/` | SSO Core サーバーのソース（`server.py` ほか）。テストの参照元 |
| `suna-core-source/` | Sunabar Core Server のアプリ |
| `business-ops/` | 業務記録 Web アプリ試作（FastAPI + SQLite + OIDC）。TUTI Operations とは別製品 |
| `XreaOperationsDesktop/` | Windows 管理者デスクトップアプリ。Rust 版（`rust/`）が現行開発ベース、C# WinForms 版が旧実装 |
| `operations/` | 配備・保守用 PowerShell スクリプト（Xrea / MainSite / SSO / Sunabar / Maintenance） |
| `docs/` | SSO・ライセンス・OIDC・Sunabar の運用手順書 |
| `tools/` | 運用スクリプトの一覧ドキュメント |
| `tests/` | Python / Node のテスト |
| `deploy-backups/` | 配備時の自動バックアップ（履歴。削除は `operations/Prune-DeployBackups.ps1` で行う） |
| `TUTI-Help.html` | ヘルプページ本体。編集後は `Update-TUTI-Help.py` と `operations/Xrea/Deploy-TUTI-Help.ps1` を使う |

## 開発・検証

- Python: 各サブプロジェクトで venv を作成し、`business-ops/requirements.txt` は完全固定バージョン。依存更新はレビュー前提で行う。
- テスト: `python -m unittest discover -s tests`（Node 側は `node tests/test_bulk_jobs.cjs` など個別実行）。
- デスクトップアプリ: `cd XreaOperationsDesktop/rust && cargo check` / `cargo run --release --target x86_64-pc-windows-msvc`。
- 起動: `business-ops` は `py -m uvicorn main:app --host 127.0.0.1 --port 8765`（環境変数は README 参照）。

## 規約

- 秘密情報（Client Secret、セッション鍵、FTP 資格情報、DPAPI 保存物、SQLite 実データ）をコミットしない。設定は環境変数または Windows DPAPI に置く。
- 本番コードの変更は `xrea-source/` を編集し、配備は `operations/` の差分スクリプト経由で行う。サーバー上のファイルを直接書き換えない。
- 配備スクリプトはローカル SHA-256 台帳（`%LOCALAPPDATA%\XreaDeploy\sync-state`）で差分判定する。台帳やバックアップを手動削除すると全送信になる点に注意。
- 生成物（`__pycache__`、`*.pyc`、`.tuti-deploy-backup-*`、`.tuti-deploy-stage-*`）は配備対象外。作業用の一時ファイルはコミットしない。
- ドキュメントは日本語で記述し、運用手順は `docs/` に追記する。

## 注意

- `operations/` の配備スクリプトは本番（XREA Primary/Backup、main.2415.jp、SSO Core）に接続する。ユーザーの明示的な指示がない限り実行しない。
- 現在 `main` は `origin/main` と 4 コミットずつ分岐している。同期前に `git log --oneline --graph --all` で確認する。
