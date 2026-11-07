# V8プロダクトキー発行の使い方

V8は、ライセンス台帳を使って発行ジョブと結果を管理するプロダクトキー発行APIです。1ジョブあたりの受付上限は100,000件です。実際の完了時間はサーバー負荷、データベース、ジョブサイズに依存します。固定の発行速度を保証するものではありません。

## 処理方式

新しい一括発行はV8を利用します。V1の1件発行は互換用に継続します。V2・V3・V7と旧HA発行入口はHTTP 410を返し、V4〜V6は新規受付のPOSTを停止します。受付済みV4〜V6ジョブの状態・結果取得・キャンセルと、処理を完了するための旧ワーカーは継続します。V1で複数件の発行を指定した場合もV8への移行案内を返します。

契約者ポータルとサービスAPIの一括発行はV8の受付・状態・結果・キャンセルを利用します。HAのエクスポート・状態確認・復元対象には `product_key_v8_jobs` と `product_key_v8_items` を含めます。

V8テーブルだけを追加・検査する場合、HA運用認証付きで `POST /ha/migrate.php` に `{"scope":"v8"}` を指定します。このモードは旧版データの移行を実行しません。移行前の待機系バックアップには、HA同期トークン付きの `GET /ha/export.php?standby_backup=1` を使えます。これは昇格操作ではなく、通常の待機系エクスポート制限は維持します。スナップショットには秘密情報が含まれるため、公開フォルダーやGitへ保存せず、暗号化して保管してください。

1,000件以下のリクエストでは、受付APIが最大2秒の予算内でインライン処理を試みます。完了すればHTTP 200で `execution: completed_inline` が返ります。時間内に完了しない場合や1,000件を超える場合は、HTTP 202で `execution: async` とジョブ情報が返ります。非同期ジョブの完了にはHAワーカーの定期実行が必要です。

この境界は実装上の処理方式であり、速度や完了時間の保証値ではありません。これまでの単発ベンチマークは、その実行環境・データ量の測定記録にすぎず、本番負荷の性能予測には使わないでください。

## 発行リクエスト

`licenses:write` スコープを持つ有効なテナントAPIキーを使います。サンドボックスでは `X-BaaS-Environment: sandbox`、本番では `production` を指定します。

```http
POST /license/api/baas/v8/issuance.php
Content-Type: application/json
X-Tenant-API-Key: <tenant-api-key>
X-BaaS-Environment: sandbox
Idempotency-Key: v8-demo-20261103-001
```

```json
{
  "product_id": 123,
  "count": 1000,
  "license_mode": "single",
  "idempotency_key": "v8-demo-20261103-001",
  "label": "社内検証"
}
```

`product_id` は対象テナントで利用できる製品のID、`count` は1～100,000です。重複送信を避けるため、同一リクエストの再試行では同じ冪等キーを使ってください。ボディと `Idempotency-Key` ヘッダーの両方を指定する場合は同じ値にします。同じキーで異なる内容を送るとHTTP 409になります。

## 完了確認と結果取得

レスポンスの `job` にある `status_endpoint` を使って状態を確認します。`succeeded_count` と `failed_count` を確認し、ジョブが `completed` になってから `results_endpoint` をページ単位で取得してください。結果取得にも同じテナントの認証情報が必要です。

```text
GET /license/api/baas/v8/issuance.php?job_id=<job-id>
GET /license/api/baas/v8/issuance-results.php?job_id=<job-id>&cursor=<cursor>&limit=1000
POST /license/api/baas/v8/issuance-cancel.php
POST /license/ha/product-key-v8-worker.php
```

受付APIと状態・結果APIの最大ページサイズは1,000件です。ワーカー用エンドポイントは一般利用者から直接実行せず、サーバー側の保護されたスケジュール実行で呼び出します。

## 実装上の上限

- 最大受付数: 100,000件/ジョブ
- インライン処理の対象: 1,000件以下、最大予算2,000ms
- 非同期処理チャンク: 10,000件
- DB挿入バッチ: 2,000件
- 結果ページ: 最大1,000件

これらは現行ソースの設定値です。変更時には `xrea-source/baas_v8_handlers.py` とこの資料を同時に更新してください。
