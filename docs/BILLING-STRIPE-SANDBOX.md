# Stripe請求書決済（メールアドレス非収集・Sandbox検証）

発行済み請求書をStripe InvoicingのHosted Invoice Pageで支払い、署名済みWebhookで入金済みにする手順です。まずSandbox環境でテストモードのカード決済を通し、本番請求と同じ流れ（請求書 → 決済 → 入金 → 監査・HA同期）を確認します。

コードは `xrea-source/stripe_billing.py`、ポータル操作は `/api/baas/v1/tenant-sso.php` の `create_invoice_checkout`、Webhookは `/api/stripe/webhook.php` です。決済状態は `stripe_invoice_payments` と `stripe_webhook_events` に保存し、スキーマ039の47表には含めません。

## 前提

- Stripeのアカウントとテスト用APIキー（`sk_test_`）、Webhook署名シークレット（`whsec_`）
- 発行済み（`issued`）の請求書。管理者が `ha/api-billing-admin.php` の `issue` で確定したもの
- ポータルへのSSO IDログイン。カード決済は `tenant:read` を持つSSOセッションでのみ開始できます

## 秘密情報の設定

リポジトリや公開ディレクトリへキーを書かないでください。非公開の `PYTHON_MIGRATION_PRIVATE_DIR` にある `runtime/runtime-secrets.json`、または環境変数で設定します。

| 用途 | runtime-secrets.json の名前 | 環境変数 |
| --- | --- | --- |
| Stripe APIキー | `stripe_secret_key` | `PYTHON_MIGRATION_STRIPE_SECRET_KEY` |
| Webhook署名シークレット | `stripe_webhook_secret` | `PYTHON_MIGRATION_STRIPE_WEBHOOK_SECRET` |
| 本番キーの有効化（`1` で有効） | `stripe_enable_live` | `PYTHON_MIGRATION_STRIPE_ENABLE_LIVE` |
| ポータル戻り先の上書き（任意） | `stripe_return_base_url` | `PYTHON_MIGRATION_STRIPE_RETURN_BASE_URL` |

テストキー（`sk_test_`）は常にテストモードとして扱い、決済画面にテストカードを要求します。本番キー（`sk_live_`）は追加で `stripe_enable_live=1`（または環境変数 `=1`）が設定されている場合だけ有効になり、Sandboxテナントからは開始できません（`stripe_live_sandbox_blocked`）。

ポータルでは `https` のホスト名から戻り先URLを組み立てます。リバースプロキシ等で異なるURLが必要な場合だけ `stripe_return_base_url` を `https://` のURLで設定してください。

`operations\Xrea\Configure-StripeBilling.ps1` のGUIから、これらの値を両ノードの `runtime-secrets.json` へまとめて設定できます。

## データベースの準備

- 新規構築: `xrea-source/db/install.sql` に加えて `xrea-source/db/migrations/030_stripe_billing.sql` を適用します。
- 既存環境: HA運用認証で `POST /ha/migrate.php` に `{"scope":"stripe"}` を送ります。コード内の `ensure_schema` と同じ内容で、追加のみを行います。

## Stripe側のWebhook設定

StripeダッシュボードのWebhookで次を登録します。

```text
https://2415.jp/license/api/stripe/webhook.php      （本番プレフィックス /license の場合）
https://<sandbox-host>/license/python-migration/api/stripe/webhook.php  （移行検証環境）
```

送信イベントは `invoice.paid` と `invoice.payment_failed` を登録します。APIキー再発行の即時決済は従来どおりCheckoutを使うため、`checkout.session.completed`、`checkout.session.expired`、`payment_intent.payment_failed` も残してください。署名シークレットを上記の `stripe_webhook_secret` に設定します。

Webhookはブラウザーや管理セッションではなく、`Stripe-Signature` のHMAC（`t` と `v1`、許容誤差300秒）で検証します。署名不一致はHTTP 400、設定不足はHTTP 503を返します。同じイベントIDは `stripe_webhook_events` で重複処理しません。

## Sandboxでのテスト手順

1. 管理者アプリまたは管理APIで、対象テナントの請求書を `issue` して発行済みにします。
2. 契約者ポータルへSSO IDでログインし、「利用・請求」→対象の請求書を開きます。
3. 「支払う」を押すとStripeのHosted Invoice Pageへ移動します。Stripeから請求メールは送信せず、ポータル上のリンクだけで案内します。テストカード `4242 4242 4242 4242`、将来の有効期限、任意のCVCを入力します。
4. 決済後はポータルを再読み込みし、`invoice.paid` Webhookの処理後に請求書が「入金済み」になることを確認します。
5. 管理APIの `list` で `status=paid`、`paid_at` が入っていることを確認します。
6. `stripe_invoice_payments` が `completed`、`stripe_webhook_events` が `processed` になっていることを確認します。
7. 監査ログに `api_billing_invoice_paid`（`provider=stripe`）が記録され、Primaryでは待機系への同期が実行されます。

3DSや失敗系はStripeのテストカード（`4000 0027 6000 3184`、`4000 0000 0000 0002` など）で確認できます。失敗時は請求書が発行済みのまま残り、`stripe_invoice_payments` が `failed` になります。

## APIキー再発行（500円）の即時決済

Stripeが有効な環境では、契約者ポータルの「APIキー再発行」は月次請求への加算ではなく、**500円（税込）の即時決済**になります。

1. ポータルの設定画面で「APIキー再発行（500円）」を開きます（SSO再認証から5分以内）。
2. 従来どおりStripe Checkoutで500円を支払います。返り先には短時間有効な `sso_ticket` を付け、ポータルのSSOセッションを復元します。
3. 署名済みWebhookが `metadata.kind=key_reissue` を確認し、決済額が500円であることを照合してから、新しいキーを作成して旧キーを60分の移行期間へ移します。
4. ポータルへ戻ると、同じリクエストIDで結果を取得し、新しいキーを表示します。

- 決済とキー発行は別トランザクションです。キー発行だけ失敗した場合は `stripe_key_reissue_payments.status=paid_unissued` として記録し、自動では再課金しません。
- `Idempotency-Key` は再発行リクエストIDとして使い、同じIDの再試行では進行中のCheckout Sessionを再利用します。
- 決済完了後の結果表示は10分以内です。過ぎた場合は二重決済を避けるため、管理者が `stripe_key_reissue_payments` とStripeの決済記録を確認してください。
- 即時決済分は `tenant_portal_key_reissues` へ入れないため、月次請求書には加算されません。
- Stripeが未設定の環境では、従来どおり月次請求書への加算で動作します。

## 金額と請求書の扱い

- StripeのJPYは整数円のため、請求書の合計（0.001円単位）を**円未満切り上げ**して送ります。
- 50円未満の請求書は `invoice_amount_too_small` で拒否します。
- Webhookでは `amount_total` と `currency` が作成時の記録と一致する場合だけ入金にします。不一致は `stripe_amount_mismatch` として拒否します。
- 決済と入金確定は同一トランザクションです。請求書が `void` などに変わっていた場合は入金にせず、決済記録を `skipped` にします。
- 同じ請求書で進行中のCheckout Sessionは再利用します。期限切れ・失敗後の再実行は新しい決済として扱います。Stripe側の `Idempotency-Key` は請求書IDと決済IDから生成します。

## 本番へ切り替えるとき

1. テストモードで請求書発行から入金・監査・HA同期まで確認します。
2. 本番シークレットを `sk_live_` のキーと本番Webhook署名シークレットへ差し替えます。
3. `PYTHON_MIGRATION_STRIPE_ENABLE_LIVE=1` を本番ノードだけに設定します。
4. 少額の実請求書で決済し、返金手順も確認します。

テストモードの決済でも請求書は `paid` になります。Sandboxで確認した請求書を本番の請求として残さないよう、テスト後に `void` へ戻すか、テスト専用テナントの請求書を使ってください。

## 主なエラー

| エラー | 意味 |
| --- | --- |
| `stripe_not_configured` | APIキーまたはWebhook署名シークレットが未設定、または本番キーが無効 |
| `invoice_not_payable` | 請求書が発行済みではない |
| `invoice_not_found` | 請求書がログイン中の契約に属していない |
| `stripe_checkout_completed` | 同じ請求書の決済が完了済み。状態を再読み込みする |
| `stripe_live_sandbox_blocked` | 本番キーでSandboxテナントから開始した |
| `stripe_checkout_failed` | Stripe APIまたはネットワーク障害。時間をおいて再試行する |
| `stripe_webhook_not_configured` / `invalid_signature` | Webhook設定・署名の不一致。設定と生の本文を確認する |

秘密情報、カード番号、Checkout SessionのURLをチャットやログへ記録しないでください。


## 個人情報・メール非収集方針

- 請求書決済用Stripe Customerにはメールアドレス、電話番号、住所、配送先を登録しません。
- Stripe Customer / Invoice metadataには内部の請求書ID・決済ID・テナントIDと `privacy_profile=no_email` のみを設定します。
- 請求書は `collection_method=send_invoice` で作成しますが、`auto_advance=false` のまま確定し、Stripeの送信API（`/send`）は呼び出しません。Stripeから請求メールを送信しません。
- テナントポータルはSSO認証・請求書のテナント所有権検証後にのみ決済URLを返します。StripeのHosted Invoice URLは秘密情報として扱い、ログ・監査情報へ記録しないでください。
- 既存DB互換性のため `stripe_invoice_payments.checkout_session_id` にStripe Invoice ID（`in_...`）を格納します。APIレスポンスの `checkout_url` は互換性維持のため残し、中身はHosted Invoice URLです。
- APIキー再発行（500円）のCheckoutは今回の変更対象外です。
