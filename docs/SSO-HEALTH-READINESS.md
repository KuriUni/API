# SSO CoreのReadiness確認（/healthz）

`GET https://sso.2415.jp/healthz`は、HTTPプロセスの応答だけでなく、認証に必要なデータベースと署名鍵のreadinessを確認します。

## 確認項目と応答

- `database`: DBファイルへ接続でき、必要なテーブルを利用できる
- `signing`: 公開鍵を読み出し、有効期限付きのテストJWT署名を実行できる

必須項目が利用可能ならHTTP 200と`{"ok":true,...}`を返します。いずれかが失敗した場合はHTTP 503と`{"ok":false,...}`を返し、`checks`に項目ごとの状態を含めます。

## 確認方法

```powershell
Invoke-WebRequest -Uri 'https://sso.2415.jp/healthz' -Method Get
```

HTTP 503の場合は応答本文の`checks`で`database`と`signing`のどちらが失敗したか確認し、サーバー上のDBファイル、テーブル、鍵の配置と読み取り権限を調べます。秘密鍵や認証情報をヘルプ、URL、チャットへ貼らないでください。

## この確認の範囲

このエンドポイントはDBへの認証フロー全体、メール配信、外部クライアント設定、ブラウザーでのログイン完了を試しません。`ok:true`はDBと署名処理のreadinessを示し、利用者のログイン成功を保証するものではありません。
