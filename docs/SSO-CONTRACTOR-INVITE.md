# 契約者SSO ID招待とtenant ID

管理者はTUTI Operationsデスクトップアプリから、招待先メールアドレスとtenant IDを指定して契約者向けSSO ID招待を作成します。招待送信前にはPasskeyによる管理者再認証が必要です。宛先とtenant IDを確認してから送信してください。

## 招待と登録

招待リンクの有効期限は24時間です。メール確認コードは10分間有効で、誤入力が5回続くと招待は無効になります。利用者は招待を受け入れた後、Passkeyを登録してSSO IDの作成を完了します。期限切れや無効化後は、管理者に新しい招待を依頼してください。

招待に指定したtenant IDは、登録されるSSO IDのテナント所属情報に結び付けられます。招待はテナントAPIキーや各APIスコープを自動発行しません。

## ポータルを利用できる条件

SSO IDを作成しただけでは契約者ポータルを利用できません。ポータル側でも、SSO IDが対象tenantに所属していること、tenantが有効であること、必要な権限を持つ有効なTenant APIキーがあることを確認します。利用できるtenantが複数ある場合はポータルで対象を選択します。

管理者用SSO IDは契約者向けポータルの利用者ではありません。管理者作業はTUTI Operationsから行ってください。

## 関連資料

- [TUTI Operationsデスクトップ管理ソフト](../tools/TUTI-OPERATIONS-DESKTOP.md)
- [OpenID Connect Discovery](./OIDC-DISCOVERY.md)
