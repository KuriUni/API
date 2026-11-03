// Search the operator's permitted destinations from one keyboard-accessible
// command surface. Existing forms and links remain the source of truth.
(() => {
  'use strict';
  const triggers = [...document.querySelectorAll('[data-admin-command-open]')];
  if (!triggers.length) return;
  const dialog = document.createElement('dialog');
  dialog.className = 'command-dialog';
  dialog.setAttribute('aria-label', '管理センターの操作検索');
  dialog.innerHTML = '<div class="command-dialog-inner"><div class="command-dialog-head"><span>移動先・操作を検索</span><button type="button" class="secondary" data-command-close aria-label="閉じる">Esc</button></div><input type="search" data-command-query placeholder="例：ライセンス、受付、監査ログ" autocomplete="off"><div class="command-list" role="listbox" aria-label="操作候補" data-command-list></div></div>';
  document.body.append(dialog);
  const query = dialog.querySelector('[data-command-query]');
  const list = dialog.querySelector('[data-command-list]');
  let entries = [];
  let activeIndex = 0;
  const buildEntries = () => {
    const found = [];
    const addLink = (node, label, detail, icon = '↗') => {
      if (!(node instanceof HTMLAnchorElement) || !label) return;
      found.push({ label, detail, icon, run: () => node.click() });
    };
    document.querySelectorAll('.workspace-nav-list a.nav-item').forEach((node) => {
      addLink(node, node.innerText.trim(), '管理メニュー', node.querySelector('.nav-icon')?.textContent?.trim() || '→');
    });
    document.querySelectorAll('.workspace-nav-list form.nav-action').forEach((form) => {
      const label = form.querySelector('.nav-item')?.innerText.trim();
      if (label) found.push({ label, detail: '管理メニュー', icon: form.querySelector('.nav-icon')?.textContent?.trim() || '→', run: () => form.requestSubmit() });
    });
    document.querySelectorAll('.ops-guide-card,.ops-reception-card,.action-list a.action-row,.panel-link').forEach((node) => {
      const label = node.querySelector('b,strong')?.textContent?.trim() || node.textContent.trim().replace(/\s+/g, ' ').slice(0, 70);
      const detail = node.querySelector('small')?.textContent?.trim() || 'ダッシュボードのショートカット';
      addLink(node, label, detail, node.querySelector('.ops-guide-number,.action-symbol')?.textContent?.trim() || '↗');
    });
    document.querySelectorAll('.action-list form.action-row,.ops-queue-card').forEach((form) => {
      const label = form.querySelector('.action-copy b,.ops-queue-label')?.textContent?.trim();
      if (label) found.push({ label, detail: form.querySelector('.action-copy small,.ops-queue-note')?.textContent?.trim() || '一覧を開く', icon: form.querySelector('.action-symbol,.ops-queue-icon')?.textContent?.trim() || '→', run: () => form.requestSubmit() });
    });
    return found;
  };
  const render = () => {
    const term = query.value.trim().toLocaleLowerCase();
    entries = buildEntries().filter((item) => `${item.label} ${item.detail}`.toLocaleLowerCase().includes(term));
    activeIndex = Math.min(activeIndex, Math.max(0, entries.length - 1));
    list.replaceChildren();
    if (!entries.length) {
      list.append(Object.assign(document.createElement('div'), { className: 'command-empty', textContent: '一致する操作がありません。' }));
      return;
    }
    entries.forEach((item, index) => {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'command-item'; button.setAttribute('role', 'option');
      button.setAttribute('aria-selected', String(index === activeIndex));
      const icon = Object.assign(document.createElement('span'), { className: 'command-item-icon', textContent: item.icon });
      const copy = document.createElement('span'); copy.className = 'command-item-copy';
      copy.append(Object.assign(document.createElement('b'), { textContent: item.label }), Object.assign(document.createElement('small'), { textContent: item.detail }));
      button.append(icon, copy);
      button.addEventListener('mouseenter', () => {
        activeIndex = index;
        list.querySelectorAll('.command-item').forEach((candidate, candidateIndex) => candidate.setAttribute('aria-selected', String(candidateIndex === activeIndex)));
      });
      button.addEventListener('click', () => { dialog.close(); item.run(); });
      list.append(button);
    });
  };
  const open = () => { render(); dialog.showModal(); query.value = ''; render(); query.focus(); };
  triggers.forEach((button) => button.addEventListener('click', open));
  dialog.querySelector('[data-command-close]').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', (event) => { if (event.target === dialog) dialog.close(); });
  query.addEventListener('input', () => { activeIndex = 0; render(); });
  query.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (!entries.length) return;
      event.preventDefault(); activeIndex = (activeIndex + (event.key === 'ArrowDown' ? 1 : -1) + entries.length) % entries.length; render();
      list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
    } else if (event.key === 'Enter' && entries[activeIndex]) {
      event.preventDefault(); const item = entries[activeIndex]; dialog.close(); item.run();
    }
  });
  document.addEventListener('keydown', (event) => {
    const target = event.target;
    const editing = target instanceof HTMLElement && (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName));
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); if (!dialog.open) open(); }
    else if (event.key === '/' && !editing && !event.metaKey && !event.ctrlKey && !event.altKey) { event.preventDefault(); if (!dialog.open) open(); }
  });
})();

// Reception's API workbench uses the production BaaS routes directly. The
// short-lived passkey token and tenant/environment scopes are rendered by PHP.
(() => {
  'use strict';
  const $ = (selector) => document.querySelector(selector);
  const category = $('#request_type');
  const service = $('#service_code');
  const reference = $('#related_reference');
  const endpoint = $('#service-endpoint');
  const serviceDescription = $('#service-description');
  const prepareApiButton = $('#reception-api-prepare');
  if (category && service) {
    const guidance = {
      tenant_api:'お客様の契約情報や、アプリを接続するためのキーに関する相談です。',
      product:'お客様が利用するアプリ・製品の登録や設定変更についての相談です。',
      issuance:'新しいライセンスの発行や、まとめて発行する作業の相談です。',
      license:'発行済みライセンスの内容変更、停止、再開についての相談です。',
      device:'機種変更や端末交換、登録済み端末の停止についての相談です。',
      activation:'アプリが起動しない、利用開始できない、認証に失敗する場合の相談です。',
      phone:'電話番号やメールを使った認証、確認コードについての相談です。',
      identity:'顔・本人確認書類・電子署名などの本人確認機能についての相談です。',
      billing_audit:'利用料金、請求書、過去の操作や接続の履歴についての相談です。',
      webhook_sdk:'アプリへの通知や、外部サービスとの連携設定についての相談です。',
      api_support:'開発担当者向けに、接続状態や操作履歴を確認します。',
      other:'手続きが一覧にない場合はこちらを選んでください。',
    };
    const updateService = () => {
      const [placeholder,...options] = [...service.options];
      const isOther = category.value === 'other';
      const hasCategory = Boolean(category.value);
      if(placeholder){placeholder.hidden=hasCategory&&!isOther;placeholder.disabled=false;placeholder.textContent=isOther?'この相談は手続きの選択が不要です':(hasCategory?'手続きも選んでください':'先に相談の種類を選んでください');}
      options.forEach((option) => { option.hidden = !hasCategory || option.dataset.type !== category.value; });
      service.disabled=!hasCategory||isOther;
      service.required=hasCategory&&!isOther;
      if(isOther)service.value='';
      const selected = options.find((option) => !option.hidden);
      if (selected && service.selectedOptions[0]?.hidden) service.value = selected.value;
      const active = service.selectedOptions[0];
      if (active && endpoint) endpoint.textContent = active.dataset.endpoint || (isOther?'API接続先なし（その他）':'API接続先は未選択です');
      if(serviceDescription)serviceDescription.textContent=guidance[category.value]||'相談の種類を選ぶと、内容に合う手続きが表示されます。';
      if (reference) {
        reference.inputMode = ['license', 'device', 'phone'].includes(category.value) ? 'numeric' : 'text';
        reference.placeholder = category.value === 'phone' ? '認証依頼に表示された番号' : (['license','device'].includes(category.value)?'ライセンスや端末に表示された番号':'対象の番号（分かる場合）');
      }
    };
    category.addEventListener('change', updateService);
    service.addEventListener('change', updateService);
    updateService();
  }

  if (prepareApiButton) prepareApiButton.addEventListener('click', () => {
    const code=service?.value||'';
    const apiOperation=$('#api-operation');
    const workbench=$('#direct-api-tools');
    const intakeTenant=$('#tenant_id');
    if(!code){window.alert('分類と手続きを選んでください。');return;}
    if(!intakeTenant?.value){window.alert('APIの対象となる契約先を選んでください。');intakeTenant?.focus();return;}
    if(!apiOperation){window.alert('API実行には管理者パスキーまたはSSO IDでログインし、画面を再読み込みしてください。');return;}
    const option=[...apiOperation.options].find((item)=>item.dataset.receptionCodes?.split(',').includes(code));
    if(!option){window.alert('この手続きに対応するAPI操作は、現在の権限では利用できません。管理者へ権限を確認してください。');return;}
    const operationChanged=apiOperation.value!==option.value;
    apiOperation.value=option.value;
    if(operationChanged)apiOperation.dispatchEvent(new Event('change',{bubbles:true}));
    if(workbench)workbench.open=true;
    const apiTenant=$('#api-tenant');
    if(intakeTenant?.value&&apiTenant){apiTenant.value=intakeTenant.value;apiTenant.dispatchEvent(new Event('change',{bubbles:true}));}
    const referenceValue=(reference?.value||'').trim();
    window.setTimeout(()=>{
      if(referenceValue){
        const fieldKey=/^[0-9]+$/.test(referenceValue)?'license_id':'search';
        const field=[...document.querySelectorAll('[data-api-key]')].find((input)=>input.dataset.apiKey===fieldKey);
        if(field&&!field.value)field.value=referenceValue;
      }
      workbench?.scrollIntoView({behavior:'smooth',block:'start'});
      const runButton=$('#api-run');
      if(runButton)runButton.click();
    },0);
  });

  const sessionToken = $('meta[name="api-session"]')?.content || '';
  const basePath = $('meta[name="api-base"]')?.content || '';
  const tenant = $('#api-tenant');
  const tenantCaption = $('#api-tenant-caption');
  const credentialLabel = $('#api-credential-label');
  const credentialInput = $('#api-credential');
  const operation = $('#api-operation');
  const route = $('#api-route');
  const environment = $('#api-environment');
  const queryInput = $('#api-query');
  const bodyInput = $('#api-body');
  const rawInputDetails = $('#api-raw-input');
  const queryFields = $('#api-query-fields');
  const bodyFields = $('#api-body-fields');
  const readableResult = $('#api-console-readable');
  const rawResultDetails = $('#api-console-json-details');
  const runButton = $('#api-run');
  const resetButton = $('#api-reset');
  const copyButton = $('#api-copy-result');
  const useSessionButton = $('#api-use-session');
  const status = $('#api-console-status');
  const resultBox = $('#api-console-result');
  if (!sessionToken || !tenant || !operation || !runButton) return;

  const getOperation = () => operation.selectedOptions[0]?.dataset.path ? operation.selectedOptions[0] : null;
  const apiFieldLabels = {
    limit:'表示する件数',cursor:'続き位置',search:'検索語',status:'状態',period:'対象月',product_id:'製品ID',
    license_id:'ライセンスID',device_id:'端末ID',job_id:'発行ジョブID',client_id:'APIクライアントID',
    webhook_id:'Webhook ID',passkey_id:'Passkey ID',tenant_id:'契約先ID',license_mode:'発行方式',
    max_devices:'利用できる端末数',evaluation_days:'評価日数',expires_at:'有効期限（UTC）',
    label:'顧客名・用途',code:'製品コード',name:'名前',count:'発行件数',execution_mode:'実行方法',
    grace_minutes:'切り替え猶予（分）',reason:'理由',scopes:'APIキーに付ける権限（1行ごと）',
    events:'通知するイベント（1行ごと）',license_ids:'削除するライセンスID（1行ごと）',url:'通知先URL',
    channel_access_token:'LINEチャネルアクセストークン',recipient_id:'LINE送信先ID',setup_code:'セットアップコード',
    session_token:'本人確認セッショントークン',frame_count:'確認に使ったフレーム数',
    random_actions_completed:'完了したランダム操作数',verification_source:'確認元',payload_sha256:'データのSHA-256',
    liveness_pass:'生体確認に合格',encrypted_transfer:'暗号化して転送',session_protection:'セッション保護を有効化',
    anti_replay_pass:'再利用防止の確認に合格',audit_ready:'監査記録を保存',random_action_pass:'ランダム操作に合格',
    confirm_fee_yen:'確認済みの料金（円）',operation:'確認内容',
  };
  const apiFieldHelp = {
    product_id:'対象製品のIDを入力します。製品一覧で確認できます。',
    license_id:'対象ライセンスのIDを入力します。ライセンス一覧で確認できます。',
    device_id:'対象端末のIDを入力します。ライセンスの端末詳細で確認できます。',
    job_id:'発行ジョブのIDを入力します。作成結果に表示されます。',
    expires_at:'日本時間で指定します。API送信時にUTCへ変換します。空欄なら期限を指定しません。',
    license_ids:'1件ずつ改行して入力します。削除はSandbox環境でのみ実行できます。',
    events:'例：license.issued、license.updated。1行に1つ入力します。',
    response:'Passkeyの登録・ログイン結果はブラウザーから取得します。通常はPasskeyオプションを選ぶと完了まで自動で進みます。',
    confirm_fee_yen:'本人確認の実行でこの料金が発生します。実行前にも確認画面を表示します。',
  };
  const apiEnums = {
    license_mode:[['single','1台用'],['volume','複数台用'],['evaluation','評価版']],
    execution_mode:[['auto','自動'],['direct','直接処理'],['vector','まとめて処理'],['async','非同期'],['x20','X20']],
    status:[['','すべて'],['active','有効'],['archived','アーカイブ済み']],
    operation:[['mnsl.face_liveness.verify','顔・動きの本人確認'],['mnsl.face.verify','顔の本人確認'],['mnsl.liveness.verify','動きの本人確認'],['mnsl.jpki.full.verify','マイナンバーカード本人確認'],['mnsl.jpki.certificate.parse','証明書を読み取る'],['mnsl.jpki.certificate.validity.verify','証明書の有効性を確認'],['mnsl.jpki.certificate.chain.verify','証明書の発行元を確認'],['mnsl.jpki.certificate.revocation.verify','証明書の失効を確認'],['mnsl.jpki.user_auth.verify','利用者を確認'],['mnsl.jpki.signature.verify','電子署名を確認'],['mnsl.jpki.challenge.verify','確認コードを検証'],['mnsl.jpki.binding.create','本人確認情報を登録'],['mnsl.jpki.binding.verify','本人確認情報を照合'],['mnsl.jpki.binding.refresh','本人確認情報を更新'],['mnsl.jpki.binding.revoke','本人確認情報を失効']],
  };
  const apiHiddenFields = new Set(['action','api_action','service','idempotency_key','tenant_id']);
  const apiIdentifierFields = new Set(['id','product_id','license_id','device_id','job_id','client_id','webhook_id','passkey_id','tenant_id']);
  const apiRequiredFields = new Set(['code','name','product_id','license_id','device_id','client_id','job_id','webhook_id','passkey_id','setup_code','channel_access_token','recipient_id','count','license_mode','execution_mode','session_token','frame_count','payload_sha256','operation']);
  const apiRequiredQueryFields = new Set(['job_id']);
  const announce = (message, kind = '') => {
    status.textContent = message;
    status.className = `api-console-status${kind ? ` ${kind}` : ''}`;
    status.hidden = false;
  };
  const apiLabel = (key) => apiFieldLabels[key] || key.replaceAll('_',' ');
  const createFieldLabel = (key) => {
    const label = document.createElement('label');
    label.className = 'api-form-field';
    label.append(document.createTextNode(apiLabel(key)));
    return label;
  };
  const addFieldHelp = (label, key, defaultText = '') => {
    const message = apiFieldHelp[key] || defaultText;
    if (!message) return;
    const hint = document.createElement('small');
    hint.className = 'api-field-hint';
    hint.textContent = message;
    label.append(hint);
  };
  const safeBodyTemplate = (selected) => {
    let value = {};
    try { value = JSON.parse(selected?.dataset.body || '{}'); } catch (_error) { value = {}; }
    const sanitize = (current, key = '') => {
      if (Array.isArray(current)) return key === 'license_ids' ? [] : current.map((item) => sanitize(item,key));
      if (current && typeof current === 'object') {
        const clean = {};
        Object.entries(current).forEach(([childKey,childValue]) => { clean[childKey] = sanitize(childValue,childKey); });
        return clean;
      }
      if (key === 'idempotency_key') return '';
      if (apiIdentifierFields.has(key) && (typeof current === 'number' || /^\d+$/.test(String(current)))) return '';
      if (['name','code','url','channel_access_token','recipient_id','setup_code','session_token','payload_sha256'].includes(key)) return '';
      return current;
    };
    return sanitize(value);
  };
  const safeQueryTemplate = (selected) => {
    const query = new URLSearchParams(selected?.dataset.query || '');
    for (const [key] of query.entries()) if (apiIdentifierFields.has(key)) query.set(key,'');
    return query;
  };
  const createScalarControl = (key,value,{query=false,row=false}={}) => {
    const label=createFieldLabel(key), sample=value;
    let control;
    if (apiEnums[key]) {
      control=document.createElement('select');
      apiEnums[key].forEach(([v,text])=>control.add(new Option(text,v)));
      if (sample!==undefined&&!apiEnums[key].some(([v])=>String(v)===String(sample))) control.add(new Option(String(sample),String(sample)));
      control.value=String(sample??apiEnums[key][0][0]);
    } else if (typeof value==='boolean') {
      control=document.createElement('select'); control.add(new Option('はい','true')); control.add(new Option('いいえ','false')); control.value=String(value);
    } else {
      control=document.createElement('input');
      const numeric=typeof value==='number'||/^(limit|cursor|product_id|license_id|device_id|job_id|client_id|webhook_id|passkey_id|tenant_id|count|max_devices|evaluation_days|grace_minutes|frame_count|random_actions_completed|confirm_fee_yen)$/.test(key);
      const secret=/token|setup_code|secret|password/i.test(key);
      control.type=key==='expires_at'?'datetime-local':(secret?'password':(numeric?'number':'text'));
      if(control.type==='number'){control.min=apiIdentifierFields.has(key)||key==='count'?'1':'0';control.step='1';}
      if(control.type==='datetime-local')control.step='60';
      let initial=value??'';
      if(apiIdentifierFields.has(key)&&(typeof initial==='number'||/^\d+$/.test(String(initial))))initial='';
      if(['expires_at','label','search','payload_sha256'].includes(key))initial='';
      if(key==='url'&&String(initial)==='https://example.com/webhook')initial='';
      control.value=String(initial);
      if(key==='expires_at')control.title='日本時間で指定します。';
      else if(apiIdentifierFields.has(key))control.placeholder='一覧に表示されているID';
      else if(key==='code')control.placeholder='例：sample-product';
      else if(key==='url')control.placeholder='https://';
      else if(key==='payload_sha256')control.placeholder='64桁の16進数';
      else if(key==='channel_access_token')control.placeholder='LINEチャネルアクセストークン';
      else if(key==='setup_code')control.placeholder='発行済みのセットアップコード';
      else if(key==='session_token')control.placeholder='本人確認APIから取得したトークン';
    }
    control.dataset.apiKey=key;
    control.dataset.apiKind=typeof sample==='boolean'?'boolean':(typeof sample==='number'||control.type==='number'?'number':'string');
    if(!query&&!row&&apiRequiredFields.has(key))control.required=true;
    if(query&&apiRequiredQueryFields.has(key))control.required=true;
    if(key==='confirm_fee_yen')control.readOnly=true;
    label.append(control); addFieldHelp(label,key);
    return {label,control};
  };
  const renderArrayField = (parent,key,values,{query=false}={}) => {
    const label=createFieldLabel(key),control=document.createElement('textarea');
    control.rows=Math.min(5,Math.max(2,values.length||2)); control.dataset.apiArrayKey=key;
    const numericItems=key==='license_ids'||values.every((item)=>typeof item==='number');
    control.dataset.apiArrayKind=numericItems?'number':'string';
    control.value=(numericItems&&apiIdentifierFields.has(key)?[]:values).map(String).join('\n');
    control.placeholder=key==='license_ids'?'例：123\n456':'1行に1つ入力';
    if(!query&&apiRequiredFields.has(key))control.required=true;
    if(numericItems){
      const validate=()=>{const items=control.value.split(/\r?\n/).map((item)=>item.trim()).filter(Boolean);control.setCustomValidity(items.some((item)=>!/^\d+$/.test(item)||Number(item)<1)?'1行に1つ、1以上の整数を入力してください。':'');};
      control.addEventListener('input',validate);validate();
    }
    label.append(control); addFieldHelp(label,key,'1行に1つずつ入力します。JSONの記号は不要です。'); parent.append(label);
  };
  const renderObjectArray = (parent,key,rows) => {
    const field=document.createElement('div'); field.className='api-form-field api-repeat-field'; field.dataset.apiRepeatKey=key;
    const title=document.createElement('b'); title.textContent=key==='items'?'一括発行するライセンス':apiLabel(key); field.append(title);
    const list=document.createElement('div'); list.className='api-repeat-list';
    const template=rows[0]||{product_id:'',label:''};
    const addRow=(source={})=>{
      const row=document.createElement('div'); row.className='api-repeat-row'; row.dataset.apiRepeatRow='true';
      Object.entries(template).forEach(([fieldKey,defaultValue])=>{
        const value=Object.prototype.hasOwnProperty.call(source,fieldKey)?source[fieldKey]:defaultValue;
        const item=createScalarControl(fieldKey,value,{row:true}); item.label.classList.add('api-repeat-control');
        if(fieldKey==='product_id')item.control.required=true;
        if(fieldKey==='label')item.control.placeholder='顧客名・用途（任意）';
        row.append(item.label);
      });
      const remove=document.createElement('button'); remove.type='button'; remove.className='secondary api-remove-row'; remove.textContent='この行を削除';
      remove.addEventListener('click',()=>{if(list.children.length>1)row.remove();}); row.append(remove); list.append(row);
    };
    (rows.length?rows:[template]).forEach((source)=>addRow(source));
    const add=document.createElement('button'); add.type='button'; add.className='secondary api-add-row'; add.textContent='＋ 発行内容を追加'; add.addEventListener('click',()=>addRow({}));
    field.append(list,add); addFieldHelp(field,key,'必要な件数分だけ追加し、各行に製品IDを指定します。'); parent.append(field);
  };
  const renderStructuredFields = (selected) => {
    if(!queryFields||!bodyFields)return;
    queryFields.replaceChildren(); bodyFields.replaceChildren();
    const query=safeQueryTemplate(selected),body=safeBodyTemplate(selected);
    let queryCount=0,bodyCount=0,needsPasskeyNotice=false;
    query.forEach((value,key)=>{
      if(apiHiddenFields.has(key))return;
      const field=createScalarControl(key,value,{query:true}); queryFields.append(field.label); queryCount++;
    });
    Object.entries(body&&typeof body==='object'?body:{}).forEach(([key,value])=>{
      if(apiHiddenFields.has(key))return;
      if(key==='response'&&value&&typeof value==='object'){needsPasskeyNotice=true;return;}
      if(Array.isArray(value)&&value.some((item)=>item&&typeof item==='object')){renderObjectArray(bodyFields,key,value);bodyCount++;return;}
      if(Array.isArray(value)){renderArrayField(bodyFields,key,value);bodyCount++;return;}
      const field=createScalarControl(key,value); bodyFields.append(field.label); bodyCount++;
    });
    queryFields.hidden=queryCount===0;
    bodyFields.hidden=selected?.dataset.method==='GET'||bodyCount===0;
    if(queryCount===0&&selected?.dataset.method==='GET'){const note=document.createElement('p');note.className='api-fields-empty';note.textContent='この操作に追加の検索条件はありません。';queryFields.append(note);queryFields.hidden=false;}
    if(needsPasskeyNotice){const note=document.createElement('p');note.className='api-passkey-flow-note';note.textContent='この操作にはブラウザーのPasskey応答が必要です。通常は「Passkey登録オプション」または「Passkeyログインオプション」を選ぶと、認証から完了まで自動で進みます。';bodyFields.append(note);bodyFields.hidden=false;}
    else if(selected?.dataset.method!=='GET'&&bodyCount===0){const note=document.createElement('p');note.className='api-fields-empty';note.textContent='追加の入力はありません。実行すると確認画面へ進みます。';bodyFields.append(note);bodyFields.hidden=false;}
  };
  const updateRoute = () => {
    const selected=getOperation(),authType=selected?.dataset.auth||'tenant';
    const selectedTenant=tenant.selectedOptions[0],selectedEnvironment=selectedTenant?.dataset.env||'';
    const needsTenant=!['runtime','public'].includes(authType),needsCredential=['tenant-key','portal-session'].includes(authType);
    if(route)route.value=selected?`${selected.dataset.method} ${selected.dataset.path}`:'';
    if(environment)environment.value=['runtime','public'].includes(authType)?'API資格情報 / Passkeyに従う':(selectedEnvironment||'未選択');
    if(tenantCaption)tenantCaption.textContent=authType==='runtime'?'対象テナント（このAPIでは未使用）':(authType==='public'?'対象テナント（このAPIでは未使用）':'対象テナント / 環境');
    tenant.required=needsTenant;
    if(credentialLabel&&credentialInput){credentialLabel.hidden=!needsCredential;credentialInput.hidden=!needsCredential;credentialInput.required=needsCredential;credentialLabel.firstChild.textContent=authType==='tenant-key'?'テナントAPIキー（このページの間だけ使用）':'Portal Passkeyセッション（このページの間だけ使用）';credentialInput.placeholder=authType==='tenant-key'?'baas_live_… / baas_sandbox_…':'Passkeyログインの session_token';}
    if(useSessionButton)useSessionButton.hidden=authType!=='portal-session';
    if(queryInput&&selected)queryInput.value=safeQueryTemplate(selected).toString();
    if(bodyInput&&selected)bodyInput.value=JSON.stringify(safeBodyTemplate(selected),null,2);
    if(selected)renderStructuredFields(selected);
    if(readableResult)readableResult.hidden=true;
    if(rawResultDetails)rawResultDetails.hidden=true;
    runButton.disabled=!selected||(needsTenant&&!tenant.value)||(needsCredential&&!credentialInput?.value.trim());
  };
  const freshRequestKey = () => {
    if (typeof crypto.randomUUID === 'function') return `rk_${crypto.randomUUID().replaceAll('-', '')}`;
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return `rk_${[...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
  };
  const parseQuery = (text) => {
    const clean = String(text || '').trim().replace(/^\?/, '');
    return new URLSearchParams(clean);
  };
  const isSpecialAdminRoute = (selected) => selected.dataset.auth === 'ha';
  const encodeBase64Url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };
  const decodeBase64Url = (value) => {
    const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
  };
  const readResponse = async (response) => {
    const text = await response.text();
    try { return JSON.parse(text); } catch (_error) { return { response_text: text.slice(0, 20000) }; }
  };
  const readControlValue = (control) => {
    if (control.dataset.apiKind === 'boolean') return control.value === 'true';
    if (control.dataset.apiKind === 'number') return control.value === '' ? null : Number(control.value);
    return control.value;
  };
  const collectStructuredQuery = () => {
    const params = new URLSearchParams();
    for (const [key,value] of safeQueryTemplate(getOperation())) if (apiHiddenFields.has(key) && value !== '') params.set(key,value);
    queryFields?.querySelectorAll('[data-api-key]').forEach((control) => {
      if (control.value !== '') params.set(control.dataset.apiKey,control.value);
    });
    return params;
  };
  const collectStructuredBody = (selected) => {
    const body = safeBodyTemplate(selected);
    bodyFields?.querySelectorAll('[data-api-key]').forEach((control) => {
      if (control.closest('[data-api-repeat-row]')) return;
      const value = readControlValue(control);
      if (value === null) delete body[control.dataset.apiKey];
      else if(control.dataset.apiKey==='expires_at'&&value!==''){
        const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
        if(!match)throw new Error('invalid expiration');
        const [,year,month,day,hour,minute]=match;
        const date=new Date(Number(year),Number(month)-1,Number(day),Number(hour),Number(minute),0);
        if(date.getFullYear()!==Number(year)||date.getMonth()!==Number(month)-1||date.getDate()!==Number(day)||date.getHours()!==Number(hour)||date.getMinutes()!==Number(minute))throw new Error('invalid expiration');
        body[control.dataset.apiKey]=date.toISOString().slice(0,19).replace('T',' ');
      }
      else body[control.dataset.apiKey] = value;
    });
    bodyFields?.querySelectorAll('[data-api-array-key]').forEach((control) => {
      const values=control.value.split(/\r?\n/).map((item)=>item.trim()).filter(Boolean);
      if(control.dataset.apiArrayKind==='number'&&values.some((item)=>!/^\d+$/.test(item)||Number(item)<1))throw new Error('invalid numeric list');
      body[control.dataset.apiArrayKey]=control.dataset.apiArrayKind==='number'?values.map(Number):values;
    });
    const repeated=bodyFields?.querySelectorAll('.api-repeat-field');
    repeated?.forEach((field)=>{
      const key=field.dataset.apiRepeatKey||'items';
      const rows=[...field.querySelectorAll('[data-api-repeat-row]')].map((row)=>{
        const value={};
        row.querySelectorAll('[data-api-key]').forEach((control)=>{
          const item=readControlValue(control);
          if(item!==null&&item!=='')value[control.dataset.apiKey]=item;
        });
        return value;
      }).filter((row)=>Object.keys(row).length);
      body[key]=rows;
    });
    if(Object.prototype.hasOwnProperty.call(body,'idempotency_key'))body.idempotency_key=freshRequestKey();
    return body;
  };
  const apiErrorMessages={
    license_not_found:'ライセンスが見つかりません。契約先とライセンスIDを確認してください。',
    product_not_found:'製品が見つかりません。契約先と製品IDを確認してください。',
    device_not_found:'端末が見つかりません。ライセンスIDと端末IDを確認してください。',
    job_not_found:'発行ジョブが見つかりません。ジョブIDを確認してください。',
    license_quota_exceeded:'契約のライセンス上限に達しています。契約内容を確認してください。',
    invalid_license_mode:'発行方式を選び直してください。',
    invalid_idempotency_key:'再試行用の識別情報が正しくありません。入力を初期化して再実行してください。',
    unauthorized:'認証できません。APIキーまたはパスキーを確認してください。',
    forbidden:'この操作に必要な権限がありません。管理者に確認してください。',
    server_not_writable:'現在このサーバーでは更新できません。しばらくしてから再試行してください。',
    invalid_request:'入力内容を確認してください。',
  };
  const apiErrorText = (payload,fallback) => {
    if(payload&&typeof payload==='object'){
      const code=String(payload.error||'');
      if(apiErrorMessages[code])return apiErrorMessages[code];
      return String(payload.message||payload.error_description||payload.message_ja||code||fallback);
    }
    return fallback;
  };
  const resultLabels={
    ok:'結果',request_id:'API照会番号',license_id:'ライセンスID',device_id:'端末ID',product_id:'製品ID',
    job_id:'発行ジョブID',client_id:'APIクライアントID',webhook_id:'Webhook ID',passkey_id:'Passkey ID',
    license_key:'ライセンスキー',api_key:'APIキー',key:'キー',label:'顧客名・用途',name:'名前',code:'製品コード',
    status:'状態',active:'有効',expires_at:'有効期限',created_at:'作成日時',updated_at:'更新日時',
    total:'合計件数',count:'件数',issued_count:'発行件数',failed_count:'失敗件数',deleted_count:'削除件数',
    revoked_count:'失効件数',restored_count:'復元件数',message:'結果メッセージ',error:'エラー',
    licenses:'ライセンス一覧',devices:'端末一覧',products:'製品一覧',items:'明細',invoices:'請求書一覧',
    api_clients:'APIクライアント',webhooks:'Webhook一覧',events:'通知イベント',session_token:'本人確認セッショントークン',
    tenant:'契約先',tenant_id:'契約先ID',environment:'環境',total_yen:'合計金額',unit_yen:'単価',request_count:'リクエスト数',next_cursor:'続き位置',
    description:'説明',message_ja:'案内',quantity:'数量',remaining:'残り',quota:'上限',used:'利用済み',
    execution_mode:'実行方法',license_mode:'発行方式',platform:'端末の種類',device_name:'端末名',
    last_seen_at:'最終利用日時',revoked_at:'失効日時',archived_at:'アーカイブ日時',deleted_at:'削除日時',
    owner:'所有者',scope:'権限',scopes:'権限',retry_after:'再試行まで（秒）',rate_limit_per_minute:'1分あたりの上限',
    grace_minutes:'切り替え猶予（分）',issued_at:'発行日時',completed_at:'完了日時',started_at:'開始日時',
    failed_at:'失敗日時',total_items:'対象件数',processed_count:'処理済み件数',success_count:'成功件数',
    webhook_url:'通知先URL',last_delivery_at:'最終送信日時',delivery_status:'送信状態',enabled:'有効',
    is_active:'有効',is_archived:'アーカイブ済み',response_text:'応答内容',
  };
  const resultLabel=(key)=>resultLabels[key]||key.replaceAll('_',' ');
  const resultValueLabels={
    status:{active:'有効',archived:'アーカイブ済み',inactive:'停止',revoked:'失効',pending:'確認待ち',queued:'待機中',running:'処理中',completed:'完了',complete:'完了',failed:'失敗',cancelled:'取消',canceled:'取消',issued:'発行済み',processing:'処理中'},
    environment:{production:'本番',sandbox:'Sandbox'},license_mode:{single:'1台用',volume:'複数台用',evaluation:'評価版'},
    execution_mode:{auto:'自動',direct:'直接処理',vector:'まとめて処理',async:'非同期',x20:'X20'},
    delivery_status:{success:'送信成功',failed:'送信失敗',pending:'送信待ち'},
  };
  const resultCell=(value,key='')=>{
    if(value===null||value===undefined||value==='')return '—';
    if(typeof value==='boolean')return value?'はい':'いいえ';
    if(typeof value==='string'&&resultValueLabels[key]?.[value])return resultValueLabels[key][value];
    if(typeof value==='number'&&/_yen$/.test(key))return `${new Intl.NumberFormat('ja-JP').format(value)}円`;
    if(Array.isArray(value))return value.map((item)=>typeof item==='object'?'詳細あり':String(item)).join('、')||'なし';
    if(typeof value==='object')return '詳細あり';
    return String(value);
  };
  const renderResultValue=(parent,key,value,state,depth=0)=>{
    if(state.count>=100)return;
    state.count++;
    if(Array.isArray(value)){
      const section=document.createElement('section');section.className='api-result-group';
      const heading=document.createElement('h4');heading.textContent=`${resultLabel(key)}（${value.length}件）`;section.append(heading);
      if(value.length&&value.every((item)=>item&&typeof item==='object'&&!Array.isArray(item))){
        const columns=[...new Set(value.slice(0,10).flatMap((item)=>Object.keys(item)))].filter((name)=>name!=='ok').slice(0,7);
        const table=document.createElement('div');table.className='api-result-table-wrap';const tableElement=document.createElement('table');
        const thead=document.createElement('thead'),headRow=document.createElement('tr');columns.forEach((column)=>{const th=document.createElement('th');th.textContent=resultLabel(column);headRow.append(th);});thead.append(headRow);tableElement.append(thead);
        const tbody=document.createElement('tbody');value.slice(0,30).forEach((item)=>{const tr=document.createElement('tr');columns.forEach((column)=>{const td=document.createElement('td');const cell=resultCell(item[column],column);if(/key|token/i.test(column)&&cell!=='—'){const code=document.createElement('code');code.textContent=cell;td.append(code);}else td.textContent=cell;tr.append(td);});tbody.append(tr);});tableElement.append(tbody);table.append(tableElement);section.append(table);
        if(value.length>30){const more=document.createElement('p');more.className='api-result-muted';more.textContent=`先頭30件を表示しています。全${value.length}件は詳細データで確認できます。`;section.append(more);}
      } else if(value.length){const list=document.createElement('ul');value.slice(0,30).forEach((item)=>{const li=document.createElement('li');li.textContent=resultCell(item);list.append(li);});section.append(list);}
      else {const empty=document.createElement('p');empty.className='api-result-muted';empty.textContent='該当するデータはありません。';section.append(empty);}
      parent.append(section);return;
    }
    if(value&&typeof value==='object'){
      if(depth>=3){const row=document.createElement('div');row.className='api-result-row';const dt=document.createElement('b');dt.textContent=resultLabel(key);const dd=document.createElement('span');dd.textContent='詳細データ';row.append(dt,dd);parent.append(row);return;}
      const section=document.createElement('section');section.className='api-result-group';const heading=document.createElement('h4');heading.textContent=resultLabel(key);section.append(heading);
      Object.entries(value).slice(0,30).forEach(([childKey,childValue])=>{if(childKey!=='ok')renderResultValue(section,childKey,childValue,state,depth+1);});parent.append(section);return;
    }
    const row=document.createElement('div');row.className='api-result-row';const dt=document.createElement('b');dt.textContent=resultLabel(key);const dd=document.createElement('span');
    const text=resultCell(value,key);if(/key|token/i.test(key)&&text!=='—'){const code=document.createElement('code');code.textContent=text;dd.append(code);}else dd.textContent=text;row.append(dt,dd);parent.append(row);
  };
  const renderReadableResult=(httpStatus,httpStatusText,payload,operationLabel)=>{
    if(!readableResult)return;
    readableResult.replaceChildren();
    const ok=httpStatus>=200&&httpStatus<300&&payload?.ok!==false;
    const title=document.createElement('h3');title.textContent=ok?'処理が完了しました':'処理を完了できませんでした';title.className=ok?'is-success':'is-error';readableResult.append(title);
    const intro=document.createElement('p');intro.textContent=`${operationLabel} · HTTP ${httpStatus} ${httpStatusText||''}`.trim();readableResult.append(intro);
    if(!ok){const error=document.createElement('p');error.className='api-result-error';error.textContent=apiErrorText(payload,'入力内容、権限、対象IDを確認してください。');readableResult.append(error);}
    if(payload&&typeof payload==='object'&&payload.request_id){const row=document.createElement('div');row.className='api-result-request-id';row.textContent=`APIリクエストID：${payload.request_id}`;readableResult.append(row);}
    const content=document.createElement('div');content.className='api-result-content';const state={count:0};
    Object.entries(payload&&typeof payload==='object'?payload:{response_text:payload}).forEach(([key,value])=>{if(['ok','request_id','error','error_description'].includes(key))return;renderResultValue(content,key,value,state);});
    if(content.childElementCount)readableResult.append(content);
    readableResult.hidden=false;
  };

  operation.addEventListener('change', updateRoute);
  tenant.addEventListener('change', updateRoute);
  credentialInput?.addEventListener('input', updateRoute);
  resetButton?.addEventListener('click', () => {
    if (!getOperation()) return;
    if(rawInputDetails)rawInputDetails.open=false;
    updateRoute();
    announce('入力を初期状態に戻しました。ID欄は空欄です。対象を確認して入力してください。');
  });
  copyButton?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(resultBox.textContent || '');
      announce('技術情報をコピーしました。', 'success');
    } catch (_error) {
      announce('クリップボードへアクセスできません。詳細データを開いてコピーしてください。', 'error');
    }
  });
  useSessionButton?.addEventListener('click', () => {
    try {
      const envelope = JSON.parse(resultBox.textContent || '{}');
      const token = envelope?.response?.session_token || envelope?.session_token;
      if (!token) throw new Error('session_tokenがレスポンスにありません');
      credentialInput.value = String(token);
      updateRoute();
      announce('Portal Passkey session_tokenを追加認証欄へセットしました。ページを閉じると消えます。', 'success');
    } catch (error) { announce(error.message || 'レスポンスを読み取れません。', 'error'); }
  });
  runButton.addEventListener('click', async () => {
    const selected = getOperation();
    const authType = selected?.dataset.auth || 'tenant';
    const selectedTenant = tenant.selectedOptions[0];
    const needsTenant = !['runtime', 'public'].includes(authType);
    const needsCredential = ['tenant-key', 'portal-session'].includes(authType);
    if (!selected || (needsTenant && (!selectedTenant || !tenant.value)) || (needsCredential && !credentialInput?.value.trim())) {
      announce('対象テナントとAPI操作を選択してください。', 'error');
      return;
    }
    const method = selected.dataset.method || 'GET';
    const isSpecial = isSpecialAdminRoute(selected);
    const chosenEnv = selectedTenant?.dataset.env || '';
    if (needsTenant && (selectedTenant?.dataset.status !== 'active' || !['production', 'sandbox'].includes(chosenEnv))) {
      announce('有効なテナントを選択してください。', 'error');
      return;
    }
    if (selected.dataset.path === '/api/baas/v1/sandbox-keys.php' && chosenEnv !== 'production') {
      announce('Sandboxキー操作は親となるProductionテナントを選択してください。', 'error');
      return;
    }
    if (selected.dataset.environment && selected.dataset.environment !== chosenEnv) {
      announce(`${selected.dataset.environment}環境のテナントを選んでください。`, 'error');
      return;
    }
    if (selected.dataset.path === '/api/baas/v1/sample-sdk-keys.php' && chosenEnv !== 'production') {
      announce('Sample SDKキーの管理には親となるProductionテナントを選択してください。', 'error');
      return;
    }

    if (!rawInputDetails?.open) {
      const invalidField = [...(queryFields?.querySelectorAll(':invalid') || []), ...(bodyFields?.querySelectorAll(':invalid') || [])][0];
      if (invalidField) { invalidField.reportValidity(); invalidField.focus(); return; }
    }
    let body = null;
    if (method !== 'GET') {
      try {
        if (rawInputDetails?.open) {
          body = bodyInput.value.trim() ? JSON.parse(bodyInput.value) : {};
          if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error('JSON object required');
          if (body.idempotency_key) body.idempotency_key = freshRequestKey();
        } else body = collectStructuredBody(selected);
      } catch (_error) {
        announce('入力内容を確認してください。詳細入力を使う場合は、JSON形式も確認してください。', 'error');
        return;
      }
    }

    const targetLabel = ['runtime', 'public'].includes(authType) ? '入力した資格情報 / Passkey' : `${selectedTenant.textContent.trim()} · ${chosenEnv}`;
    const operationLabel = selected.textContent.trim();
    const actionName = String(body?.action || body?.api_action || '');
    const sideEffectNote = actionName === 'reissue_api_key' ? '\n確認済み料金：500円。新しいAPIキーを発行します。' : (['complete', 'record_verification'].includes(actionName) ? '\nこの操作は本人確認の利用記録・料金に反映されます。' : (method !== 'GET' ? '\nこの操作は実データを変更します。対象を確認してください。' : ''));
    const flowNote = '';
    if (method !== 'GET' && !window.confirm(`${operationLabel}\n${method} ${selected.dataset.path}\n対象: ${targetLabel}${sideEffectNote}${flowNote}\n\nこのAPIを実行します。続けますか？`)) return;

    const url = new URL(`${basePath}${selected.dataset.path}`, location.origin);
    const params = rawInputDetails?.open ? parseQuery(queryInput?.value || '') : collectStructuredQuery();
    if (isSpecial) {
      if (method === 'GET') params.set('tenant_id', tenant.value);
      else body.tenant_id = Number(tenant.value);
    }
    params.forEach((value, key) => url.searchParams.set(key, value));
    const headers = { 'Accept': 'application/json' };
    if (authType === 'tenant' || authType === 'ha') headers['X-HA-Session'] = sessionToken;
    if (authType === 'tenant') headers['X-Tenant-ID'] = tenant.value;
    if (['tenant', 'tenant-key', 'portal-session'].includes(authType)) {
      headers['X-BaaS-Environment'] = chosenEnv;
    }
    if (authType === 'tenant-key') headers['X-Tenant-API-Key'] = credentialInput.value.trim();
    if (authType === 'portal-session') headers['X-Tenant-Portal-Session'] = credentialInput.value.trim();
    const options = { method, headers, cache: 'no-store', credentials: 'same-origin' };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
      if (body.idempotency_key) headers['Idempotency-Key'] = String(body.idempotency_key);
    }
    runButton.disabled = true;
    if (copyButton) copyButton.hidden = true;
    if (resultBox) { resultBox.hidden = true; resultBox.textContent = ''; }
    if (readableResult) { readableResult.hidden = true; readableResult.replaceChildren(); }
    if (rawResultDetails) rawResultDetails.hidden = true;
    announce(`${method} ${selected.dataset.path} を実行しています…`);
    try {
      const response = await fetch(url, { ...options, signal: AbortSignal.timeout(120000) });
      let payload = await readResponse(response);
      let responseStatus = response.status;
      let responseStatusText = response.statusText;
      const steps = [{ http_status: response.status, status_text: response.statusText, response: payload }];
      if (resultBox) {
        resultBox.textContent = JSON.stringify({ http_status: responseStatus, status_text: responseStatusText, steps, response: payload }, null, 2);
        resultBox.hidden = false;
      }
      if (rawResultDetails) rawResultDetails.hidden = false;
      renderReadableResult(responseStatus,responseStatusText,payload,operationLabel);
      if (copyButton) copyButton.hidden = false;
      const requestId = payload && typeof payload === 'object' ? payload.request_id : '';
      const failed = responseStatus < 200 || responseStatus >= 300 || payload?.ok === false;
      announce(failed ? `処理を完了できませんでした（HTTP ${responseStatus}）。${requestId ? `APIリクエストID：${requestId}。` : ''}${apiErrorText(payload,'入力内容や権限を確認してください。')}` : `処理が完了しました（HTTP ${responseStatus}）。${requestId ? `APIリクエストID：${requestId}` : ''}`, failed ? 'error' : 'success');
    } catch (error) {
      announce(error?.name === 'TimeoutError' ? '応答が2分でタイムアウトしました。ジョブ状態を再取得してください。' : `APIへ接続できません: ${error?.message || 'network_error'}`, 'error');
    } finally {
      runButton.disabled = false;
    }
  });
  if (!operation.value) {
    const first = [...operation.options].find((item) => item.dataset.path);
    if (first) operation.value = first.value;
  }
  updateRoute();
})();
