(() => {
  const $ = id => document.getElementById(id);
  const now = new Date();
  const state = { year: now.getFullYear(), month: now.getMonth()+1, employee: '', csrf: '' };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const dateText = d => `${state.year}-${String(state.month).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
  async function api(url, options={}) {
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set('Content-Type','application/json');
    if (state.csrf && options.method && options.method !== 'GET') headers.set('X-CSRF-Token',state.csrf);
    const response = await fetch(url,{...options,headers,credentials:'same-origin'});
    if (response.status === 401) { showLoggedOut(); throw new Error('ログインの有効期限が切れました。再度ログインしてください。'); }
    const data = response.headers.get('content-type')?.includes('application/json') ? await response.json() : null;
    if (!response.ok) throw new Error(data?.detail || '処理に失敗しました');
    return data;
  }
  function toast(message){const el=$('toast');el.textContent=message;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2600)}
  function showLoggedOut(){ $('welcome').classList.remove('hidden');$('workspace').classList.add('hidden');$('identity').textContent='SSO IDで安全にログイン';$('logout').classList.add('hidden'); }
  async function init(){
    try { const me=await api('/api/me'); state.csrf=me.csrf; $('identity').textContent=me.name||'SSO IDでログイン中';$('logout').classList.remove('hidden');$('welcome').classList.add('hidden');$('workspace').classList.remove('hidden'); await loadMonth(); }
    catch(e){ if(!e.message.includes('ログインの有効期限')) showLoggedOut(); }
  }
  async function loadMonth(){
    $('month-label').textContent=`${state.year}年 ${String(state.month).padStart(2,'0')}月`;
    const [month,summary]=await Promise.all([api(`/api/month?year=${state.year}&month=${state.month}`),api(`/api/summary?year=${state.year}&month=${state.month}`)]);
    $('days').textContent=summary.days;$('hours').textContent=Number(summary.hours).toFixed(2);$('overtime').textContent=summary.over_8h_days;$('issues').textContent=summary.issues.length;
    const issueBox=$('issue-list'); issueBox.classList.toggle('hidden',!summary.issues.length); issueBox.replaceChildren();
    summary.issues.forEach(x=>{const line=document.createElement('div');line.textContent=`${x.date}　${x.message}`;issueBox.append(line)});
    const byDate=new Map(month.entries.map(x=>[x.work_date,x])); const count=new Date(state.year,state.month,0).getDate();const host=$('entries');host.replaceChildren();
    for(let d=1;d<=count;d++){
      const key=dateText(d),row=byDate.get(key)||{}; const date=new Date(state.year,state.month-1,d);const weekday=['日','月','火','水','木','金','土'][date.getDay()];
      const card=document.createElement('div');card.className='day-card';card.dataset.date=key;
      card.innerHTML=`<div class="day-label">${state.month}/${d}<small>${weekday}曜日</small></div><label><input aria-label="${key} 出勤" type="time" value="${esc(row.start_time||'')}"></label><label><input aria-label="${key} 退勤" type="time" value="${esc(row.end_time||'')}"></label><label><input aria-label="${key} 休憩時間（分）" type="number" min="0" max="1440" step="5" value="${row.break_minutes ?? 60}" placeholder="休憩 分"></label><input class="task" aria-label="${key} 作業内容" type="text" maxlength="2000" value="${esc(row.task||'')}" placeholder="作業内容"><button class="save">保存</button>`;
      card.querySelector('.save').addEventListener('click',()=>save(card));host.append(card);
    }
  }
  async function save(card){const inputs=card.querySelectorAll('input');const start=inputs[0].value||null,end=inputs[1].value||null;if(Boolean(start)!==Boolean(end)){toast('出勤と退勤は両方入力してください');return;}try{await api('/api/attendance',{method:'PUT',body:JSON.stringify({work_date:card.dataset.date,start_time:start,end_time:end,break_minutes:Number(inputs[2].value||0),task:inputs[3].value})});toast('保存しました');await loadMonth()}catch(e){toast(e.message)}}
  $('prev').addEventListener('click',()=>{if(--state.month<1){state.month=12;state.year--}loadMonth()});$('next').addEventListener('click',()=>{if(++state.month>12){state.month=1;state.year++}loadMonth()});
  $('check').addEventListener('click',async()=>{try{const s=await api(`/api/summary?year=${state.year}&month=${state.month}`);toast(s.issues.length?`確認事項が${s.issues.length}件あります`:'入力チェック完了。問題ありません');await loadMonth()}catch(e){toast(e.message)}});
  $('pdf').addEventListener('click',()=>window.print());
  $('export').addEventListener('click',async()=>{try{const response=await fetch(`/api/export.csv?year=${state.year}&month=${state.month}`,{credentials:'same-origin'});if(!response.ok)throw new Error('CSV出力に失敗しました');const blob=await response.blob(),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`${state.year}年${String(state.month).padStart(2,'0')}月_業務報告.csv`;a.click();URL.revokeObjectURL(a.href)}catch(e){toast(e.message)}});
  $('logout').addEventListener('click',async()=>{try{await api('/auth/logout',{method:'POST'});}finally{showLoggedOut()}});
  init();
})();
