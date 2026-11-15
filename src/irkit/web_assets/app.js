import {sourceCardHTML, sourceDetailHTML, sourceTaskHTML, reportHTML} from '/sources.js';
import {agentTree, workspaceUI} from '/workspace.js';
import {eventCardHTML, eventDetailHTML, eventTitle, integrityHTML, historyHTML, reviewBadge} from '/events.js';
import {conversation} from '/conversation.js';
import {esc, timestamp as time, prose, messageHTML, reconcile, captureAnchor, restoreAnchor} from '/timeline.js';
let state={objects:[],counts:{}}, events=[], context=[], sessions=[], run='', agent='', tab='run', cursor=0, loading=false, generation=0, hasOlder=false;
const agentPages=new Map();
const displayedEvents=()=>[...new Map([...events,...(agentPages.get(agent)?.rows||[])].map(e=>[e.seq,e])).values()];
const moreHistory=()=>agent?(agentPages.get(agent)?.more??true):hasOlder;
const el=id=>document.getElementById(id);
let caseId=new URLSearchParams(location.search).get('case')||'';
let projectId=new URLSearchParams(location.search).get('project')||'';
const folded=new Set();
const caseUrl=path=>path+(path.includes('?')?'&':'?')+'case='+encodeURIComponent(caseId)+'&project='+encodeURIComponent(projectId);
let control={jobs:[]}, requestId='', posting=false, watchSessionAfter=null;
const statusNames={idle:'未启动',running:'进行中',completed:'已交付',partial:'阶段报告已保存',pending:'待派发',failed:'失败',candidate:'候选证据',stale:'已过期',draft:'待人工审阅',succeeded:'已处理',ended:'已返回',observed:'最近有活动',incomplete:'未完成交付',interrupted:'已中断'};
const tag=s=>'<span class="tag '+esc(s)+'">'+esc(statusNames[s]||s||'未标记')+'</span>';
const pretty=v=>typeof v==='string'?v:JSON.stringify(v,null,2);
async function api(path){const r=await fetch(caseUrl(path));const d=await r.json();if(!r.ok)throw Error(d.error||r.status);return d;}
function matching(o){return JSON.stringify(o).toLowerCase().includes(el('search').value.toLowerCase());}
function item(o,body){return '<button class="entry" data-object="'+esc(o.id)+'"><div class="meta">'+tag(o.status)+'<span>'+esc(o.card_type==='observation'?'观察事实':o.card_type==='inference'?'推断':o.kind)+'</span></div><p>'+esc(body)+'</p><code>'+esc(o.id)+'</code></button>';}
function transcript(){
 const view=conversation(displayedEvents(),context);
 for(const a of view.agents){
  const linked=state.objects.filter(t=>t.kind==='task'&&a.taskIds.has(t.id));
  if(a.id!=='main'&&linked.some(t=>t.source_lead_id)){a.name='来源行为复查（历史）';a.description=linked.filter(t=>t.source_lead_id).map(t=>t.question).join(' · ');}
  if(a.id!=='main'&&a.status==='interrupted'&&!a.failed&&linked.length&&linked.every(t=>t.status==='completed')){a.status='ended';a.last='任务产物已交付';}
 }
 return view;
}
function render(){
 const view=transcript(), selected=view.agents.find(a=>a.id===agent), taskIds=selected?.taskIds||new Set();
 const tasks=state.objects.filter(o=>o.kind==='task'), taskArtifacts=new Set(tasks.filter(t=>taskIds.has(t.id)).flatMap(t=>t.artifact_ids||[]));
 const current=sessions.find(s=>s.run_id===run), sessionEnding=view.ending||current?.ending;
 const job=control.jobs.find(j=>j.case_dir?.split('/').pop()===control.case_id && current && j.created<=current.started && (!j.updated||j.updated>=current.started));
 const outcome=sessionEnding?.outcome||(job&&!['starting','preparing','running'].includes(job.status)?job:null);
 const ending=sessionEnding||(outcome?{exit_code:job?.exit_code??1,outcome}:null);
 if(ending)for(const a of view.agents)if(!a.ended){a.status='interrupted';a.last='会话已结束，未确认任务交付';}
 const scroll=el('scroll'), anchor=captureAnchor(scroll,el('content'));
 el('agent-count').textContent=view.agents.length;
 el('agents').innerHTML=agentTree(view.agents,agent,folded);
 el('all-agents').classList.toggle('selected',!agent);el('task-count').textContent=tasks.length;
 el('tasks').innerHTML=tasks.map(t=>'<button class="task" data-object="'+esc(t.id)+'"><strong>'+esc(t.role)+'</strong><p>'+esc(t.question)+'</p>'+tag(t.status==='running'&&ending?'interrupted':t.status)+'</button>').join('');
 el('metrics').innerHTML='<span><b>'+(state.counts.card||0)+'</b> 卡片</span><span><b>'+state.objects.filter(o=>['card','link'].includes(o.kind)&&(o.review_state==='needs_review'||o.status==='stale')).length+'</b> 待复核节点/关系</span><span><b>'+(state.counts.report||0)+'</b> 报告</span>';
 el('session-status').innerHTML=!current?'尚无会话':outcome?tag(outcome.status):ending?tag('ended'):tag('running');
 el('run-overview').className=outcome?.status==='completed'?'delivered':ending?'attention':'';
 el('run-overview').innerHTML='<strong>'+(!current?'准备开始日志调查':outcome?.status==='completed'?'综合报告已生成，等待人工审阅':ending?'本轮会话已结束'+(outcome?.status!=='completed'?' · 尚未完成报告交付':''):'调查正在进行')+'</strong><p>'+esc(outcome?.error||(!ending?view.agents.filter(a=>!a.ended&&a.at).map(a=>a.name+'：'+a.last).join(' · '):'可查看会话过程及已经保存的证据'))+'</p>'+(outcome?.report_ids||[]).map(id=>'<button class="small" data-object="'+esc(id)+'">查看报告</button>').join('');
 el('view-context').textContent=tab==='sources'?'本调查全部来源 · 从事件卡聚合已查范围、结果与缺口':(selected?.name||'全部 Agent')+' · 本地时间';
 el('follow-label').hidden=tab!=='run';el('message-filter').hidden=tab!=='run';el('older').hidden=tab!=='run'||!moreHistory();
 el('older').disabled=loading;el('older').textContent=loading?'正在加载…':'↑ 加载更早消息';
 if(tab==='run'){
  const filter=el('message-filter').value;
  const rows=view.entries.filter(e=>(!agent||e.agent===agent)&&matching(e)&&(filter==='all'||(filter==='text'?['text','thinking'].includes(e.kind):filter==='tool'?['tool','result'].includes(e.kind):e.kind==='error'||e.error)));
  reconcile(el('content'),rows.length?rows.map(e=>({key:e.key,kind:e.kind,html:messageHTML(e,view.agents.find(a=>a.id===e.agent),ending)})):[{key:'empty',kind:'empty',html:loading?'正在读取会话…':'当前已加载消息中没有匹配项。可继续向上加载历史或清除筛选。'}]);
 }else{
  const rows=state.objects.filter(o=>o.kind===(tab==='cards'?'card':tab==='sources'?'source_view':'report')&&(tab==='sources'||!agent||taskArtifacts.has(o.id)||taskIds.has(o.task_id)||taskIds.has(o.followup_task_id))&&matching(o));
  reconcile(el('content'),rows.length?rows.map(o=>({key:o.id,kind:'artifact-row',html:o.kind==='source_view'?sourceCardHTML(o):o.kind==='card'?eventCardHTML(o):item(o,o.statement||o.assessment||o.path)})):[{key:'empty',kind:'empty',html:'当前范围暂无产物'}]);
 }
 const artifacts=state.objects.filter(o=>['card','check','report'].includes(o.kind)&&(!agent||taskArtifacts.has(o.id)||taskIds.has(o.task_id)||taskIds.has(o.followup_task_id)));
 el('artifacts').innerHTML='<div class="artifact-label">'+(agent?'当前 Agent 关联产物':'案件最新产物')+' · 显示 '+Math.min(8,artifacts.length)+' / '+artifacts.length+'</div>'+artifacts.slice(0,8).map(o=>'<button class="artifact" data-object="'+esc(o.id)+'"><span>'+esc(o.kind==='card'?(o.event?'事件卡':'历史文本卡'):o.kind==='report'?'报告':'排查结论')+' · '+esc(statusNames[o.status]||o.status)+'</span><p>'+esc(o.event?.title||o.statement||o.conclusion||o.question||o.assessment||o.id)+'</p></button>').join('');
 if(tab==='run'&&el('follow').checked&&!loading)scroll.scrollTop=scroll.scrollHeight;
 else restoreAnchor(scroll,el('content'),anchor);
 updateLatest();
 el('footer').textContent=tab==='sources'?'来源行为 · 仅本调查 · 聚合事件卡和普通检查，无独立复查队列':'已加载 '+events.length+' / '+(current?.event_count||0)+' 条会话事件 · '+(moreHistory()?'向上滚动继续读取历史':'当前视图历史已加载')+' · 搜索仅限已加载消息';
}
function updateLatest(){el('latest').hidden=tab!=='run'||el('follow').checked;}
async function detail(id){
 showDetail(true);
 try{
 const o=await api("/api/object?id="+encodeURIComponent(id));
 let html='<div class="id">'+esc(o.id)+(o.revision?' · r'+esc(o.revision):'')+'</div><h2>'+esc(['source_view','source_lead'].includes(o.kind)?'来源行为':o.kind==='card'?eventTitle(o):(o.role||o.kind))+'</h2>'+(o.kind==='source_view'?'':tag(o.status))+(o.kind==='card'?'':'<p>'+esc(o.question||o.summary||o.conclusion||"")+'</p>');
 if(o.kind==="source_view")html+=sourceDetailHTML(o);
 if(o.kind==="source_lead")html+='<p>历史来源记录（独立复查流程已停用）</p><pre>'+esc(pretty(o))+'</pre>';
 if(o.kind==="task"){
  if(o.source_lead_id)html+='<button class="ref" data-object="'+esc(o.source_lead_id)+'">历史来源记录</button>'+sourceTaskHTML(o);
  html+='<button class="small" data-task-chat="'+esc(id)+'">定位关联 Agent 会话</button>';
  if(o.parent_card_id)html+='<button class="ref" data-object="'+esc(o.parent_card_id)+'">起点卡片 '+esc(o.parent_card_id)+'</button>';
 }
 if(['card','link','check'].includes(o.kind))html+=integrityHTML(o);
 if(o.kind==='card'){html+=eventDetailHTML(o);for(const source of state.objects.filter(x=>x.kind==='source_view'&&x.cards.some(c=>c.id===o.id)))html+='<button class="ref" data-object="'+esc(source.id)+'">来源行为 '+esc(source.address)+'</button>';}
 if(o.kind==="card"){
  const questions=state.objects.filter(t=>t.parent_card_id===id);
  html+='<h2>补证派发与复核记录</h2>'+(questions.map(t=>'<div class="edge">'+esc({upstream:"前置",downstream:"后续",both:"前后"}[t.direction]||"补证")+' · '+tag(t.status)+'<button data-object="'+esc(t.id)+'">'+esc(t.question)+'</button></div>').join("")||'<p>尚未派发独立补证任务'+(o.event?'，关键问题见上方':'')+'。</p>');
  html+='<h2>相邻节点</h2>'+state.objects.filter(l=>l.kind==="link"&&(l.from_card===id||l.to_card===id)).map(l=>'<div class="edge">'+reviewBadge(l)+esc(l.inferred?"推断关系":"观察关系")+' · '+esc(l.relation)+'<button data-object="'+esc(l.from_card===id?l.to_card:l.from_card)+'">'+esc(state.objects.find(c=>c.id===(l.from_card===id?l.to_card:l.from_card))?.event?.title||(l.from_card===id?l.to_card:l.from_card))+'</button></div>').join("");
 }
 for(const ref of o.evidence||[]){
  if(ref.source_id)html+='<button class="ref" data-source="'+esc(ref.source_id)+'" data-line="'+ref.start+'">原始行 '+esc(ref.source_id)+':'+ref.start+'</button>';
  else if(ref.query_id)html+='<button class="ref" data-object="'+esc(ref.query_id)+'">查询 '+esc(ref.query_id)+'</button>';
  else if(ref.dataset_id)html+='<div class="ref">数据行 '+esc(ref.dataset_id)+':'+esc(ref.row_id)+'<button data-object="'+esc(ref.dataset_id)+'">查看数据集</button></div>';
 }
 for(const oid of o.artifact_ids||[])html+='<button class="ref" data-object="'+esc(oid)+'">产物 '+esc(oid)+'</button>';
 if(o.kind==="report"){const report=await api("/api/report?id="+encodeURIComponent(id));html+='<h2>报告正文</h2><div class="report-text">'+reportHTML(report.text)+'</div>';}
 if(o.history)html+='<h2>修订记录</h2><div class="revision-history">'+historyHTML(o.history,o.id)+'</div>';
 html+='<details><summary>完整记录</summary><pre>'+esc(JSON.stringify(o,null,2))+'</pre></details>';
 el("detail").innerHTML=html;el("detail").dataset.detailObject=id;el("detail").closest(".detail").scrollTop=0;
 }catch(e){el("detail").textContent=e.message;}
}
function sessionOptions(){
 el("session").innerHTML=sessions.map((s,i)=>'<option value="'+esc(s.run_id)+'">'+esc(new Date(s.started).toLocaleString("zh-CN",{hour12:false}))+' · '+esc(s.run_id.slice(-6))+(i===0?" · 最新":"")+'</option>').join("");
 el("session").value=run;
}
async function selectRun(id){
 const gen=++generation;run=id;agent="";events=[];context=[];agentPages.clear();el("follow").checked=true;loading=true;hasOlder=false;sessionOptions();render();
 try{
  const nav=await api("/api/session-context?run="+encodeURIComponent(id));if(gen!==generation)return;context=nav;
  let before="", rows=[];
  // Initial window includes up to 500 raw events; older pages remain explicitly accessible.
  for(let i=0;i<5;i++){
   const page=await api("/api/events?run="+encodeURIComponent(id)+(before?"&before="+before:""));
   if(gen!==generation)return;
   rows=[...page,...rows];hasOlder=page.length===100;
   if(!hasOlder)break;before=page[0].seq;
  }
  events=[...new Map([...rows,...events].map(e=>[e.seq,e])).values()].sort((a,b)=>a.seq-b.seq);
 }catch(e){el("connection").textContent=e.message;}
 finally{if(gen===generation){loading=false;render();}}
}
let lastSessions="";
async function refresh(){
 const [next,runs,commands]=await Promise.all([api("/api/snapshot"),api("/api/sessions"),api("/api/control")]);
 control=commands;renderJobs();
 const changed=state.version!==next.version;state=next;sessions=runs;sessionOptions();
 if(watchSessionAfter!==null && sessions.length && sessions[0].run_id!==watchSessionAfter){
  watchSessionAfter=null;await selectRun(sessions[0].run_id);
 }else if(!run&&sessions.length)await selectRun(sessions[0].run_id);
 else if(run&&!sessions.some(s=>s.run_id===run)){run="";events=[];context=[];if(sessions.length)await selectRun(sessions[0].run_id);else render();}
 else if(changed || JSON.stringify(runs)!==lastSessions){render();}
 lastSessions=JSON.stringify(runs);
}
document.addEventListener("click",async e=>{
 const section=e.target.closest('[data-report-section]');if(section){el('detail').querySelector('[data-report-heading="'+section.dataset.reportSection+'"]')?.scrollIntoView({block:'start'});return;}
 const fold=e.target.closest('[data-fold]');if(fold){folded.has(fold.dataset.fold)?folded.delete(fold.dataset.fold):folded.add(fold.dataset.fold);render();return;}
 const hb=e.target.closest('[data-history]');
 if(hb){hb.disabled=true;try{const page=await api('/api/object-history?id='+encodeURIComponent(hb.dataset.history)+'&offset='+hb.dataset.offset);if(el('detail').dataset.detailObject===hb.dataset.history)hb.outerHTML=historyHTML(page,hb.dataset.history);}catch(err){hb.disabled=false;hb.textContent='加载失败，点击重试';}return;}
 const b=e.target.closest("[data-tab],[data-agent],[data-object],[data-source],[data-task-chat]");
 if(!b)return;
 if(b.dataset.tab){tab=b.dataset.tab;document.querySelectorAll("nav button").forEach(x=>x.classList.toggle("active",x===b));render();}
 if(b.dataset.agent){agent=b.dataset.agent;render();if(!agentPages.has(agent))await loadAgentPage(agent);}
 if(b.dataset.object)detail(b.dataset.object);
 if(b.dataset.taskChat){const a=transcript().agents.find(a=>a.taskIds.has(b.dataset.taskChat));if(a){agent=a.id;tab="run";document.querySelector('[data-tab="run"]').click();}else el("detail").insertAdjacentHTML("beforeend",'<p>当前已加载会话未找到此任务，请切换会话或加载更早消息。</p>');}
 if(b.dataset.source){try{const raw=await api("/api/raw?source="+encodeURIComponent(b.dataset.source)+"&line="+b.dataset.line);el("detail").innerHTML='<h2>原始记录</h2><pre>'+esc(pretty(raw))+'</pre>';}catch(err){el("detail").textContent=err.message;}}
});
function showDetail(open){document.body.classList.toggle('details-open',open);el('toggle-detail').setAttribute('aria-expanded',String(open));}
showDetail(window.innerWidth>=1250);
el('toggle-detail').onclick=()=>showDetail(!document.body.classList.contains('details-open'));
el('close-detail').onclick=()=>showDetail(false);
document.addEventListener('keydown',e=>{if(e.key==='Escape')showDetail(false);});
el("all-agents").onclick=()=>{agent="";render();};
el("search").oninput=render;
el("session").onchange=()=>selectRun(el("session").value);
el("message-filter").onchange=render;
function latest(){el("follow").checked=true;el("scroll").scrollTop=el("scroll").scrollHeight;updateLatest();}
el("latest").onclick=latest;
el("follow").onchange=()=>{if(el("follow").checked)latest();else updateLatest();};
function pauseFollow(){el("follow").checked=false;updateLatest();}
el("scroll").addEventListener("wheel",e=>{if(e.deltaY<0)pauseFollow();},{passive:true});
el("scroll").addEventListener("touchmove",pauseFollow,{passive:true});
el("scroll").addEventListener("keydown",e=>{if(["ArrowUp","PageUp","Home"].includes(e.key))pauseFollow();});
el("scroll").addEventListener("scroll",()=>{
 const box=el("scroll");
 if(box.scrollHeight-box.clientHeight-box.scrollTop>100)pauseFollow();
 if(box.scrollTop<100&&!el("follow").checked&&moreHistory()&&!loading&&tab==="run")loadOlder();
},{passive:true});
async function loadOlder(){
 if(agent){await loadAgentPage(agent);return;}
 if(loading||!hasOlder||!events.length)return;
 const gen=generation;loading=true;pauseFollow();el("older").disabled=true;
 try{const page=await api("/api/events?run="+encodeURIComponent(run)+"&before="+events[0].seq);if(gen!==generation)return;hasOlder=page.length===100;events=[...new Map([...page,...events].map(e=>[e.seq,e])).values()].sort((a,b)=>a.seq-b.seq);}
 catch(e){el("connection").textContent=e.message;}
 finally{if(gen===generation){loading=false;render();}}
}
async function loadAgentPage(id){
 if(loading)return;
 const gen=generation, cached=agentPages.get(id);if(cached&&!cached.more)return;
 loading=true;
 try{
  const page=await api('/api/events?run='+encodeURIComponent(run)+'&agent='+encodeURIComponent(id)+(cached?.rows.length?'&before='+cached.rows[0].seq:''));
  if(gen!==generation)return;
  agentPages.set(id,{rows:[...new Map([...page,...(cached?.rows||[])].map(e=>[e.seq,e])).values()].sort((a,b)=>a.seq-b.seq),more:page.length===100});
 }catch(e){el('connection').textContent=e.message;}
 finally{if(gen===generation){loading=false;render();}}
}
el("older").onclick=loadOlder;
async function begin(){
 try{
  const initial=await api("/api/sessions");cursor=Math.max(0,...initial.map(s=>s.last_seq));await refresh();
  const stream=new EventSource(caseUrl("/api/stream?after="+cursor));
  stream.onopen=()=>{el("connection").textContent="● 已连接 · 实时更新";};
  stream.onerror=()=>{el("connection").textContent="连接重试中";};
  let dirty=false,pending=false;
  stream.addEventListener("runtime",e=>{
   const row=JSON.parse(e.data);if(row.seq<=cursor)return;cursor=row.seq;
   if(row.run_id===run&&!events.some(x=>x.seq===row.seq)){events.push(row);dirty=true;}
  });
  stream.addEventListener("refresh",async()=>{
   if(pending)return;pending=true;
   try{await refresh();if(dirty){dirty=false;render();}}
   catch(e){el("connection").textContent=e.message;}finally{pending=false;}
  });
 }catch(e){el("connection").textContent=e.message;setTimeout(begin,3000);}
}
const jobLabels={starting:"正在启动",preparing:"正在复制登记日志",running:"Claude 正在调查",completed:"报告已交付",incomplete:"未完成交付",failed:"启动或执行失败",interrupted:"执行已中断"};
function renderJobs(){
 const j=control.active_job;
 el("jobs").hidden=!j;
 el("jobs").innerHTML=j?'<div class="job-line"><span class="live-dot"></span><strong>'+esc(jobLabels[j.status])+'</strong><span>'+esc(j.investigation_name||'日志调查')+'</span><span>切换项目不会中断运行</span>'+(j.case_id?'<button class="small" data-open-case="'+esc(j.case_id)+'" data-open-project="'+esc(j.project_id)+'">查看运行</button>':'')+'</div>':'';
 el("submit-job").disabled=posting||!!j;
}

function jobMode(){
 workspace.jobSources();
 el("job-name-label").hidden=el("job-mode").value==="current";
 const fresh=el("job-mode").value==="new";
 el("log-dir-label").hidden=!fresh;el("job-log-dir").required=fresh;
 el("analysis-only-label").hidden=fresh||el("job-mode").value==="fresh";
 el("job-mode-note").textContent=fresh?"新建案件并复制登记原始日志；大目录可能需要较长时间和额外磁盘空间。":el("job-mode").value==="fresh"?"复用不可变的入库分区，新建空白事件卡、任务和会话；不继承之前的分析结论。":"使用所选调查已有的事件卡与数据，在新 Claude 会话中继续。";
}
el("new-job").onclick=()=>{
 workspace.prepareJob();
 requestId=crypto.randomUUID();
 el("job-analysis-only").checked=!!state.counts.dataset;
 el("job-error").textContent=!!control.active_job?"已有调查正在执行，结束后可下发下一项。":"";
 jobMode();el("job-dialog").showModal();
};
el("close-job").onclick=el("cancel-job").onclick=()=>el("job-dialog").close();
el("job-mode").onchange=jobMode;
el("job-form").addEventListener("input",()=>{requestId=crypto.randomUUID();});
el("job-form").onsubmit=async e=>{
 e.preventDefault();if(posting)return;
 posting=true;renderJobs();el("job-error").textContent="";
 try{
  const response=await fetch("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json","X-IRKit-Token":control.token},body:JSON.stringify({
   request_id:requestId,case_id:el("job-case").value,project_id:el("job-project").value,investigation_name:el("job-name").value.trim(),mode:el("job-mode").value,
   log_dir:el("job-log-dir").value.trim(),background:el("job-background").value,
   budget:Number(el("job-budget").value),analysis_only:el("job-analysis-only").checked
  })});
  const job=await response.json();if(!response.ok)throw Error(job.error||response.status);
  if(job.mode==="current")watchSessionAfter=sessions[0]?.run_id||"";
  el("job-dialog").close();if(job.mode==="current"&&job.case_dir?.split("/").pop()!==caseId){workspace.navigate(job.project_id,job.case_dir.split("/").pop());return;}await workspace.refresh();if(caseId)await refresh();else{control=workspace.data;renderJobs();}
 }catch(error){el("job-error").textContent=error.message;}
 finally{posting=false;renderJobs();}
};
document.addEventListener("click",async e=>{
 const b=e.target.closest("[data-open-case],[data-job-log]");if(!b)return;
 if(b.dataset.openCase){
  if(b.dataset.openCase===control.case_id){if(sessions.length)await selectRun(sessions[0].run_id);}
  else workspace.navigate(b.dataset.openProject||projectId,b.dataset.openCase);
 }
 if(b.dataset.jobLog){el("workspace-dialog").close();showDetail(true);try{const log=await api("/api/job-log?id="+encodeURIComponent(b.dataset.jobLog));el("detail").innerHTML='<h2>任务运行日志</h2><p>'+esc(log.truncated?"仅显示末尾 20 KB":"完整运行输出")+'</p><pre>'+esc(log.text||"任务已接收，等待启动输出。")+'</pre>';}catch(error){el("detail").textContent=error.message;}}
});
const workspace=workspaceUI({api,onChange:()=>{if(caseId)refresh().catch(e=>el('connection').textContent=e.message);}});
async function boot(){
 try{
  const initial=await workspace.refresh();control=initial;renderJobs();
  projectId=initial.project_id||'';caseId=initial.case_id||'';
  history.replaceState(null,'','?project='+encodeURIComponent(projectId)+(caseId?'&case='+encodeURIComponent(caseId):''));
  if(caseId)begin();
  else{
   el('connection').textContent='项目已就绪';el('run-overview').innerHTML='<strong>开始一次日志调查</strong><p>点击右上角下发调查任务，选择日志目录。后续可以复用入库数据开展独立分析。</p>';
   el('content').innerHTML='<div class="empty">此项目尚无调查<br><small>各项目分别管理数据、事件卡、报告与会话。</small></div>';
  }
  setInterval(async()=>{try{await workspace.refresh();if(!caseId){control=workspace.data;renderJobs();if(workspace.data.case_id)workspace.navigate(projectId,workspace.data.case_id);}}catch(e){el('connection').textContent=e.message;}},5000);
 }catch(e){el('connection').textContent=e.message;el('content').innerHTML='<div class="empty">'+esc(e.message)+'<p><a href="/">返回项目列表</a></p></div>';}
}
boot();
