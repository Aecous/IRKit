import {esc} from './timeline.js';
export function agentTree(agents, selected='', folded=new Set()) {
 const known=new Set(agents.map(a=>a.id)), children=new Map();
 for(const a of agents){
  let parent=a.id==='main'?null:known.has(a.parentId)&&a.parentId!==a.id?a.parentId:null;
  const seen=new Set([a.id]); let p=parent;
  while(p){if(seen.has(p)){parent=null;break;}seen.add(p);p=agents.find(x=>x.id===p)?.parentId;}
  if(!children.has(parent))children.set(parent,[]);children.get(parent).push(a);
 }
 const names={idle:'等待',observed:'活动中',ended:'已返回',interrupted:'已中断',failed:'失败'};
 const draw=(a)=>{
  const subs=children.get(a.id)||[], open=!folded.has(a.id);
  return '<li class="agent-node '+(a.id==='main'?'agent-root':'')+'"><div class="tree-row '+(selected===a.id?'selected':'')+'">'+(subs.length?'<button class="tree-toggle" data-fold="'+esc(a.id)+'" aria-label="折叠或展开 '+esc(a.name)+'" aria-expanded="'+open+'">'+(open?'▾':'▸')+'</button>':'<span class="tree-spacer"></span>')+'<button class="tree-agent" data-agent="'+esc(a.id)+'" title="'+esc(a.description||a.last)+'"><span class="tree-heading"><strong>'+esc(a.name)+'</strong><span class="tree-status '+esc(a.status)+'">'+esc(names[a.status]||a.status||'等待')+'</span></span><span class="tree-description">'+esc(a.description||(a.id==='main'?'分工 · 协调 · 交付报告':'委派关系未记录'))+'</span><span class="tree-last">'+esc(a.last||'')+(subs.length?' · '+subs.length+' 个子 Agent':'')+'</span></button></div>'+(subs.length&&open?'<ul class="agent-children">'+subs.map(draw).join('')+'</ul>':'')+'</li>';
 };
 return '<ul class="agent-tree">'+(children.get(null)||[]).map(draw).join('')+'</ul>';
}
export const jobLabels={starting:'正在启动',preparing:'准备数据',running:'调查中',completed:'已交付',incomplete:'未完成交付',failed:'执行失败',interrupted:'已中断',idle:'尚未启动'};
export function workspaceUI({api, onChange}){
 const el=id=>document.getElementById(id);let data={projects:[],investigations:[],jobs:[]};
 const visibleProjects=()=>data.projects.filter(p=>!p.deleted_at);
 const cases=pid=>data.investigations.filter(c=>c.project_id===pid&&!c.deleted_at);
 function navigate(pid,cid=''){location.search='?project='+encodeURIComponent(pid)+(cid?'&case='+encodeURIComponent(cid):'');}
 function confirmTrash(kind){return new Promise(resolve=>{el('delete-note').textContent='原始日志与入库数据不会删除，可从回收站恢复。'+(kind==='run'?'仅隐藏本次运行及会话；调查中的卡片与报告保留。':'所属记录会一并隐藏。');const dialog=el('delete-dialog');const finish=answer=>{dialog.close();resolve(answer);};el('cancel-delete').onclick=()=>finish(false);el('confirm-delete').onclick=()=>finish(true);dialog.oncancel=()=>resolve(false);dialog.showModal();});}
 async function change(payload){const r=await fetch('/api/workspace',{method:'POST',headers:{'Content-Type':'application/json','X-IRKit-Token':data.token},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok)throw Error(d.error);return d;}
 function paint(){
  const p=data.projects.find(p=>p.id===data.project_id), c=data.investigations.find(c=>c.id===data.case_id);
  el('project-select').innerHTML=visibleProjects().map(p=>'<option value="'+esc(p.id)+'">'+esc(p.name)+'</option>').join('');el('project-select').value=data.project_id||'';
  el('investigation-select').innerHTML=cases(data.project_id).map(c=>'<option value="'+esc(c.id)+'">'+esc(c.name)+'</option>').join('')||'<option value="">暂无调查</option>';el('investigation-select').value=data.case_id||'';
  el('case').textContent=(p?.name||'分析项目')+(c?' / '+c.name:' / 尚未添加日志');
  el('manage-project').disabled=!p;
 }
 function history(){
  el('workspace-error').textContent='';
  el('workspace-title').textContent='调查与运行记录';
  const rows=cases(data.project_id);
  el('workspace-content').innerHTML='<p class="form-hint">调查保留独立事件卡和报告。删除移入回收站，原始日志与入库数据保留。</p>'+ (rows.map(c=>'<section class="history-case"><div class="history-title"><button data-navigate="'+esc(c.id)+'"><strong>'+esc(c.name)+'</strong></button><span>'+c.dataset_count+' 个数据集 · '+Number(c.row_count).toLocaleString()+' 行</span><button class="small" data-rename="'+esc(c.id)+'" data-kind="investigation">重命名</button><button class="small danger" data-trash="'+esc(c.id)+'" data-kind="investigation" '+(c.active?'disabled':'')+'>删除调查</button></div>'+data.jobs.filter(j=>j.case_id===c.id&&j.visible).map(j=>'<div class="history-run"><span>'+esc(new Date(j.created).toLocaleString('zh-CN'))+'</span><span>'+esc(['starting','preparing','running'].includes(j.status)?jobLabels[j.status]:j.status==='failed'?'执行失败':j.status==='interrupted'?'已中断':'运行结束')+'</span><span class="tag '+esc(j.status)+'">'+esc(j.mode==='report'?(j.status==='completed'?'结果报告已生成':'结果报告未生成'):j.status==='completed'?'报告已交付':'报告未交付')+'</span><button class="small" data-job-log="'+esc(j.id)+'">日志</button><button class="small danger" data-trash="'+esc(j.id)+'" data-kind="run" '+(['starting','preparing','running'].includes(j.status)?'disabled':'')+'>删除记录</button></div>').join('')+'</section>').join('')||'<div class="empty">项目中还没有调查，点击“下发调查任务”添加日志。</div>');
  const unattached=data.jobs.filter(j=>j.project_id===data.project_id&&!j.case_id&&j.visible);
  if(unattached.length)el('workspace-content').insertAdjacentHTML('beforeend','<h3>尚未建立调查的运行</h3>'+unattached.map(j=>'<div class="history-run"><span>'+esc(j.investigation_name||j.id)+'</span><span>'+esc(jobLabels[j.status])+'</span><button class="small" data-job-log="'+esc(j.id)+'">日志</button><button class="small danger" data-trash="'+esc(j.id)+'" data-kind="run" '+(['starting','preparing','running'].includes(j.status)?'disabled':'')+'>删除记录</button></div>').join(''));
  el('workspace-dialog').showModal();
 }
 function trash(){
  el('workspace-error').textContent='';
  el('workspace-title').textContent='回收站';
  const rows=[...data.projects.map(x=>({...x,kind:'project'})),...data.investigations.map(x=>({...x,kind:'investigation'})),...data.jobs.map(x=>({...x,kind:'run'}))].filter(x=>x.deleted_at);
  el('workspace-content').innerHTML='<p class="form-hint">仅移除工作台记录，不删除磁盘文件。请先恢复项目，再恢复调查与运行记录。</p>'+(rows.map(x=>'<div class="history-run"><span>'+esc({project:'项目',investigation:'调查',run:'运行'}[x.kind])+'</span><strong>'+esc(x.name||x.id)+'</strong><button class="small" data-restore="'+esc(x.id)+'" data-kind="'+x.kind+'">恢复</button></div>').join('')||'<div class="empty">回收站为空</div>');el('workspace-dialog').showModal();
 }
 let edit=null;
 function editName(kind,id=null){edit={kind,id};const source=kind==='project'?data.projects:data.investigations;el('name-title').textContent=id?'重命名':'新建分析项目';el('workspace-name').value=source.find(x=>x.id===id)?.name||'';el('name-error').textContent='';el('name-dialog').showModal();el('workspace-name').focus();}
 el('name-form').onsubmit=async e=>{e.preventDefault();try{const obj=await change({action:edit.id?'rename':'create',...edit,name:el('workspace-name').value});el('name-dialog').close();if(!edit.id)navigate(obj.id);else{await refresh();if(el('workspace-dialog').open)history();}}catch(e){el('name-error').textContent=e.message;}};
 el('cancel-name').onclick=()=>el('name-dialog').close();el('close-workspace').onclick=()=>el('workspace-dialog').close();
 el('project-select').onchange=()=>navigate(el('project-select').value);
 el('investigation-select').onchange=()=>navigate(data.project_id,el('investigation-select').value);
 el('create-project').onclick=()=>editName('project');
 el('manage-project').onclick=()=>{el('workspace-title').textContent='项目设置';const p=data.projects.find(p=>p.id===data.project_id);el('workspace-content').innerHTML='<h3>'+esc(p.name)+'</h3><p class="form-hint">项目下的调查、事件卡和会话独立保存。删除项目可从回收站恢复。</p><div class="dialog-actions"><button class="small" data-rename="'+esc(p.id)+'" data-kind="project">重命名</button><button class="small danger" data-trash="'+esc(p.id)+'" data-kind="project">删除项目</button></div>';el('workspace-dialog').showModal();};
 el('history-button').onclick=history;el('trash-button').onclick=trash;
 document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-navigate],[data-rename],[data-trash],[data-restore]');if(!b)return;
  if(b.dataset.navigate){navigate(data.project_id,b.dataset.navigate);return;}
  if(b.dataset.rename){editName(b.dataset.kind,b.dataset.rename);return;}
  const action=b.dataset.trash?'trash':'restore', id=b.dataset.trash||b.dataset.restore;
  if(action==='trash'&&!await confirmTrash(b.dataset.kind))return;
  b.disabled=true;
  try{await change({action,kind:b.dataset.kind,id});
   if(action==='trash'&&(id===data.project_id||id===data.case_id)){location.search=id===data.project_id?'':'?project='+data.project_id;return;}
   await refresh();onChange?.();action==='restore'?trash():history();
  }catch(e){el('workspace-error').textContent=e.message;b.disabled=false;}
 });
 function jobSources(){
  const pid=el('job-project').value, mode=el('job-mode').value;
  const list=cases(pid).filter(c=>mode==='report'?c.card_count>0:mode!=='fresh'||c.dataset_count>0), previous=el('job-case').value;
  el('job-case').innerHTML=list.map(c=>'<option value="'+esc(c.id)+'">'+esc(c.name)+' · '+(mode==='report'?c.card_count+' 张事件卡':c.dataset_count+' 数据集 / '+Number(c.row_count).toLocaleString()+' 行')+'</option>').join('');
  el('job-case').value=list.some(c=>c.id===previous)?previous:list.some(c=>c.id===data.case_id)?data.case_id:list[0]?.id||'';
  el('job-case-label').hidden=mode==='new';el('job-case').required=mode!=='new';
  el('job-case-title').textContent=mode==='report'?'使用哪次调查的结果':mode==='fresh'?'复用哪次调查的入库数据':'继续哪次调查';
  const source=list.find(c=>c.id===el('job-case').value);
  el('job-source-note').textContent=mode==='new'?'新日志将归入所选项目。':mode==='report'?(source?'读取该调查的 '+source.card_count+' 张现有事件卡及关联证据。':'该项目暂无有事件卡的调查，请先完成日志分析。'):source?'固定使用该调查当前的 '+source.dataset_count+' 个可用数据集；提交后不会自动切换来源。':'该项目没有可用调查，请选择“分析新的日志目录”。';
 }
 el('job-project').onchange=jobSources;el('job-case').onchange=jobSources;
 function prepareJob(){el('job-project').innerHTML=visibleProjects().map(p=>'<option value="'+esc(p.id)+'">'+esc(p.name)+'</option>').join('');el('job-project').value=data.project_id||'';if(!cases(data.project_id).length)el('job-mode').value='new';jobSources();}
 async function refresh(){data=await api('/api/workspace');paint();return data;}
 return {refresh,paint,jobSources,prepareJob,navigate,get data(){return data;}};
}
