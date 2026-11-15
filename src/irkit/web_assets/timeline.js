import {readable} from './conversation.js';
export const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const timestamp=at=>at?new Date(at).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}):'';
// Render only a small safe Markdown subset; raw HTML and external links stay text.
export function prose(text) {
 return esc(text).split(/(```[\s\S]*?```)/).map(part=>part.startsWith('```')?'<pre>'+part.replace(/^```[^\n]*\n?/, '').replace(/```$/, '')+'</pre>':part.split('\n').map(line=>{
  const inline=line.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>');
  if(/^#{1,4} /.test(line))return '<h3>'+inline.replace(/^#{1,4} /,'')+'</h3>';
  if(/^[-*] /.test(line))return '<div class="prose-item">'+inline.slice(2)+'</div>';
  return inline+'<br>';
 }).join('')).join('');
}
export function messageHTML(e, agent, ending) {
 const head='<div class="meta"><strong>'+esc(agent?.name||e.agent)+'</strong><time>'+timestamp(e.at)+'</time></div>';
 if(['tool','result'].includes(e.kind)) {
  const error=e.error||e.results.some(r=>r.error);
  const status=e.background?'已派发，结果见子 Agent':e.results.length?(error?'调用失败':'已返回'):(ending?'未捕获结果':'执行中');
  const links=new Set((readable(e.input)+' '+readable(e.results)).match(/(?:source_lead|card|task|check|report)_[0-9a-f]{16}/g)||[]);
  return head+'<details data-key="'+esc(e.key)+'"><summary><span class="tool-title">'+esc(e.title||e.text)+'</span><span class="tool-state '+(error?'danger':'')+'">'+status+'</span>'+(e.description?'<span class="action-description">'+esc(e.description)+'</span>':'')+'</summary><div class="tool-detail"><h3>调用参数</h3><pre>'+esc(readable(e.input))+'</pre>'+e.results.map(r=>'<h3>返回 · '+timestamp(r.at)+'</h3><pre>'+esc(readable(r.content))+'</pre>').join('')+'<div class="id">'+esc(e.text)+' · '+esc(e.callId)+'</div></div></details><div class="object-links">'+[...links].slice(0,12).map(id=>'<button data-object="'+esc(id)+'">'+esc(id.startsWith('source_lead_')?'来源线索':id.startsWith('card_')?'证据卡片':id.startsWith('check_')?'排查结论':id.startsWith('report_')?'报告':'任务')+' · '+id.slice(-6)+'</button>').join('')+'</div>';
 }
 if(e.kind==='thinking')return head+'<details data-key="'+esc(e.key)+'"><summary>分析过程 <span>模型返回的思考内容</span></summary><div class="text">'+prose(e.text)+'</div></details>';
 if(e.kind==='instruction')return head+'<details data-key="'+esc(e.key)+'"><summary>任务与上下文 <span>展开指令</span></summary><div class="text">'+prose(e.text)+'</div></details>';
 return head+'<div class="text">'+prose(e.text)+'</div>';
}
// Keep existing nodes (and selection/expanded state) when events don't change.
export function reconcile(container, rows) {
 const existing=new Map([...container.children].map(node=>[node.dataset.entry,node]));
 let next=container.firstElementChild;
 for(const row of rows) {
  let node=existing.get(row.key);
  if(!node){node=document.createElement('article');node.dataset.entry=row.key;}
  if(node._html!==row.html){
   const open=new Set([...node.querySelectorAll('details[open]')].map(d=>d.dataset.key));
   node.innerHTML=row.html;node._html=row.html;
   for(const d of node.querySelectorAll('details'))if(open.has(d.dataset.key))d.open=true;
  }
  node.className='message '+row.kind;
  if(node!==next)container.insertBefore(node,next);else next=next.nextElementSibling;
  existing.delete(row.key);
 }
 for(const node of existing.values())node.remove();
}
export function captureAnchor(scroll, content) {
 const top=scroll.getBoundingClientRect().top;
 const node=[...content.children].find(n=>n.getBoundingClientRect().bottom>top);
 return {key:node?.dataset.entry,offset:node?node.getBoundingClientRect().top-top:0,top:scroll.scrollTop};
}
export function restoreAnchor(scroll, content, anchor) {
 const node=[...content.children].find(n=>n.dataset.entry===anchor.key);
 if(node)scroll.scrollTop+=node.getBoundingClientRect().top-scroll.getBoundingClientRect().top-anchor.offset;
 else scroll.scrollTop=anchor.top;
}
