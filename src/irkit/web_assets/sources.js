import {esc} from './timeline.js';
export const sourceStates={pending:'待派发',assigned:'已派发',running:'行为复查中',needs_incremental:'有增量待补查',awaiting_review:'待独立复核',reviewed:'已复核'};
const judgments={suspected:'疑似来源',attack_evidenced:'存在攻击行为证据',excluded:'已排除（限已查范围）',inconclusive:'无法判定'};
const trusts={unverified:'来源可信度未验证',direct_peer:'日志直连对端',trusted_proxy:'已声明可信代理（需依据）'};
const ref=(id,label)=>'<button class="ref" data-object="'+esc(id)+'">'+esc(label||id)+'</button>';
export function sourceCardHTML(o){
 const s=o.investigation||{}, cards=Object.values(o.cards||{}).filter(c=>c.linked);
 return '<button class="entry source-card" data-object="'+esc(o.id)+'"><div class="meta"><span class="event-state '+(s.complete?'':'event-open')+'">'+esc(sourceStates[s.state]||'待检查')+'</span><span>'+esc(judgments[o.judgment]||o.judgment)+'</span></div><h2>'+esc(o.address)+'</h2><p>'+esc(o.reason)+'</p><div class="event-foot">'+esc(o.field)+' · '+esc(trusts[o.attribution]||o.attribution)+'</div><div class="source-summary"><span>'+cards.length+' 个关联事件</span><span>'+new Set(cards.map(c=>c.environment)).size+' 个环境</span><span>'+(s.missing_card_ids||[]).length+' 个待覆盖事件</span></div></button>';
}
export function sourceDetailHTML(o){
 const s=o.investigation||{};
 let html='<h2>'+esc(o.address)+'</h2><span class="event-state">'+esc(sourceStates[s.state]||'待检查')+'</span><p>'+esc(judgments[o.judgment]||o.judgment)+(s.complete?'':' · 历史判断不能代替当前增量复查')+'</p><p>'+esc(o.judgment_note)+'</p><div class="event-scope">来源字段：'+esc(o.field)+'<br>匹配方式：'+esc(o.match_mode)+'<br>'+esc(trusts[o.attribution]||o.attribution)+'</div><p>来源关联不自动证明同一攻击者或因果关系。</p><h2>关联事件与观测范围</h2>';
 for(const c of Object.values(o.cards||{}))html+='<section class="source-event">'+ref(c.id,c.title)+'<div class="event-foot">r'+c.revision+' · '+esc(c.environment)+' / '+esc(c.asset)+'<br>'+esc(c.time_range)+'<br>'+esc(c.linked?'关联中':'已撤销关联（历史保留）')+' · '+esc(c.status)+'</div>'+(s.missing_card_ids?.includes(c.id)?'<span class="event-state event-open">尚未被当前复查覆盖</span>':'')+'</section>';
 html+='<h2>行为复查任务</h2>'+(o.tasks||[]).map(sourceTaskHTML).join('');
 return html;
}
export function sourceTaskHTML(t){
 const r=t.source_result, snap=t.source_snapshot||{};
 let html='<section class="source-task">'+ref(t.id,t.question)+'<div class="event-foot">'+esc(t.status)+' · 固定 '+Object.keys(snap.datasets||{}).length+' 个数据集 / '+Object.keys(snap.cards||{}).length+' 个事件<br>本轮增量 '+(t.source_delta_card_ids||[]).length+' 个事件 · 可复用 '+Object.keys(t.source_base_checks||{}).length+' 项既有查询检查</div><p>'+esc(t.scope)+'</p>';
 if(r){html+='<h3>实际检查的行为</h3>'+r.behavior_categories.map(b=>'<div class="source-event"><strong>'+esc(b.behavior)+'</strong><p>'+esc(b.conclusion)+'</p>'+b.check_ids.map(id=>ref(id,'查看排查记录')).join('')+'</div>').join('')+'<p>证据缺口：'+esc(r.limitations)+'</p><p>综合复核：'+esc(t.source_review?.verdict==='supported'?'支持有界结论':t.source_review?.verdict==='needs_more_evidence'?'仍需补证':'尚未复核')+'</p>';}
 return html+'</section>';
}
function inline(s){
 const plain=s.replace(/<br>/g,' ').replace(/&(amp|lt|gt|quot|#x27|#39|#96|#124);/g,(_,k)=>({amp:'&',lt:'<',gt:'>',quot:'"','#x27':"'",'#39':"'",'#96':'`','#124':'|'}[k]));
 return esc(plain).replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\[(E-\d+)\]\(#evidence-((?:card|check|link)_[a-f0-9]{16})\)/g,'<button class="report-citation" data-object="$2">$1</button>');
}
export function reportHTML(text){
 const lines=text.split('\n');let html='',table=false,code=false,appendix=false;
 for(const line of lines){
  if(line.startsWith('```')){if(code){html+='</pre>';code=false;}else{html+='<pre>';code=true;}continue;}
  if(code){html+=esc(line)+'\n';continue;}
  if(/^<a id="evidence-[a-z0-9_]+"><\/a>$/.test(line))continue;
  if(line.startsWith('|')){
   if(/^\|[\s:|\-]+\|$/.test(line))continue;
   if(!table){html+='<div class="report-table-wrap"><table>';table=true;}
   html+='<tr>'+line.split('|').slice(1,-1).map(c=>'<td>'+inline(c.trim())+'</td>').join('')+'</tr>';continue;
  }
  if(table){html+='</table></div>';table=false;}
  if(line.startsWith('## 附录')){html+='<details class="report-appendix"><summary>展开证据与调查记录附录</summary>';appendix=true;continue;}
  if(/^## [1-5]\. /.test(line)){const n=line[3];html+='<h2 data-report-heading="'+n+'">'+inline(line.slice(3))+'</h2>';continue;}
  if(/^#{1,4} /.test(line)){html+='<h3>'+inline(line.replace(/^#{1,4} /,''))+'</h3>';continue;}
  html+=line?'<p>'+inline(line)+'</p>':'';
 }
 if(table)html+='</table></div>';if(code)html+='</pre>';if(appendix)html+='</details>';
 return '<div class="report-chapters">'+['背景与范围','结论与影响','时间线与路径','来源与行为','缺口与建议'].map((t,i)=>'<button class="small" data-report-section="'+(i+1)+'">'+(i+1)+'. '+t+'</button>').join('')+'</div>'+html;
}
