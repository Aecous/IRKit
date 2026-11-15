import {esc} from './timeline.js';
const trusts={unverified:'来源可信度未验证',direct_peer:'日志直连对端',trusted_proxy:'已声明可信代理（需依据）'};
const outcomes={hits:'有命中',zero_hits:'限定范围内无命中',incomplete:'检查未完成',inconclusive:'无法定论'};
const ref=(id,label)=>'<button class="ref" data-object="'+esc(id)+'">'+esc(label||id)+'</button>';
export function sourceCardHTML(o){
 const cards=o.cards||[], checks=o.checks||[];
 return '<button class="entry source-card" data-object="'+esc(o.id)+'"><div class="meta">事件卡聚合 · '+esc(o.match_mode)+'</div><h2>'+esc(o.address)+'</h2><div class="event-foot">'+esc(o.field)+' · '+esc(trusts[o.attribution]||o.attribution)+'</div><div class="source-summary"><span>'+cards.filter(c=>c.current).length+' 个当前事件</span><span>'+checks.filter(c=>c.current).length+' 条有效检查关联</span><span>'+checks.filter(c=>c.historical).length+' 条历史检查关联</span><span>'+(o.gaps||[]).length+' 条缺口/待查提示</span></div></button>';
}
export function sourceDetailHTML(o){
 let html='<h2>'+esc(o.address)+'</h2><div class="event-scope">来源字段：'+esc(o.field)+'<br>匹配方式：'+esc(o.match_mode)+'<br>'+esc(trusts[o.attribution]||o.attribution)+'</div><p>从事件卡聚合；没有检查不代表没有攻击，同一来源不自动证明同一攻击者。检查有效仅指引用仍有效，不代表所有行为已解释。</p><h2>关联事件与观测范围</h2>';
 for(const c of o.cards||[])html+='<section class="source-event">'+ref(c.id,c.title)+'<div class="event-foot">r'+esc(c.revision)+' · '+esc(c.environment)+' / '+esc(c.asset)+'<br>'+esc(c.time_range)+' · '+esc(c.current?'当前事件':'历史或待复核事件')+'</div></section>';
 html+='<h2>已查范围与结果</h2>';
 for(const c of o.checks||[])html+='<section class="source-event">'+ref(c.id,c.question)+'<div class="event-foot">'+esc(c.historical?'历史来源复查记录':c.current?'当前检查':'过期或待复核检查')+' · '+ref(c.card_id,'关联事件')+'</div><p>已查范围：'+esc(c.scope)+'</p><p>结果：'+esc(outcomes[c.outcome]||c.outcome)+'</p><p>结论：'+esc(c.conclusion||'未单独记录，见检查和事件卡')+'</p><p>限制：'+esc(c.limitations)+'</p>'+(c.query_ids||[]).map(id=>ref(id,'查看查询')).join('')+'</section>';
 if(!(o.checks||[]).length)html+='<p>尚未关联来源行为检查。</p>';
 html+='<h2>缺口与待查问题</h2>'+(o.gaps||[]).map(g=>'<p>'+esc(g)+'</p>').join('');
 if(o.legacy_task_ids?.length)html+='<h3>历史来源任务（不再单独派发）</h3>'+o.legacy_task_ids.map(id=>ref(id)).join('');
 return html;
}
export function sourceTaskHTML(t){
 const r=t.source_result, snap=t.source_snapshot||{};
 let html='<section class="source-task">'+ref(t.id,t.question)+'<div class="event-foot">'+esc(t.status)+' · 历史快照 '+Object.keys(snap.datasets||{}).length+' 个数据集 / '+Object.keys(snap.cards||{}).length+' 个事件<br>本轮增量 '+(t.source_delta_card_ids||[]).length+' 个事件 · 可复用 '+Object.keys(t.source_base_checks||{}).length+' 项既有查询检查</div><p>'+esc(t.scope)+'</p>';
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
