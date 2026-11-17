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
function inline(s, labels={}){
 const plain=s.replace(/<br>/g,' ').replace(/&(amp|lt|gt|quot|#x27|#39|#96|#124);/g,(_,k)=>({amp:'&',lt:'<',gt:'>',quot:'"','#x27':"'",'#39':"'",'#96':'`','#124':'|'}[k]));
 return esc(plain).replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\[(E-\d+)\]\(#evidence-((?:card|check|link)_[a-f0-9]{16})\)/g,'<button class="report-citation" data-object="$2">$1</button>')
 .replace(/\[(E-\d+)\]\(report_[a-f0-9]{16}\.evidence\.md#e-\d+\)/g,(_,label)=>{const id=Object.keys(labels).find(id=>labels[id]===label);return id?'<button class="report-citation" data-object="'+esc(id)+'">'+label+'</button>':label;})
 .replace(/\[证据明细附录\]\(report_[a-f0-9]{16}\.evidence\.md\)/g,'证据明细见下方独立附录。')
 .replace(/\\([\\`*_{}\[\]#|])/g,'$1');
}
export function reportStatus(o){
 if(o.status==='stale')return '报告已过期，需重新生成';
 if(o.task_mode==='report')return '现有结果报告 · 不代表调查闭环';
 if(o.delivery==='progress')return '阶段报告 · 调查未完成';
 if(o.status==='generated')return '最终报告已生成 · 待人工审阅';
 return '历史报告 · 待人工审阅';
}
export function deliveryDetailsHTML(o){
 const r=o.readiness||o.closure_readiness;
 const mode=o.review_mode||r?.review_mode;
 let html=o.task_mode==='report'?'<p>本次仅整理已有结果；下方为调查本身的交付检查，不影响写作任务的完成状态。</p>':'';
 html+='<p>'+esc(mode==='off'?'快速模式 · 未经独立综合复核':mode==='full'?'完整模式 · 要求独立综合复核':'历史记录 · 未记录复核模式')+'</p>';
 if(!r)return html;
 if(!r.blockers)return html+'<p>历史检查尚未分类，请查看原始记录；不自动判为已完成。</p>';
 html+='<p>交付阻塞 '+r.blockers.length+' 项 · 修订/补证待复核 '+(r.review_pending||[]).length+' 项 · 已记录证据局限 '+(r.evidence_gaps||[]).length+' 项。待复核不等于原始日志缺失。</p>';
 for(const [key,title] of [['investigation_pending','尚未完成的调查'],['review_pending','卡片修订与补证待复核'],['evidence_gaps','已查范围的证据局限']]){
  const rows=r[key]||[];
  html+='<details><summary>'+title+'（'+rows.length+'）</summary>';
  for(const row of rows)html+='<section class="source-event">'+(row.object_id?ref(row.object_id):'')+'<p>'+esc(row.question||row.code||'')+'</p><p>'+esc(row.scope||'')+'</p><p>'+esc(row.limitations||row.action||'')+'</p></section>';
  html+='</details>';
 }
 return html;
}
export function reportHTML(text, labels={}, templateVersion=1){
 const lines=text.split('\n');let html='',table=false,code=false,appendix=false;
 for(const line of lines){
  if(line.startsWith('```')){if(code){html+='</pre>';code=false;}else{html+='<pre>';code=true;}continue;}
  if(code){html+=esc(line)+'\n';continue;}
  if(/^<a id="evidence-[a-z0-9_]+"><\/a>$/.test(line))continue;
  if(line.startsWith('|')){
   if(/^\|[\s:|\-]+\|$/.test(line))continue;
   if(!table){html+='<div class="report-table-wrap"><table>';table=true;}
   html+='<tr>'+line.split('|').slice(1,-1).map(c=>'<td>'+inline(c.trim(),labels)+'</td>').join('')+'</tr>';continue;
  }
  if(table){html+='</table></div>';table=false;}
  if(line.startsWith('## 附录')){html+='<details class="report-appendix"><summary>展开证据与调查记录附录</summary>';appendix=true;continue;}
  if(/^## [1-5]\. /.test(line)){const n=line[3];html+='<h2 data-report-heading="'+n+'">'+inline(line.slice(3),labels)+'</h2>';continue;}
  if(/^#{1,4} /.test(line)){const depth=line.match(/^#+/)[0].length;html+='<h'+depth+'>'+inline(line.replace(/^#{1,4} /,''),labels)+'</h'+depth+'>';continue;}
  html+=line?'<p>'+inline(line,labels)+'</p>':'';
 }
 if(table)html+='</table></div>';if(code)html+='</pre>';if(appendix)html+='</details>';
 return '<div class="report-chapters">'+(templateVersion>=2?['事件概述','攻击链路','后渗透与影响','时间线与来源','局限与建议']:['背景与范围','结论与影响','时间线与路径','来源与行为','缺口与建议']).map((t,i)=>'<button class="small" data-report-section="'+(i+1)+'">'+(i+1)+'. '+t+'</button>').join('')+'</div>'+html;
}
