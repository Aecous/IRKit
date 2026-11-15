import {esc} from './timeline.js';

const states={open:'待追查',assigned:'取证中',awaiting_review:'待复核',needs_evidence:'仍需补证',reviewed:'已复核',bounded:'已查并说明边界',not_applicable:'不适用',stale:'需重新核查'};
export function eventTitle(card){return card.event?.title||'历史文本卡';}
function question(card,side){return card.investigation?.[side]||{...card.event[side],state:card.event[side].status};}
function pill(q){return '<span class="event-state '+(q.blocking?'event-open':'')+'">'+esc(states[q.state]||q.state)+'</span>';}
function values(items,empty){return items?.length?'<ul>'+items.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ul>':'<p class="unknown">'+empty+'</p>';}
export function eventCardHTML(card){
 if(!card.event)return '<button class="entry legacy-event" data-object="'+esc(card.id)+'"><span class="event-state">历史文本卡 · '+esc(card.status)+'</span>'+reviewBadge(card)+'<p>'+esc(card.statement)+'</p><code>'+esc(card.id)+'</code></button>';
 const e=card.event;
 return '<button class="entry event-card" data-object="'+esc(card.id)+'"><div class="meta"><span class="event-state">事件 · '+esc(card.status)+'</span><span>'+esc(e.environment)+' · '+esc(e.asset)+'</span></div><h2>'+esc(e.title)+'</h2>'+reviewBadge(card)+'<div class="event-time">'+esc(card.time_range)+'</div><p class="event-observed">'+esc(e.observed)+'</p><div class="event-directions"><span>前因 '+pill(question(card,'upstream'))+'</span><span>后果 '+pill(question(card,'downstream'))+'</span></div><div class="event-foot">'+(card.evidence||[]).length+' 处证据 · '+e.possible_causes.length+' 个前因假设 · '+e.potential_impacts.length+' 项潜在影响</div></button>';
}
export function eventDetailHTML(card){
 if(!card.event)return '<p class="unknown">历史文本卡，保留原始描述；未自动推断事件字段。</p><p>'+esc(card.statement)+'</p>';
 const e=card.event;
 let html='<div class="event-scope">'+esc(e.environment)+' / '+esc(e.asset)+'<br>'+esc(card.time_range)+'</div><section class="event-section observed"><h3>已观察行为</h3><p>'+esc(e.observed)+'</p></section><section class="event-section hypothesis"><h3>可能前因 <span>假设，待证实</span></h3>'+values(e.possible_causes,'尚未提出前因假设')+'</section><section class="event-section observed"><h3>已观察后果</h3>'+values(e.observed_effects,'尚无结果证据')+'</section><section class="event-section hypothesis"><h3>潜在影响 <span>不代表已发生</span></h3>'+values(e.potential_impacts,'影响范围待判断')+'</section>';
 for(const [side,label] of [['upstream','向前追查'],['downstream','向后追查']]){
  const q=question(card,side);html+='<section class="event-question"><h3>'+label+' '+pill(q)+'</h3><p>'+esc(q.question||'无适用问题')+'</p><div class="event-foot">'+(q.priority==='critical'?'关键问题':'线索备注')+'</div>'+(q.reason?'<p class="unknown">'+esc(q.reason)+'</p>':'')+(q.task_ids||[]).map(id=>'<button class="ref" data-object="'+esc(id)+'">查看补证任务 '+esc(id)+'</button>').join('')+(q.check_ids||[]).map(id=>'<button class="ref" data-object="'+esc(id)+'">查看检查依据 '+esc(id)+'</button>').join('')+'</section>';
 }
 return html;
}

export function reviewBadge(o){
 const waiting=o.review_state==='needs_review'||o.status==='stale';
 return waiting?'<span class="event-state event-open">前提变化 · 待复核，事实保留</span>':o.disposition?'<span class="event-state">'+esc({retain:'复核保留',merge:'已合并迁移',withdraw:'已撤销'}[o.disposition.decision]||o.disposition.decision)+'</span>':'';
}
function refHTML(r){
 if(r.source_id)return '<button class="ref" data-source="'+esc(r.source_id)+'" data-line="'+esc(r.start)+'">原始行 '+esc(r.source_id)+':'+esc(r.start)+'</button>';
 if(r.dataset_id)return '<button class="ref" data-object="'+esc(r.dataset_id)+'">数据行 '+esc(r.dataset_id)+':'+esc(r.row_id)+'</button>';
 return '<button class="ref" data-object="'+esc(r.query_id)+'">查询 '+esc(r.query_id)+'</button>';
}
export function integrityHTML(o){
 let html=reviewBadge(o);
 const causes=Object.entries(o.review_causes||{});
 if(causes.length)html+='<section class="event-question"><h3>为什么需要复核</h3><p>相关前提发生变更；下列事件和原始证据仍然保留，等待重新核验。</p>'+causes.map(([id,r])=>'<button class="ref" data-object="'+esc(id)+'">'+esc(id)+' · r'+esc(r)+'</button>').join('')+'</section>';
 if(o.disposition){const d=o.disposition;html+='<section class="event-section"><h3>复核处置</h3><p>'+esc(d.reason)+'</p>'+ (d.target_ids||[]).map(id=>'<button class="ref" data-object="'+esc(id)+'">事实迁移至 '+esc(id)+'</button>').join('')+'</section>';}
 const levels={request:'提交行为',response:'响应记录',application:'应用结果',inference:'推断'};
 for(const c of o.event?.claims||[]){
  html+='<section class="claim"><h3>'+esc(c.key)+' <span>'+esc(levels[c.level]||c.level)+'</span></h3><p>'+esc(c.statement)+'</p><div class="event-scope">环境：'+esc(c.scope.environment)+'<br>'+Object.entries(c.scope.dimensions||{}).map(([k,v])=>esc(k)+': '+esc(v.join(', '))).join(' · ')+'</div>'+(c.evidence||[]).map(refHTML).join('');
  const s=c.statistic_snapshot;
  if(s)html+='<div class="stat-contract"><strong>'+esc(s.value)+' '+esc(s.unit)+'</strong><p>统计对象：'+esc(s.population)+'</p><p>范围仅限此查询及分组'+(s.truncated?' · 结果已截断':'')+'</p><details><summary>查看分组与查询口径</summary><pre>'+esc(JSON.stringify(s.result_row,null,2))+'</pre><pre>'+esc(s.sql)+'</pre></details></div>';
  html+='</section>';
 }
 if(o.retired_claims?.length)html+='<section class="event-section"><h3>已撤销的结论</h3>'+o.retired_claims.map(c=>'<p>'+esc(c.key)+'：'+esc(c.claim.statement)+'<br>撤销原因：'+esc(c.reason)+'</p>').join('')+'</section>';
 return html;
}
export function historyHTML(page,objectId){
 let html=page.items.map(h=>'<div class="revision-entry"><strong>r'+esc(h.revision)+'</strong> <time>'+esc(h.at)+'</time><p>'+esc(h.reason||h.disposition?.reason||(h.review_state==='needs_review'?'关联前提变化，等待复核':h.action==='create'?'建立事件记录':'更新记录'))+'</p>'+(objectId.startsWith('source_lead_')?'':'<div class="event-foot">新增 '+h.evidence_added.length+' / 移除 '+h.evidence_removed.length+' 处证据</div>')+h.evidence_removed.map(r=>'<div>已移除引用（历史保留）'+refHTML(r)+'</div>').join('')+'</div>').join('');
 if(page.next_offset!==null)html+='<button class="small" data-history="'+esc(objectId)+'" data-offset="'+esc(page.next_offset)+'">加载更早修订</button>';
 return html;
}
