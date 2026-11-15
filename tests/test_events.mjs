import test from 'node:test';
import assert from 'node:assert/strict';
import {eventCardHTML,eventDetailHTML} from '../src/irkit/web_assets/events.js';

test('event view separates facts, hypotheses and linked investigation state safely',()=>{
 const q={question:'Which account <script>x</script>?',priority:'critical',status:'open',check_ids:[]};
 const card={id:'card_x',status:'candidate',time_range:'UTC',evidence:[],event:{title:'Unexpected service change',environment:'lab',asset:'host-a',observed:'Observed <img src=x onerror=alert(1)>',possible_causes:['Credential misuse?'],observed_effects:[],potential_impacts:['May affect restart'],upstream:q,downstream:q},investigation:{upstream:{...q,state:'assigned',blocking:true,task_ids:['task_x']},downstream:{...q,state:'bounded',blocking:false}}};
 const html=eventDetailHTML(card);
 assert.match(html,/可能前因/);assert.match(html,/不代表已发生/);assert.match(html,/尚无结果证据/);
 assert.match(html,/取证中/);assert.match(html,/data-object="task_x"/);assert.ok(!html.includes('<script>'));
 assert.match(eventCardHTML(card),/Unexpected service change/);assert.ok(!html.includes('<img src='));
});
test('legacy cards remain explicit rather than receiving fabricated structure',()=>{
 const html=eventDetailHTML({statement:'Old text <b>untrusted</b>'});
 assert.match(html,/历史文本卡/);assert.match(html,/&lt;b&gt;/);assert.ok(!html.includes('可能前因'));
});

test('review state preserves visible events and exposes migration and evidence history safely',async()=>{
 const {integrityHTML,historyHTML,reviewBadge}=await import('../src/irkit/web_assets/events.js');
 const card={id:'card_x',status:'candidate',review_state:'needs_review',review_causes:{card_parent:3},disposition:{decision:'merge',reason:'Moved <script>alert(1)</script>',target_ids:['card_target']},event:{claims:[{key:'failure',statement:'Attempt denied',level:'response',scope:{environment:'lab',dimensions:{host:['node-a']}},evidence:[{source_id:'src_x',start:1,end:1}]}]}};
 const html=integrityHTML(card);
 assert.match(reviewBadge(card),/事实保留/);assert.match(html,/data-object="card_parent"/);assert.match(html,/data-object="card_target"/);assert.match(html,/data-source="src_x"/);assert.ok(!html.includes('<script>'));
 const history=historyHTML({items:[{revision:3,at:'UTC',reason:'Explicit withdrawal',evidence_added:[],evidence_removed:[{source_id:'src_x',start:2}],action:'update'}],next_offset:10},'card_x');
 assert.match(history,/历史保留/);assert.match(history,/data-offset="10"/);
});

test('statistical claims show their actual value, population and query grouping',async()=>{
 const {integrityHTML}=await import('../src/irkit/web_assets/events.js');
 const html=integrityHTML({event:{claims:[{key:'total',statement:'Recorded responses',level:'response',scope:{environment:'lab'},evidence:[],statistic_snapshot:{value:3,unit:'requests',population:'Multiple paths on node-a',sql:'SELECT host,count(*) GROUP BY host',result_row:{host:'node-a',n:3},truncated:true}}]}});
 assert.match(html,/3 requests/);assert.match(html,/Multiple paths/);assert.match(html,/结果已截断/);assert.match(html,/GROUP BY host/);
});
