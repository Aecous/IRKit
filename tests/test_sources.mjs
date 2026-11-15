import test from 'node:test';
import assert from 'node:assert/strict';
import {sourceCardHTML,sourceDetailHTML,reportHTML} from '../src/irkit/web_assets/sources.js';
test('source board separates judgment, pending delta and historical association safely',()=>{
 const source={id:'source_lead_1234567890abcdef',address:'192.0.2.1',field:'client',reason:'<script>bad</script>',judgment:'attack_evidenced',attribution:'unverified',
 cards:{a:{id:'card_1234567890abcdef',title:'Changed setting',revision:3,linked:true,environment:'lab',asset:'host',status:'candidate',time_range:'2026-01-01 UTC'},b:{id:'card_0000000000000000',title:'Withdrawn',linked:false}},investigation:{state:'needs_incremental',complete:false,missing_card_ids:['card_1234567890abcdef'],task_ids:[]},tasks:[]};
 const html=sourceCardHTML(source)+sourceDetailHTML(source);
 assert.ok(html.includes('有增量待补查'));assert.ok(html.includes('存在攻击行为证据'));assert.ok(html.includes('历史判断不能代替'));
 assert.ok(html.includes('已撤销关联'));assert.ok(html.includes('data-object="card_1234567890abcdef"'));
 assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
});
test('report shows chapter navigation, tables, real evidence buttons and folded appendix without raw HTML',()=>{
 const html=reportHTML('## 1. 事件背景与调查范围\n<script>alert(1)</script>\n## 3. 攻击时间线与攻击路径\n| 时间 | 证据 |\n|---|---|\n| UTC | [E-001](#evidence-card_1234567890abcdef) |\n## 附录：证据与调查记录\n<a id="evidence-card_1234567890abcdef"></a>\nBody');
 assert.ok(html.includes('data-report-section="5"'));assert.ok(html.includes('<table>'));
 assert.ok(html.includes('data-object="card_1234567890abcdef"'));assert.ok(html.includes('<details class="report-appendix">'));
 assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<a id='));
});
