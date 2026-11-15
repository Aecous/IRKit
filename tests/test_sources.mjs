import test from 'node:test';
import assert from 'node:assert/strict';
import {sourceCardHTML,sourceDetailHTML,reportHTML} from '../src/irkit/web_assets/sources.js';
test('source view preserves scopes results gaps and historical evidence safely',()=>{
 const source={id:'source_view_1234567890abcdef',address:'192.0.2.1',field:'client',match_mode:'exact',attribution:'unverified',
 cards:[{id:'card_1234567890abcdef',title:'Changed setting',revision:3,current:true,environment:'lab',asset:'host',status:'candidate',time_range:'2026-01-01 UTC'}],
 checks:[{id:'check_1234567890abcdef',card_id:'card_1234567890abcdef',scope:'lab full day',question:'Other actions?',outcome:'inconclusive',conclusion:'Change then retry',limitations:'<script>bad</script>',current:false,historical:true,query_ids:['run_1234567890abcdef']}],gaps:['No permission baseline']};
 const html=sourceCardHTML(source)+sourceDetailHTML(source);
 assert.ok(html.includes('从事件卡聚合'));assert.ok(html.includes('lab full day'));assert.ok(html.includes('Change then retry'));
 assert.ok(html.includes('历史来源复查记录'));assert.ok(html.includes('No permission baseline'));
 assert.ok(html.includes('data-object="card_1234567890abcdef"'));assert.ok(html.includes('data-object="run_1234567890abcdef"'));
 assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
 assert.ok(!html.includes('待派发'));assert.ok(!html.includes('已复核'));
});
test('report shows chapter navigation, tables, real evidence buttons and folded appendix without raw HTML',()=>{
 const html=reportHTML('## 1. 事件背景与调查范围\n<script>alert(1)</script>\n## 3. 攻击时间线与攻击路径\n| 时间 | 证据 |\n|---|---|\n| UTC | [E-001](#evidence-card_1234567890abcdef) |\n## 附录：证据与调查记录\n<a id="evidence-card_1234567890abcdef"></a>\nBody');
 assert.ok(html.includes('data-report-section="5"'));assert.ok(html.includes('<table>'));
 assert.ok(html.includes('data-object="card_1234567890abcdef"'));assert.ok(html.includes('<details class="report-appendix">'));
 assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<a id='));
});
