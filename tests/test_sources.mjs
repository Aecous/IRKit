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

test('report delivery, review debt and evidence limits remain distinct',async()=>{
 const {reportStatus,deliveryDetailsHTML}=await import('../src/irkit/web_assets/sources.js');
 const report={status:'generated',delivery:'final',review_mode:'off',readiness:{blockers:[],investigation_pending:[],
 review_pending:[{code:'PARENT_CHANGED',object_id:'card_one',action:'Recheck revision'}],
 evidence_gaps:[{object_id:'check_one',question:'Transfer?',scope:'host-a UTC',limitations:'Missing <network> logs'}]}};
 assert.match(reportStatus(report),/最终报告已生成/);
 assert.match(reportStatus({...report,status:'stale'}),/已过期/);
 assert.match(reportStatus({...report,delivery:'progress'}),/调查未完成/);
 const html=deliveryDetailsHTML(report);
 assert.match(html,/未经独立综合复核/);
 assert.match(html,/交付阻塞 0 项/);
 assert.match(html,/修订\/补证待复核 1 项/);
 assert.match(html,/已记录证据局限 1 项/);
 assert.match(html,/host-a UTC/);
 assert.match(html,/&lt;network&gt;/);
 assert.doesNotMatch(html,/<network>/);
 assert.match(deliveryDetailsHTML({readiness:{issues:[]}}),/历史检查尚未分类/);
});

test('narrative report shows new chapters and maps external appendix citations to evidence',()=>{
 const html=reportHTML('## 1. 事件概述\nObserved [E-001](report_1234567890abcdef.evidence.md#e-001)\n### 2.1 Host chain\nC:\\\\Temp\\\\sample.bin\n[证据明细附录](report_1234567890abcdef.evidence.md)',{'card_1234567890abcdef':'E-001'},2);
 assert.match(html,/攻击链路/);assert.match(html,/后渗透与影响/);
 assert.match(html,/data-object="card_1234567890abcdef"/);
 assert.match(html,/<h3>2.1 Host chain<\/h3>/);
 assert.match(html,/C:\\Temp\\sample.bin/);
 assert.doesNotMatch(html,/report_1234567890abcdef.evidence.md/);
});

test('result-only reports do not imply investigation closure', async()=>{
 const {reportStatus,deliveryDetailsHTML}=await import('../src/irkit/web_assets/sources.js');
 const report={status:'generated',delivery:'progress',task_mode:'report',review_mode:'full'};
 assert.match(reportStatus(report),/现有结果报告/);
 assert.match(reportStatus(report),/不代表调查闭环/);
 assert.match(deliveryDetailsHTML(report),/本次仅整理已有结果/);
});
