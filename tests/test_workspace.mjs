import test from 'node:test';
import assert from 'node:assert/strict';
import {agentTree} from '../src/irkit/web_assets/workspace.js';
import {conversation} from '../src/irkit/web_assets/conversation.js';
test('delegation is nested, foldable and escaped',()=>{
 const events=[{seq:1,agent_id:'main',payload:{message:{content:[{type:'tool_use',name:'Agent',id:'child',input:{description:'<script>bad</script>'}}]}}},{seq:2,agent_id:'child',payload:{message:{content:[{type:'tool_use',name:'Agent',id:'grandchild',input:{}}]}}}];
 const view=conversation(events);
 assert.equal(view.agents[1].parentId,'main');assert.equal(view.agents[2].parentId,'child');
 const html=agentTree(view.agents,'child');
 assert.equal((html.match(/class="agent-children"/g)||[]).length,2);
 assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));
 const folded=agentTree(view.agents,'child',new Set(['main']));
 assert.ok(!folded.includes('data-agent="child"'));assert.ok(folded.includes('aria-expanded="false"'));
});
test('missing parents and cycles remain visible without inventing delegation',()=>{
 const html=agentTree([{id:'main',name:'Main'},{id:'a',parentId:'b',name:'A'},{id:'b',parentId:'a',name:'B'},{id:'orphan',parentId:'missing',name:'Orphan'}]);
 assert.equal((html.match(/data-agent=/g)||[]).length,4);
 assert.ok(!html.includes('agent-children'));
});
