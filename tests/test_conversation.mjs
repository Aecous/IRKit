import test from "node:test";
import assert from "node:assert/strict";
import {conversation} from "../src/irkit/web_assets/conversation.js";
const event=(seq,agent,content)=>({seq,at:"2026-11-14T12:00:00Z",agent_id:agent,event_type:"assistant",payload:{message:{content}}});
test("native dispatch links child, preserves thinking and pairs tool errors",()=>{
 const data=[
 event(1,"main",[{type:"tool_use",id:"child",name:"Agent",input:{subagent_type:"ir-investigate",prompt:"task_1234567890abcdef; background task_0000000000000000"}}]),
 event(2,"child",[{type:"thinking",thinking:"A returned reasoning block"},{type:"tool_use",id:"query",name:"mcp__ir__query",input:{sql:"SELECT 1"}}]),
 {...event(3,"child",[{type:"tool_result",tool_use_id:"query",is_error:true,content:"query failed"}]),event_type:"user"},
 event(4,"main",[{type:"tool_result",tool_use_id:"child",content:"done"}]),
 {seq:5,event_type:"session_end",payload:{exit_code:0}},
 ];
 const v=conversation(data);
 assert.equal(v.agents.length,2);
 assert.ok(v.agents[1].taskIds.has("task_1234567890abcdef"));
 assert.equal(v.agents[1].taskIds.size,1);
 assert.equal(v.agents[1].ended,true);
 assert.equal(v.entries.find(e=>e.kind==="thinking").text,"A returned reasoning block");
 assert.equal(v.entries.find(e=>e.callId==="query").results[0].content,"query failed");
 assert.equal(v.entries.find(e=>e.callId==="query").error,true);
});
test("heartbeats do not create fabricated thinking; orphan results remain visible",()=>{
 const v=conversation([{seq:1,event_type:"system",payload:{subtype:"thinking_tokens",tokens:300}},
 event(2,"main",[{type:"tool_result",tool_use_id:"earlier-call",content:"saved result"}]),
 event(3,"main",[{type:"text",text:"x".repeat(1200)}])]);
 assert.equal(v.entries.length,2);
 assert.equal(v.entries[0].kind,"result");
 assert.equal(v.entries[1].text.length,1200);
 assert.equal(v.agents[0].status,"observed");
});

test('background launch acknowledgement is not completion, stopped notification wins',()=>{
 const start=event(1,'main',[{type:'tool_use',id:'child',name:'Agent',input:{subagent_type:'ir-investigate',run_in_background:true}}]);
 const ack=event(2,'main',[{type:'tool_result',tool_use_id:'child',content:[{type:'text',text:'Async agent launched successfully. working in the background'}]}]);
 const live=conversation([start,ack]);
 assert.equal(live.agents[1].ended,false);
 const stopped=conversation([start,ack,{seq:3,event_type:'system',payload:{subtype:'task_notification',tool_use_id:'child',status:'stopped'}},{seq:4,event_type:'session_end',payload:{exit_code:0}}]);
 assert.equal(stopped.agents[1].status,'interrupted');
 assert.ok(stopped.entries.some(e=>e.kind==='error'));
});

test('navigation context preserves agent identity on late history pages',()=>{
 const context=[event(1,'main',[{type:'tool_use',id:'child',name:'Agent',input:{subagent_type:'ir-investigate',description:'UAT',prompt:'task_1234567890abcdef'}}])];
 const v=conversation([event(500,'child',[{type:'text',text:'Finding'}])],context);
 assert.equal(v.agents[1].description,'UAT');
 assert.equal(v.entries.length,1);
});

import {prose, messageHTML} from '../src/irkit/web_assets/timeline.js';
test('message formatting escapes untrusted log HTML and exposes tool details only on demand',()=>{
 assert.ok(!prose('<img src=x onerror=alert(1)>').includes('<img'));
 assert.ok(prose('**observed**').includes('<strong>observed</strong>'));
 const html=messageHTML({key:'1',kind:'tool',text:'mcp__ir__query',title:'查询日志',input:{sql:'SELECT 1'},results:[],agent:'main'},null,null);
 assert.ok(html.includes('查询日志'));
 assert.ok(html.includes('<details '));
 assert.ok(!html.includes('<details open'));
});

test('terminal lifecycle survives a paginated history window',()=>{
 const nav=[event(1,'main',[{type:'tool_use',id:'child',name:'Agent',input:{subagent_type:'ir-investigate'}}]),event(4,'main',[{type:'tool_result',tool_use_id:'child',content:'done'}])];
 const v=conversation([event(900,'main',[{type:'text',text:'Other work'}])],nav);
 assert.equal(v.agents.find(a=>a.id==='child').status,'ended');
 assert.equal(v.entries.length,1);
});
test('SendMessage resume shares the original worker identity and messages',()=>{
 const nav=[event(1,'main',[{type:'tool_use',id:'child',name:'Agent',input:{subagent_type:'ir-synthesize'}}]),{seq:2,event_type:'system',payload:{subtype:'task_started',task_id:'native',tool_use_id:'child',subagent_type:'ir-synthesize'}},event(3,'main',[{type:'tool_result',tool_use_id:'child',content:'done'}]),event(4,'main',[{type:'tool_use',id:'resume',name:'SendMessage',input:{to:'native'}}]),{seq:5,event_type:'system',payload:{subtype:'task_started',task_id:'native',tool_use_id:'resume',subagent_type:'ir-synthesize'}}];
 const v=conversation([event(10,'child',[{type:'text',text:'Actual ongoing analysis'}]),{seq:11,agent_id:'resume',event_type:'tool_progress',payload:{heartbeat:true}}],nav);
 assert.equal(v.agents.length,2);
 assert.equal(v.agents[1].name,'综合复核');
 assert.equal(v.agents[1].ended,false);
 assert.ok(v.entries.some(e=>e.agent==='child'&&e.text==='Actual ongoing analysis'));
 const done=conversation([{seq:12,event_type:'system',payload:{subtype:'task_notification',tool_use_id:'resume',status:'completed'}}],nav);
 assert.equal(done.agents[1].status,'ended');
});
