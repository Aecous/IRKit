// Project the transcript into a readable timeline. Never infer unreturned reasoning.
export const roleNames = {"ir-prepare":"数据准备", "ir-investigate":"取证分析", "ir-synthesize":"综合复核"};
export const readable = value => typeof value === "string" ? value : Array.isArray(value)
  ? value.map(b=>b.text ?? JSON.stringify(b,null,2)).join("\n") : JSON.stringify(value ?? {},null,2);
export function toolSummary(name, input={}) {
  const n=name.replace("mcp__ir__", "");
  const titles={register_source_lead:"登记来源线索",source_queue:"检查来源复查队列",plan_source_review:"安排来源行为复查",source_behavior_overview:"查询来源行为概览",complete_source_review:"提交来源复查结果",review_source_task:"独立复核来源行为",query:"查询日志",read_query_result:"读取查询结果",read_dataset_row:"回查数据行",read_source:"回查原始日志",get_object:"查看案件记录",list_objects:"检查已有产物",case_context:"读取案件背景",board_context:"查看证据索引",create_task:"安排调查任务",update_task:"更新任务进度",submit_card:"提交证据卡片",submit_check:"记录排查结论",propose_followup:"提出补证问题",review_followup:"复核补证结果",submit_link:"关联证据节点",render_report:"生成综合报告",start_jsonl_ingest:"启动日志入库",ingest_status:"检查入库进度",start_decode:"登记正文解析任务",decode_batch:"处理一批正文",read_decoded:"读取解析索引",inspect_request_bodies:"回查请求正文",Agent:"委派子 Agent",Task:"委派子 Agent",TaskOutput:"等待子 Agent 返回",SendMessage:"协调子 Agent"};
  const description = input.description || input.question || input.statement || input.summary || input.sql || input.assessment || input.source_id || input.task_id || input.id || "";
  return {title:titles[n]||n, description:String(description).replace(/\s+/g," ").slice(0,180)};
}
export function conversation(events, context=[]) {
  const visible=new Set(events.map(e=>e.seq));
  const all=[...new Map([...context,...events].map(e=>[e.seq,e])).values()].sort((a,b)=>a.seq-b.seq);
  const aliases=new Map(), native=new Map();
  for(const e of all){const p=e.payload||{};if(p.subtype==='task_started'&&p.tool_use_id){const id=native.get(p.task_id)||p.tool_use_id;native.set(p.task_id,id);aliases.set(p.tool_use_id,id);}}
  const canonical=id=>aliases.get(id)||id;
  const agents=new Map([["main",{id:"main",name:"主 Agent",taskIds:new Set(),last:"等待记录",ended:false}]]);
  const calls=new Map(), entries=[], sorted=all;
  for(const e of sorted) {
    const blocks=e.payload?.message?.content;
    for(const b of Array.isArray(blocks)?blocks:[]) if(b.type==="tool_use"&&["Agent","Task"].includes(b.name)) {
      const input=b.input||{};
      const id=canonical(b.id);
      agents.set(id,{id,parentId:canonical(e.agent_id||e.payload?.parent_tool_use_id||"main"),name:roleNames[input.subagent_type]||input.subagent_type||"取证 Agent",description:input.description||"",taskIds:new Set(((input.prompt||"").match(/task_[0-9a-f]{16}/)||[]).slice(0,1)),last:"已派发",ended:false,background:!!input.run_in_background,at:e.at});
    }
    const p=e.payload||{};
    if(p.subtype==='task_started'&&p.tool_use_id){const id=canonical(p.tool_use_id);if(!agents.has(id))agents.set(id,{id,parentId:'main',name:roleNames[p.subagent_type]||p.subagent_type||'取证 Agent',description:p.description||'',taskIds:new Set(),ended:false,last:'已派发',at:e.at});}
  }
  let ending=null;
  for(const e of sorted) {
    const p=e.payload||{}, aid=canonical(e.agent_id||p.parent_tool_use_id||"main");
    if(!agents.has(aid)) agents.set(aid,{id:aid,name:"子 Agent · "+aid.slice(-6),taskIds:new Set(),last:"等待记录",ended:false});
    const a=agents.get(aid); if(e.task_id?.startsWith("task_"))a.taskIds.add(e.task_id);a.at=e.at;
    let index=0;
    const add=(kind,text,extra={})=>{const row={key:e.seq+":"+index++,seq:e.seq,at:e.at,agent:aid,kind,text,...extra};if(visible.has(e.seq))entries.push(row);return row;};
    if(['task_started','task_progress'].includes(p.subtype)){
      const child=agents.get(canonical(p.tool_use_id));
      if(child){child.ended=false;child.failed=false;child.status=null;child.at=e.at;child.last=p.last_tool_name?toolSummary(p.last_tool_name).title:'正在执行委派任务';}
    }
    if(e.event_type==="session_start")add("instruction",p.instruction||"按案件目标开始调查");
    if(e.event_type==="session_end") {ending=p;add("status",p.outcome?.error|| (p.exit_code===0?"模型进程已结束；以报告交付状态为准":"会话异常结束 · 退出码 "+p.exit_code));}
    if(e.event_type==="result") {a.ended=true;a.failed=!!p.is_error;if(p.is_error)add("error",p.result||(p.errors||[]).join("\n")||p.subtype);}
    if(p.subtype==="task_notification") {
      const child=agents.get(canonical(p.tool_use_id));
      if(child){child.ended=true;child.failed=["stopped","failed"].includes(p.status);child.status=p.status==="stopped"?"interrupted":child.failed?"failed":"ended";child.last=p.status==="stopped"?"运行被停止":child.failed?"执行失败":"已返回主 Agent";child.at=e.at;}
      add(["stopped","failed"].includes(p.status)?"error":"status",(child?.name||"子 Agent")+" · "+(child?.last||p.status)+(p.summary?" · "+p.summary:""));
    }
    const blocks=p.message?.content;
    if(typeof blocks==="string")add(e.event_type==="user"?"instruction":"text",blocks);
    for(const b of Array.isArray(blocks)?blocks:[]) {
      if(b.type==="text"){add(e.event_type==="user"?"instruction":"text",b.text);a.last=e.event_type==="user"?"收到任务":"输出分析";}
      if(b.type==="thinking"){add("thinking",b.thinking);a.last="输出思考";}
      if(b.type==="tool_use"){
        const row=add("tool",b.name,{callId:b.id,input:b.input||{},results:[],...toolSummary(b.name,b.input)});calls.set(b.id,row);a.last=row.title;
        if(b.input?.task_id)a.taskIds.add(b.input.task_id);
      }
      if(b.type==="tool_result"){
        const call=calls.get(b.tool_use_id), asyncLaunch=/Async agent launched|working in the background/.test(readable(b.content));
        if(call){call.results.push({content:b.content,error:!!b.is_error,at:e.at});call.error ||= !!b.is_error;call.background=asyncLaunch;}
        else add("result","早前工具的返回",{callId:b.tool_use_id,results:[{content:b.content,error:!!b.is_error,at:e.at}]});
        const child=agents.get(canonical(b.tool_use_id));
        if(child&&call?.text!=='SendMessage'){child.ended=!asyncLaunch;child.failed=!!b.is_error;child.background=asyncLaunch;child.last=asyncLaunch?"后台取证中":b.is_error?"执行失败":"已返回主 Agent";}
        a.last=b.is_error?"工具返回错误":"收到工具结果";
      }
    }
  }
  for(const a of agents.values()) {
    if(!a.status) a.status=a.failed?"failed":a.ended?"ended":ending?"interrupted":a.at?"observed":"idle";
    if(ending&&!a.ended){a.ended=true;a.last="会话结束前未确认交付";}
    if(a.status==="interrupted"&&a.failed)a.last="原生子 Agent 已被停止";
  }
  return {agents:[...agents.values()],entries,ending};
}
