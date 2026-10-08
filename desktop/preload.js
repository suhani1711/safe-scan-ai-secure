const {contextBridge,ipcRenderer:ipc}=require("electron");
const g=(k,cb)=>ipc.invoke("store:get",k).then(cb);
contextBridge.exposeInMainWorld("deskStore",{get:g,set:(o,cb)=>ipc.invoke("store:set",o).then(()=>cb&&cb()),remove:(k,cb)=>ipc.invoke("store:remove",k).then(()=>cb&&cb())});
contextBridge.exposeInMainWorld("desk",{dragStart:()=>ipc.send("drag:start"),dragMove:(x,y)=>ipc.send("drag:move",x,y),dragEnd:()=>ipc.send("drag:end"),menu:()=>ipc.send("shield:menu"),onResult:cb=>ipc.on("result:update",(e,s)=>cb(s)),resultReady:()=>ipc.send("result:ready"),resultSize:h=>ipc.send("result:size",h),resultAction:a=>ipc.send("result:action",a),menuAction:i=>ipc.send("menu:action",i),menuSize:h=>ipc.send("menu:size",h),menuEnter:()=>ipc.send("menu:enter"),menuLeave:()=>ipc.send("menu:leave"),
snipImage:()=>ipc.invoke("snip:image"),snipDone:r=>ipc.send("snip:done",r)});
