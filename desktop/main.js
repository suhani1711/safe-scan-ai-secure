const {app,BrowserWindow,Menu,Tray,screen,ipcMain,desktopCapturer,nativeImage,clipboard,globalShortcut,session,shell}=require("electron");
const path=require("path"),fs=require("fs"),{exec}=require("child_process");
const jsQR=require("./jsQR.js");
app.commandLine.appendSwitch("disable-features","CalculateNativeWinOcclusion"); // stops Windows from treating the shield as hidden when other windows open
if(!app.requestSingleInstanceLock()){app.quit()}
let shield,tray,scanner,snipWin,snipShot=null,drag=null;
// ---- tiny JSON store (local only) ----
const file=()=>path.join(app.getPath("userData"),"safescan.json");
const rd=()=>{try{return JSON.parse(fs.readFileSync(file(),"utf8"))}catch(e){return{}}};
const wr=o=>{try{fs.writeFileSync(file(),JSON.stringify(o))}catch(e){}};
const pick=(o,k)=>{const ks=Array.isArray(k)?k:[k],r={};ks.forEach(x=>{if(o[x]!==undefined)r[x]=o[x]});return r};
ipcMain.handle("store:get",(e,k)=>pick(rd(),k));
ipcMain.handle("store:set",(e,o)=>{wr(Object.assign(rd(),o))});
ipcMain.handle("store:remove",(e,k)=>{const o=rd();(Array.isArray(k)?k:[k]).forEach(x=>delete o[x]);wr(o)});
const set=o=>wr(Object.assign(rd(),o));
// ---- floating shield (always on top, over every app) ----
function clampPos(x,y){const d=screen.getDisplayNearestPoint({x,y}).workArea;return[Math.max(d.x,Math.min(x,d.x+d.width-80)),Math.max(d.y,Math.min(y,d.y+d.height-80))]}
function makeShield(){const d=screen.getPrimaryDisplay().workArea,p=rd().pos||{x:d.x+d.width-90,y:d.y+d.height-90},[x,y]=clampPos(p.x,p.y);
shield=new BrowserWindow({x,y,width:80,height:80,frame:false,transparent:true,backgroundColor:"#00000000",thickFrame:false,resizable:false,movable:false,skipTaskbar:true,hasShadow:false,alwaysOnTop:true,focusable:false,fullscreenable:false,show:false,webPreferences:{backgroundThrottling:false,preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false,sandbox:true}});
shield.setAlwaysOnTop(true,"screen-saver");shield.setVisibleOnAllWorkspaces(true,{visibleOnFullScreen:true});shield.loadFile("shield.html");
shield.on("closed",()=>{shield=null;if(!quitting)makeShield()});shield.webContents.on("render-process-gone",()=>{try{shield.reload()}catch(e){}});
shield.once("ready-to-show",()=>{if(!rd().hidden)shield.showInactive()})}
ipcMain.on("drag:start",()=>{drag=shield.getPosition();menuHide()});
ipcMain.on("drag:move",(e,dx,dy)=>{if(!drag||!shield)return;const[x,y]=clampPos(drag[0]+Math.round(dx),drag[1]+Math.round(dy));shield.setPosition(x,y)});
ipcMain.on("drag:end",()=>{if(shield){const[x,y]=shield.getPosition();set({pos:{x,y}})}drag=null});
function setShield(v){set({hidden:!v});if(!shield)return;v?shield.showInactive():shield.hide();buildTray()}
function resetPos(){const d=screen.getPrimaryDisplay().workArea;shield.setPosition(d.x+d.width-90,d.y+d.height-90);set({pos:null})}
// ---- scanner window (Links / SMS / Mail / QR / Dashboard / Help) ----
function openScanner(tab,extra){setTimeout(keepShield,300);setTimeout(keepShield,1200);set({prefill:Object.assign({tab},extra||{})});
if(scanner&&!scanner.isDestroyed()){scanner.loadFile("scanner.html",{query:{tab}});scanner.show();scanner.focus();return}
scanner=new BrowserWindow({width:480,height:760,title:"SafeScan AI",backgroundColor:"#0b1020",autoHideMenuBar:true,icon:path.join(__dirname,"icon.png"),webPreferences:{preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false,sandbox:true}});
scanner.setMenu(null);scanner.loadFile("scanner.html",{query:{tab}});
scanner.webContents.setWindowOpenHandler(({url})=>{if(/^https:\/\/scansafeai\.vercel\.app\//.test(url))shell.openExternal(url);return{action:"deny"}});
scanner.on("closed",()=>{scanner=null})}
// ---- scan selected text (in any app): copies your selection, scans it, then restores your clipboard ----
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const log=m=>{try{fs.appendFileSync(path.join(app.getPath("userData"),"safescan-debug.log"),new Date().toISOString()+" "+m+"\n")}catch(e){}};
let K=null;
try{if(process.platform==="win32"){const koffi=require("koffi"),u=koffi.load("user32.dll");
K={ke:u.func("void __stdcall keybd_event(uint8_t bVk, uint8_t bScan, uint32_t dwFlags, uintptr_t dwExtraInfo)"),mv:u.func("uint32_t __stdcall MapVirtualKeyW(uint32_t uCode, uint32_t uMapType)"),gk:u.func("int16_t __stdcall GetAsyncKeyState(int vKey)")}}}catch(e){K=null;log("native keys unavailable: "+e)}
async function nativeCopy(){const key=(vk,up)=>K.ke(vk,K.mv(vk,0),up?2:0,0),MODS=[0x10,0x11,0x12,0x5B,0x5C];
for(let i=0;i<30&&MODS.some(v=>(K.gk(v)&0x8000)!==0);i++)await sleep(50); // wait until the shortcut keys are released
[0x10,0x12,0x5B,0x5C].forEach(v=>key(v,true));await sleep(30);
key(0x11);key(0x43);await sleep(50);key(0x43,true);key(0x11,true);return{err:null,so:"",se:""}}
const PS_COPY=`Add-Type -Name K -Namespace S -MemberDefinition '[DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte sc, uint fl, UIntPtr ex);'
$z=[UIntPtr]::Zero
[S.K]::keybd_event(0x10,0,2,$z)
Start-Sleep -Milliseconds 80
[S.K]::keybd_event(0x11,0,0,$z);Start-Sleep -Milliseconds 40
[S.K]::keybd_event(0x43,0,0,$z);Start-Sleep -Milliseconds 40
[S.K]::keybd_event(0x43,0,2,$z);[S.K]::keybd_event(0x11,0,2,$z)
`;
function runPs(name,script){return new Promise(res=>{const enc=Buffer.from(script,"utf16le").toString("base64");
exec("powershell -NoProfile -NonInteractive -EncodedCommand "+enc,{windowsHide:true,timeout:10000,encoding:"utf8"},(err,so,se)=>res({err,so:String(so||""),se:String(se||"")}))})}
const PS_UIA=`Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
try{$e=[System.Windows.Automation.AutomationElement]::FocusedElement;$p=$null
if($e.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern,[ref]$p)){($p.GetSelection()|ForEach-Object{$_.GetText(5000)}) -join [Environment]::NewLine}}catch{}`;
function sendCopy(){if(K)return nativeCopy().catch(e=>({err:e,so:"",se:""}));if(process.platform==="win32")return runPs("copy.ps1",PS_COPY);
return new Promise(res=>exec(process.platform==="darwin"?"osascript -e 'tell application \"System Events\" to keystroke \"c\" using command down'":"xdotool key ctrl+c",{timeout:10000},(err,so,se)=>res({err,so:String(so||""),se:String(se||"")})))}
const isUrlText=t=>/^(https?:\/\/)?[^\s\/]+\.[a-z]{2,}(\/\S*)?$/i.test(t)&&!/\s/.test(t);
// ---- result popup (shows near the shield, never steals focus) ----
let resultWin,resultState=null,resultReady=false;
function placeNear(win,w,h){const[sx,sy]=shield.getPosition(),wa=screen.getDisplayNearestPoint({x:sx,y:sy}).workArea;let y=sy-h+12;if(y<wa.y)y=sy+68;
let x=sx+80-w-6;x=Math.max(wa.x,Math.min(x,wa.x+wa.width-w));y=Math.max(wa.y,Math.min(y,wa.y+wa.height-h));win.setBounds({x,y,width:w,height:h})}
function showResult(st){resultState=st;
if(!resultWin||resultWin.isDestroyed()){resultReady=false;resultWin=new BrowserWindow({width:340,height:140,frame:false,transparent:true,backgroundColor:"#00000000",thickFrame:false,resizable:false,movable:false,skipTaskbar:true,hasShadow:false,alwaysOnTop:true,focusable:false,show:false,webPreferences:{preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false,sandbox:true}});
resultWin.setAlwaysOnTop(true,"screen-saver");resultWin.loadFile("result.html")}else if(resultReady)resultWin.webContents.send("result:update",st);
if(shield)placeNear(resultWin,340,resultWin.getBounds().height);resultWin.showInactive()}
ipcMain.on("result:ready",()=>{resultReady=true;if(resultWin&&resultState)resultWin.webContents.send("result:update",resultState)});
ipcMain.on("result:size",(e,h)=>{if(resultWin&&!resultWin.isDestroyed()&&shield)placeNear(resultWin,340,Math.min(640,Math.max(80,Math.round(h))))});
ipcMain.on("result:action",(e,a)=>{if(!resultWin||resultWin.isDestroyed())return;
if(a==="close"){resultWin.hide();return}
if(a==="full"&&resultState&&resultState.text){const t=resultState.text;resultWin.hide();openScanner(isUrlText(t)?"link":"sms",{text:t,auto:true})}
if(a==="paste"){resultWin.hide();openScanner("sms",{})}});
// ---- scan selected text: copy it, scan it, show the result, restore your clipboard ----
let busy=false;
async function scanSelected(){if(busy)return;busy=true;const diag=[];
try{showResult({state:"loading"});
const oldText=String(await clipboard.readText()||""),SENT="__safescan_probe_"+Date.now();
clipboard.writeText(SENT);await sleep(150);
const r1=await sendCopy();diag.push("Ctrl+C"+(K?" (native)":" (powershell)")+": "+(r1.err?"error "+String(r1.err.message).slice(0,120):"sent")+(r1.se.trim()?" ("+r1.se.trim().slice(0,100)+")":""));
let t="";for(let n=0;n<12&&!t;n++){await sleep(150);const c=String(await clipboard.readText()||"");if(c&&c!==SENT)t=c.trim()}
let how="copy";
if(!t&&process.platform==="win32"){const r2=await runPs("uia.ps1",PS_UIA);t=r2.so.trim();how="uia";diag.push("Accessibility read: "+(t?"ok":(r2.err?"error "+String(r2.err.message).slice(0,80):"nothing selected")))}
try{clipboard.writeText(oldText)}catch(e){}
let fromClip=false;if(!t&&oldText.trim()){t=oldText.trim();fromClip=true}
log("selection how="+how+" len="+t.length+" fromClipboard="+fromClip+" | "+diag.join(" | "));
if(!t)showResult({state:"fail",detail:diag.join("\n")});else showResult({state:"ok",text:t.slice(0,5000),fromClip});
}catch(e){log("scanSelected error "+e);showResult({state:"fail",detail:String(e&&e.message||e)})}finally{busy=false}}
// ---- snip a QR anywhere on screen ----
async function snipScreen(){if(snipWin)return;const pt=screen.getCursorScreenPoint(),disp=screen.getDisplayNearestPoint(pt),sf=disp.scaleFactor;
const hadShield=shield&&shield.isVisible();if(hadShield)shield.hide();await new Promise(r=>setTimeout(r,250));
let src;try{const s=await desktopCapturer.getSources({types:["screen"],thumbnailSize:{width:Math.round(disp.bounds.width*sf),height:Math.round(disp.bounds.height*sf)}});src=s.find(x=>String(x.display_id)===String(disp.id))||s[0]}catch(e){}
if(hadShield)shield.showInactive();if(!src){openScanner("qr",{none:true});return}
snipShot={img:src.thumbnail,disp};
snipWin=new BrowserWindow({x:disp.bounds.x,y:disp.bounds.y,width:disp.bounds.width,height:disp.bounds.height,frame:false,resizable:false,movable:false,skipTaskbar:true,alwaysOnTop:true,fullscreenable:false,backgroundColor:"#000",webPreferences:{preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false,sandbox:true}});
snipWin.setAlwaysOnTop(true,"screen-saver");snipWin.loadFile("snip.html");snipWin.on("closed",()=>{snipWin=null;snipShot=null})}
ipcMain.handle("snip:image",()=>snipShot?snipShot.img.toDataURL():"");
function decodeCrop(img,r){const sz=img.getSize(),k=sz.width/r.vw,pad=Math.max(r.w,r.h)*.12;
const x=Math.max(0,Math.round((r.x-pad)*k)),y=Math.max(0,Math.round((r.y-pad)*k)),w=Math.min(sz.width-x,Math.round((r.w+2*pad)*k)),h=Math.min(sz.height-y,Math.round((r.h+2*pad)*k));
let c=img.crop({x,y,width:w,height:h});const up=Math.min(4,Math.max(1,400/Math.min(w,h)));if(up>1)c=c.resize({width:Math.round(w*up),height:Math.round(h*up),quality:"best"});
const s=c.getSize(),b=c.toBitmap(),d=new Uint8ClampedArray(b.length);for(let i=0;i<b.length;i+=4){d[i]=b[i+2];d[i+1]=b[i+1];d[i+2]=b[i];d[i+3]=255}
const q=jsQR(d,s.width,s.height);return q?q.data:null}
ipcMain.on("snip:done",(e,r)=>{const shot=snipShot;if(snipWin){snipWin.close()}if(!r||!shot)return;let t=null;try{t=decodeCrop(shot.img,r)}catch(x){}openScanner("qr",t?{qr:t}:{none:true})});
// ---- shield menu + tray ----
const items=()=>[{label:"🔗 Links",click:()=>openScanner("link")},{label:"💬 SMS",click:()=>openScanner("sms")},{label:"📧 Mail",click:()=>openScanner("email")},
{label:"🔳 QR",submenu:[{label:"📷 Camera / Upload",click:()=>openScanner("qr")},{label:"✂️ Snip QR on screen",accelerator:"CommandOrControl+Shift+Q",registerAccelerator:false,click:snipScreen}]},
{type:"separator"},{label:"📊 Dashboard",click:()=>openScanner("dash")},{label:"🚨 Help (already clicked?)",click:()=>openScanner("help")}];
let menuWin,menuTimer,menuAbove=true;const MW=236;
const menuHide=()=>{clearTimeout(menuTimer);if(menuWin&&!menuWin.isDestroyed()&&menuWin.isVisible())menuWin.hide()};
function menuPlace(h){const[sx,sy]=shield.getPosition(),wa=screen.getDisplayNearestPoint({x:sx,y:sy}).workArea;
let y=menuAbove?sy-h+12:sy+68,x=sx+80-MW-6;if(menuAbove&&y<wa.y){menuAbove=false;y=sy+68}
x=Math.max(wa.x,Math.min(x,wa.x+wa.width-MW));y=Math.max(wa.y,Math.min(y,wa.y+wa.height-h));menuWin.setBounds({x,y,width:MW,height:h})}
function shieldMenu(){if(menuWin&&!menuWin.isDestroyed()&&menuWin.isVisible()){menuHide();return}
if(!menuWin||menuWin.isDestroyed()){menuWin=new BrowserWindow({width:MW,height:420,frame:false,transparent:true,backgroundColor:"#00000000",thickFrame:false,resizable:false,movable:false,skipTaskbar:true,hasShadow:false,alwaysOnTop:true,focusable:false,show:false,webPreferences:{preload:path.join(__dirname,"preload.js"),contextIsolation:true,nodeIntegration:false,sandbox:true}});
menuWin.setAlwaysOnTop(true,"screen-saver");menuWin.loadFile("menu.html")}
menuAbove=true;menuPlace(menuWin.getBounds().height);menuWin.showInactive();clearTimeout(menuTimer);menuTimer=setTimeout(menuHide,3500)}
ipcMain.on("menu:size",(e,h)=>{if(menuWin&&!menuWin.isDestroyed()&&shield){menuPlace(Math.min(560,Math.max(60,Math.round(h))))}});
ipcMain.on("menu:enter",()=>clearTimeout(menuTimer));ipcMain.on("menu:leave",()=>{clearTimeout(menuTimer);menuTimer=setTimeout(menuHide,600)});
ipcMain.on("menu:action",(e,id)=>{menuHide();const A={link:()=>openScanner("link"),sms:()=>openScanner("sms"),email:()=>openScanner("email"),qrcam:()=>openScanner("qr"),snip:snipScreen,sel:()=>setTimeout(scanSelected,150),dash:()=>openScanner("dash"),help:()=>openScanner("help"),reset:resetPos,hide:()=>setShield(false),quit:()=>app.quit()};A[id]&&A[id]()});
ipcMain.on("shield:menu",shieldMenu);
function buildTray(){const m=Menu.buildFromTemplate([{label:"Show floating shield",type:"checkbox",checked:!rd().hidden,click:i=>setShield(i.checked)},{type:"separator"},...items(),{type:"separator"},
{label:"Start with computer",type:"checkbox",checked:app.getLoginItemSettings().openAtLogin,click:i=>app.setLoginItemSettings({openAtLogin:i.checked,args:process.defaultApp?[app.getAppPath()]:[]})},{label:"Reset shield position",click:resetPos},{label:"Quit SafeScan",click:()=>app.quit()}]);tray.setContextMenu(m)}
// ---- keep the shield on screen no matter what else opens ----
let quitting=false;app.on("before-quit",()=>{quitting=true});
function keepShield(){if(quitting||!shield||shield.isDestroyed()||rd().hidden)return;
if(!shield.isVisible())shield.showInactive();shield.setAlwaysOnTop(true,"screen-saver");shield.moveTop()}
function reclamp(){if(!shield||shield.isDestroyed())return;const[x,y]=shield.getPosition(),[cx,cy]=clampPos(x,y);if(cx!==x||cy!==y)shield.setPosition(cx,cy)}
app.on("second-instance",()=>{if(shield&&!rd().hidden)shield.showInactive();else setShield(true)});
app.on("window-all-closed",e=>e.preventDefault&&e.preventDefault());
app.whenReady().then(()=>{
session.defaultSession.setPermissionRequestHandler((wc,p,cb)=>cb(p==="media"&&/scanner\.html/.test(wc.getURL())));
session.defaultSession.setPermissionCheckHandler((wc,p)=>p==="media"&&!!wc&&/scanner\.html/.test(wc.getURL()||""));
tray=new Tray(nativeImage.createFromPath(path.join(__dirname,"icon.png")).resize({width:20,height:20}));tray.setToolTip("SafeScan AI");tray.on("click",()=>setShield(true));buildTray();makeShield();setInterval(keepShield,1500);["display-added","display-removed","display-metrics-changed"].forEach(ev=>screen.on(ev,()=>{reclamp();keepShield()}));
globalShortcut.register("CommandOrControl+Shift+Q",snipScreen);globalShortcut.register("CommandOrControl+Shift+S",scanSelected)});
app.on("will-quit",()=>globalShortcut.unregisterAll());
