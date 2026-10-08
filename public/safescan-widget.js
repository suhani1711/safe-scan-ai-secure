/*! SafeScan AI Web Widget v1.0 - drop-in scam/phishing scanner. No dependencies. */
(function () {
  if (window.__safescanLoaded) return;
  window.__safescanLoaded = true;

  const SafeScan=(()=>{
const RULES=[[/urgent|immediately|act now|final notice|expires? (today|soon)|within \d+ ?(hours|hrs)/i,"Urgent or time-pressure language",18,"Urgency & Pressure"],[/suspend|blocked|locked|terminated|legal action|arrest|penalty/i,"Threatening language",18,"Threats"],[/won|winner|prize|reward|lottery|gift ?card|cashback|free (gift|iphone)/i,"Fake reward or prize claim",20,"Fake Rewards"],[/\botp\b|one.?time password|verification code|\bpin\b|cvv/i,"Asks for OTP, PIN or code",25,"OTP & Credentials"],[/(password|login|sign.?in|verify your).{0,40}(here|below|link)|confirm your (identity|account)/i,"Credential request",22,"OTP & Credentials"],[/bank|kyc|card number|net ?banking|account (number|verification)|refund/i,"Banking or KYC request",18,"Banking & Payments"],[/upi|wire|bitcoin|crypto|processing fee|transfer/i,"Payment request",15,"Banking & Payments"],[/dear (customer|user|client)|kindly|revert back/i,"Generic or unusual wording",8,"Impersonation"],[/\b(paypal|amazon|apple|microsoft|netflix|hdfc|sbi|icici|fedex|dhl|irs|india post)\b/i,"Mentions a well-known brand (possible impersonation)",8,"Impersonation"]];
const URLRE=/https?:\/\/[^\s<>"')]+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl)\/\S+/gi;
const SHORT=/^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|ow\.ly)$/i,TLD=/\.(zip|top|xyz|click|work|country|gq|tk|ml|cf|ga|icu|rest)$/i,BR="paypal|amazon|apple|microsoft|google|netflix|sbi|hdfc|icici";
const HANDLES=/^(okaxis|oksbi|okhdfcbank|okicici|ybl|ibl|axl|paytm|apl|upi|sbi|hdfcbank|icici|axisbank|kotak|pnb|boi|cnrb|barodampay|fbl|yesbank|idfcbank|indus|federal|aubank|postbank|ikwik|freecharge|jupiteraxis|slc|waaxis|wahdfcbank|wasbi|waicici)$/i;
const status=s=>s<30?"SAFE":s<60?"SUSPICIOUS":"PHISHING DETECTED";
const REC={"SAFE":"No major red flags, but never share OTPs or passwords, and only log in on sites you reached yourself.","SUSPICIOUS":"Don't click links, reply, pay or enter details. Verify through an official channel first.","PHISHING DETECTED":"Do not click, reply, pay or share codes. Delete it and report it to your bank or the cybercrime helpline (India: 1930)."};
const acc=()=>({s:0,i:[],ps:{}}),add=(a,l,p,c)=>{a.s+=p;a.i.push(l);a.ps[c]=(a.ps[c]||0)+p};
function out(type,a,dest,extra){const s=Math.min(100,Math.round(a.s)),st=status(s);
const breakdown=Object.entries(a.ps).map(([k,v])=>({name:k,level:Math.min(100,Math.round(v*3))})).sort((x,y)=>y.level-x.level);
return Object.assign({type,score:s,trust:100-s,status:st,indicators:a.i.length?a.i:["No common phishing indicators found"],breakdown,recommendation:REC[st],destination:dest},extra||{})}
function urlCore(raw,a){let u;try{u=new URL(/^[a-z]+:\/\//i.test(raw)?raw:"https://"+raw)}catch(e){throw new Error("Unable to analyze this URL. Please try again.")}
const h=u.hostname,L="Link & Domain";
if(u.protocol!=="https:")add(a,"Not using HTTPS",20,L);if(/^\d+\.\d+\.\d+\.\d+$/.test(h))add(a,"Raw IP address instead of a domain",35,L);
if(SHORT.test(h))add(a,"Shortened URL hides the real destination",25,L);if(h.split(".").length>4)add(a,"Excessive subdomains",15,L);
if(/xn--/.test(h))add(a,"Punycode look-alike domain",25,"Impersonation");if(TLD.test(h))add(a,"Domain ending often abused for scams",15,L);
if(/login|verify|secure|update|account|wallet|bank|confirm/i.test(h))add(a,"Sensitive keywords in domain",18,L);
if((h.match(/-/g)||[]).length>=3)add(a,"Many hyphens in domain",12,L);if(/redirect=|url=|=https?:/i.test(u.search))add(a,"Redirect parameter in URL",12,"Hidden Redirects");
if(new RegExp(BR,"i").test(h)&&!new RegExp("(^|\\.)("+BR+")\\.(com|in|co\\.in|net|bank\\.in)$","i").test(h))add(a,"Brand name on an unofficial domain (look-alike)",25,"Impersonation");
if(u.href.length>120)add(a,"Unusually long URL",8,L);return u.href}
function textCore(t,a){RULES.forEach(r=>{if(r[0].test(t))add(a,r[1],r[2],r[3])});
(t.match(URLRE)||[]).forEach(x=>{try{const b=acc();const hr=urlCore(x,b);if(b.s>=15){a.s+=b.s/2;a.i.push("Suspicious link: "+new URL(hr).hostname);a.ps["Link & Domain"]=(a.ps["Link & Domain"]||0)+b.s/2}}catch(e){}})}
const need=v=>{if(!String(v||"").trim())throw new Error("No content provided.")};
function upi(c){const a=acc(),B="Banking & Payments";let q;try{q=new URL(c).searchParams}catch(e){throw new Error("QR code could not be read as a payment.")}
const pa=(q.get("pa")||"").trim(),pn=(q.get("pn")||"").trim(),am=q.get("am"),tn=q.get("tn")||"",hd=pa.split("@")[1]||"";
if(!/^[\w.\-]{2,}@[a-z]{2,}$/i.test(pa))add(a,"UPI handle is missing or malformed",30,B);else if(!HANDLES.test(hd))add(a,"Unrecognized UPI bank handle (@"+hd+")",15,B);
if(!pn)add(a,"No merchant name in the payment QR",10,"Impersonation");
if(am)add(a,"Amount is pre-filled. Check it before paying",8,B);
if(/cashback|reward|refund|lottery|prize|offer|win/i.test(pa+" "+pn+" "+tn))add(a,"Cashback or reward wording in a payment QR",40,"Fake Rewards");
if(/collect/i.test((q.get("mode")||"")+c))add(a,"Collect (money request) instead of a payment",25,B);
return out("QR",a,"UPI payment to "+(pn||"unknown")+" ("+(pa||"no handle")+")",{qrType:"UPI Payment",upi:{payee:pn||"Not provided",handle:pa||"Not provided",amount:am||"Not set"},
recommendation:status(Math.min(100,Math.round(a.s)))==="SAFE"?"Confirm the merchant name on your payment app matches the shop. Remember: your UPI PIN is only for paying, never for receiving money.":REC[status(Math.min(100,Math.round(a.s)))]+" Your UPI PIN is only for paying, never for receiving money."})}
return{status,
url(r){need(r);const a=acc(),h=urlCore(r.trim(),a);return out("Link",a,h)},
sms(t){need(t);const a=acc();textCore(t,a);return out("SMS",a)},
email(f){if(!String(f.body||"").trim()&&!String(f.sender||"").trim())throw new Error("No content provided.");
const a=acc();textCore((f.subject||"")+" "+(f.body||""),a);const dom=e=>(String(e).split("@")[1]||"").trim().toLowerCase(),d=dom(f.sender),S="Sender Identity";
if(f.sender&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.sender))add(a,"Sender address looks malformed",15,S);
if(f.replyTo&&dom(f.replyTo)&&dom(f.replyTo)!==d)add(a,"Reply-To domain differs from sender domain",25,S);
if(d&&(TLD.test(d)||/-.*-/.test(d)||/(secure|verify|support|alert)/.test(d)))add(a,"Suspicious sender domain",15,S);return out("Email",a)},
qr(c){need(c);if(/^upi:\/\//i.test(c))return upi(c);const t=/^https?:\/\//i.test(c)?"URL":/^WIFI:/i.test(c)?"Wi-Fi":/^(BEGIN:VCARD|MECARD)/i.test(c)?"Contact":"Text";
const a=acc();let d;if(t==="URL")d=urlCore(c.trim(),a);else{textCore(c,a);d=c.slice(0,200)}return out("QR",a,d,{qrType:t})}
}})();


  var KEY = "safescan:v1";
  var store = {
    get: function () { try { return localStorage.getItem(KEY); } catch (e) { return null; } },
    set: function (v) { try { localStorage.setItem(KEY, v); } catch (e) {} },
    del: function () { try { localStorage.removeItem(KEY); } catch (e) {} }
  };
  var esc = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };

  var CSS = [
    ":host{all:initial}",
    "*{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
    ".fab{position:fixed;right:20px;bottom:20px;width:56px;height:56px;border-radius:50%;border:0;cursor:pointer;background:linear-gradient(135deg,#3b5bff,#7c3aed);box-shadow:0 4px 14px rgba(59,91,255,.55);display:grid;place-items:center;z-index:2147483646;transition:transform .15s}",
    ".fab:hover{transform:scale(1.08)}.fab:focus-visible{outline:3px solid #fff;outline-offset:2px}",
    ".card{position:fixed;right:20px;bottom:20px;width:min(340px,calc(100vw - 32px));background:#0b1020;color:#e8ecff;border:1px solid #27305a;border-radius:16px;padding:18px;box-shadow:0 12px 40px rgba(0,0,0,.45);z-index:2147483647;animation:up .25s ease}",
    "@keyframes up{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}",
    ".card h2{margin:0 0 6px;font-size:16px;display:flex;gap:8px;align-items:center}",
    ".card p{margin:0 0 14px;font-size:13px;line-height:1.5;color:#b8c0e6}",
    ".row{display:flex;gap:8px}",
    ".btn{flex:1;border:1px solid #27305a;background:#151c3a;color:#e8ecff;border-radius:10px;padding:10px 12px;font-size:14px;font-weight:600;cursor:pointer}",
    ".btn:hover{filter:brightness(1.15)}.btn.p{background:linear-gradient(135deg,#3b5bff,#7c3aed);border:0;color:#fff}",
    ".panel{position:fixed;right:20px;bottom:88px;width:min(380px,calc(100vw - 32px));max-height:min(620px,calc(100vh - 110px));overflow:auto;background:#0b1020;color:#e8ecff;border:1px solid #27305a;border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,.45);z-index:2147483647;animation:up .2s ease}",
    ".hd{display:flex;justify-content:space-between;align-items:center;padding:14px 16px 8px;font-weight:700}",
    ".x{background:none;border:0;color:#b8c0e6;font-size:20px;cursor:pointer;line-height:1}",
    ".tabs{display:flex;gap:4px;padding:0 12px}",
    ".tabs button{flex:1;background:#151c3a;border:0;color:#b8c0e6;padding:8px 4px;border-radius:8px;font-size:13px;cursor:pointer}",
    ".tabs button[aria-selected=true]{background:#3b5bff;color:#fff}",
    ".body{padding:12px 16px 16px}",
    "label{display:block;font-size:12px;color:#b8c0e6;margin:10px 0 4px}",
    "input,textarea{width:100%;background:#151c3a;border:1px solid #27305a;color:#e8ecff;border-radius:10px;padding:10px;font-size:14px}",
    "textarea{min-height:90px;resize:vertical}input:focus,textarea:focus{outline:2px solid #3b5bff}",
    ".go{width:100%;margin-top:12px;padding:11px;border:0;border-radius:10px;background:linear-gradient(135deg,#3b5bff,#7c3aed);color:#fff;font-weight:700;font-size:14px;cursor:pointer}",
    ".mu{font-size:12px;color:#8f99c8;margin-top:10px;line-height:1.5}",
    ".res{margin-top:14px;background:#10173a;border:1px solid #27305a;border-radius:12px;padding:14px}",
    ".tr{display:flex;gap:14px;align-items:center}",
    ".ring{--p:50;--c:#16a34a;width:64px;height:64px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--c) calc(var(--p)*1%),#27305a 0)}",
    ".ring b{width:50px;height:50px;border-radius:50%;background:#10173a;display:grid;place-items:center;font-size:18px}",
    ".badge{display:inline-block;color:#fff;font-weight:700;font-size:12px;padding:4px 10px;border-radius:99px;margin-top:4px}",
    ".res h4{margin:14px 0 6px;font-size:13px}.res ul{margin:0;padding-left:18px;font-size:13px;color:#cfd6f5;line-height:1.55}",
    ".bk{display:flex;align-items:center;gap:8px;font-size:12px;margin:5px 0}.bk span{width:125px;color:#b8c0e6}",
    ".bar{flex:1;height:7px;background:#27305a;border-radius:9px;overflow:hidden}.bar i{display:block;height:100%;background:#ef4444}",
    ".rec{margin-top:12px;font-size:13px;line-height:1.5;background:#151c3a;border-radius:10px;padding:10px}",
    ".err{color:#fca5a5;font-size:13px;margin-top:10px}",
    ".sel{position:fixed;z-index:2147483647;background:linear-gradient(135deg,#3b5bff,#7c3aed);color:#fff;border:0;border-radius:99px;padding:7px 12px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.35)}",
    ".link{background:none;border:0;color:#8f99c8;text-decoration:underline;font-size:12px;cursor:pointer;padding:0}"
  ].join("");

  var SHIELD = '<svg width="30" height="34" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 1 2 6v10c0 8 5.5 14 13 17 7.5-3 13-9 13-17V6z" fill="#5eb3e8" stroke="#f0c14b" stroke-width="2"/><path d="M15 1v32C7.5 30 2 24 2 16V6z" fill="#3b7fd4"/></svg>';

  var host, root, fab, panel, prompt, selBtn, tab = "link";

  function mount() {
    host = document.createElement("div");
    host.id = "safescan-widget";
    root = host.attachShadow({ mode: "open" });
    root.innerHTML = "<style>" + CSS + "</style>";
    document.body.appendChild(host);
  }
  function clear(el) { if (el && el.parentNode) el.parentNode.removeChild(el); }
  function el(html) { var d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstChild; }

  /* ---------- one-click opt-in prompt ---------- */
  function askUser() {
    clear(prompt);
    prompt = el(
      '<div class="card" role="dialog" aria-label="SafeScan AI">' +
      '<h2>' + SHIELD.replace('width="30" height="34"', 'width="22" height="25"') + ' Turn on SafeScan protection?</h2>' +
      '<p>Check links, messages, emails and QR codes for scams right on this site. It runs in your browser and nothing is uploaded.</p>' +
      '<div class="row"><button class="btn p" data-a="yes">Yes, turn on</button><button class="btn" data-a="no">No thanks</button></div></div>'
    );
    prompt.addEventListener("click", function (e) {
      var a = e.target.getAttribute && e.target.getAttribute("data-a");
      if (a === "yes") { store.set("on"); clear(prompt); enable(); }
      if (a === "no") { store.set("off"); clear(prompt); }
    });
    root.appendChild(prompt);
  }

  /* ---------- floating shield ---------- */
  function enable() {
    store.set("on");
    if (fab) return;
    fab = el('<button class="fab" aria-label="Open SafeScan scanner" title="SafeScan">' + SHIELD + "</button>");
    fab.addEventListener("click", function () { panel ? closePanel() : openPanel(tab); });
    root.appendChild(fab);
    document.addEventListener("mouseup", onSelect);
    document.addEventListener("keyup", onSelect);
  }
  function disable() {
    store.set("off");
    closePanel(); clear(fab); fab = null; clear(selBtn); selBtn = null;
    document.removeEventListener("mouseup", onSelect);
    document.removeEventListener("keyup", onSelect);
  }

  /* ---------- scan highlighted text anywhere on the page ---------- */
  function onSelect(ev) {
    if (ev.target === host) return;
    setTimeout(function () {
      var s = window.getSelection(), t = s ? String(s).trim() : "";
      clear(selBtn); selBtn = null;
      if (t.length < 4 || !s.rangeCount) return;
      var r = s.getRangeAt(0).getBoundingClientRect();
      selBtn = el('<button class="sel">🛡 Scan selection</button>');
      selBtn.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 150)) + "px";
      selBtn.style.top = Math.max(8, r.top - 40) + "px";
      selBtn.addEventListener("mousedown", function (e) { e.preventDefault(); });
      selBtn.addEventListener("click", function () {
        var text = t.slice(0, 5000), isUrl = /^(https?:\/\/)?[^\s\/]+\.[a-z]{2,}(\/\S*)?$/i.test(text);
        clear(selBtn); selBtn = null;
        openPanel(isUrl ? "link" : "sms", text, true);
      });
      root.appendChild(selBtn);
    }, 10);
  }

  /* ---------- scanner panel ---------- */
  var FORMS = {
    link: '<label for="a">URL</label><input id="a" placeholder="https://example.com" autocomplete="off"><button class="go" data-run>Check link</button><div id="o"></div>',
    sms: '<label for="a">Suspicious message</label><textarea id="a" placeholder="Paste the suspicious SMS or chat message..."></textarea><button class="go" data-run>Analyze message</button><div id="o"></div>',
    email: '<label for="a">Sender email</label><input id="a"><label for="b">Subject</label><input id="b"><label for="c">Email content</label><textarea id="c"></textarea><label for="d">Reply-To (optional)</label><input id="d"><button class="go" data-run>Analyze email</button><div id="o"></div>',
    qr: '<button class="go" data-qr>📁 Upload a QR image</button><input type="file" id="f" accept="image/png,image/jpeg,image/webp" hidden><p class="mu">The image is decoded in your browser. It is never uploaded and the destination is never opened.</p><div id="o"></div>'
  };
  var NAMES = { link: "🔗 Link", sms: "💬 SMS", email: "📧 Mail", qr: "🔳 QR" };

  function openPanel(t, prefill, auto) {
    tab = t || "link";
    clear(panel);
    panel = el(
      '<div class="panel" role="dialog" aria-label="SafeScan scanner"><div class="hd"><span>🛡 SafeScan AI</span><button class="x" aria-label="Close">×</button></div>' +
      '<div class="tabs">' + Object.keys(NAMES).map(function (k) {
        return '<button data-t="' + k + '" aria-selected="' + (k === tab) + '">' + NAMES[k] + "</button>";
      }).join("") + '</div><div class="body">' + FORMS[tab] +
      '<p class="mu" style="margin-top:14px">Tip: highlight any text on the page to scan it. <button class="link" data-off>Turn SafeScan off</button></p></div></div>'
    );
    panel.addEventListener("click", function (e) {
      var t2 = e.target.getAttribute("data-t");
      if (t2) return openPanel(t2);
      if (e.target.classList.contains("x")) return closePanel();
      if (e.target.hasAttribute("data-off")) return disable();
      if (e.target.hasAttribute("data-run")) return run();
      if (e.target.hasAttribute("data-qr")) return panel.querySelector("#f").click();
    });
    var f = panel.querySelector("#f");
    if (f) f.addEventListener("change", function () { if (f.files[0]) readQR(f.files[0]); });
    root.appendChild(panel);
    var a = panel.querySelector("#a");
    if (prefill && a) { a.value = prefill; if (auto) run(); }
  }
  function closePanel() { clear(panel); panel = null; }

  function val(id) { var n = panel.querySelector("#" + id); return n ? n.value : ""; }
  function run() {
    try {
      var r = tab === "link" ? SafeScan.url(val("a"))
        : tab === "sms" ? SafeScan.sms(val("a"))
        : SafeScan.email({ sender: val("a"), subject: val("b"), body: val("c"), replyTo: val("d") });
      show(r);
    } catch (e) { panel.querySelector("#o").innerHTML = '<div class="err">' + esc(e.message) + "</div>"; }
  }
  function show(r) {
    var C = { "SAFE": ["#16a34a", "🟢 Safe"], "SUSPICIOUS": ["#d97706", "🟠 Suspicious"], "PHISHING DETECTED": ["#dc2626", "🔴 Phishing detected"] }[r.status];
    panel.querySelector("#o").innerHTML =
      '<div class="res" aria-live="polite">' +
      (r.qrType ? "<h4>QR code detected (" + esc(r.qrType) + ")</h4>" : "") +
      (r.destination ? '<p class="mu">Destination: ' + esc(r.destination) + "</p>" : "") +
      (r.upi ? '<p class="mu">Payee: ' + esc(r.upi.payee) + " · Handle: " + esc(r.upi.handle) + " · Amount: " + esc(r.upi.amount) + "</p>" : "") +
      '<div class="tr"><div class="ring" style="--p:' + r.trust + ";--c:" + C[0] + '"><b>' + r.trust + '</b></div><div><div class="mu" style="margin:0">Trust score</div><span class="badge" style="background:' + C[0] + '">' + C[1] + "</span></div></div>" +
      (r.breakdown.length ? "<h4>Threat breakdown</h4>" + r.breakdown.map(function (b) {
        return '<div class="bk"><span>' + esc(b.name) + '</span><div class="bar"><i style="width:' + b.level + '%"></i></div></div>';
      }).join("") : "") +
      "<h4>Why</h4><ul>" + r.indicators.map(function (i) { return "<li>" + esc(i) + "</li>"; }).join("") + "</ul>" +
      '<div class="rec">' + esc(r.recommendation) + "</div></div>";
  }

  function readQR(file) {
    var o = panel.querySelector("#o");
    o.innerHTML = '<p class="mu">Reading QR code...</p>';
    var img = new Image(), url = URL.createObjectURL(file);
    img.onload = function () {
      loadJsQR(function (ok) {
        if (!ok) { o.innerHTML = '<div class="err">QR reader could not load. Check your connection.</div>'; return; }
        var c = document.createElement("canvas"), k = Math.min(1, 1200 / Math.max(img.width, img.height));
        c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        var x = c.getContext("2d"); x.drawImage(img, 0, 0, c.width, c.height);
        var d = x.getImageData(0, 0, c.width, c.height), q = window.jsQR(d.data, d.width, d.height);
        URL.revokeObjectURL(url);
        if (!q) { o.innerHTML = '<div class="err">No QR code found in that image.</div>'; return; }
        try { show(SafeScan.qr(q.data)); } catch (e) { o.innerHTML = '<div class="err">' + esc(e.message) + "</div>"; }
      });
    };
    img.onerror = function () { o.innerHTML = '<div class="err">Could not open that image.</div>'; };
    img.src = url;
  }
  function loadJsQR(cb) {
    if (window.jsQR) return cb(true);
    var s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";
    s.onload = function () { cb(!!window.jsQR); };
    s.onerror = function () { cb(false); };
    document.head.appendChild(s);
  }

  /* ---------- start ---------- */
  function start() {
    mount();
    var s = store.get();
    if (s === "on") enable();
    else if (s !== "off") askUser();
  }
  window.SafeScanWidget = {
    ask: function () { store.del(); clear(prompt); askUser(); },   // show the one-click prompt again
    enable: enable,
    disable: disable,
    open: function (t) { if (!fab) enable(); openPanel(t || "link"); },
    scan: SafeScan
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
