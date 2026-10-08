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
