const DBKEY=window.INDICA_CONFIG.storageKey;
const defaultData={
 campaign:{name:"Outubro Premiado",badge:"CAMPANHA ATIVA",title:"Indique. Ganhe. Evolua.",subtitle:"Indique novos alunos, acumule tickets e participe de sorteios incríveis.",logoText:"Indica+",primary:"#6d28d9",secondary:"#8b5cf6"},
 prizes:[{id:"p1",name:"Bolsa de Estudos Integral",desc:"Uma bolsa de estudos para transformar sua próxima fase.",icon:"🎓",stock:2,active:true},{id:"p2",name:"Kit Evolua+",desc:"Um kit especial para acompanhar sua jornada.",icon:"🎒",stock:10,active:true},{id:"p3",name:"Curso Premium",desc:"Acesso a um curso premium da campanha.",icon:"💻",stock:8,active:true},{id:"p4",name:"1 Mês Grátis",desc:"Um mês de acesso sem custo.",icon:"⭐",stock:20,active:true}],
 students:[], referrals:[], tickets:[], wins:[]
};
function getData(){let d=localStorage.getItem(DBKEY);if(!d){localStorage.setItem(DBKEY,JSON.stringify(defaultData));return structuredClone(defaultData)}return JSON.parse(d)}
function saveData(d){localStorage.setItem(DBKEY,JSON.stringify(d))}
function toast(msg){const t=document.getElementById("toast");if(!t)return;t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2800)}
function uid(prefix="id"){return prefix+"_"+Math.random().toString(36).slice(2,9)+Date.now().toString(36).slice(-4)}
function fmtDate(s){return new Date(s).toLocaleDateString("pt-BR")}
function currentStudent(){return JSON.parse(localStorage.getItem("indica_current_student")||"null")}
function setStudent(s){localStorage.setItem("indica_current_student",JSON.stringify(s))}
function ensureStudent(phone,name="Novo aluno"){let d=getData();let p=phone.replace(/\D/g,"");let s=d.students.find(x=>x.phone===p);if(!s){s={id:uid("stu"),name,phone:p,email:"",createdAt:new Date().toISOString()};d.students.push(s);saveData(d)}return s}

function initPublic(){
 const d=getData(), c=d.campaign;
 document.documentElement.style.setProperty("--primary",c.primary);document.documentElement.style.setProperty("--primary2",c.secondary);
 const set=(id,val)=>{const e=document.getElementById(id);if(e)e.innerHTML=val};
 set("brandName",(c.logoText||"Indica+").replace("+","<span>+</span>"));set("campaignBadge",c.badge);set("campaignTitle",c.title.replace(/Evolua\./i,"<span>Evolua.</span>"));set("campaignSubtitle",c.subtitle);
 const tickets=d.tickets.filter(t=>t.status==="available").length;
 set("heroTickets",tickets);set("heroPrizes",d.prizes.filter(p=>p.active).length);set("heroIndications",d.referrals.length);
 const grid=document.getElementById("publicPrizes");if(grid)grid.innerHTML=d.prizes.filter(p=>p.active).map(p=>`<article class="prize"><div class="prize-icon">${p.icon}</div><h3>${p.name}</h3><p>${p.desc}</p></article>`).join("");
 const form=document.getElementById("loginForm");if(form)form.onsubmit=e=>{e.preventDefault();const phone=document.getElementById("loginPhone").value;const s=ensureStudent(phone);setStudent(s);location.href="aluno.html"};
}
function initStudent(){
 const s=currentStudent();if(!s){location.href="index.html#acessar";return}renderStudent();
 document.getElementById("logoutBtn").onclick=()=>{localStorage.removeItem("indica_current_student");location.href="index.html"};
 document.getElementById("openReferral").onclick=()=>document.getElementById("referralModal").classList.add("open");
 document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>b.closest(".modal").classList.remove("open"));
 document.getElementById("referralForm").onsubmit=e=>{e.preventDefault();let d=getData();d.referrals.push({id:uid("ref"),studentId:s.id,name:document.getElementById("refName").value.trim(),phone:document.getElementById("refPhone").value.replace(/\D/g,""),email:document.getElementById("refEmail").value.trim(),status:"pending",createdAt:new Date().toISOString(),eligibleAt:new Date(Date.now()+7*86400000).toISOString()});saveData(d);e.target.reset();document.getElementById("referralModal").classList.remove("open");toast("Indicação registrada!");renderStudent()};
 document.getElementById("drawForm").onsubmit=e=>{e.preventDefault();drawTicket()};
}
function renderStudent(){
 const s=currentStudent(),d=getData(),refs=d.referrals.filter(r=>r.studentId===s.id), tickets=d.tickets.filter(t=>t.studentId===s.id),available=tickets.filter(t=>t.status==="available"),wins=d.wins.filter(w=>w.studentId===s.id);
 document.getElementById("studentName").textContent=s.name;document.getElementById("helloName").textContent=s.name.split(" ")[0];document.getElementById("mIndications").textContent=refs.length;document.getElementById("mConfirmed").textContent=refs.filter(r=>r.status==="confirmed").length;document.getElementById("mTickets").textContent=available.length;document.getElementById("mWins").textContent=wins.length;document.getElementById("ticketCount").textContent=`${available.length} disponíveis`;
 document.getElementById("ticketList").innerHTML=available.length?available.map(t=>`<div class="ticket-row"><div><code>${t.code}</code><small>Ticket disponível</small></div><span class="status confirmed">DISPONÍVEL</span></div>`).join(""):`<div class="empty">Você ainda não tem tickets disponíveis. Continue indicando! 🚀</div>`;
 document.getElementById("referralList").innerHTML=refs.length?refs.slice().reverse().map(r=>`<div class="ref-row"><strong>${r.name}</strong><span class="status ${r.status==="confirmed"?"confirmed":r.status==="cancelled"?"cancelled":"pending"}">${r.status==="confirmed"?"CONFIRMADA":r.status==="cancelled"?"CANCELADA":"AGUARDANDO"}</span><small>${r.status==="pending"?`Aguardando confirmação da matrícula. Elegível em ${fmtDate(r.eligibleAt)}`:`Indicação convertida em matrícula.`}</small></div>`).join(""):`<div class="empty">Nenhuma indicação ainda.</div>`;
}
function drawTicket(){
 const s=currentStudent(),d=getData(),input=document.getElementById("ticketInput").value.trim().toUpperCase(),t=d.tickets.find(x=>x.studentId===s.id&&x.code===input&&x.status==="available"),out=document.getElementById("drawResult");
 if(!t){out.innerHTML=`<div class="win-card"><div class="big">🎟️</div><b>Ticket não encontrado</b><p>Confira o código e tente novamente.</p></div>`;return}
 const pool=d.prizes.filter(p=>p.active&&p.stock>0);if(!pool.length){out.innerHTML=`<div class="win-card"><div class="big">⚠️</div><b>Campanha sem prêmios disponíveis</b></div>`;return}
 const prize=pool[Math.floor(Math.random()*pool.length)];t.status="used";t.usedAt=new Date().toISOString();t.prizeId=prize.id;prize.stock--;d.wins.push({id:uid("win"),studentId:s.id,ticketId:t.id,prizeId:prize.id,createdAt:new Date().toISOString()});saveData(d);
 out.innerHTML=`<div class="win-card"><div class="big">${prize.icon}</div><h3>Você ganhou!</h3><p><b>${prize.name}</b></p><small>Ticket ${t.code} utilizado em ${new Date().toLocaleString("pt-BR")}</small></div>`;document.getElementById("ticketInput").value="";renderStudent();
}
if(location.pathname.endsWith("/aluno.html"))initStudent();else if(!location.pathname.includes("/admin/"))initPublic();
