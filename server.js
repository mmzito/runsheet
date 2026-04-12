require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Issuer, generators } = require('openid-client');
const https = require('https');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'runsheet-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 8 * 60 * 60 * 1000 }
}));

const CLIENT_ID = process.env.XERO_CLIENT_ID;
const CLIENT_SECRET = process.env.XERO_CLIENT_SECRET;
const REDIRECT_URI = process.env.XERO_REDIRECT_URI || 'http://localhost:3000/callback';
const SCOPES = 'openid profile email offline_access accounting.transactions.read accounting.contacts.read accounting.reports.read accounting.settings.read';

let xeroClient = null;

async function getClient() {
  if (!xeroClient) {
    const issuer = await Issuer.discover('https://identity.xero.com');
    xeroClient = new issuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: [REDIRECT_URI],
      response_types: ['code'],
    });
  }
  return xeroClient;
}

function requireAuth(req, res, next) {
  if (!req.session.tokenSet) return res.redirect('/connect');
  next();
}

// ── PAGES ──────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect(req.session.tokenSet ? '/app' : '/connect'));

app.get('/connect', (req, res) => {
  const err = req.query.error ? `<div style="background:#FDECEA;border-left:4px solid #c0392b;padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:20px;color:#7B2222">Connection failed: ${decodeURIComponent(req.query.error)}</div>` : '';
  res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Runsheet — Connect Xero</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'DM Sans',sans-serif;background:#0F1F12;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;padding:48px 40px;max-width:420px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
.logo{font-family:'DM Serif Display',serif;font-size:32px;color:#0F1F12;margin-bottom:4px}.logo span{color:#52B788}
.tagline{font-size:12px;color:#718096;text-transform:uppercase;letter-spacing:0.12em;margin-bottom:28px}
h2{font-size:18px;color:#0F1F12;margin-bottom:10px}p{font-size:13px;color:#5A6672;line-height:1.6;margin-bottom:24px}
.btn-xero{display:block;background:#0F1F12;color:#fff;text-decoration:none;padding:14px 28px;border-radius:10px;font-size:15px;font-weight:700;transition:background 0.2s;margin-bottom:10px}
.btn-xero:hover{background:#1A3320}
.btn-demo{display:block;background:transparent;color:#5A6672;text-decoration:none;padding:12px;border-radius:10px;font-size:13px;border:1.5px solid #D4E6DA;transition:all 0.2s}
.btn-demo:hover{border-color:#2D6A4F;color:#2D6A4F}
.sec{font-size:11px;color:#A0ADB8;margin-top:16px}</style></head>
<body><div class="card">
  <div class="logo">Run<span>sheet</span></div>
  <div class="tagline">52-Week Cashflow Forecasting</div>
  ${err}
  <h2>Connect your Xero account</h2>
  <p>Runsheet reads your invoices, bills, and payroll from Xero to build your 52-week cashflow forecast. Read-only — we never modify your data.</p>
  <a class="btn-xero" href="/auth">Connect with Xero →</a>
  <a class="btn-demo" href="/app?demo=true">Try with demo data (Creted Civil)</a>
  <p class="sec">🔒 Secure OAuth 2.0 with PKCE · Read-only · Disconnect anytime</p>
</div></body></html>`);
});

// ── AUTH ────────────────────────────────────────────────────────────────────
app.get('/auth', async (req, res) => {
  try {
    const client = await getClient();
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();
    req.session.codeVerifier = codeVerifier;
    req.session.oauthState = state;
    const url = client.authorizationUrl({
      scope: SCOPES,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state
    });
    console.log('Redirecting to Xero auth, state:', state.substring(0,8) + '...');
    res.redirect(url);
  } catch (err) {
    console.error('Auth error:', err.message);
    res.status(500).send(`<pre>Auth setup error: ${err.message}</pre>`);
  }
});

app.get('/callback', async (req, res) => {
  try {
    const client = await getClient();
    const params = client.callbackParams(req);
    console.log('Callback params:', JSON.stringify({ code: params.code ? 'present' : 'missing', state: params.state }));
    const tokenSet = await client.callback(REDIRECT_URI, params, {
      code_verifier: req.session.codeVerifier,
      state: req.session.oauthState
    });
    req.session.tokenSet = tokenSet;
    req.session.codeVerifier = null;
    req.session.oauthState = null;

    // Get tenants
    const tenants = await getConnectedTenants(tokenSet.access_token);
    req.session.tenants = tenants;
    console.log('Tenants:', tenants.map(t => t.tenantName));
    if (tenants.length === 1) {
      req.session.activeTenantId = tenants[0].tenantId;
      req.session.activeTenantName = tenants[0].tenantName;
    }
    res.redirect(tenants.length > 1 ? '/select-org' : '/app');
  } catch (err) {
    console.error('Callback error:', err.message);
    res.redirect('/connect?error=' + encodeURIComponent(err.message));
  }
});

// ── HELPERS ──────────────────────────────────────────────────────────────────
async function getConnectedTenants(accessToken) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.xero.com',
      path: '/connections',
      method: 'GET',
      headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
    };
    const req = https.request(options, (r) => {
      let data = '';
      r.on('data', chunk => data += chunk);
      r.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Failed to parse tenants: ' + data.substring(0,100))); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function getAccessToken(req) {
  let tokenSet = req.session.tokenSet;
  if (!tokenSet) throw new Error('Not authenticated');
  // Check expiry
  const exp = tokenSet.expires_at || (tokenSet.expires_in ? Math.floor(Date.now()/1000) + tokenSet.expires_in : null);
  if (exp && Math.floor(Date.now()/1000) > exp - 60) {
    const client = await getClient();
    const newTokenSet = await client.refresh(tokenSet.refresh_token);
    req.session.tokenSet = newTokenSet;
    tokenSet = newTokenSet;
    console.log('Token refreshed');
  }
  return tokenSet.access_token;
}

async function xeroGet(path, accessToken, tenantId) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.xero.com',
      path: path,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Xero-tenant-id': tenantId,
        'Accept': 'application/json'
      }
    };
    const req = https.request(options, (r) => {
      let data = '';
      r.on('data', chunk => data += chunk);
      r.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Parse error: ' + data.substring(0,100))); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ── TENANT SELECTION ─────────────────────────────────────────────────────────
app.get('/select-org', requireAuth, (req, res) => {
  const tenants = req.session.tenants || [];
  if (tenants.length <= 1) return res.redirect('/app');
  res.send(`<!DOCTYPE html><html><head><title>Select Org</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'DM Sans',sans-serif;background:#F5F0E8;padding:40px 20px;display:flex;justify-content:center}
.card{background:#fff;border-radius:12px;padding:32px;max-width:480px;width:100%}
h2{font-size:20px;color:#0F1F12;margin-bottom:8px}p{color:#5A6672;margin-bottom:20px;font-size:14px}
.org{display:block;padding:14px 18px;border:1.5px solid #D4E6DA;border-radius:8px;margin-bottom:10px;text-decoration:none;color:#0F1F12;font-weight:600;transition:all 0.15s}
.org:hover{border-color:#2D6A4F;background:#D8F3DC}</style></head>
<body><div class="card"><h2>Select Organisation</h2><p>Which Xero organisation do you want to connect?</p>
${tenants.map(t => `<a class="org" href="/select-org/${t.tenantId}">${t.tenantName}</a>`).join('')}
</div></body></html>`);
});

app.get('/select-org/:id', requireAuth, (req, res) => {
  const t = (req.session.tenants || []).find(t => t.tenantId === req.params.id);
  if (!t) return res.redirect('/select-org');
  req.session.activeTenantId = t.tenantId;
  req.session.activeTenantName = t.tenantName;
  res.redirect('/app');
});

app.get('/disconnect', (req, res) => { req.session.destroy(); res.redirect('/connect'); });

// ── API ENDPOINTS ─────────────────────────────────────────────────────────────
app.get('/api/summary', requireAuth, async (req, res) => {
  try {
    const token = await getAccessToken(req);
    const tenantId = req.session.activeTenantId;
    const [invData, billData] = await Promise.all([
      xeroGet('/api.xro/2.0/Invoices?Statuses=AUTHORISED&Type=ACCREC&SummaryOnly=true', token, tenantId),
      xeroGet('/api.xro/2.0/Invoices?Statuses=AUTHORISED&Type=ACCPAY&SummaryOnly=true', token, tenantId)
    ]);
    const invoices = (invData.Invoices || []).filter(i => i.AmountDue > 0).map(i => ({
      client: i.Contact?.Name, ref: i.InvoiceNumber,
      amount: i.AmountDue, due: i.DueDateString?.substring(0,10), status: i.Status
    }));
    const bills = (billData.Invoices || []).filter(b => b.AmountDue > 0).map(b => ({
      supplier: b.Contact?.Name, amount: b.AmountDue,
      due: b.DueDateString?.substring(0,10), status: b.Status
    }));
    const totalReceivables = invoices.reduce((s,i)=>s+(i.amount||0),0);
    const totalPayables = bills.reduce((s,b)=>s+(b.amount||0),0);
    res.json({ tenantName: req.session.activeTenantName, invoices, bills, totalReceivables, totalPayables, netPosition: totalReceivables-totalPayables, generatedAt: new Date().toISOString() });
  } catch(e) {
    console.error('Summary error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/invoices', requireAuth, async (req, res) => {
  try {
    const token = await getAccessToken(req);
    const data = await xeroGet('/api.xro/2.0/Invoices?Statuses=AUTHORISED&Type=ACCREC', token, req.session.activeTenantId);
    const invoices = (data.Invoices || []).filter(i=>i.AmountDue>0).map(i=>({
      client: i.Contact?.Name, ref: i.InvoiceNumber, amount: i.AmountDue,
      due: i.DueDateString?.substring(0,10), status: i.Status
    }));
    res.json({ invoices });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/bills', requireAuth, async (req, res) => {
  try {
    const token = await getAccessToken(req);
    const data = await xeroGet('/api.xro/2.0/Invoices?Statuses=AUTHORISED&Type=ACCPAY', token, req.session.activeTenantId);
    const bills = (data.Invoices || []).filter(b=>b.AmountDue>0).map(b=>({
      supplier: b.Contact?.Name, amount: b.AmountDue,
      due: b.DueDateString?.substring(0,10), status: b.Status
    }));
    res.json({ bills });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/payroll', requireAuth, async (req, res) => {
  try {
    const token = await getAccessToken(req);
    const data = await xeroGet('/payroll.xro/1.0/PayRuns', token, req.session.activeTenantId);
    const payRuns = (data.PayRuns || []).slice(0,12).map(r=>({
      startDate: r.StartDate, endDate: r.EndDate, paymentDate: r.PaymentDate,
      wages: r.Wages, super: r.Superannuation, payg: r.Tax, totalNetPay: r.NetPay
    }));
    res.json({ payRuns });
  } catch(e) { res.json({ payRuns: [], note: 'Payroll requires Xero Payroll: ' + e.message }); }
});

app.get('/health', (req, res) => res.json({ status: 'ok', service: 'Runsheet', version: '1.1.0' }));

// ── MAIN APP ──────────────────────────────────────────────────────────────────
app.get('/app', async (req, res) => {
  const isDemo = req.query.demo === 'true';
  if (!isDemo && !req.session.tokenSet) return res.redirect('/connect');
  const orgName = req.session.activeTenantName || (isDemo ? 'Creted Civil Pty Ltd (Demo)' : 'Your Business');
  const isMultiTenant = (req.session.tenants || []).length > 1;
  res.send(buildAppHTML(orgName, isDemo, isMultiTenant));
});

function buildAppHTML(orgName, isDemo, isMultiTenant) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Runsheet — ${orgName}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--dark:#0F1F12;--accent:#2D6A4F;--light:#52B788;--pale:#D8F3DC;--sand:#F5F0E8;--orange:#E07B39;--text:#1A1A1A;--muted:#5A6672;--border:#D4E6DA;--white:#fff;--danger:#C0392B;--amber:#B7690A;--r:8px}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'DM Sans',sans-serif;background:var(--sand);color:var(--text);min-height:100vh;font-size:14px}
.topbar{background:var(--dark);height:58px;display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.logo{font-family:'DM Serif Display',serif;font-size:22px;color:#fff}.logo span{color:var(--light)}
.topbar-right{display:flex;align-items:center;gap:14px}
.org-badge{font-size:12px;color:rgba(255,255,255,0.5)}
.demo-badge{background:var(--orange);color:#fff;font-size:10px;font-weight:700;padding:3px 8px;border-radius:10px;text-transform:uppercase}
.btn-sm{background:transparent;border:1px solid rgba(255,255,255,0.2);color:rgba(255,255,255,0.6);padding:5px 12px;border-radius:6px;font-size:12px;cursor:pointer;font-family:'DM Sans',sans-serif;transition:all 0.15s;text-decoration:none}
.btn-sm:hover{border-color:var(--light);color:var(--light)}
.layout{display:flex;min-height:calc(100vh - 58px)}
.sidebar{width:210px;flex-shrink:0;background:#fff;border-right:1px solid var(--border);padding:16px 0;position:sticky;top:58px;height:calc(100vh - 58px);overflow-y:auto}
.sidebar-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.12em;color:var(--muted);padding:0 16px;margin:16px 0 6px}
.nav-btn{display:flex;align-items:center;gap:10px;padding:9px 16px;width:100%;background:transparent;border:none;font-family:'DM Sans',sans-serif;font-size:13px;font-weight:500;color:var(--muted);cursor:pointer;transition:all 0.15s;text-align:left}
.nav-btn:hover{background:var(--sand);color:var(--text)}.nav-btn.active{background:var(--pale);color:var(--dark);font-weight:700}
.balance-box{margin:12px;padding:14px;background:var(--dark);border-radius:var(--r);color:#fff}
.balance-lbl{font-size:10px;color:rgba(255,255,255,0.45);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:4px}
.balance-val{font-family:'DM Serif Display',serif;font-size:24px}
.main{flex:1;padding:24px;min-width:0}
.section{display:none}.section.active{display:block}
.page-title{font-family:'DM Serif Display',serif;font-size:26px;color:var(--dark);margin-bottom:4px}
.page-sub{font-size:13px;color:var(--muted);margin-bottom:20px}
.card{background:#fff;border-radius:var(--r);border:1px solid var(--border);overflow:hidden;margin-bottom:18px}
.card-hdr{padding:13px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.card-title{font-weight:700;font-size:13px}.card-body{padding:18px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.stat{background:#fff;border-radius:var(--r);padding:16px 18px;border:1px solid var(--border);border-top:3px solid var(--light)}
.stat.red{border-top-color:var(--danger)}.stat.amber{border-top-color:var(--amber)}
.stat-lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:6px}
.stat-val{font-family:'DM Serif Display',serif;font-size:26px;color:var(--text)}.stat-val.neg{color:var(--danger)}
.stat-sub{font-size:11px;color:var(--muted);margin-top:3px}
.alert{padding:11px 14px;border-radius:6px;margin-bottom:10px;font-size:13px;display:flex;align-items:flex-start;gap:10px;line-height:1.5}
.alert-red{background:#FDECEA;border-left:4px solid var(--danger);color:#7B2222}
.alert-amber{background:#FEF3E2;border-left:4px solid var(--amber);color:#6B3E00}
.alert-green{background:var(--pale);border-left:4px solid var(--light);color:#1A3320}
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--dark);color:#fff;padding:8px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--sand);vertical-align:middle}
tr:hover td{background:var(--sand)}tr:last-child td{border-bottom:none}
.badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;text-transform:uppercase;white-space:nowrap}
.bg{background:var(--pale);color:var(--dark)}.br{background:#FDECEA;color:var(--danger)}.ba{background:#FEF3E2;color:var(--amber)}.bgr{background:#f0f0f0;color:#666}
.btn{padding:7px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:none;font-family:'DM Sans',sans-serif;transition:all 0.15s}
.btn-primary{background:var(--orange);color:#fff}.btn-primary:hover{background:#C96A28}
.btn-outline{background:transparent;border:1.5px solid var(--border);color:var(--muted)}.btn-outline:hover{border-color:var(--dark);color:var(--dark)}
.loading{text-align:center;padding:32px;color:var(--muted);font-size:14px}
.week-row{display:flex;align-items:center;gap:8px;padding:5px 4px;border-bottom:1px solid var(--sand);font-size:12px}
.week-row:hover{background:var(--sand);border-radius:4px}
.wk-lbl{width:55px;color:var(--muted);font-weight:600;flex-shrink:0}
.wk-mo{width:50px;color:var(--muted);font-size:11px;flex-shrink:0}
.wk-in{width:100px;color:var(--accent);font-weight:600;text-align:right;flex-shrink:0}
.wk-out{width:100px;color:var(--danger);text-align:right;flex-shrink:0}
.wk-bal{width:110px;font-weight:700;text-align:right;flex-shrink:0}
.wk-bal.ok{color:var(--accent)}.wk-bal.low{color:var(--amber)}.wk-bal.neg{color:var(--danger)}
.wk-bar{flex:1;display:flex;gap:2px;align-items:center}
.bar-in{height:10px;background:var(--light);border-radius:2px;opacity:0.8}
.bar-out{height:10px;background:rgba(224,123,57,0.7);border-radius:2px}
.danger-row{background:rgba(192,57,43,0.06);border-radius:4px}.amber-row{background:rgba(183,105,10,0.05);border-radius:4px}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:1000;align-items:flex-start;justify-content:center;padding:40px 16px;overflow-y:auto}
.modal-overlay.open{display:flex}
.modal{background:#fff;border-radius:12px;width:100%;max-width:560px;box-shadow:0 12px 48px rgba(0,0,0,0.2);margin:auto}
.modal-hdr{padding:16px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.modal-title{font-family:'DM Serif Display',serif;font-size:20px;color:var(--dark)}
.modal-close{background:none;border:none;font-size:22px;cursor:pointer;color:var(--muted)}.modal-close:hover{color:var(--danger)}
.modal-body{padding:22px}.modal-footer{padding:14px 22px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:10px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.form-field{display:flex;flex-direction:column;gap:5px}
.form-field label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted)}
.form-field input,.form-field select{padding:8px 11px;border:1.5px solid var(--border);border-radius:6px;font-family:'DM Sans',sans-serif;font-size:13px}
.form-field input:focus,.form-field select:focus{outline:none;border-color:var(--accent)}
.toast-container{position:fixed;bottom:20px;right:20px;z-index:2000;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--dark);color:#fff;padding:11px 16px;border-radius:8px;font-size:13px;box-shadow:0 4px 20px rgba(0,0,0,0.2);animation:slideIn 0.2s;border-left:3px solid var(--light);min-width:200px}
@keyframes slideIn{from{transform:translateX(60px);opacity:0}to{transform:translateX(0);opacity:1}}
@media(max-width:768px){.sidebar{display:none}.main{padding:16px}.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">Run<span>sheet</span></div>
  <div class="topbar-right">
    <span class="org-badge">${orgName}</span>
    ${isDemo ? '<span class="demo-badge">Demo</span>' : ''}
    ${isMultiTenant ? '<a class="btn-sm" href="/select-org">Switch Org</a>' : ''}
    ${isDemo ? '<a class="btn-sm" href="/connect">Connect Xero</a>' : '<a class="btn-sm" href="/disconnect">Disconnect</a>'}
  </div>
</div>
<div class="layout">
  <aside class="sidebar">
    <div class="balance-box">
      <div class="balance-lbl">Opening Balance</div>
      <div class="balance-val" id="sidebar-balance">...</div>
    </div>
    <div class="sidebar-label">Overview</div>
    <button class="nav-btn active" onclick="nav('dashboard')"><span>📊</span> Dashboard</button>
    <button class="nav-btn" onclick="nav('forecast')"><span>📅</span> 52-Week Forecast</button>
    <div class="sidebar-label">Money In</div>
    <button class="nav-btn" onclick="nav('invoices')"><span>📥</span> Invoices</button>
    <div class="sidebar-label">Money Out</div>
    <button class="nav-btn" onclick="nav('bills')"><span>📤</span> Bills</button>
    <button class="nav-btn" onclick="nav('payroll')"><span>💼</span> Payroll</button>
    <div class="sidebar-label">Planning</div>
    <button class="nav-btn" onclick="nav('jobs')"><span>🏗️</span> Job Pipeline</button>
  </aside>
  <main class="main">
    <div class="section active" id="section-dashboard">
      <div class="page-title">Dashboard</div>
      <div class="page-sub" id="dash-sub">Loading from Xero...</div>
      <div id="dash-alerts"></div>
      <div class="stats" id="dash-stats"><div class="loading">Fetching your Xero data...</div></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px">
        <div class="card"><div class="card-hdr"><span class="card-title">📥 Due In — Next 30 Days</span></div><div class="card-body" id="dash-in"><div class="loading">Loading...</div></div></div>
        <div class="card"><div class="card-hdr"><span class="card-title">📤 Due Out — Next 30 Days</span></div><div class="card-body" id="dash-out"><div class="loading">Loading...</div></div></div>
      </div>
    </div>
    <div class="section" id="section-forecast">
      <div class="page-title">52-Week Cashflow Forecast</div>
      <div class="page-sub">Week-by-week bank balance projection based on your Xero data</div>
      <div class="card">
        <div class="card-hdr">
          <span class="card-title">Weekly Balance Projection</span>
          <div style="display:flex;align-items:center;gap:10px;font-size:12px">
            <span style="color:var(--light)">■ In</span><span style="color:var(--orange)">■ Out</span>
            Alert threshold: <input type="number" id="threshold" value="10000" style="width:90px;padding:4px 8px;border:1.5px solid var(--border);border-radius:5px;font-size:12px" onchange="buildForecast()">
          </div>
        </div>
        <div class="card-body" style="overflow-x:auto">
          <div style="min-width:700px">
            <div style="display:flex;gap:8px;padding:6px 4px;border-bottom:2px solid var(--dark);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted)">
              <div style="width:55px">Week</div><div style="width:50px">Month</div>
              <div style="width:100px;text-align:right">Inflows</div>
              <div style="width:100px;text-align:right">Outflows</div>
              <div style="width:110px;text-align:right">Balance</div>
              <div style="flex:1;padding-left:8px">Flow</div>
            </div>
            <div id="forecast-rows"><div class="loading">Visit Dashboard first to load data</div></div>
          </div>
        </div>
      </div>
    </div>
    <div class="section" id="section-invoices">
      <div class="page-title">Invoice Tracker</div>
      <div class="page-sub">Outstanding invoices from Xero</div>
      <div id="inv-stats" class="stats"></div>
      <div class="card">
        <div class="card-hdr"><span class="card-title">Outstanding Invoices</span><button class="btn btn-outline" onclick="loadInvoices()">🔄 Refresh</button></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Client</th><th>Ref</th><th>Amount Due</th><th>Due Date</th><th>Days</th><th>Status</th></tr></thead>
          <tbody id="inv-tbody"><tr><td colspan="6" class="loading">Loading...</td></tr></tbody>
        </table></div>
      </div>
    </div>
    <div class="section" id="section-bills">
      <div class="page-title">Bills Tracker</div>
      <div class="page-sub">Outstanding bills from Xero</div>
      <div id="bill-stats" class="stats"></div>
      <div class="card">
        <div class="card-hdr"><span class="card-title">Outstanding Bills</span><button class="btn btn-outline" onclick="loadBills()">🔄 Refresh</button></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Supplier</th><th>Amount Due</th><th>Due Date</th><th>Days</th><th>Status</th></tr></thead>
          <tbody id="bill-tbody"><tr><td colspan="5" class="loading">Loading...</td></tr></tbody>
        </table></div>
      </div>
    </div>
    <div class="section" id="section-payroll">
      <div class="page-title">Payroll</div>
      <div class="page-sub">Recent pay runs from Xero Payroll</div>
      <div class="card">
        <div class="card-hdr"><span class="card-title">Pay Run History</span><button class="btn btn-outline" onclick="loadPayroll()">🔄 Refresh</button></div>
        <div class="tbl-wrap"><table>
          <thead><tr><th>Period</th><th>Payment Date</th><th>Gross Wages</th><th>Super</th><th>PAYG</th><th>Net to Bank</th></tr></thead>
          <tbody id="payroll-tbody"><tr><td colspan="6" class="loading">Loading...</td></tr></tbody>
        </table></div>
      </div>
    </div>
    <div class="section" id="section-jobs">
      <div class="page-title">Job Pipeline</div>
      <div class="page-sub">Add upcoming jobs to see payment timing in your 52-week forecast</div>
      <div class="alert alert-green">💡 <b>Key feature:</b> Enter jobs with payment terms to see exactly when costs land vs when money arrives.</div>
      <div style="margin:14px 0;display:flex;justify-content:flex-end"><button class="btn btn-primary" onclick="openModal('job-modal')">+ Add Job</button></div>
      <div id="jobs-content"></div>
    </div>
  </main>
</div>
<div class="modal-overlay" id="job-modal">
  <div class="modal">
    <div class="modal-hdr"><span class="modal-title">Add Job to Pipeline</span><button class="modal-close" onclick="closeModal('job-modal')">×</button></div>
    <div class="modal-body">
      <div class="form-row"><div class="form-field"><label>Job Name</label><input type="text" id="job-name"></div><div class="form-field"><label>Client / Council</label><input type="text" id="job-client"></div></div>
      <div class="form-row"><div class="form-field"><label>Work Start</label><input type="date" id="job-start"></div><div class="form-field"><label>Work End</label><input type="date" id="job-end"></div></div>
      <div class="form-row"><div class="form-field"><label>Revenue (ex-GST) $</label><input type="number" id="job-rev" oninput="previewJob()"></div><div class="form-field"><label>Direct Costs (ex-GST) $</label><input type="number" id="job-costs" oninput="previewJob()"></div></div>
      <div class="form-field" style="margin-bottom:14px"><label>Payment Terms</label>
        <select id="job-terms" onchange="previewJob()">
          <option value="30eom">30 Days End of Month</option>
          <option value="14">14 Days from Invoice</option>
          <option value="30">30 Days from Invoice</option>
          <option value="progress">Progress Claims</option>
        </select>
      </div>
      <div style="background:var(--sand);border-radius:8px;padding:14px;font-size:13px" id="job-preview">Enter details above.</div>
    </div>
    <div class="modal-footer"><button class="btn btn-outline" onclick="closeModal('job-modal')">Cancel</button><button class="btn btn-primary" onclick="saveJob()">Add to Pipeline</button></div>
  </div>
</div>
<div class="toast-container" id="toasts"></div>
<script>
const IS_DEMO = ${isDemo};
let D = { invoices:[], bills:[], payRuns:[], jobs:JSON.parse(localStorage.getItem('rs_jobs')||'[]'), balance: 16875.81 };
const fc = n => n==null?'—':(n<0?'-$':'$')+Math.abs(n).toLocaleString('en-AU',{minimumFractionDigits:0,maximumFractionDigits:0});
const days = d => Math.ceil((new Date(d)-new Date())/86400000);

function nav(id) {
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.getElementById('section-'+id).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>{if(b.getAttribute('onclick')?.includes("'"+id+"'"))b.classList.add('active')});
  if(id==='invoices')loadInvoices();
  else if(id==='bills')loadBills();
  else if(id==='payroll')loadPayroll();
  else if(id==='jobs')renderJobs();
  else if(id==='forecast')buildForecast();
}

async function api(url) {
  if(IS_DEMO) return demoData(url);
  const r = await fetch(url);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

function demoData(url) {
  if(url==='/api/summary') return {tenantName:'Creted Civil Pty Ltd (Demo)',totalReceivables:231111.01,totalPayables:46227.17,netPosition:184883.84,
    invoices:[{client:'Metro Asphalt Pty Ltd',ref:'INV#20261085',amount:171833.75,due:'2026-04-28',status:'AUTHORISED'},{client:'Novacon Group',ref:'INV#20261084',amount:59277.26,due:'2026-04-23',status:'AUTHORISED'}],
    bills:[{supplier:'Holcim Australia Pty Ltd',amount:10446.48,due:'2026-01-30',status:'OVERDUE'},{supplier:'Mesh & Bar Pty Ltd',amount:21801.97,due:'2026-04-15',status:'AUTHORISED'},{supplier:'Campbellfield Concrete',amount:13979.72,due:'2026-04-20',status:'AUTHORISED'}]};
  if(url==='/api/payroll') return {payRuns:[
    {startDate:'2026-03-01',endDate:'2026-03-07',paymentDate:'2026-03-07',wages:18310,super:2105.65,payg:3662,totalNetPay:14648},
    {startDate:'2026-03-08',endDate:'2026-03-14',paymentDate:'2026-03-14',wages:18310,super:2105.65,payg:3662,totalNetPay:14648}]};
  return {invoices:D.invoices,bills:D.bills};
}

async function loadDashboard() {
  try {
    const data = await api('/api/summary');
    D.invoices = data.invoices||[]; D.bills = data.bills||[];
    document.getElementById('sidebar-balance').textContent = fc(D.balance);
    document.getElementById('dash-sub').textContent = IS_DEMO ? 'Demo data — Creted Civil Pty Ltd' : 'Live data from '+data.tenantName+' · '+new Date().toLocaleTimeString('en-AU');
    const now=new Date(), d30=new Date(); d30.setDate(d30.getDate()+30);
    const od = D.invoices.filter(i=>days(i.due)<0).reduce((s,i)=>s+(i.amount||0),0);
    document.getElementById('dash-stats').innerHTML = \`
      <div class="stat"><div class="stat-lbl">Total Receivables</div><div class="stat-val">\${fc(data.totalReceivables)}</div><div class="stat-sub">unpaid invoices</div></div>
      <div class="stat \${od>0?'red':''}"><div class="stat-lbl">Overdue Invoices</div><div class="stat-val \${od>0?'neg':''}">\${fc(od)}</div><div class="stat-sub">\${od>0?'⚠ follow up now':'all current'}</div></div>
      <div class="stat amber"><div class="stat-lbl">Total Payables</div><div class="stat-val">\${fc(data.totalPayables)}</div><div class="stat-sub">outstanding bills</div></div>
      <div class="stat"><div class="stat-lbl">Net Position</div><div class="stat-val \${data.netPosition<0?'neg':''}">\${fc(data.netPosition)}</div><div class="stat-sub">receivables minus payables</div></div>\`;
    if(od>0) document.getElementById('dash-alerts').innerHTML = \`<div class="alert alert-amber">⚠️ <b>\${fc(od)}</b> in overdue invoices — chase these immediately</div>\`;
    const in30 = D.invoices.filter(i=>new Date(i.due)<=d30&&new Date(i.due)>=now).sort((a,b)=>new Date(a.due)-new Date(b.due));
    document.getElementById('dash-in').innerHTML = in30.length===0?'<div style="color:var(--muted);text-align:center;padding:16px;font-size:13px">No invoices due in next 30 days</div>':
      in30.slice(0,6).map(i=>\`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--sand);font-size:13px"><div><b>\${i.client||i.ref}</b><div style="font-size:11px;color:var(--muted)">Due \${i.due}</div></div><b style="color:var(--accent)">\${fc(i.amount)}</b></div>\`).join('');
    const out30 = D.bills.filter(b=>new Date(b.due)<=d30&&new Date(b.due)>=now).sort((a,b)=>new Date(a.due)-new Date(b.due));
    document.getElementById('dash-out').innerHTML = out30.length===0?'<div style="color:var(--muted);text-align:center;padding:16px;font-size:13px">No bills due in next 30 days</div>':
      out30.slice(0,6).map(b=>\`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--sand);font-size:13px"><div><b>\${b.supplier||'Supplier'}</b><div style="font-size:11px;color:var(--muted)">Due \${b.due}</div></div><b style="color:var(--danger)">\${fc(b.amount)}</b></div>\`).join('');
    toast('Data loaded ✓');
  } catch(e) {
    document.getElementById('dash-stats').innerHTML = \`<div class="alert alert-red">⚠ Failed to load: \${e.message} — <a href="/connect" style="color:var(--danger)">Reconnect Xero</a></div>\`;
  }
}

function buildForecast() {
  const threshold = parseFloat(document.getElementById('threshold')?.value)||10000;
  const weeklyOut = 22681;
  let balance = D.balance;
  const start = new Date(); start.setDate(start.getDate()-start.getDay()+1);
  const weeks = [];
  for(let w=0;w<52;w++) {
    const ws=new Date(start); ws.setDate(start.getDate()+w*7);
    const we=new Date(ws); we.setDate(ws.getDate()+6);
    const inflows = D.invoices.filter(i=>{const d=new Date(i.due);return d>=ws&&d<=we;}).reduce((s,i)=>s+(i.amount||0),0)
      + D.jobs.filter(j=>j.paymentDate&&new Date(j.paymentDate)>=ws&&new Date(j.paymentDate)<=we).reduce((s,j)=>s+(parseFloat(j.revenue)||0),0);
    const outflows = D.bills.filter(b=>{const d=new Date(b.due);return d>=ws&&d<=we;}).reduce((s,b)=>s+(b.amount||0),0)+weeklyOut;
    balance+=inflows-outflows;
    const mo=ws.toLocaleDateString('en-AU',{month:'short',year:'2-digit'});
    weeks.push({w:w+1,ws,we,inflows,outflows,balance,mo,isDanger:balance<threshold,isNeg:balance<0});
  }
  const maxFlow=Math.max(...weeks.map(w=>Math.max(w.inflows,w.outflows)),1);
  document.getElementById('forecast-rows').innerHTML = weeks.map(w=>\`<div class="week-row \${w.isNeg?'danger-row':w.isDanger?'amber-row':''}">
    <div class="wk-lbl">Wk \${w.w}</div><div class="wk-mo">\${w.mo}</div>
    <div class="wk-in">\${w.inflows>0?'+'+fc(w.inflows):'—'}</div>
    <div class="wk-out">\${w.outflows>0?'-'+fc(w.outflows):'—'}</div>
    <div class="wk-bal \${w.isNeg?'neg':w.isDanger?'low':'ok'}">\${fc(w.balance)}</div>
    <div class="wk-bar">
      \${w.inflows>0?\`<div class="bar-in" style="width:\${Math.min(Math.round(w.inflows/maxFlow*180),180)}px"></div>\`:''}
      \${w.outflows>0?\`<div class="bar-out" style="width:\${Math.min(Math.round(w.outflows/maxFlow*180),180)}px"></div>\`:''}
      \${w.isDanger?' <span style="font-size:11px;color:var(--danger)">⚠</span>':''}
    </div></div>\`).join('');
}

async function loadInvoices() {
  document.getElementById('inv-tbody').innerHTML = '<tr><td colspan="6" class="loading">Loading...</td></tr>';
  try {
    const data = IS_DEMO ? {invoices:D.invoices} : await api('/api/invoices');
    const invs = data.invoices||[];
    const total=invs.reduce((s,i)=>s+(i.amount||0),0), od=invs.filter(i=>days(i.due)<0).reduce((s,i)=>s+(i.amount||0),0);
    document.getElementById('inv-stats').innerHTML=\`<div class="stat"><div class="stat-lbl">Outstanding</div><div class="stat-val">\${fc(total)}</div></div><div class="stat \${od>0?'red':''}"><div class="stat-lbl">Overdue</div><div class="stat-val \${od>0?'neg':''}">\${fc(od)}</div></div><div class="stat"><div class="stat-lbl">Count</div><div class="stat-val">\${invs.length}</div></div>\`;
    document.getElementById('inv-tbody').innerHTML = invs.length===0?'<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">No outstanding invoices</td></tr>':
      invs.map(i=>{const d=days(i.due);return\`<tr><td><b>\${i.client||'—'}</b></td><td style="font-size:11px;color:var(--muted)">\${i.ref||'—'}</td><td><b>\${fc(i.amount)}</b></td><td style="color:\${d<0?'var(--danger)':d<=7?'var(--amber)':'inherit'}">\${i.due||'—'}</td><td style="color:\${d<0?'var(--danger)':d<=7?'var(--amber)':'inherit'};font-weight:\${d<=7?700:400}">\${d<0?Math.abs(d)+' OD':d+' days'}</td><td><span class="badge \${d<0?'br':d<=7?'ba':'bg'}">\${d<0?'Overdue':'Current'}</span></td></tr>\`;}).join('');
  } catch(e) { document.getElementById('inv-tbody').innerHTML=\`<tr><td colspan="6" style="color:var(--danger);padding:16px">Error: \${e.message}</td></tr>\`; }
}

async function loadBills() {
  document.getElementById('bill-tbody').innerHTML = '<tr><td colspan="5" class="loading">Loading...</td></tr>';
  try {
    const data = IS_DEMO ? {bills:D.bills} : await api('/api/bills');
    const bls = data.bills||[];
    const total=bls.reduce((s,b)=>s+(b.amount||0),0), od=bls.filter(b=>days(b.due)<0).reduce((s,b)=>s+(b.amount||0),0);
    document.getElementById('bill-stats').innerHTML=\`<div class="stat amber"><div class="stat-lbl">Outstanding</div><div class="stat-val">\${fc(total)}</div></div><div class="stat \${od>0?'red':''}"><div class="stat-lbl">Overdue</div><div class="stat-val \${od>0?'neg':''}">\${fc(od)}</div></div><div class="stat"><div class="stat-lbl">Count</div><div class="stat-val">\${bls.length}</div></div>\`;
    document.getElementById('bill-tbody').innerHTML = bls.length===0?'<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">No outstanding bills</td></tr>':
      bls.map(b=>{const d=days(b.due);return\`<tr><td><b>\${b.supplier||'—'}</b></td><td><b>\${fc(b.amount)}</b></td><td style="color:\${d<0?'var(--danger)':d<=7?'var(--amber)':'inherit'}">\${b.due||'—'}</td><td style="color:\${d<0?'var(--danger)':d<=7?'var(--amber)':'inherit'};font-weight:\${d<=7?700:400}">\${d<0?Math.abs(d)+' OD':d+' days'}</td><td><span class="badge \${d<0?'br':d<=7?'ba':'bg'}">\${d<0?'Overdue':'Current'}</span></td></tr>\`;}).join('');
  } catch(e) { document.getElementById('bill-tbody').innerHTML=\`<tr><td colspan="5" style="color:var(--danger);padding:16px">Error: \${e.message}</td></tr>\`; }
}

async function loadPayroll() {
  try {
    const data = await api('/api/payroll');
    const runs = data.payRuns||[];
    document.getElementById('payroll-tbody').innerHTML = runs.length===0?'<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">No pay runs. Requires Xero Payroll subscription.</td></tr>':
      runs.map(r=>\`<tr><td>\${r.startDate||'—'} – \${r.endDate||'—'}</td><td>\${r.paymentDate||'—'}</td><td><b>\${fc(r.wages)}</b></td><td style="color:var(--amber)">\${fc(r.super)}</td><td style="color:var(--orange)">\${fc(r.payg)}</td><td><b>\${fc(r.totalNetPay)}</b></td></tr>\`).join('');
  } catch(e) { document.getElementById('payroll-tbody').innerHTML=\`<tr><td colspan="6" style="color:var(--danger);padding:16px">Error: \${e.message}</td></tr>\`; }
}

function renderJobs() {
  const el=document.getElementById('jobs-content');
  if(D.jobs.length===0){el.innerHTML='<div style="text-align:center;padding:32px;color:var(--muted)">No jobs yet. Add upcoming jobs to see payment timing in the forecast.</div>';return;}
  el.innerHTML=\`<div class="card"><div class="card-hdr"><span class="card-title">Job Pipeline</span></div><div class="tbl-wrap"><table>
    <thead><tr><th>Job</th><th>Client</th><th>Revenue</th><th>Costs</th><th>Margin</th><th>Payment Date</th><th>Cash Gap</th><th>Status</th><th></th></tr></thead>
    <tbody>\${D.jobs.map((j,i)=>{const rev=parseFloat(j.revenue)||0,costs=parseFloat(j.costs)||0,margin=rev>0?((rev-costs)/rev*100).toFixed(1):0,gapDays=j.paymentDate&&j.endDate?Math.ceil((new Date(j.paymentDate)-new Date(j.endDate))/86400000):null,isLoss=parseFloat(margin)<0;
    return\`<tr><td><b>\${j.name}</b></td><td>\${j.client}</td><td style="color:var(--accent);font-weight:700">\${fc(rev)}</td><td style="color:var(--danger)">\${fc(costs)}</td>
    <td style="font-weight:700;color:\${isLoss?'var(--danger)':parseFloat(margin)>=20?'var(--accent)':'var(--amber)'}">\${margin}%</td>
    <td style="font-size:12px">\${j.paymentDate||'—'}</td>
    <td style="font-weight:700;color:\${gapDays&&gapDays>45?'var(--danger)':'inherit'}">\${gapDays?gapDays+' days\${gapDays>45?" ⚠":""}':'—'}</td>
    <td><span class="badge \${isLoss?'br':parseFloat(margin)>=20?'bg':'ba'}">\${isLoss?'Loss':parseFloat(margin)>=20?'On Target':'Below'}</span></td>
    <td><button class="btn btn-outline" onclick="deleteJob(\${i})" style="font-size:11px;padding:4px 8px">✕</button></td></tr>\`;}).join('')}
    </tbody></table></div></div>\`;
}

function previewJob() {
  const rev=parseFloat(document.getElementById('job-rev').value)||0,costs=parseFloat(document.getElementById('job-costs').value)||0;
  const terms=document.getElementById('job-terms').value,endDate=document.getElementById('job-end').value;
  if(!rev){document.getElementById('job-preview').textContent='Enter details above.';return;}
  const gp=rev-costs,margin=rev>0?(gp/rev*100).toFixed(1):0;
  let payDate='',gapDays=null;
  if(endDate){const end=new Date(endDate);
    if(terms==='30eom'){const p=new Date(end.getFullYear(),end.getMonth()+2,0);payDate=p.toLocaleDateString('en-AU');gapDays=Math.ceil((p-end)/86400000);}
    else if(terms==='14'){const p=new Date(end);p.setDate(p.getDate()+15);payDate=p.toLocaleDateString('en-AU');gapDays=15;}
    else if(terms==='30'){const p=new Date(end);p.setDate(p.getDate()+31);payDate=p.toLocaleDateString('en-AU');gapDays=31;}
  }
  const isLoss=parseFloat(margin)<0;
  document.getElementById('job-preview').innerHTML=\`<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px">
    <div>Revenue: <b style="color:var(--accent)">\${fc(rev)}</b></div><div>Costs: <b style="color:var(--danger)">\${fc(costs)}</b></div>
    <div>Gross profit: <b>\${fc(gp)}</b></div><div>Margin: <b style="color:\${isLoss?'var(--danger)':parseFloat(margin)>=20?'var(--accent)':'var(--amber)'}">\${margin}%</b></div>
    \${payDate?\`<div>Est. payment: <b>\${payDate}</b></div>\`:''}
    \${gapDays?\`<div>Cash gap: <b style="color:\${gapDays>45?'var(--danger)':'inherit'}">\${gapDays} days</b></div>\`:''}
  </div>
  \${isLoss?'<div class="alert alert-red" style="margin-top:8px">⛔ Loss-making. Do not accept without renegotiating rates.</div>':''}
  \${gapDays&&gapDays>45?'<div class="alert alert-amber" style="margin-top:8px">⚠ Large cash gap — consider requesting a progress claim.</div>':''}\`;
}

function saveJob() {
  const terms=document.getElementById('job-terms').value,endDate=document.getElementById('job-end').value;
  let paymentDate='';
  if(endDate){const end=new Date(endDate);
    if(terms==='30eom'){const p=new Date(end.getFullYear(),end.getMonth()+2,0);paymentDate=p.toISOString().substring(0,10);}
    else if(terms==='14'){const p=new Date(end);p.setDate(p.getDate()+15);paymentDate=p.toISOString().substring(0,10);}
    else if(terms==='30'){const p=new Date(end);p.setDate(p.getDate()+31);paymentDate=p.toISOString().substring(0,10);}
  }
  const j={name:document.getElementById('job-name').value,client:document.getElementById('job-client').value,
    startDate:document.getElementById('job-start').value,endDate,revenue:document.getElementById('job-rev').value,
    costs:document.getElementById('job-costs').value,terms,paymentDate};
  if(!j.name||!j.revenue){alert('Enter job name and revenue');return;}
  D.jobs.push(j);localStorage.setItem('rs_jobs',JSON.stringify(D.jobs));
  closeModal('job-modal');renderJobs();buildForecast();toast('Job added ✓');
}

function deleteJob(i){if(!confirm('Remove?'))return;D.jobs.splice(i,1);localStorage.setItem('rs_jobs',JSON.stringify(D.jobs));renderJobs();toast('Removed');}
function openModal(id){document.getElementById(id).classList.add('open');}
function closeModal(id){document.getElementById(id).classList.remove('open');}
document.querySelectorAll('.modal-overlay').forEach(o=>o.addEventListener('click',e=>{if(e.target===o)o.classList.remove('open');}));
function toast(msg){const tc=document.getElementById('toasts'),t=document.createElement('div');t.className='toast';t.textContent=msg;tc.appendChild(t);setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity 0.4s';setTimeout(()=>t.remove(),400);},3000);}

loadDashboard();
</script>
</body></html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Runsheet v1.1 running on port ${PORT}`));
