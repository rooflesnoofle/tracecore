document.addEventListener('DOMContentLoaded', function () {
    /* ==================================================================
       OSINTDog API config
       Uses local proxy (proxy.js) because osintdog.com lacks CORS headers
       ================================================================== */
    var OSINTDOG = {
        base: 'http://localhost:8787',
        key: 'fd568d8d-4aa4-4608-aa52-2adf78b1800a',
        fieldKeys: { ip: 'ip', domain: 'domain', email: 'email', phone: 'phone', username: 'username' },
        toolLabels: { ip: 'IP Intelligence', domain: 'Domain Intelligence', email: 'Email Intelligence',
                      phone: 'Phone Intelligence', username: 'Username Intelligence' }
    };

    var TOOL_ICONS = { ip: 'IP', domain: 'DM', email: 'EM', phone: 'PH', username: 'US' };

    /* ==================================================================
       OSINTDog service registry — every endpoint from the docs
       ================================================================== */
    var SVC = {
        /* --- DATA BREACH --- */
        snusbase:     { cat:'Data breach', label:'Snusbase',          ep:'/api/snusbase/search',      f:[{ k:'q',l:'Query',p:'email, username, hash...' }, { k:'t',l:'Type',s:['email','username','lastip','hash','password'] }], body:function(v){return {terms:[v.q],types:[v.t||'email'],wildcard:false}} },
        leakcheck:    { cat:'Data breach', label:'LeakCheck v2',      ep:'/api/leakcheck/v2',         f:[{ k:'q',l:'Query',p:'email, username, phone, domain, ip...' }, { k:'t',l:'Type',s:['auto','email','username','phone','domain','ip','hash'] }], body:function(v){return {term:v.q,search_type:v.t||'auto',limit:1000,offset:0}} },
        hackcheck:    { cat:'Data breach', label:'HackCheck',         ep:'/api/hackcheck',            f:[{ k:'q',l:'Query',p:'email, username, lastip...' }, { k:'t',l:'Type',s:['email','username','lastip'] }], body:function(v){return {term:v.q,search_type:v.t||'email'}} },
        breachbase:   { cat:'Data breach', label:'BreachBase',        ep:'/api/breachbase',           f:[{ k:'q',l:'Query',p:'email, username, lastip...' }, { k:'t',l:'Type',s:['email','username','lastip'] }], body:function(v){return {term:v.q,search_type:v.t||'email'}} },
        intelvault:   { cat:'Data breach', label:'IntelVault',        ep:'/api/intelvault',           f:[{ k:'q',l:'Query',p:'email, first_name, last_name...' }, { k:'t',l:'Mode',s:['breaches','stealer-logs'] }], body:function(v){return v.t==='stealer-logs'?{type:'stealer-logs',query:v.q}:{type:'breaches',field:[{first_name:v.q}],useWildcard:true}} },
        breachvip:    { cat:'Data breach', label:'BreachVIP',         ep:'/api/breachvip/search',     f:[{ k:'q',l:'Query',p:'email, username, phone, ip...' }, { k:'t',l:'Field',s:['email','username','password','domain','ip','phone','uuid','steamid','discordid'] }], body:function(v){return {term:v.q,fields:[v.t||'email'],wildcard:false,case_sensitive:false}} },
        leakosint:    { cat:'Data breach', label:'LeakOSINT',         ep:'/api/leakosint/search',     f:[{ k:'q',l:'Query',p:'email, phone, ip...' }, { k:'t',l:'Type',s:['email','phone','ip'] }], body:function(v){return {query:v.q,type:v.t||'email',lang:'en'}} },
        cypher:       { cat:'Data breach', label:'Cypher Dynamics',   ep:'/api/cypherdynamics/search', m:'GET', f:[{ k:'q',l:'Query',p:'email, username, email:pass...' }, { k:'t',l:'Type',s:['email','username','email_pass'] }], qp:function(v){return '?term='+encodeURIComponent(v.q)+'&type='+encodeURIComponent(v.t||'email')} },
        dropbase:     { cat:'Data breach', label:'Dropbase — Search', ep:'/api/dropbase/search',     f:[{ k:'q',l:'Query',p:'email, domain, username...' }, { k:'t',l:'Table',s:['breaches','malware'] }], body:function(v){return {table:v.t||'breaches',criteria:[{col:'email',val:v.q,wildcard:!v.q.includes('@')}],limit:500}} },
        dropbase_osint:{ cat:'Data breach', label:'Dropbase — OSINT', ep:'/api/dropbase/osint',      f:[{ k:'q',l:'Query',p:'email, username, phone, ip, domain...' }], body:function(v){return {query:v.q}} },
        dumpcat:      { cat:'Data breach', label:'Dump.cat — Init',   ep:'/api/dumpcat/search/init',  f:[{ k:'q',l:'Term',p:'email, username...' }], body:function(v){return {term:v.q,sort:2}} },
        intelx:       { cat:'Data breach', label:'IntelX',            ep:'/api/intelx',                m:'GET', f:[{ k:'q',l:'System ID',p:'uuid...' }], qp:function(v){return '?system_id='+encodeURIComponent(v.q)} },
        melissa:      { cat:'Data breach', label:'MELISSA',           ep:'/api/melissa/lookup',       f:[{ k:'q',l:'Input',p:'email, phone, name, or address' }], body:function(v){return {input:v.q}} },

        /* --- REGIONAL --- */
        rutify_rut:   { cat:'Regional', label:'Rutify — RUT',         ep:'/api/rutify/rut',           f:[{ k:'q',l:'RUT',p:'12345678-9' }], body:function(v){return {rut:v.q}} },
        rutify_name:  { cat:'Regional', label:'Rutify — Name',        ep:'/api/rutify/name',          f:[{ k:'q',l:'Full name',p:'Juan Pérez González' }], body:function(v){return {name:v.q}} },
        rutify_car:   { cat:'Regional', label:'Rutify — Vehicle',     ep:'/api/rutify/car',           f:[{ k:'q',l:'Plate',p:'ABCD12' }], body:function(v){return {plate:v.q}} },
        rutify_sii:   { cat:'Regional', label:'Rutify — SII',         ep:'/api/rutify/sii',           f:[{ k:'q',l:'RUT',p:'12345678-9' }], body:function(v){return {rut:v.q}} },
        akula:        { cat:'Regional', label:'Akula Database',       ep:'/api/akula',                f:[{ k:'q',l:'Query',p:'email, username, domain...' }, { k:'t',l:'Type',s:['email','username','domain'] }], body:function(v){return {searchTerm:v.q,search_type:v.t||'email'}} },
        leaksight:    { cat:'Regional', label:'LeakSight',            ep:'/api/leaksight',            f:[{ k:'q',l:'Query',p:'email, username, phone, domain, ip...' }, { k:'t',l:'Type',s:['email','username','phone','domain','ip','ipgeo'] }], body:function(v){return {term:v.q,search_type:v.t||'email'}} },

        /* --- SOCIAL & OSINT --- */
        room101:      { cat:'Social', label:'Room 101 (Reddit)',      ep:'/api/room101/analyze',       m:'GET', f:[{ k:'q',l:'Reddit username',p:'username' }], qp:function(v){return '/'+encodeURIComponent(v.q)} },
        room101_search:{ cat:'Social', label:'Room 101 — Search',     ep:'/api/room101/search',        m:'GET', f:[{ k:'q',l:'Keywords',p:'keyword' }], qp:function(v){return '?terms='+encodeURIComponent(v.q)} },
        'oathnet-h':   { cat:'Social', label:'OathNet — Holehe',      ep:'/api/oathnet/holehe',        m:'GET', f:[{ k:'q',l:'Email',p:'user@example.com' }], qp:function(v){return '?email='+encodeURIComponent(v.q)} },
        'oathnet-g':   { cat:'Social', label:'OathNet — GHunt',       ep:'/api/oathnet/ghunt',         m:'GET', f:[{ k:'q',l:'Email',p:'user@gmail.com' }], qp:function(v){return '?email='+encodeURIComponent(v.q)} },
        'oathnet-r':   { cat:'Social', label:'OathNet — Roblox',      ep:'/api/oathnet/roblox-userinfo', m:'GET', f:[{ k:'q',l:'Username',p:'player123' }], qp:function(v){return '?username='+encodeURIComponent(v.q)} },
        'oathnet-x':   { cat:'Social', label:'OathNet — Xbox',         ep:'/api/oathnet/xbox',          m:'GET', f:[{ k:'q',l:'XBL ID',p:'xuid...' }], qp:function(v){return '?xbl_id='+encodeURIComponent(v.q)} },
        'oathnet-dr':  { cat:'Social', label:'OathNet — Disc→Roblox',  ep:'/api/oathnet/discord-to-roblox', m:'GET', f:[{ k:'q',l:'Discord ID',p:'123456789...' }], qp:function(v){return '?discord_id='+encodeURIComponent(v.q)} },
        'oathnet-s':   { cat:'Social', label:'OathNet — Steam',       ep:'/api/oathnet/steam',         m:'GET', f:[{ k:'q',l:'Steam ID',p:'7656119...' }], qp:function(v){return '?steam_id='+encodeURIComponent(v.q)} },
        'oathnet-mc':  { cat:'Social', label:'OathNet — Minecraft',   ep:'/api/oathnet/mc-history',    m:'GET', f:[{ k:'q',l:'Username',p:'Notch' }], qp:function(v){return '?username='+encodeURIComponent(v.q)} },
        seon:         { cat:'Social', label:'SEON — Email',           ep:'/api/seon/email',            m:'GET', f:[{ k:'q',l:'Email',p:'user@example.com'                                 }], qp:function(v){return '?email='+encodeURIComponent(v.q)} },
        seon_phone:   { cat:'Social', label:'SEON — Phone',           ep:'/api/seon/phone',            m:'GET', f:[{ k:'q',l:'Phone',p:'+1234567890' }], qp:function(v){return '?phone='+encodeURIComponent(v.q)} },
        tiktokrecon:  { cat:'Social', label:'TikTok Recon',           ep:'/api/tiktokrecon',           f:[{ k:'q',l:'Username',p:'tiktoker123' }, { k:'t',l:'Type',s:['basic','full'] }], body:function(v){return {username:v.q,type:v.t||'basic'}} },

        /* --- SPECIALIZED --- */
        'inf0sec-leaks':   { cat:'Specialized', label:'INF0SEC — Leaks',     ep:'/api/inf0sec/leaks',    m:'GET', f:[{ k:'q',l:'Query',p:'email, username...' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-discord': { cat:'Specialized', label:'INF0SEC — Discord',   ep:'/api/inf0sec/discord',  m:'GET', f:[{ k:'q',l:'Query',p:'user ID, token...' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-npd':     { cat:'Specialized', label:'INF0SEC — NPD',       ep:'/api/inf0sec/npd',      m:'GET', f:[{ k:'q',l:'Query',p:'name, email...' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-domain':  { cat:'Specialized', label:'INF0SEC — Domain',    ep:'/api/inf0sec/domain',   m:'GET', f:[{ k:'q',l:'Domain',p:'example.com' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-username':{ cat:'Specialized', label:'INF0SEC — Username',  ep:'/api/inf0sec/username', m:'GET', f:[{ k:'q',l:'Username',p:'targetuser' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-hlr':     { cat:'Specialized', label:'INF0SEC — HLR',       ep:'/api/inf0sec/hlr',      m:'GET', f:[{ k:'q',l:'Phone',p:'+123456789' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'inf0sec-cfx':     { cat:'Specialized', label:'INF0SEC — CFX',       ep:'/api/inf0sec/cfx',      m:'GET', f:[{ k:'q',l:'Query',p:'identifier...' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'shodan-host':     { cat:'Specialized', label:'Shodan — Host',       ep:'/api/shodan/host',      f:[{ k:'q',l:'IP',p:'8.8.8.8' }], body:function(v){return {ip:v.q,history:false,minify:false}} },
        'shodan-search':   { cat:'Specialized', label:'Shodan — Search',     ep:'/api/shodan/search',    f:[{ k:'q',l:'Query string',p:'apache country:US' }], body:function(v){return {query:v.q,facets:'',page:1}} },
        'shodan-dns':      { cat:'Specialized', label:'Shodan — DNS',        ep:'/api/shodan/dns',       f:[{ k:'q',l:'Domain',p:'example.com' }], body:function(v){return {domain:v.q,history:false,type:'A',page:1}} },
        'shodan-exploits': { cat:'Specialized', label:'Shodan — Exploits',   ep:'/api/shodan/exploits',  f:[{ k:'q',l:'Query',p:'apache' }], body:function(v){return {query:v.q,facets:'',page:1}} },
        'shodan-honey':    { cat:'Specialized', label:'Shodan — Honeyscore', ep:'/api/shodan/honeyscore', f:[{ k:'q',l:'IP',p:'8.8.8.8' }], body:function(v){return {ip:v.q}} },
        'shodan-ports':    { cat:'Specialized', label:'Shodan — Ports',      ep:'/api/shodan/ports',      m:'GET', f:[], qp:function(){return ''} },
        'shodan-protocols':{ cat:'Specialized', label:'Shodan — Protocols',  ep:'/api/shodan/protocols',  m:'GET', f:[], qp:function(){return ''} },
        'shodan-api':      { cat:'Specialized', label:'Shodan — API Info',   ep:'/api/shodan/api-info',   m:'GET', f:[], qp:function(){return ''} },
        'intelfetch-gh':   { cat:'Specialized', label:'IntelFetch — GitHub', ep:'/api/intelfetch/github', m:'GET', f:[{ k:'q',l:'Username',p:'octocat' }], qp:function(v){return '?username='+encodeURIComponent(v.q)+'&extensive=true'} },
        'intelfetch-disc': { cat:'Specialized', label:'IntelFetch — Discord',ep:'/api/intelfetch/discord', m:'GET', f:[{ k:'q',l:'Discord ID / query',p:'123456789012345678' }], qp:function(v){return '?query='+encodeURIComponent(v.q)} },
        'intelfetch-ip':   { cat:'Specialized', label:'IntelFetch — IP',     ep:'/api/intelfetch/ip-lookup', f:[{ k:'q',l:'IP',p:'8.8.8.8' }], body:function(v){return {ip:v.q}} },
        'intelfetch-court':{ cat:'Specialized', label:'IntelFetch — Courts', ep:'/api/intelfetch/courtsearch', m:'GET', f:[{ k:'q',l:'Name',p:'John Smith' }], qp:function(v){return '?mode=name&terms='+encodeURIComponent(v.q)} },
        'intelfetch-mc':   { cat:'Specialized', label:'IntelFetch — MC',     ep:'/api/intelfetch/minecraft', m:'GET', f:[{ k:'q',l:'Server host',p:'hypixel.net' }], qp:function(v){return '?server='+encodeURIComponent(v.q)} },
        'intelfetch-dom':  { cat:'Specialized', label:'IntelFetch — Domain', ep:'/api/intelfetch/domain',  m:'GET', f:[{ k:'q',l:'Domain',p:'example.com' }], qp:function(v){return '?domain='+encodeURIComponent(v.q)} },
        'intelfetch-fb':   { cat:'Specialized', label:'IntelFetch — Fetchbase',ep:'/api/intelfetch/fetchbase', m:'GET', f:[{ k:'q',l:'Query',p:'email, username...' }], qp:function(v){return '?query='+encodeURIComponent(v.q)+'&size=50'} },
        'intelfetch-ent':  { cat:'Specialized', label:'IntelFetch — Enterprise',ep:'/api/intelfetch/enterprise', m:'GET', f:[{ k:'q',l:'Domain',p:'company.com' }], qp:function(v){return '?query='+encodeURIComponent(v.q)+'&size=50'} },
        'intelfetch-npd':  { cat:'Specialized', label:'IntelFetch — NPD',    ep:'/api/intelfetch/npd',      m:'GET', f:[{ k:'q',l:'Last name',p:'Smith' }], qp:function(v){return '?lastname='+encodeURIComponent(v.q)} },
        'intelfetch-crypto':{ cat:'Specialized', label:'IntelFetch — Crypto', ep:'/api/intelfetch/crypto', f:[{ k:'q',l:'Address',p:'1A1z...' }, { k:'t',l:'Type',s:['BTC','ETH','LTC'] }], body:function(v){return {crypto_type:v.t||'BTC',address:v.q}} },

        /* --- USER LOOKUPS --- */
        'genesis-disc':   { cat:'User Lookups', label:'Genesis — Discord',   ep:'/api/genesis/discord',   m:'GET', f:[{ k:'q',l:'Discord user ID',p:'123456789...' }], qp:function(v){return '?id='+encodeURIComponent(v.q)} },
        'genesis-steam':  { cat:'User Lookups', label:'Genesis — Steam',     ep:'/api/genesis/steam',     m:'GET', f:[{ k:'q',l:'Steam ID',p:'7656119...' }], qp:function(v){return '?id='+encodeURIComponent(v.q)} },
        'github-ue':      { cat:'User Lookups', label:'GitHub — User->Email',ep:'/api/github/usertoemail', m:'GET', f:[{ k:'q',l:'Username',p:'torvalds' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        'github-eu':      { cat:'User Lookups', label:'GitHub — Email->User',ep:'/api/github/emailtouser', m:'GET', f:[{ k:'q',l:'Email',p:'user@example.com' }], qp:function(v){return '?q='+encodeURIComponent(v.q)} },
        minecraft:        { cat:'User Lookups', label:'Minecraft OSINT',     ep:'/api/minecraft',          m:'GET', f:[{ k:'q',l:'Query',p:'Notch' }, { k:'t',l:'Type',s:['username','ip','password','email','uuid'] }], qp:function(v){return '?query='+encodeURIComponent(v.q)+'&type='+encodeURIComponent(v.t||'username')} },
        'discord-monitor':{ cat:'User Lookups', label:'Discord Monitor',     ep:'/api/discord-monitor',    m:'GET', f:[{ k:'q',l:'Discord user ID',p:'123456789...' }], qp:function(v){return '?query='+encodeURIComponent(v.q)} }
    };

    /* ==================================================================
       DOM refs
       ================================================================== */
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('overlay');
    var menuBtn = document.getElementById('menuBtn');
    var notifBtn = document.getElementById('notifBtn');
    var notifPop = document.getElementById('notifPop');
    var toastEl = document.getElementById('toast');
    var lookupInput = document.getElementById('lookupInput');
    var lookupBtn = document.getElementById('lookupBtn');
    var activityBody = document.getElementById('activityBody');
    var lookupCount = document.getElementById('lookupCount');
    var pages = document.querySelectorAll('.page');
    var apiKeyEl = document.getElementById('apiKey');
    var copyKey = document.getElementById('copyKey');
    var genKeyBtn = document.getElementById('genKeyBtn');
    var sourcesOnlineEl = document.getElementById('sourcesOnlineStat');
    var sourcesTrendEl = document.getElementById('sourcesTrend');
    var sourceStatusPanel = document.getElementById('sourceStatusPanel');
    var apiStatusTag = document.getElementById('apiStatusTag');

    /* ==================================================================
       Helpers
       ================================================================== */
    function esc(s) {
        return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function metric(label, value) {
        return '<div class="metric"><span>' + esc(label) + '</span><strong>' + value + '</strong></div>';
    }

    function parseBody(r) {
        return r.text().then(function (t) {
            var msg;
            if (!t) {
                if (r.status === 404) msg = 'Endpoint not found (404).';
                else if (r.status === 403) msg = 'Access denied (403) — rate limit or blocked.';
                else if (r.status === 429) msg = 'Rate limited (429) — too many requests. Wait and try again.';
                else msg = (r.ok ? 'Empty response' : 'HTTP ' + r.status + ' — no response body');
                var e = new Error(msg); e.status = r.status; e.body = { error: msg }; throw e;
            }
            // If non-OK with non-JSON body, show status + text preview
            if (!r.ok) {
                var isHtml = t.trim().startsWith('<') || !t.trim().startsWith('{');
                if (isHtml) {
                    if (r.status === 429) msg = 'Rate limited (429) — wait a moment before retrying.';
                    else if (r.status === 500) msg = 'Upstream server error (500).';
                    else msg = 'HTTP ' + r.status + ' — upstream returned a non-JSON response.';
                    var e = new Error(msg); e.status = r.status; e.body = { error: msg, text: t.slice(0, 300) }; throw e;
                }
            }
            try {
                var j = JSON.parse(t);
                if (!r.ok) {
                    var jmsg = 'HTTP ' + r.status;
                    if (j.error) jmsg += ': ' + j.error;
                    if (j.detail) jmsg += ': ' + j.detail;
                    var e = new Error(jmsg); e.status = r.status; e.body = j; throw e;
                }
                return j;
            } catch (se) {
                if (se.status) throw se;
                if (!r.ok) {
                    var e = new Error('HTTP ' + r.status + ' — non-JSON response'); e.status = r.status;
                    e.body = { error: 'Non-JSON response', text: t.slice(0, 500) }; throw e;
                }
                throw new Error('Invalid JSON in response');
            }
        });
    }

    function apiPost(path, body) {
        return fetch(OSINTDOG.base + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        }).then(parseBody);
    }

    function apiGet(path) {
        return fetch(OSINTDOG.base + path, { method: 'GET' }).then(parseBody);
    }

    /* ==================================================================
       Toast
       ================================================================== */
    var toastTimer = null;
    function toast(msg) {
        if (!toastEl) return;
        toastEl.innerHTML = '<span class="toast-ic"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6 9 17l-5-5"/></svg></span>' + msg;
        toastEl.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2600);
    }

    /* ==================================================================
       Page navigation
       ================================================================== */
    function showPage(name) {
        var target = document.getElementById('page-' + name);
        pages.forEach(function (p) { p.classList.remove('active'); });
        if (target) target.classList.add('active');
        document.querySelectorAll('.nav-item').forEach(function (n) {
            if (name === 'service') {
                n.classList.toggle('active', n.dataset.page === 'service' && n.dataset.service === currentSvc);
            } else {
                n.classList.toggle('active', n.dataset.page === name && !n.dataset.service);
            }
        });
        closeSidebar();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    document.querySelectorAll('.nav-item[data-page]').forEach(function (item) {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            if (item.dataset.page === 'service' && item.dataset.service) {
                showService(item.dataset.service);
            } else {
                showPage(item.dataset.page);
            }
        });
    });
    document.querySelectorAll('[data-goto]').forEach(function (el) {
        el.addEventListener('click', function (e) { e.preventDefault(); showPage(el.dataset.goto); });
    });

    function closeSidebar() {
        if (!sidebar) return;
        sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('show');
    }

    if (menuBtn) menuBtn.addEventListener('click', function () {
        sidebar.classList.toggle('open');
        if (overlay) overlay.classList.toggle('show');
    });
    if (overlay) overlay.addEventListener('click', closeSidebar);

    /* ==================================================================
       Status check — updates dashboard source stats on load
       ================================================================== */
    function checkStatus() {
        apiGet('/api/status').then(function (s) {
            var all = [];
            var cats = {};
            if (s.services) {
                Object.keys(s.services).forEach(function (k) {
                    var list = s.services[k];
                    cats[k === 'data_breach' ? 'Data breach' : 'Social / OSINT'] = (cats[k] || 0) + list.length;
                    list.forEach(function (n) { all.push(n); });
                });
            }
            if (sourcesOnlineEl) sourcesOnlineEl.textContent = all.length + '/' + all.length;
            if (sourcesTrendEl) sourcesTrendEl.innerHTML = '<span class="td-dot"></span>' + (s.status === 'online' ? 'All online' : 'Degraded');
            if (apiStatusTag) {
                apiStatusTag.innerHTML = '<i></i>' + s.status.toUpperCase();
                apiStatusTag.className = 'live-tag ' + (s.status === 'online' ? '' : 'warn-tag');
            }
            if (sourceStatusPanel) {
                var html = '';
                Object.keys(cats).forEach(function (k, i) {
                    var pct = 100 - i * 8;
                    html += '<div class="src-row"><span>' + k + '</span><i class="src-bar"><b style="width:' + pct + '%"></b></i><small>' + cats[k] + ' svc</small></div>';
                });
                sourceStatusPanel.innerHTML = html;
            }
        }).catch(function () {
            if (sourcesOnlineEl) sourcesOnlineEl.textContent = '–/–';
            if (apiStatusTag) { apiStatusTag.innerHTML = '<i></i>OFFLINE'; apiStatusTag.className = 'live-tag warn-tag'; }
        });
    }
    checkStatus();

    /* ==================================================================
       Notifications
       ================================================================== */
    if (notifBtn && notifPop) {
        notifBtn.addEventListener('click', function (e) { e.stopPropagation(); notifPop.classList.toggle('open'); });
        document.addEventListener('click', function (e) {
            if (notifPop && !notifPop.contains(e.target) && e.target !== notifBtn) notifPop.classList.remove('open');
        });
    }

    /* ==================================================================
       Dashboard quick lookup
       ================================================================== */
    var chips = document.querySelectorAll('.chip');
    chips.forEach(function (chip) {
        chip.addEventListener('click', function () {
            chips.forEach(function (c) { c.classList.remove('active'); });
            chip.classList.add('active');
            if (lookupInput) lookupInput.placeholder = 'Enter ' + chip.dataset.type + '...';
        });
    });

    var pool = {
        ip:       { tag: 'IP',      cls: 'tag-ip',     samples: ['198.51.100.22', '192.0.2.141', '203.0.113.90'] },
        domain:   { tag: 'DOMAIN',  cls: 'tag-domain', samples: ['coldstream.example', 'netscope.example', 'darksurf.io'] },
        email:    { tag: 'EMAIL',   cls: 'tag-email',  samples: ['m.vega@corpmail.com', 'tracer_7@anonbox.org', 'k.novak@mail.link'] },
        phone:    { tag: 'PHONE',   cls: 'tag-phone',  samples: ['+44 20 7946 0958', '+1 (555) 042-8812', '+49 151 2233 4477'] },
        username: { tag: 'USERNAME',cls: 'tag-user',   samples: ['ghostwire', 'nullbyte_42', 'sapphire.lee'] }
    };
    var confs = ['92%', '86%', '97%', '74%', '89%'];

    function recordCount(data) {
        var results = data.results || {};
        var total = 0;
        Object.keys(results).forEach(function (k) {
            var s = results[k];
            if (!s || typeof s !== 'object' || s.status === 'failed') return;
            if (Array.isArray(s.results)) total += s.results.length;
            else if (s.results && typeof s.results === 'object') total += Object.keys(s.results).length;
            else if (typeof s.size === 'number') total += s.size;
        });
        return total;
    }

    function svcCount(data) {
        var results = data.results || {};
        return Object.keys(results).filter(function (k) {
            var s = results[k];
            return s && typeof s === 'object' && s.status !== 'failed';
        }).length;
    }

    function runLookup() {
        var active = document.querySelector('.chip.active');
        var type = active ? active.dataset.type : 'username';
        var p = pool[type] || pool.username;
        var query = (lookupInput.value || '').trim() || p.samples[Math.floor(Math.random() * p.samples.length)];
        var fieldObj = {};
        fieldObj[OSINTDOG.fieldKeys[type]] = query;

        lookupInput.value = '';

        apiPost('/api/search', { field: [fieldObj] }).then(function (data) {
            var matches = recordCount(data);
            var srcs = svcCount(data);
            insertActivityRow(p, query, matches, srcs, data.success ? '92%' : '—');
            lookupCount.textContent = parseInt(lookupCount.textContent, 10) + 1;
            toast('Live trace: <strong>' + esc(query) + '</strong> — ' + matches + ' records, ' + srcs + ' services');
        }).catch(function () {
            var matches = 1 + Math.floor(Math.random() * 12);
            var srcs = 3 + Math.floor(Math.random() * 14);
            var conf = confs[Math.floor(Math.random() * confs.length)];
            insertActivityRow(p, query, matches, srcs, conf);
            lookupCount.textContent = parseInt(lookupCount.textContent, 10) + 1;
            toast('Demo trace: <strong>' + esc(query) + '</strong> (' + matches + ' matches) — proxy offline');
        });
        lookupInput.focus();
    }

    function insertActivityRow(p, query, matches, srcs, conf) {
        var row = document.createElement('tr');
        row.innerHTML =
            '<td><span class="tag ' + p.cls + '">' + p.tag + '</span></td>' +
            '<td class="mono">' + esc(query) + '</td>' +
            '<td>' + matches + '</td>' +
            '<td>' + srcs + '</td>' +
            '<td><span class="conf' + (parseInt(conf) < 80 ? ' low' : '') + '">' + conf + '</span></td>' +
            '<td class="muted">now</td>';
        activityBody.insertBefore(row, activityBody.firstChild);
        while (activityBody.children.length > 8) activityBody.removeChild(activityBody.lastChild);
    }

    if (lookupBtn) lookupBtn.addEventListener('click', runLookup);
    if (lookupInput) lookupInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') runLookup(); });

    /* ==================================================================
       Tool pages — real API traces
       ================================================================== */
    document.querySelectorAll('.run-btn').forEach(function (btn) {
        btn.addEventListener('click', function () { runTool(btn.dataset.tool); });
    });
    document.querySelectorAll('.ex[data-tool]').forEach(function (el) {
        el.addEventListener('click', function () {
            var tool = el.dataset.tool;
            var input = document.querySelector('.tool-input[data-query="' + tool + '"]');
            if (input) input.value = el.textContent.trim();
            runTool(tool);
        });
    });
    document.querySelectorAll('.tool-row input').forEach(function (input) {
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') {
                var tool = input.dataset.query;
                if (tool) runTool(tool);
            }
        });
    });

    function runTool(tool) {
        var result = document.getElementById('result-' + tool);
        var input = document.querySelector('.tool-input[data-query="' + tool + '"]');
        var query = (input && input.value.trim()) || 'sample query';
        if (!result) return;

        result.classList.add('loading');
        result.innerHTML =
            '<div class="result-empty"><span class="loading-spin"></span><h3>Querying OSINTDog...</h3>' +
            '<p>Tracing <span class="mono" style="color:var(--indigo)">' + esc(query) + '</span> across LeakCheck &amp; HackCheck</p></div>';

        var fieldObj = {};
        fieldObj[OSINTDOG.fieldKeys[tool]] = query;
        var started = Date.now();

        apiPost('/api/search', { field: [fieldObj] }).then(function (data) {
            result.classList.remove('loading');
            result.innerHTML = renderSearch(tool, query, data, Date.now() - started);
            toast('OSINTDog trace done — <strong>' + esc(query) + '</strong>');
            if (lookupCount) lookupCount.textContent = parseInt(lookupCount.textContent, 10) + 1;
        }).catch(function (err) {
            result.classList.remove('loading');
            result.innerHTML = renderError(tool, query, err);
        });
    }

    /* ==================================================================
       API result renderer
       ================================================================== */
    function lat(ms) {
        return '<span class="res-latency"><span class="ok-dot"></span>' + (ms / 1000).toFixed(1) + 's</span>';
    }

    function svcBadge(svc) {
        if (!svc || svc.status === 'failed' || svc.error) {
            return '<span class="svc-badge fail">' + (svc && svc.http_status ? 'HTTP ' + svc.http_status : 'FAILED') + '</span>';
        }
        return '<span class="svc-badge ok">OK</span>';
    }

    var COL_ORDER = ['email', 'username', 'full_name', 'phone_number', 'ip_address', 'password', 'hash'];

    function rowsTable(rows) {
        var cols = [];
        var seen = {};
        COL_ORDER.forEach(function (k) {
            if (rows.some(function (r) { return r[k] !== undefined && r[k] !== null && r[k] !== ''; })) {
                cols.push(k);
                seen[k] = true;
            }
        });
        rows.forEach(function (r) {
            Object.keys(r).forEach(function (k) {
                if (!seen[k] && k !== 'id' && k !== 'other_fields' && k !== 'sensitive_fields' && k !== 'source') {
                    cols.push(k);
                    seen[k] = true;
                }
            });
        });
        if (rows.some(function (r) { return r.source; })) cols.push('source');
        if (cols.length > 6) cols = cols.slice(0, 6);

        var head = '<tr>' + cols.map(function (c) { return '<th>' + c.replace(/_/g, ' ') + '</th>'; }).join('') + '</tr>';
        var body = rows.slice(0, 50).map(function (r) {
            return '<tr>' + cols.map(function (c) {
                var v = r[c];
                if (c === 'source' && v && typeof v === 'object') v = (v.name || '') + (v.date ? ' · ' + v.date : '');
                var sv = String(v == null || v === '' ? '—' : v);
                if (sv.length > 70) sv = sv.slice(0, 67) + '…';
                return '<td class="mono">' + esc(sv) + '</td>';
            }).join('') + '</tr>';
        }).join('');

        var more = rows.length > 50 ? '<p class="svc-more">Showing first 50 of ' + rows.length + ' entries</p>' : '';
        return '<div class="svc-table-wrap table-wrap"><table><thead>' + head + '</thead><tbody>' + body + '</tbody></table></div>' + more;
    }

    function renderSvcCard(name, svc) {
        if (!svc || svc.status === 'failed' || svc.error) {
            return '<div class="svc-card svc-fail"><div class="svc-head"><strong>' + esc(name) + '</strong>' + svcBadge(svc) + '</div>' +
                   '<p class="svc-err">' + esc(svc && (svc.error || svc.errors) ? String(svc.error || svc.errors) : 'No data returned') + '</p></div>';
        }
        var inner = '';
        if (Array.isArray(svc.results)) {
            inner = rowsTable(svc.results);
        } else if (svc.results && typeof svc.results === 'object') {
            var keys = Object.keys(svc.results);
            inner = '<div class="kv-list">' + keys.slice(0, 30).map(function (k) {
                var val = svc.results[k] === '' ? '—' : esc(String(svc.results[k] || '').trim());
                return '<div class="kv"><span title="' + esc(k) + '">' + esc(k.length > 48 ? k.slice(0, 45) + '…' : k) + '</span><code>' + val + '</code></div>';
            }).join('') + '</div>';
            if (keys.length > 30) inner += '<p class="svc-more">' + keys.length + ' databases matched</p>';
        } else if (typeof svc.size === 'number') {
            inner = '<div class="metric-grid"><div class="metric"><span>Records</span><strong>' + svc.size + '</strong></div></div>';
        }
        var took = svc.took != null ? '<span class="svc-took">' + (Number(svc.took)).toFixed(1) + 'ms</span>' : '';
        return '<div class="svc-card"><div class="svc-head"><strong>' + esc(name) + '</strong>' + svcBadge(svc) + took + '</div>' + inner + '</div>';
    }

    function renderSearch(tool, query, data, ms, label) {
        var title = label || OSINTDOG.toolLabels[tool] || tool;
        var results = data.results;
        if (!results && data.data) results = data.data;

        // Detect response shape
        var isServiceNamespace = results && typeof results === 'object' && !Array.isArray(results) &&
            Object.keys(results).length > 0 &&
            Object.keys(results).every(function (k) {
                var v = results[k];
                return v && typeof v === 'object' && !Array.isArray(v) &&
                    ('status' in v || 'took' in v || 'results' in v || 'size' in v || 'error' in v || 'http_status' in v);
            });

        if (isServiceNamespace) {
            // Multi-service response (Snusbase, HackCheck, etc.)
            return renderMultiService(title, query, data, results, ms);
        }

        // Single-service / flat / array response
        return renderGeneric(title, query, data, results, ms);
    }

    function renderMultiService(title, query, data, results, ms) {
        var svcKeys = Object.keys(results).filter(function (k) { return results[k] !== null; });
        var liveSvcs = svcKeys.filter(function (k) { var s = results[k]; return s && typeof s === 'object' && s.status !== 'failed'; }).length;
        var totalRecords = recordCount(data);
        var cards = svcKeys.map(function (k) { return renderSvcCard(k, results[k]); }).join('');
        return [
            '<div class="result-head"><div><h3>' + title + '</h3><span class="result-query">' + esc(query) + '</span></div>' + lat(ms) + '</div>',
            '<div class="metric-grid">',
            '<div class="metric"><span>Search type</span><strong>' + (data.search_type || tool) + '</strong></div>',
            '<div class="metric"><span>Status</span><strong>' + (data.success ? '&#10003; OK' : 'Failed') + '</strong></div>',
            '<div class="metric"><span>Services</span><strong>' + liveSvcs + ' / ' + svcKeys.length + '</strong></div>',
            '<div class="metric"><span>Records found</span><strong>' + totalRecords + '</strong></div>',
            '</div>',
            cards || '<p class="svc-err">No results returned from any service.</p>',
            '<details class="raw-details"><summary>Raw JSON response</summary><pre class="json-view">' + esc(JSON.stringify(data, null, 2)) + '</pre></details>',
            '<p class="powered">Powered by <strong>OSINTDog</strong> — lookup via osintdog.com</p>'
        ].join('');
    }

    function renderGeneric(title, query, data, results, ms) {
        var metrics = [];
        if (data.success !== undefined)      metrics.push(metric('Status', data.success ? '&#10003; OK' : 'Failed'));
        if (data.service)                    metrics.push(metric('Service', data.service));
        if (data.search_term || data.query)  metrics.push(metric('Query', data.search_term || data.query));
        if (data.sources_count)              metrics.push(metric('Sources', data.sources_count));
        if (data.total_entries != null)      metrics.push(metric('Entries', data.total_entries));
        while (metrics.length < 4 && metrics.length < Object.keys(data).length + 2) { metrics.push(metric('Response', 'Loaded')); if (metrics.length >= 4) break; }
        if (metrics.length > 4) metrics = metrics.slice(0, 4);

        // Build a flat KV list from whatever data we have
        var source = results;
        if (!source || typeof source !== 'object' || Object.keys(source).length === 0) source = data;

        var kvHtml = '';
        function addKv(key, val) {
            var display;
            if (val === null || val === undefined || val === '') display = '<span class="muted">—</span>';
            else if (typeof val === 'object') display = '<code class="muted">' + esc(JSON.stringify(val).slice(0, 140)) + '</code>';
            else display = '<code>' + esc(String(val).slice(0, 240)) + '</code>';
            kvHtml += '<div class="kv"><span>' + esc(String(key).slice(0, 48)) + '</span>' + display + '</div>';
        }

        var srcKeys = Object.keys(source);
        if (srcKeys.length > 0) {
            // Show first 20 keys
            srcKeys.slice(0, 20).forEach(function (k) {
                if (k === 'success' || k === 'credit' || k === 'service' || k === 'search_term') return;
                addKv(k, source[k]);
            });
            if (srcKeys.length > 20) kvHtml += '<div class="kv"><span class="muted">...' + (srcKeys.length - 20) + ' more fields</span><code class="muted">see raw JSON</code></div>';
        }

        return [
            '<div class="result-head"><div><h3>' + title + '</h3><span class="result-query">' + esc(query) + '</span></div>' + lat(ms) + '</div>',
            metrics.length ? '<div class="metric-grid">' + metrics.join('') + '</div>' : '',
            kvHtml ? '<div class="kv-list">' + kvHtml + '</div>' : '<p class="svc-err">No data returned.</p>',
            '<details class="raw-details"><summary>Raw JSON response</summary><pre class="json-view">' + esc(JSON.stringify(data, null, 2)) + '</pre></details>',
            '<p class="powered">Powered by <strong>OSINTDog</strong> — lookup via osintdog.com</p>'
        ].join('');
    }

    function renderError(tool, query, err) {
        var msg = '';
        var isNet = err && err.message === 'Failed to fetch';
        if (isNet) {
            msg = 'Network error — is the proxy running?<br><code style="font-size:12px;color:var(--muted)">node proxy.js</code>';
        } else if (err && err.body && err.body.error) {
            msg = '<span class="svc-err">' + esc(String(err.body.error)) + '</span>';
        } else {
            msg = esc(String(err.message || err));
        }
        var tip = isNet
            ? '<div class="tool-tip" style="margin-top:14px"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16v.01"/></svg>Make sure <code>node proxy.js</code> is running on <code>http://localhost:8787</code>.</div>'
            : '';
        return [
            '<div class="result-head"><div><h3>Trace failed</h3><span class="result-query">' + esc(query) + '</span></div><span class="muted">Error</span></div>',
            '<div class="svc-card svc-fail"><div class="svc-head"><strong>OSINTDog API</strong><span class="svc-badge fail">ERROR</span></div>',
            msg, '</div>',
            tip
        ].join('');
    }

    /* ==================================================================
       Dynamic service page (sidebar lookup tools)
       ================================================================== */
    var currentSvc = null;

    function showService(id) {
        var s = SVC[id];
        if (!s) return;
        currentSvc = id;
        showPage('service');

        var svcCat = document.getElementById('svcCat');
        var svcTitle = document.getElementById('svcTitle');
        var svcForm = document.getElementById('svcForm');
        var resultSvc = document.getElementById('result-service');

        if (svcCat) svcCat.textContent = s.cat.toUpperCase();
        if (svcTitle) svcTitle.textContent = s.label;

        if (svcForm) {
            var html = '<div class="tool-label"><span class="dot-ic">' + s.cat.slice(0, 2).toUpperCase() + '</span><h3>' + s.label + '</h3></div>';
            s.f.forEach(function (f, i) {
                var isLast = i === s.f.length - 1;
                if (f.s) {
                    html += '<div class="field" style="margin-bottom:12px"><label>' + f.l + '</label><select class="svc-input" data-key="' + f.k + '" style="border:1px solid var(--border-2);border-radius:10px;padding:9px 12px;font-size:13.5px;background:var(--panel);color:var(--text);outline:none;width:100%">';
                    f.s.forEach(function (o) { html += '<option>' + o + '</option>'; });
                    html += '</select></div>';
                }
            });
            s.f.filter(function (f) { return !f.s; }).forEach(function (f) {
                html += '<div class="tool-row" style="margin-top:' + (s.f.length > 2 ? '6px' : '0') + '"><input type="text" class="svc-input" data-key="' + f.k + '" placeholder="' + f.p + '" style="flex:1;min-width:0;border:1px solid var(--border-2);border-radius:11px;padding:10px 14px;font-size:13.5px;font-family:var(--mono);outline:none;color:var(--text);background:var(--panel)"><button class="btn btn-primary svc-run">Run</button></div>';
            });
            if (s.f.length === 0) {
                html += '<button class="btn btn-primary svc-run" style="width:100%;justify-content:center">Run Query</button>';
            }
            svcForm.innerHTML = html;
            bindSvcHandlers();
        }

        if (resultSvc) {
            resultSvc.innerHTML = '<div class="result-empty"><svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16v.01"/></svg><h3>' + s.label + '</h3><p>Enter a query and press <strong>Run</strong> to call this OSINTDog endpoint.</p></div>';
        }
    }

    function bindSvcHandlers() {
        document.querySelectorAll('.svc-run').forEach(function (b) {
            b.removeEventListener('click', runSvcCall);
            b.addEventListener('click', runSvcCall);
        });
        document.querySelectorAll('.svc-input[type="text"]').forEach(function (inp) {
            inp.addEventListener('keydown', function (e) { if (e.key === 'Enter') runSvcCall(); });
        });
    }

    function runSvcCall() {
        if (!currentSvc || !SVC[currentSvc]) return;
        var s = SVC[currentSvc];
        var vals = {};
        document.querySelectorAll('.svc-input').forEach(function (el) { vals[el.dataset.key] = (el.value || '').trim(); });
        var query = vals.q || '';
        var resultSvc = document.getElementById('result-service');
        if (!resultSvc) return;

        resultSvc.classList.add('loading');
        resultSvc.innerHTML = '<div class="result-empty"><span class="loading-spin"></span><h3>Calling ' + s.label + '...</h3><p><span class="mono" style="color:var(--indigo)">' + esc(query) + '</span></p></div>';

        var started = Date.now();
        var promise;
        if (s.method === 'GET' && s.qp) {
            promise = apiGet(s.ep + s.qp(vals));
        } else {
            promise = apiPost(s.ep, s.body ? s.body(vals) : { term: query });
        }

        promise.then(function (data) {
            resultSvc.classList.remove('loading');
            resultSvc.innerHTML = renderSearch('service', query, data, Date.now() - started, s.label);
            toast(s.label + ' — done');
            if (lookupCount) lookupCount.textContent = parseInt(lookupCount.textContent, 10) + 1;
        }).catch(function (err) {
            resultSvc.classList.remove('loading');
            resultSvc.innerHTML = renderError('service', query, err);
        });
    }

    /* ==================================================================
       New investigation
       ================================================================== */
    var caseGrid = document.getElementById('caseGrid');
    var caseSeq = 230;

    function newCase() {
        var cid = 'A-' + caseSeq++;
        var card = document.createElement('div');
        card.className = 'case-card';
        card.style.opacity = '0';
        card.style.transform = 'translateY(12px)';
        card.style.transition = 'opacity .4s ease, transform .4s ease';
        card.innerHTML =
            '<div class="case-top"><span class="case-id">' + cid + '</span><span class="badge-st status-active"><span class="sd"></span>ACTIVE</span></div>' +
            '<h3>Untitled investigation</h3>' +
            '<p class="case-desc">New case created from the console. Add a target to begin tracing.</p>' +
            '<div class="case-meta"><div><span>Target</span><strong class="mono">—</strong></div><div><span>Type</span><strong>—</strong></div></div>' +
            '<div class="case-progress"><i><b style="width:0%"></b></i><small>0% coverage</small></div>' +
            '<div class="case-foot"><span class="muted">Just now</span><button class="icon-btn" data-goto="dashboard">Set target</button></div>';

        if (caseGrid) {
            caseGrid.insertBefore(card, caseGrid.firstChild);
            requestAnimationFrame(function () { card.style.opacity = '1'; card.style.transform = 'none'; });
            card.querySelector('[data-goto]').addEventListener('click', function (e) { e.preventDefault(); showPage('dashboard'); });
        }
        toast('Investigation <strong>' + cid + '</strong> created');
        showPage('investigations');
    }

    var newInvBtns = document.querySelectorAll('#newInvTop, #newInvestBtn, [data-new-case]');
    newInvBtns.forEach(function (b) { b.addEventListener('click', newCase); });

    /* ==================================================================
       API & Keys page
       ================================================================== */
    if (copyKey) copyKey.addEventListener('click', function () {
        navigator.clipboard && navigator.clipboard.writeText(OSINTDOG.key);
        toast('OSINTDog API key copied to clipboard');
    });

    if (genKeyBtn) genKeyBtn.addEventListener('click', function () {
        checkStatus();
        toast('Pinging OSINTDog status endpoint via proxy...');
    });

    /* ==================================================================
       Reports download
       ================================================================== */
    document.querySelectorAll('[data-dl]').forEach(function (b) {
        b.addEventListener('click', function () {
            toast('Exporting <strong>' + b.dataset.dl + '</strong> as PDF...');
        });
    });

    /* ==================================================================
       Global search shortcut
       ================================================================== */
    document.addEventListener('keydown', function (e) {
        var tag = e.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        if (e.key === '/') {
            e.preventDefault();
            var gs = document.getElementById('globalSearch');
            if (gs) gs.focus();
        }
    });

    /* ==================================================================
       Live feed ticker
       ================================================================== */
    var feedMessages = [
        ['fc-warn', '<strong>Breach watch</strong> — 2 new credential pairs indexed.'],
        ['fc-info', '<strong>Username Search</strong> — new profile matched for "ghostwire".'],
        ['fc-ok', '<strong>IP Lookup</strong> — geolocation refresh for relay node 14.'],
        ['fc-info', '<strong>Domain OSINT</strong> — cert transparency diff complete.']
    ];
    var feedIdx = 0;
    setInterval(function () {
        var feed = document.getElementById('liveFeed');
        if (!feed) return;
        var msg = feedMessages[feedIdx++ % feedMessages.length];
        var item = document.createElement('div');
        item.className = 'feed-item';
        item.innerHTML =
            '<span class="feed-ic ' + msg[0] + '"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 2 20h20L12 3z"/></svg></span>' +
            '<p>' + msg[1] + '</p><small>just now</small>';
        feed.insertBefore(item, feed.firstChild);
        while (feed.children.length > 5) feed.removeChild(feed.lastChild);
    }, 9000);
});
