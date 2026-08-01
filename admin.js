document.addEventListener('DOMContentLoaded', function () {
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('overlay');
    var menuBtn = document.getElementById('menuBtn');
    var toastEl = document.getElementById('toast');
    var pages = document.querySelectorAll('.page');
    var userPanel = document.getElementById('userPanel');
    var userOverlay = document.getElementById('userModalOverlay');
    var currentUser = null;

    /* ---------- Toast ---------- */
    var toastTimer = null;
    function toast(msg) {
        if (!toastEl) return;
        toastEl.innerHTML = '<span class="toast-ic"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6 9 17l-5-5"/></svg></span>' + msg;
        toastEl.classList.add('show');
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2600);
    }

    /* ---------- Page nav ---------- */
    function showPage(name) {
        var target = document.getElementById('page-' + name);
        if (!target) return;
        pages.forEach(function (p) { p.classList.remove('active'); });
        target.classList.add('active');
        document.querySelectorAll('.nav-item').forEach(function (n) {
            n.classList.toggle('active', n.dataset.page === name);
        });
        closeSidebar();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    document.querySelectorAll('.nav-item[data-page]').forEach(function (item) {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            showPage(item.dataset.page);
        });
    });

    document.querySelectorAll('[data-goto]').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            showPage(el.dataset.goto);
        });
    });

    /* ---------- Sidebar mobile ---------- */
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

    /* ---------- User management panel ---------- */
    var userData = [
        { name:'Aiden K.',     email:'aiden@tracecore.io',   plan:'Investigator', lookups:'847 / Unlimited', joined:'Mar 11, 2026', last:'2 min ago', ip:'192.0.2.141', keys:['tc_live_4f8a2c9d71b3e5a0','tc_live_9d4f1a7c2e8bf3a1'], status:'active', initials:'AK', color:'#6366f1' },
        { name:'Marcus R.',    email:'marcus@tracecore.io',  plan:'Operations',    lookups:'2,104 / Unlimited', joined:'Feb 3, 2026', last:'14 min ago', ip:'198.51.100.22', keys:['tc_live_b72c3a8d14e2','tc_live_5a22f9c','tc_live_88d3a','tc_live_21ef7'], status:'active', initials:'MR', color:'#f59e0b' },
        { name:'Sasha L.',     email:'sasha.l@corp.com',     plan:'Operations',    lookups:'1,582 / Unlimited', joined:'Jan 17, 2026', last:'8 min ago', ip:'203.0.113.45', keys:['tc_live_c8d7b2a4'], status:'active', initials:'SL', color:'#8b5cf6' },
        { name:'James M.',     email:'james@secure.io',      plan:'Scout',         lookups:'42 / 50', joined:'Jul 28, 2026', last:'3 hrs ago', ip:'203.0.113.90', keys:['tc_live_12efb7'], status:'idle', initials:'JM', color:'#98a2b3' },
        { name:'Rita K.',      email:'rita@startup.dev',     plan:'Scout',         lookups:'0 / 50', joined:'Jul 14, 2026', last:'2 days ago', ip:'203.0.113.45', keys:[], status:'suspended', initials:'RK', color:'#f43f5e' },
        { name:'Tomas P.',     email:'tomas@agency.io',      plan:'Investigator',  lookups:'612 / Unlimited', joined:'Apr 22, 2026', last:'1 hr ago', ip:'198.51.100.12', keys:['tc_live_77ab3'], status:'active', initials:'TP', color:'#10b981' },
        { name:'Nina W.',      email:'nina@startup.dev',     plan:'Scout',         lookups:'28 / 50', joined:'Jun 5, 2026', last:'6 hrs ago', ip:'192.0.2.88', keys:['tc_live_f4e21'], status:'active', initials:'NW', color:'#ec4899' },
        { name:'Dan H.',       email:'dan.h@altmail.io',     plan:'Investigator',  lookups:'1,982 / Unlimited', joined:'Jan 8, 2026', last:'22 min ago', ip:'198.51.100.44', keys:['tc_live_2e1a7','tc_live_9ca3f','tc_live_41d88'], status:'active', initials:'DH', color:'#38bdf8' }
    ];

    function openUserPanel(data) {
        currentUser = data;
        document.getElementById('upAvatar').textContent = data.initials;
        document.getElementById('upAvatar').style.background = data.color;
        document.getElementById('upName').textContent = data.name;
        document.getElementById('upEmail').textContent = data.email;
        document.getElementById('upPlan').textContent = data.plan;
        document.getElementById('upLookups').textContent = data.lookups;
        document.getElementById('upJoined').textContent = data.joined;
        document.getElementById('upLastActive').textContent = data.last;
        document.getElementById('upIP').textContent = data.ip;
        document.getElementById('upKeys').textContent = data.keys.length + ' active';
        document.getElementById('upPlanSelect').value = data.plan.toLowerCase();

        // Status
        var st = document.getElementById('upStatus');
        st.className = 'up-status ' + data.status + '-st';
        st.textContent = data.status.charAt(0).toUpperCase() + data.status.slice(1);

        // Keys
        var keyList = document.getElementById('upKeyList');
        if (data.keys.length) {
            keyList.innerHTML = data.keys.map(function(k) {
                return '<div class="up-key"><code>' + k + '</code><span class="key-tag ok">Active</span><button class="key-revoke" data-action="revoke-key">Revoke</button></div>';
            }).join('');
        } else {
            keyList.innerHTML = '<p class="muted" style="font-size:13px;padding:8px 0">No API keys generated.</p>';
        }
        bindKeyRevoke();

        // Update danger buttons based on status
        var isBanned = data.status === 'banned';
        document.getElementById('btnSuspend').style.display = isBanned ? 'none' : '';
        document.getElementById('btnSuspend').textContent = data.status === 'suspended' ? 'Unsuspend user' : 'Suspend user';
        document.getElementById('btnBan').textContent = data.status === 'banned' ? 'Unban user' : 'Ban user';

        userPanel.classList.add('open');
        userOverlay.classList.add('show');
    }

    function closeUserPanel() {
        userPanel.classList.remove('open');
        userOverlay.classList.remove('show');
        currentUser = null;
    }

    document.getElementById('closeUserPanel').addEventListener('click', closeUserPanel);
    userOverlay.addEventListener('click', closeUserPanel);

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && userPanel.classList.contains('open')) closeUserPanel();
    });

    function bindKeyRevoke() {
        document.querySelectorAll('.key-revoke').forEach(function (b) {
            b.removeEventListener('click', onRevokeKey);
            b.addEventListener('click', onRevokeKey);
        });
    }

    function onRevokeKey(e) {
        var row = e.target.closest('.up-key');
        var code = row.querySelector('code').textContent;
        row.querySelector('.key-tag').textContent = 'Revoked';
        row.querySelector('.key-tag').className = 'key-tag revoked';
        e.target.remove();
        toast('Key <strong>' + code.slice(-10) + '</strong> revoked');
        setTimeout(function () { if (currentUser) currentUser.keys = currentUser.keys.filter(function (k) { return k !== code; }); }, 200);
    }

    document.getElementById('btnSuspend').addEventListener('click', function () {
        if (!currentUser) return;
        if (currentUser.status === 'suspended') {
            currentUser.status = 'active';
            toast('<strong>' + currentUser.name + '</strong> unsuspended');
        } else {
            currentUser.status = 'suspended';
            toast('<strong>' + currentUser.name + '</strong> suspended');
        }
        closeUserPanel();
    });

    document.getElementById('btnBan').addEventListener('click', function () {
        if (!currentUser) return;
        if (currentUser.status === 'banned') {
            currentUser.status = 'active';
            toast('<strong>' + currentUser.name + '</strong> unbanned');
        } else {
            currentUser.status = 'banned';
            toast('<strong>' + currentUser.name + '</strong> banned');
        }
        closeUserPanel();
    });

    document.getElementById('btnRevokeAll').addEventListener('click', function () {
        if (!currentUser) return;
        currentUser.keys = [];
        document.getElementById('upKeyList').innerHTML = '<p class="muted" style="font-size:13px;padding:8px 0">No API keys generated.</p>';
        toast('All keys revoked for <strong>' + currentUser.name + '</strong>');
    });

    document.getElementById('btnDelete').addEventListener('click', function () {
        if (!currentUser) return;
        var name = currentUser.name;
        toast('<strong>' + name + '</strong> account deleted');
        currentUser = null;
        closeUserPanel();
    });

    document.getElementById('changePlanBtn').addEventListener('click', function () {
        if (!currentUser) return;
        var newPlan = document.getElementById('upPlanSelect').value;
        var planNames = { scout:'Scout', investigator:'Investigator', operations:'Operations' };
        currentUser.plan = planNames[newPlan] || newPlan;
        document.getElementById('upPlan').textContent = currentUser.plan;
        toast('Plan changed to <strong>' + currentUser.plan + '</strong> for ' + currentUser.name);
    });

    document.getElementById('genKeyBtn2').addEventListener('click', function () {
        if (!currentUser) return;
        var chars = 'abcdef0123456789';
        var key = 'tc_live_';
        for (var i = 0; i < 16; i++) key += chars[Math.floor(Math.random() * chars.length)];
        currentUser.keys.push(key);
        var keyList = document.getElementById('upKeyList');
        var div = document.createElement('div');
        div.className = 'up-key';
        div.innerHTML = '<code>' + key + '</code><span class="key-tag ok">Active</span><button class="key-revoke" data-action="revoke-key">Revoke</button>';
        if (keyList.querySelector('.muted')) keyList.innerHTML = '';
        keyList.appendChild(div);
        bindKeyRevoke();
        toast('New key generated for <strong>' + currentUser.name + '</strong>');
    });

    /* ---------- Bulk user actions ---------- */
    var selectAll = document.getElementById('selectAll');
    var bulkBar = document.getElementById('bulkBar');
    var bulkCount = document.getElementById('bulkCount');

    function updateBulkBar() {
        var checks = document.querySelectorAll('.user-check:checked');
        if (!bulkBar || !bulkCount) return;
        bulkCount.textContent = checks.length + ' selected';
        bulkBar.style.display = checks.length ? 'flex' : 'none';
    }

    if (selectAll) {
        selectAll.addEventListener('change', function () {
            document.querySelectorAll('.user-check').forEach(function (c) { c.checked = selectAll.checked; });
            updateBulkBar();
        });
    }

    document.querySelectorAll('.user-check').forEach(function (c) {
        c.addEventListener('change', updateBulkBar);
    });

    document.querySelectorAll('.bulk-act').forEach(function (b) {
        b.addEventListener('click', function () {
            var action = b.dataset.bulk;
            var checks = document.querySelectorAll('.user-check:checked');
            var names = [];
            checks.forEach(function (c) {
                var row = c.closest('tr');
                if (row) { var strong = row.querySelector('strong'); if (strong) names.push(strong.textContent); }
            });
            if (!names.length) return;
            if (action === 'suspend') toast('<strong>' + names.join(', ') + '</strong> ' + (names.length > 1 ? 'suspended' : 'suspended'));
            if (action === 'delete') toast('<strong>' + names.join(', ') + '</strong> ' + (names.length > 1 ? 'deleted' : 'deleted'));
        });
    });

    /* ---------- Key management ---------- */
    var selectAllKeys = document.getElementById('selectAllKeys');
    var keyBulkBar = document.getElementById('keyBulkBar');
    var keyBulkCount = document.getElementById('keyBulkCount');
    var keySearch = document.getElementById('keySearch');
    var revokeSelectedKeys = document.getElementById('revokeSelectedKeys');

    function updateKeyBulk() {
        var checks = document.querySelectorAll('.key-check:checked');
        if (keyBulkBar) keyBulkBar.style.display = checks.length ? 'flex' : 'none';
        if (keyBulkCount) keyBulkCount.textContent = checks.length + ' selected';
        if (revokeSelectedKeys) revokeSelectedKeys.disabled = !checks.length;
    }

    if (selectAllKeys) {
        selectAllKeys.addEventListener('change', function () {
            document.querySelectorAll('.key-check:checked, .key-check').forEach(function (c) {
                var row = c.closest('tr');
                if (row && row.style.display !== 'none') c.checked = selectAllKeys.checked;
            });
            updateKeyBulk();
        });
    }

    document.querySelectorAll('.key-check').forEach(function (c) {
        c.addEventListener('change', updateKeyBulk);
    });

    if (keySearch) {
        keySearch.addEventListener('input', function () {
            var q = keySearch.value.toLowerCase();
            document.querySelectorAll('#keyTableBody tr').forEach(function (row) {
                var text = row.textContent.toLowerCase();
                row.style.display = text.indexOf(q) !== -1 ? '' : 'none';
            });
        });
    }

    if (revokeSelectedKeys) {
        revokeSelectedKeys.addEventListener('click', function () {
            var checks = document.querySelectorAll('.key-check:checked');
            var count = checks.length;
            checks.forEach(function (c) {
                var row = c.closest('tr');
                var statusEl = row && row.querySelector('.status');
                var btn = row && row.querySelector('.revoke-btn');
                if (statusEl) { statusEl.textContent = 'Revoked'; statusEl.className = 'status off'; }
                if (btn) btn.style.display = 'none';
                c.checked = false;
            });
            updateKeyBulk();
            toast('<strong>' + count + ' keys</strong> revoked');
        });
    }

    document.querySelectorAll('.revoke-btn').forEach(function (b) {
        b.addEventListener('click', function () {
            var row = b.closest('tr');
            var code = row.querySelector('.mono').textContent;
            var statusEl = row.querySelector('.status');
            if (statusEl) { statusEl.textContent = 'Revoked'; statusEl.className = 'status off'; }
            b.style.display = 'none';
            row.querySelector('.key-check').checked = false;
            updateKeyBulk();
            toast('Key <strong>' + code.slice(0,16) + '...</strong> revoked');
        });
    });

    /* ---------- Alerts ---------- */
    var testAlertBtn = document.getElementById('testAlertBtn');
    if (testAlertBtn) testAlertBtn.addEventListener('click', function () { toast('Test alert sent to all enabled channels'); });

    /* ---------- Backup ---------- */
    var runBackupBtn = document.getElementById('runBackupBtn');
    if (runBackupBtn) runBackupBtn.addEventListener('click', function () { toast('Manual backup initiated — estimated 2 min'); });

    document.querySelectorAll('.exp-btn').forEach(function (b) {
        b.addEventListener('click', function () {
            var name = b.querySelector('strong').textContent;
            toast('Exporting <strong>' + name + '</strong>...');
        });
    });

    /* ---------- Interactive elements ---------- */
    document.querySelectorAll('.icon-btn').forEach(function (b) {
        b.addEventListener('click', function () {
            if (b.textContent.trim() === 'Manage') {
                var email = null;
                var row = b.closest('tr');
                if (row) {
                    var emailCell = row.querySelector('.mono');
                    if (emailCell) email = emailCell.textContent.trim();
                }
                var u = email ? userData.find(function (d) { return d.email === email; }) : null;
                if (u) openUserPanel(u);
                else toast('Opening user management...');
            }
            if (b.textContent.trim() === 'Export CSV') toast('Exporting usage report...');
            if (b.textContent.trim() === 'Export') toast('Exporting audit logs as CSV...');
            if (b.textContent.trim() === 'Filter') toast('Filter panel opened.');
            if (b.textContent.trim() === 'Next') toast('Page navigation...');
            if (b.textContent.trim() === 'Run diagnostic') toast('Running system diagnostic...');
        });
    });

    document.querySelectorAll('.btn-ghost:not(.sm)').forEach(function (b) {
        b.addEventListener('click', function (e) {
            if (b.textContent.trim() === 'Add User') toast('Opening new user form...');
            if (b.textContent.trim() === 'Refresh') location.reload();
        });
    });

    document.querySelectorAll('.pager .icon-btn').forEach(function (b) {
        b.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelectorAll('.pager .icon-btn').forEach(function (p) { p.classList.remove('active'); });
            b.classList.add('active');
            toast('Page ' + b.textContent.trim());
        });
    });

    /* ---------- Rev bar animation ---------- */
    var observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.isIntersecting) {
                var bars = entry.target.querySelectorAll('.rev-bar b, .dist-bar b');
                bars.forEach(function (b) {
                    var w = b.style.width;
                    b.style.transition = 'none';
                    b.style.width = '0';
                    requestAnimationFrame(function () {
                        b.style.transition = 'width .8s cubic-bezier(.4,0,.2,1)';
                        b.style.width = w;
                    });
                });
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.3 });

    document.querySelectorAll('.rev-block, .dist-list').forEach(function (el) {
        observer.observe(el);
    });
});
