function showPopup(id) {
    var popup = document.getElementById(id);
    if (popup) {
        popup.style.display = 'block';
        $(popup).css({ transform: "none", top: "50%", left: "50%" });
        $(popup).draggable({
            start: function () { $(this).css({ transform: "none" }); }
        });
        // Bring to front
        document.querySelectorAll('.draggable').forEach(function(el) { el.style.zIndex = 10; });
        popup.style.zIndex = 20;
    }
    // Close start menu
    var sm = document.getElementById('startMenu');
    if (sm) sm.style.display = 'none';
}

function closePopup(id) {
    var popup = document.getElementById(id);
    if (popup) popup.style.display = 'none';
}

function togglePopup(id) {
    var popup = document.getElementById(id);
    if (popup) popup.style.display = popup.style.display === 'none' ? 'block' : 'none';
}

function updateClock() {
    var now = new Date();
    var hours = now.getHours();
    var minutes = now.getMinutes();
    var ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    minutes = minutes < 10 ? '0' + minutes : minutes;
    var timeStr = hours + ':' + minutes + ' ' + ampm;
    var el = document.querySelector('.time');
    if (el) el.textContent = timeStr;
}

function createParticles() {
    var container = document.getElementById('particles');
    if (!container) return;
    var colors = ['#4a8c3f', '#7ab86a', '#c4a747', '#3a6a2a', '#5a8a4a'];
    for (var i = 0; i < 25; i++) {
        var p = document.createElement('div');
        p.className = 'particle';
        p.style.left = Math.random() * 100 + '%';
        p.style.width = (2 + Math.random() * 4) + 'px';
        p.style.height = p.style.width;
        p.style.background = colors[Math.floor(Math.random() * colors.length)];
        p.style.animationDuration = (8 + Math.random() * 12) + 's';
        p.style.animationDelay = (Math.random() * 10) + 's';
        p.style.opacity = 0.2 + Math.random() * 0.4;
        container.appendChild(p);
    }
}

document.addEventListener('DOMContentLoaded', function () {
    updateClock();
    setInterval(updateClock, 1000);
    createParticles();

    var enterEl = document.getElementById('enter');
    if (enterEl) {
        enterEl.addEventListener('click', function () {
            enterEl.style.opacity = '0';
            setTimeout(function () { enterEl.style.display = 'none'; }, 500);
        });
    }

    var startBtn = document.getElementById('startBtn');
    var startMenu = document.getElementById('startMenu');
    if (startBtn && startMenu) {
        startBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            startMenu.style.display = startMenu.style.display === 'none' ? 'flex' : 'none';
        });
        document.addEventListener('click', function (e) {
            if (!startMenu.contains(e.target) && e.target !== startBtn) {
                startMenu.style.display = 'none';
            }
        });
    }
});
