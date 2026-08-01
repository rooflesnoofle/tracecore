document.addEventListener('DOMContentLoaded', function () {
    var nav = document.querySelector('.nav');
    var menuToggle = document.getElementById('menuToggle');

    function onScroll() {
        if (window.scrollY > 10) {
            nav.classList.add('scrolled');
        } else {
            nav.classList.remove('scrolled');
        }
    }

    window.addEventListener('scroll', onScroll);
    onScroll();

    if (menuToggle) {
        menuToggle.addEventListener('click', function () {
            nav.classList.toggle('open');
        });
    }

    var heroStat = document.querySelector('.stat strong');
    if (heroStat) {
        var targets = document.querySelectorAll('.stat strong');
        targets.forEach(function (el) {
            if (el.textContent.indexOf('<') === 0) return;
            var text = el.textContent;
            var match = text.match(/(\d+)([BM]?)/);
            if (!match) return;
            var end = parseInt(match[1], 10);
            var suffix = match[2];
            var start = 0;
            var duration = 1200;
            var t0 = null;

            function tick(ts) {
                if (!t0) t0 = ts;
                var p = Math.min((ts - t0) / duration, 1);
                var eased = 1 - Math.pow(1 - p, 3);
                el.textContent = Math.floor(start + (end - start) * eased) + suffix;
                if (p < 1) requestAnimationFrame(tick);
            }

            var observer = new IntersectionObserver(function (entries) {
                entries.forEach(function (entry) {
                    if (entry.isIntersecting) {
                        requestAnimationFrame(tick);
                        observer.disconnect();
                    }
                });
            }, { threshold: 0.5 });
            observer.observe(el);
        });
    }

    var cards = document.querySelectorAll('.card, .feature, .price-card, .step-num');
    if ('IntersectionObserver' in window) {
        var reveal = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'none';
                    reveal.unobserve(entry.target);
                }
            });
        }, { threshold: 0.15 });

        cards.forEach(function (el, i) {
            el.style.opacity = '0';
            el.style.transform = 'translateY(18px)';
            el.style.transition = 'opacity 0.5s ease ' + (i % 3) * 0.08 + 's, transform 0.5s ease';
            reveal.observe(el);
        });
    }
});
