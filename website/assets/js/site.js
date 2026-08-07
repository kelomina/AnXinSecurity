/* =============================================================================
   AnXin Security — 官方网站交互 / Site interactions
   原生 JavaScript，无第三方依赖。所有动画均可通过顶栏"动效"开关关闭，
   并且默认尊重系统的"减少动态效果"设置。
   ============================================================================= */
(function () {
  'use strict';

  var STORAGE_THEME = 'anxin-site-theme';
  var STORAGE_MOTION = 'anxin-site-motion';
  var THEMES = ['system', 'light', 'dark'];
  var THEME_LABEL = { system: '跟随系统', light: '日间（浅色）', dark: '夜间（深色）' };

  var root = document.documentElement;
  var body = document.body;
  var prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var supportsHover = window.matchMedia('(hover: hover) and (pointer: fine)');

  function read(key, fallback) {
    try {
      return window.localStorage.getItem(key) || fallback;
    } catch (err) {
      return fallback;
    }
  }

  function write(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (err) {
      /* 隐私模式下忽略 */
    }
  }

  function motionEnabled() {
    return body.getAttribute('data-animations') !== 'off';
  }

  /* ---------------------------------------------------------------------------
     主题：跟随系统 / 浅色 / 深色
     ------------------------------------------------------------------------ */
  function resolvedTheme(mode) {
    if (mode === 'system') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return mode;
  }

  function applyTheme(mode) {
    root.setAttribute('data-theme', mode);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute('content', resolvedTheme(mode) === 'dark' ? '#141414' : '#f5f5f5');
    }
    document.querySelectorAll('[data-theme-btn]').forEach(function (btn) {
      btn.setAttribute('title', '主题：' + THEME_LABEL[mode] + '（点击切换）');
      btn.setAttribute('aria-label', '切换主题，当前：' + THEME_LABEL[mode]);
      btn.querySelectorAll('[data-theme-glyph]').forEach(function (glyph) {
        glyph.classList.toggle('is-shown', glyph.getAttribute('data-theme-glyph') === mode);
      });
    });
  }

  function initTheme() {
    var mode = read(STORAGE_THEME, 'system');
    if (THEMES.indexOf(mode) === -1) mode = 'system';
    applyTheme(mode);

    document.querySelectorAll('[data-theme-btn]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var current = root.getAttribute('data-theme') || 'system';
        var next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
        applyTheme(next);
        write(STORAGE_THEME, next);
      });
    });
  }

  /* ---------------------------------------------------------------------------
     动效开关（对应应用内"启用动画"设置）
     ------------------------------------------------------------------------ */
  function applyMotion(state) {
    body.setAttribute('data-animations', state);
    document.querySelectorAll('[data-motion-btn]').forEach(function (btn) {
      var on = state !== 'off';
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      btn.setAttribute('title', on ? '动效：已启用（点击关闭）' : '动效：已关闭（点击启用）');
      btn.setAttribute('aria-label', on ? '关闭页面动效' : '启用页面动效');
      btn.querySelectorAll('[data-motion-glyph]').forEach(function (glyph) {
        glyph.classList.toggle('is-shown', glyph.getAttribute('data-motion-glyph') === (on ? 'on' : 'off'));
      });
    });
  }

  function initMotion() {
    var stored = read(STORAGE_MOTION, '');
    var state = stored === 'off' || stored === 'on' ? stored : prefersReduced.matches ? 'off' : 'on';
    applyMotion(state);

    document.querySelectorAll('[data-motion-btn]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var next = motionEnabled() ? 'off' : 'on';
        applyMotion(next);
        write(STORAGE_MOTION, next);
        if (next === 'on') {
          document.querySelectorAll('[data-reveal]').forEach(function (el) {
            el.classList.add('is-visible');
          });
        }
      });
    });
  }

  /* ---------------------------------------------------------------------------
     顶栏状态、滚动进度、返回顶部
     ------------------------------------------------------------------------ */
  function initScrollChrome() {
    var topbar = document.querySelector('[data-topbar]');
    var progress = document.querySelector('[data-progress]');
    var ticking = false;

    function update() {
      var y = window.scrollY || window.pageYOffset;
      if (topbar) topbar.classList.toggle('topbar--scrolled', y > 8);
      if (progress) {
        var max = document.documentElement.scrollHeight - window.innerHeight;
        var ratio = max > 0 ? Math.min(1, y / max) : 0;
        progress.style.transform = 'scaleX(' + ratio.toFixed(4) + ')';
      }
      ticking = false;
    }

    window.addEventListener(
      'scroll',
      function () {
        if (!ticking) {
          ticking = true;
          window.requestAnimationFrame(update);
        }
      },
      { passive: true }
    );
    update();
  }

  /* ---------------------------------------------------------------------------
     移动端抽屉导航
     ------------------------------------------------------------------------ */
  function initDrawer() {
    var toggle = document.querySelector('[data-drawer-btn]');
    var drawer = document.querySelector('[data-drawer]');
    if (!toggle || !drawer) return;

    function setOpen(open) {
      drawer.classList.toggle('is-open', open);
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      drawer.setAttribute('aria-hidden', open ? 'false' : 'true');
    }

    toggle.addEventListener('click', function () {
      setOpen(!drawer.classList.contains('is-open'));
    });

    drawer.addEventListener('click', function (event) {
      if (event.target.closest('a')) setOpen(false);
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && drawer.classList.contains('is-open')) {
        setOpen(false);
        toggle.focus();
      }
    });

    window.addEventListener('resize', function () {
      if (window.innerWidth > 980) setOpen(false);
    });

    setOpen(false);
  }

  /* ---------------------------------------------------------------------------
     滚动进场（含同组错峰延迟）
     ------------------------------------------------------------------------ */
  function initReveal() {
    var items = Array.prototype.slice.call(document.querySelectorAll('[data-reveal]'));
    if (!items.length) return;

    // 同一父容器内的元素依次错峰出现
    var counters = new Map();
    items.forEach(function (el) {
      if (el.style.getPropertyValue('--i')) return;
      var parent = el.parentElement || body;
      var index = counters.get(parent) || 0;
      counters.set(parent, index + 1);
      el.style.setProperty('--i', String(Math.min(index, 9)));
    });

    if (!('IntersectionObserver' in window) || !motionEnabled()) {
      items.forEach(function (el) {
        el.classList.add('is-visible');
      });
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: '0px 0px -8% 0px', threshold: 0.08 }
    );

    items.forEach(function (el) {
      observer.observe(el);
    });
  }

  /* ---------------------------------------------------------------------------
     数字滚动计数
     ------------------------------------------------------------------------ */
  function animateCount(el) {
    var target = parseFloat(el.getAttribute('data-count'));
    if (isNaN(target)) return;
    var decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
    var duration = parseInt(el.getAttribute('data-duration') || '1400', 10);
    var grouped = el.hasAttribute('data-sep');

    function format(value) {
      if (decimals > 0) return value.toFixed(decimals);
      var whole = Math.round(value);
      return grouped ? whole.toLocaleString('zh-CN') : String(whole);
    }

    if (!motionEnabled()) {
      el.textContent = format(target);
      return;
    }

    var start = null;
    function frame(now) {
      if (start === null) start = now;
      var p = Math.min(1, (now - start) / duration);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = format(target * eased);
      if (p < 1) window.requestAnimationFrame(frame);
      else el.textContent = format(target);
    }
    window.requestAnimationFrame(frame);
  }

  function initCounters() {
    var counters = Array.prototype.slice.call(document.querySelectorAll('[data-count]'));
    if (!counters.length) return;

    if (!('IntersectionObserver' in window)) {
      counters.forEach(animateCount);
      return;
    }

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            animateCount(entry.target);
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.4 }
    );

    counters.forEach(function (el) {
      observer.observe(el);
    });
  }

  /* ---------------------------------------------------------------------------
     标签页（顶部标签 + 应用侧边栏共同驱动同一组面板）
     ------------------------------------------------------------------------ */
  function initTabs() {
    var lists = Array.prototype.slice.call(document.querySelectorAll('[data-tabgroup]'));
    if (!lists.length) return;

    var groups = {};
    lists.forEach(function (list) {
      var name = list.getAttribute('data-tabgroup');
      if (!groups[name]) groups[name] = { lists: [], panels: [] };
      groups[name].lists.push(list);
    });

    Object.keys(groups).forEach(function (name) {
      var group = groups[name];
      var host = document.querySelector('[data-tabpanels="' + name + '"]');
      group.panels = host
        ? Array.prototype.slice.call(host.querySelectorAll('[data-panel]'))
        : [];

      function moveIndicator(list, tab) {
        var indicator = list.querySelector('[data-indicator]');
        if (!indicator || !tab) return;
        indicator.style.width = tab.offsetWidth + 'px';
        indicator.style.transform = 'translateX(' + (tab.offsetLeft - list.clientLeft) + 'px)';
      }

      function activate(key, focusTab) {
        group.lists.forEach(function (list) {
          var tabs = Array.prototype.slice.call(list.querySelectorAll('[data-tab]'));
          tabs.forEach(function (tab) {
            var on = tab.getAttribute('data-tab') === key;
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
            tab.setAttribute('tabindex', on ? '0' : '-1');
            if (on) {
              moveIndicator(list, tab);
              if (focusTab && list.contains(document.activeElement)) tab.focus();
            }
          });
        });

        group.panels.forEach(function (panel) {
          var on = panel.getAttribute('data-panel') === key;
          panel.hidden = !on;
          panel.classList.toggle('is-active', on);
        });
      }

      group.lists.forEach(function (list) {
        var tabs = Array.prototype.slice.call(list.querySelectorAll('[data-tab]'));

        list.addEventListener('click', function (event) {
          var tab = event.target.closest('[data-tab]');
          if (tab && list.contains(tab)) activate(tab.getAttribute('data-tab'), false);
        });

        list.addEventListener('keydown', function (event) {
          var codes = ['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp', 'Home', 'End'];
          if (codes.indexOf(event.key) === -1) return;
          var current = tabs.indexOf(document.activeElement.closest('[data-tab]'));
          if (current === -1) return;
          event.preventDefault();
          var next = current;
          if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (current + 1) % tabs.length;
          else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (current - 1 + tabs.length) % tabs.length;
          else if (event.key === 'Home') next = 0;
          else if (event.key === 'End') next = tabs.length - 1;
          tabs[next].focus();
          activate(tabs[next].getAttribute('data-tab'), true);
        });
      });

      var initial = null;
      group.lists.forEach(function (list) {
        var selected = list.querySelector('[data-tab][aria-selected="true"]');
        if (!initial && selected) initial = selected.getAttribute('data-tab');
      });
      if (!initial) {
        var first = group.lists[0].querySelector('[data-tab]');
        initial = first ? first.getAttribute('data-tab') : null;
      }
      if (initial) activate(initial, false);

      window.addEventListener('resize', function () {
        group.lists.forEach(function (list) {
          var selected = list.querySelector('[data-tab][aria-selected="true"]');
          if (selected) moveIndicator(list, selected);
        });
      });
    });
  }

  /* ---------------------------------------------------------------------------
     手风琴 FAQ
     ------------------------------------------------------------------------ */
  function initAccordion() {
    document.querySelectorAll('[data-faq-q]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var item = btn.closest('.faq__item');
        if (!item) return;
        var open = item.classList.toggle('is-open');
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    });
  }

  /* ---------------------------------------------------------------------------
     指针跟随高光（Fluent Reveal）
     ------------------------------------------------------------------------ */
  function initGlow() {
    if (!supportsHover.matches) return;
    var pending = false;
    var queue = [];

    function flush() {
      queue.forEach(function (item) {
        item.el.style.setProperty('--mx', item.x + '%');
        item.el.style.setProperty('--my', item.y + '%');
      });
      queue = [];
      pending = false;
    }

    document.querySelectorAll('.glow').forEach(function (el) {
      el.addEventListener(
        'pointermove',
        function (event) {
          if (!motionEnabled()) return;
          var rect = el.getBoundingClientRect();
          queue.push({
            el: el,
            x: (((event.clientX - rect.left) / rect.width) * 100).toFixed(1),
            y: (((event.clientY - rect.top) / rect.height) * 100).toFixed(1)
          });
          if (!pending) {
            pending = true;
            window.requestAnimationFrame(flush);
          }
        },
        { passive: true }
      );
    });
  }

  /* ---------------------------------------------------------------------------
     首屏窗口 3D 视差
     ------------------------------------------------------------------------ */
  function initTilt() {
    var stage = document.querySelector('[data-tilt]');
    if (!stage || !supportsHover.matches) return;
    var frame = null;

    stage.addEventListener(
      'pointermove',
      function (event) {
        if (!motionEnabled() || window.innerWidth <= 1180) return;
        if (frame) return;
        frame = window.requestAnimationFrame(function () {
          var rect = stage.getBoundingClientRect();
          var px = (event.clientX - rect.left) / rect.width - 0.5;
          var py = (event.clientY - rect.top) / rect.height - 0.5;
          stage.classList.add('is-hovered');
          stage.style.setProperty('--ry', (-px * 10 - 2).toFixed(2) + 'deg');
          stage.style.setProperty('--rx', (py * 8 + 1).toFixed(2) + 'deg');
          frame = null;
        });
      },
      { passive: true }
    );

    stage.addEventListener('pointerleave', function () {
      stage.classList.remove('is-hovered');
      stage.style.removeProperty('--rx');
      stage.style.removeProperty('--ry');
    });
  }

  /* ---------------------------------------------------------------------------
     日志流演示（界面示意，非真实运行数据）
     ------------------------------------------------------------------------ */
  var LOG_LINES = [
    { lvl: 'INFO', kind: 'info', msg: 'etw_service: session started, 4 providers' },
    { lvl: 'INFO', kind: 'info', msg: 'snapshot_service: 182 processes enumerated' },
    { lvl: ' OK ', kind: 'ok', msg: 'engine_service: axon + raven modules ready' },
    { lvl: 'WARN', kind: 'warn', msg: 'risk_service: suspicious autorun write' },
    { lvl: 'INFO', kind: 'info', msg: 'file_monitor: 24 events flushed to sqlite' },
    { lvl: ' OK ', kind: 'ok', msg: 'quarantine_service: item sealed (aes-128-gcm)' },
    { lvl: 'INFO', kind: 'info', msg: 'trust_service: signature chain verified' },
    { lvl: 'WARN', kind: 'warn', msg: 'interception: process suspended, awaiting user' },
    { lvl: 'INFO', kind: 'info', msg: 'process_monitor: pid 7412 module scan done' },
    { lvl: ' OK ', kind: 'ok', msg: 'scan_result_cache: 1,204 verdicts reused' }
  ];

  function clockText(offsetSeconds) {
    var base = 8 * 3600 + 42 * 60;
    var total = (base + offsetSeconds) % 86400;
    var h = Math.floor(total / 3600);
    var m = Math.floor((total % 3600) / 60);
    var s = total % 60;
    function pad(n) {
      return (n < 10 ? '0' : '') + n;
    }
    return pad(h) + ':' + pad(m) + ':' + pad(s);
  }

  function initLogStream() {
    var host = document.querySelector('[data-logstream]');
    if (!host) return;
    var cursor = 0;
    var tick = 0;
    var timer = null;

    function push() {
      var entry = LOG_LINES[cursor % LOG_LINES.length];
      cursor += 1;
      tick += 3 + (cursor % 4);
      var line = document.createElement('div');
      line.className = 'logline logline--' + entry.kind;
      var time = document.createElement('span');
      time.className = 'logline__time';
      time.textContent = clockText(tick);
      var lvl = document.createElement('span');
      lvl.className = 'logline__lvl';
      lvl.textContent = entry.lvl;
      var msg = document.createElement('span');
      msg.className = 'logline__msg';
      msg.textContent = entry.msg;
      line.appendChild(time);
      line.appendChild(lvl);
      line.appendChild(msg);
      host.appendChild(line);
      while (host.children.length > 6) host.removeChild(host.firstChild);
    }

    for (var i = 0; i < 6; i += 1) push();

    function start() {
      if (timer || !motionEnabled()) return;
      timer = window.setInterval(function () {
        if (document.hidden) return;
        push();
      }, 2100);
    }

    function stop() {
      if (timer) {
        window.clearInterval(timer);
        timer = null;
      }
    }

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) stop();
      else start();
    });

    document.querySelectorAll('[data-motion-btn]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (motionEnabled()) start();
        else stop();
      });
    });

    start();
  }

  /* ---------------------------------------------------------------------------
     扫描进度环（示意动画）
     ------------------------------------------------------------------------ */
  function initScanRing() {
    var ring = document.querySelector('[data-scanring]');
    if (!ring) return;
    var bar = ring.querySelector('.ring__bar');
    var pct = ring.querySelector('[data-scanpct]');
    var files = ring.querySelector('[data-scanfiles]');
    if (!bar || !pct) return;

    var CIRC = 314;
    var visible = false;
    var start = null;
    var running = false;

    function render(value) {
      bar.style.strokeDashoffset = String(CIRC - (CIRC * value) / 100);
      pct.textContent = String(Math.round(value));
      if (files) files.textContent = (Math.round(value * 128.4)).toLocaleString('zh-CN');
    }

    function frame(now) {
      if (!visible || !motionEnabled()) {
        running = false;
        return;
      }
      if (start === null) start = now;
      var elapsed = (now - start) % 7200;
      var p = Math.min(1, elapsed / 5600);
      var eased = 1 - Math.pow(1 - p, 2.2);
      render(eased * 100);
      window.requestAnimationFrame(frame);
    }

    function boot() {
      if (running) return;
      running = true;
      start = null;
      bar.style.animation = 'none';
      window.requestAnimationFrame(frame);
    }

    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          visible = entry.isIntersecting;
          if (visible && motionEnabled()) boot();
        });
      }, { threshold: 0.25 }).observe(ring);
    } else {
      render(100);
    }

    if (!motionEnabled()) render(100);
  }

  /* ---------------------------------------------------------------------------
     复制按钮
     ------------------------------------------------------------------------ */
  function initCopy() {
    document.querySelectorAll('[data-copy]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var selector = btn.getAttribute('data-copy');
        var source = selector ? document.querySelector(selector) : null;
        var text = source ? source.innerText : btn.getAttribute('data-copy-text') || '';
        if (!text) return;

        function done() {
          var label = btn.querySelector('[data-copy-label]');
          btn.classList.add('is-done');
          if (label) label.textContent = '已复制';
          window.setTimeout(function () {
            btn.classList.remove('is-done');
            if (label) label.textContent = '复制';
          }, 1800);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {
            legacyCopy(text, done);
          });
        } else {
          legacyCopy(text, done);
        }
      });
    });
  }

  function legacyCopy(text, done) {
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', 'readonly');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      done();
    } catch (err) {
      /* 忽略复制失败 */
    }
    body.removeChild(area);
  }

  /* ---------------------------------------------------------------------------
     首页锚点导航高亮
     ------------------------------------------------------------------------ */
  function initSectionNav() {
    var links = Array.prototype.slice.call(
      document.querySelectorAll('[data-nav] a[href^="#"], [data-drawer] a[href^="#"]')
    );
    if (!links.length || !('IntersectionObserver' in window)) return;

    var map = {};
    links.forEach(function (link) {
      var id = link.getAttribute('href').slice(1);
      if (!id) return;
      if (!map[id]) map[id] = [];
      map[id].push(link);
    });

    var ids = Object.keys(map);
    if (!ids.length) return;

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          links.forEach(function (link) {
            link.classList.remove('is-active');
          });
          (map[entry.target.id] || []).forEach(function (link) {
            link.classList.add('is-active');
          });
        });
      },
      { rootMargin: '-45% 0px -50% 0px', threshold: 0 }
    );

    ids.forEach(function (id) {
      var section = document.getElementById(id);
      if (section) observer.observe(section);
    });
  }

  /* ---------------------------------------------------------------------------
     其它零碎
     ------------------------------------------------------------------------ */
  function initMisc() {
    document.querySelectorAll('[data-year]').forEach(function (el) {
      el.textContent = String(new Date().getFullYear());
    });
  }

  /* ---------------------------------------------------------------------------
     启动
     ------------------------------------------------------------------------ */
  function boot() {
    initTheme();
    initMotion();
    initScrollChrome();
    initDrawer();
    initReveal();
    initCounters();
    initTabs();
    initAccordion();
    initGlow();
    initTilt();
    initLogStream();
    initScanRing();
    initCopy();
    initSectionNav();
    initMisc();
    body.classList.add('is-ready');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
