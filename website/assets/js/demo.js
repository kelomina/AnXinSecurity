/* =============================================================================
   AnXin Security — 30 秒动态功能演示 / Demo timeline engine
   数据驱动的分镜时间轴：steps（离散事件）+ tweens（连续插值），支持
   播放 / 暂停 / 拖拽进度 / 章节跳转 / 重播；模拟指针在真实界面控件上操作。
   ============================================================================= */
(function () {
  'use strict';

  var shell = document.querySelector('[data-demo]');
  if (!shell) return;

  var scaler = shell.querySelector('[data-scaler]');
  var stage = shell.querySelector('[data-stage]');
  var caption = shell.querySelector('[data-caption]');
  var captionNum = shell.querySelector('[data-caption-num]');
  var captionText = shell.querySelector('[data-caption-text]');
  var poster = shell.querySelector('[data-poster]');
  var posterHint = shell.querySelector('[data-poster-hint]');
  var playBtn = shell.querySelector('[data-play]');
  var replayBtn = shell.querySelector('[data-replay]');
  var track = shell.querySelector('[data-track]');
  var trackFill = shell.querySelector('[data-track-fill]');
  var timeEl = shell.querySelector('[data-time]');

  var DURATION = 31.0;

  /* 章节：与页面下方亮点卡共用 */
  var CHAPTERS = [
    { t: 0.0, title: '启动快照 · 建立可信环境' },
    { t: 3.6, title: '安全概览 · 引擎状态与关键指标' },
    { t: 8.7, title: '双引擎文件扫描 · 检出与处置' },
    { t: 15.8, title: '威胁拦截 · 处置权交给你' },
    { t: 20.2, title: '加密隔离区 · 封存与恢复' },
    { t: 24.8, title: 'EDR 行为监控 · ETW 事件流' },
    { t: 28.6, title: '安芯安全 · 开源免费 本地优先' },
  ];

  /* ---------------------------------------------------------------------------
     基础工具
     ------------------------------------------------------------------------ */
  function $(sel) {
    return stage.querySelector('[data-d="' + sel + '"]');
  }

  function fmt(n) {
    return Math.round(n).toLocaleString('zh-CN');
  }

  function easeOut(k) {
    return 1 - Math.pow(1 - k, 3);
  }

  function easeInOut(k) {
    return k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
  }

  function motionEnabled() {
    return document.body.getAttribute('data-animations') !== 'off';
  }

  /* 元素中心点（舞台逻辑坐标）。
     必须用 getBoundingClientRect 而不是 offsetLeft/offsetTop 链：
     offset 系列不包含 CSS transform，拦截弹窗（translate(-50%,-50%) 居中）
     等目标会得到偏移半个弹窗尺寸的错误坐标；rect 差值再除以舞台缩放即可。 */
  function centerOf(sel) {
    var el = $(sel);
    if (!el) return null;
    var stageRect = stage.getBoundingClientRect();
    var rect = el.getBoundingClientRect();
    var scale = stageRect.width / 960;
    if (!scale || !rect.width) return null;
    return {
      x: (rect.left - stageRect.left + rect.width / 2) / scale,
      y: (rect.top - stageRect.top + rect.height / 2) / scale,
    };
  }

  /* ---------------------------------------------------------------------------
     时间轴原语
     ------------------------------------------------------------------------ */
  var steps = [];
  var tweens = [];

  function at(t, fn) {
    steps.push({ t: t, fn: fn });
  }

  function tween(t0, t1, apply) {
    tweens.push({ t0: t0, t1: t1, apply: apply, state: {} });
  }

  /* 指针移动（带缓动）。起点在补间开始时缓存一次；
     目标点每帧重算——目标控件若仍在进场过渡中，指针会吸附到其真实中心。 */
  function cursorTo(sel, t0, t1) {
    tween(t0, t1, function (k, state) {
      var cursor = $('cursor');
      if (!cursor) return;
      if (!state.from) {
        state.from = { x: cursor.offsetLeft, y: cursor.offsetTop };
      }
      var to = centerOf(sel) || state.to || state.from;
      state.to = to;
      var e = easeInOut(k);
      cursor.style.left = (state.from.x + (to.x - state.from.x) * e).toFixed(1) + 'px';
      cursor.style.top = (state.from.y + (to.y - state.from.y) * e).toFixed(1) + 'px';
    });
  }

  /* 指针点击：按压反馈 + 波纹（拖拽跳转时跳过纯视觉瞬态） */
  function click(sel, t) {
    at(t, function (live) {
      var target = $(sel);
      var cursor = $('cursor');
      if (!live) return;
      if (cursor) {
        cursor.classList.remove('is-clicking');
        void cursor.offsetWidth;
        cursor.classList.add('is-clicking');
      }
      if (target) {
        target.classList.add('is-pressed');
        window.setTimeout(function () {
          target.classList.remove('is-pressed');
        }, 240);
      }
    });
  }

  function setNav(name) {
    ['overview', 'scan', 'quarantine', 'behavior', 'settings'].forEach(function (id) {
      var el = $('nav-' + id);
      if (el) el.classList.toggle('is-active', id === name);
    });
  }

  function setPage(name, live) {
    ['overview', 'scan', 'quarantine', 'behavior'].forEach(function (id) {
      var el = $('page-' + id);
      if (!el) return;
      var on = id === name;
      el.hidden = !on;
      el.classList.remove('is-entering');
      if (on && live) {
        void el.offsetWidth;
        el.classList.add('is-entering');
      }
    });
  }

  function setCaption(index) {
    if (!captionText) return;
    if (captionNum) captionNum.textContent = String(index + 1);
    caption.classList.add('is-switching');
    var apply = function () {
      captionText.textContent = CHAPTERS[index].title;
      caption.classList.remove('is-switching');
    };
    window.setTimeout(apply, 120);
  }

  function appendLog(kind, time, lvl, msg) {
    var host = $('logbody');
    if (!host) return;
    var line = document.createElement('div');
    line.className = 'dm-logline dm-logline--' + kind;
    line.innerHTML =
      '<span class="dm-logline__time">' + time + '</span>' +
      '<span class="dm-logline__lvl">' + lvl + '</span>' +
      '<span class="dm-logline__msg"></span>';
    line.lastElementChild.textContent = msg;
    host.appendChild(line);
    while (host.children.length > 6) host.removeChild(host.firstChild);
  }

  function appendEvent(time, provider, op, target) {
    var host = $('b-events');
    if (!host) return;
    var tr = document.createElement('tr');
    tr.className = 'is-new';
    tr.innerHTML =
      '<td>' + time + '</td><td>' + provider + '</td><td>' + op + '</td><td class="dm-filepath"></td>';
    tr.lastElementChild.textContent = target;
    host.appendChild(tr);
  }

  /* ---------------------------------------------------------------------------
     分镜脚本（时间单位：秒）
     ------------------------------------------------------------------------ */

  /* —— 第 1 章 0.0–3.6 启动快照（SplashScreen） —— */
  var PHASES = 7; /* 加载安全配置 → 进入主界面 */
  for (var p = 0; p < PHASES; p += 1) {
    (function (idx) {
      at(0.15 + idx * 0.42, function () {
        var phases = $('splash-phases');
        if (!phases) return;
        var items = phases.children;
        for (var i = 0; i < items.length; i += 1) {
          items[i].classList.toggle('is-done', i < idx);
          items[i].classList.toggle('is-active', i === idx);
          var status = items[i].querySelector('.dm-phase__status');
          if (status) status.textContent = i < idx ? '完成' : i === idx ? '进行中' : '等待';
        }
      });
    })(p);
  }
  at(3.25, function () {
    var phases = $('splash-phases');
    if (!phases) return;
    Array.prototype.forEach.call(phases.children, function (item) {
      item.classList.remove('is-active');
      item.classList.add('is-done');
      var status = item.querySelector('.dm-phase__status');
      if (status) status.textContent = '完成';
    });
  });
  tween(0.2, 3.2, function (k) {
    var bar = $('splash-bar');
    var pct = $('splash-pct');
    var e = easeOut(k);
    if (bar) bar.style.transform = 'scaleX(' + e.toFixed(4) + ')';
    if (pct) pct.textContent = Math.round(e * 100) + '%';
  });
  tween(1.0, 3.0, function (k) {
    var el = $('snap-count');
    if (el) el.textContent = '启动快照：' + Math.round(easeOut(k) * 182) + '/182 个进程';
  });
  at(3.3, function () {
    var splash = $('splash');
    if (splash) splash.classList.add('is-done');
  });
  at(3.5, function () {
    var app = $('app');
    if (app) app.classList.add('is-shown');
  });

  /* —— 第 2 章 3.6–8.7 安全概览（OverviewPage） —— */
  var METRICS = [
    { d: 'm1', v: 128394 },
    { d: 'm2', v: 3 },
    { d: 'm3', v: 42801 },
    { d: 'm4', v: 17 },
  ];
  METRICS.forEach(function (m, i) {
    tween(4.0 + i * 0.15, 5.8 + i * 0.15, function (k) {
      var el = $(m.d);
      if (el) el.textContent = fmt(m.v * easeOut(k));
    });
  });
  var LOGS = [
    [4.2, 'ok', '08:41:52', ' OK ', 'engine_service: Axon + Raven 引擎就绪'],
    [4.7, 'info', '08:41:53', 'INFO', 'snapshot_service: 启动快照完成，182 个进程可信'],
    [5.2, 'info', '08:41:55', 'INFO', 'etw_service: 会话已启动，4 个 provider'],
    [5.9, 'info', '08:41:58', 'INFO', 'file_monitor: 24 条事件已写入 SQLite'],
    [6.6, 'warn', '08:42:03', 'WARN', 'risk_service: 检测到可疑自启动写入'],
    [7.3, 'ok', '08:42:05', ' OK ', 'trust_service: 签名链验证通过'],
  ];
  LOGS.forEach(function (l) {
    at(l[0], function () {
      appendLog(l[1], l[2], l[3], l[4]);
    });
  });
  at(6.9, function () {
    var cursor = $('cursor');
    if (cursor) cursor.classList.add('is-shown');
  });
  cursorTo('nav-scan', 7.5, 8.4);
  click('nav-scan', 8.55);

  /* —— 第 3 章 8.7–15.8 文件扫描（ScanPage） —— */
  at(8.7, function (live) {
    setNav('scan');
    setPage('scan', live);
  });
  cursorTo('btn-dir', 9.0, 9.8);
  click('btn-dir', 9.9);
  at(10.15, function () {
    var card = $('sel-card');
    if (card) card.hidden = false;
  });
  cursorTo('btn-start', 10.5, 11.1);
  click('btn-start', 11.2);
  at(11.35, function () {
    var sel = $('sel-card');
    var prog = $('prog-card');
    if (sel) sel.hidden = true;
    if (prog) prog.hidden = false;
  });
  tween(11.35, 13.35, function (k) {
    var fill = $('prog-fill');
    var pct = $('prog-pct');
    var e = easeInOut(k);
    if (fill) fill.style.transform = 'scaleX(' + e.toFixed(4) + ')';
    if (pct) pct.textContent = Math.round(e * 100) + '%';
  });
  var SCAN_FILES = [
    [11.5, 'C:\\Users\\demo\\Downloads\\setup_v2.1.exe'],
    [12.0, 'C:\\Users\\demo\\Downloads\\invoice_scan.exe'],
    [12.5, 'C:\\Users\\demo\\AppData\\Local\\Temp\\update_helper.dll'],
    [12.9, 'C:\\Program Files\\Common Files\\shell_ext.dll'],
  ];
  SCAN_FILES.forEach(function (f) {
    at(f[0], function () {
      var el = $('prog-file');
      if (el) el.textContent = '正在扫描: ' + f[1];
    });
  });
  at(13.45, function (live) {
    var prog = $('prog-card');
    var stats = $('stats');
    var threats = $('threats');
    if (prog) prog.hidden = true;
    if (stats) stats.hidden = false;
    if (threats) threats.hidden = false;
    if (live && threats) {
      Array.prototype.forEach.call(threats.querySelectorAll('tbody tr'), function (tr) {
        tr.classList.add('is-new');
      });
    }
  });
  cursorTo('chk-all', 13.7, 14.2);
  click('chk-all', 14.3);
  at(14.35, function () {
    ['chk-all', 'chk-1', 'chk-2'].forEach(function (d) {
      var el = $(d);
      if (el) el.classList.add('is-checked');
    });
    var badge = $('sel-badge');
    if (badge) badge.textContent = '已选 2';
  });
  cursorTo('btn-clear', 14.5, 15.0);
  click('btn-clear', 15.1);
  at(15.25, function () {
    var threats = $('threats');
    if (threats) {
      Array.prototype.forEach.call(threats.querySelectorAll('tbody tr'), function (tr) {
        tr.classList.add('is-leaving');
      });
    }
  });
  at(15.5, function () {
    var toast = $('toast');
    if (toast) toast.classList.add('is-shown');
  });
  at(16.9, function () {
    var toast = $('toast');
    if (toast) toast.classList.remove('is-shown');
  });

  /* —— 第 4 章 15.8–20.2 威胁拦截（InterceptionModal · 高危） —— */
  at(15.9, function () {
    var dim = $('dim');
    if (dim) dim.classList.add('is-shown');
  });
  at(16.05, function () {
    var modal = $('modal');
    if (modal) modal.classList.add('is-shown');
  });
  [[16.05, '5s'], [17.05, '4s'], [18.05, '3s']].forEach(function (c) {
    at(c[0], function () {
      var el = $('cd-time');
      if (el) el.textContent = c[1];
    });
  });
  tween(16.05, 19.3, function (k) {
    var bar = $('cd-bar');
    if (bar) bar.style.transform = 'scaleX(' + (1 - 0.62 * k).toFixed(4) + ')';
  });
  cursorTo('btn-block', 18.2, 19.0);
  click('btn-block', 19.15);
  at(19.45, function () {
    var modal = $('modal');
    if (modal) modal.classList.remove('is-shown');
  });
  at(19.65, function () {
    var dim = $('dim');
    if (dim) dim.classList.remove('is-shown');
  });

  /* —— 第 5 章 20.2–24.8 隔离区（QuarantinePage） —— */
  cursorTo('nav-quarantine', 19.6, 20.0);
  click('nav-quarantine', 20.1);
  at(20.2, function (live) {
    setNav('quarantine');
    setPage('quarantine', live);
  });
  at(20.5, function (live) {
    var row = $('q-row-2');
    if (row) {
      row.hidden = false;
      if (live) row.classList.add('is-new');
    }
  });
  at(20.9, function (live) {
    var row = $('q-row-3');
    if (row) {
      row.hidden = false;
      if (live) row.classList.add('is-new');
    }
  });
  tween(20.4, 21.2, function (k) {
    var el = $('q-count');
    if (el) el.textContent = String(Math.max(1, Math.round(1 + 2 * k)));
  });
  at(21.0, function () {
    var el = $('q-size');
    if (el) el.textContent = '3.2 MB';
  });
  cursorTo('q-restore', 21.6, 22.5);
  cursorTo('nav-behavior', 24.0, 24.6);
  click('nav-behavior', 24.7);

  /* —— 第 6 章 24.8–28.6 EDR 行为监控（BehaviorPage） —— */
  at(24.85, function (live) {
    setNav('behavior');
    setPage('behavior', live);
  });
  var BSTATS = [
    { d: 'b-total', v: 1284 },
    { d: 'b-proc', v: 312 },
    { d: 'b-file', v: 649 },
    { d: 'b-reg', v: 323 },
  ];
  BSTATS.forEach(function (s, i) {
    tween(25.0 + i * 0.1, 26.2 + i * 0.1, function (k) {
      var el = $(s.d);
      if (el) el.textContent = fmt(s.v * easeOut(k));
    });
  });
  var EVENTS = [
    [25.3, '10:24:01', 'Process', 'ProcessStart', 'cmd.exe /c reg query ...'],
    [25.8, '10:24:03', 'Registry', 'RegSetValue', 'HKCU\\...\\CurrentVersion\\Run'],
    [26.3, '10:24:05', 'File', 'FileWrite', 'C:\\Temp\\stage2.exe'],
    [26.8, '10:24:07', 'Process', 'ImageLoad', 'C:\\Temp\\unsigned.dll'],
    [27.3, '10:24:08', 'Process', 'Suspended', 'interception_service · 等待用户决策'],
  ];
  EVENTS.forEach(function (e) {
    at(e[0], function () {
      appendEvent(e[1], e[2], e[3], e[4]);
    });
  });
  at(27.6, function () {
    var count = $('b-count');
    if (count) count.textContent = '已显示 5 条';
  });

  /* —— 第 7 章 28.6–31.0 收尾 —— */
  at(28.4, function () {
    var cursor = $('cursor');
    if (cursor) cursor.classList.remove('is-shown');
  });
  at(28.6, function () {
    var end = $('end');
    if (end) end.classList.add('is-shown');
  });

  steps.sort(function (a, b) {
    return a.t - b.t;
  });

  /* ---------------------------------------------------------------------------
     播放器
     ------------------------------------------------------------------------ */
  var template = stage.innerHTML;
  var current = 0;
  var playing = false;
  var finished = false;
  var stepIndex = 0;
  var rafId = null;
  var lastTs = null;
  var chapterIndex = -1;
  var autoplayed = false;

  function resetStage() {
    stage.innerHTML = template;
    tweens.forEach(function (tw) {
      tw.state = {};
    });
    stepIndex = 0;
    chapterIndex = -1;
  }

  function applyTweens(t) {
    tweens.forEach(function (tw) {
      /* 未开始的补间不得执行：否则指针补间会过早缓存起点坐标 */
      if (t < tw.t0) return;
      var k = (t - tw.t0) / (tw.t1 - tw.t0);
      if (k > 1) k = 1;
      tw.apply(k, tw.state);
    });
  }

  function runStepsUpTo(t, live) {
    while (stepIndex < steps.length && steps[stepIndex].t <= t) {
      steps[stepIndex].fn(live);
      stepIndex += 1;
    }
  }

  function updateChapter(t) {
    var idx = 0;
    for (var i = 0; i < CHAPTERS.length; i += 1) {
      if (t >= CHAPTERS[i].t) idx = i;
    }
    if (idx !== chapterIndex) {
      chapterIndex = idx;
      setCaption(idx);
    }
    if (track) {
      var markers = track.querySelectorAll('.demo-track__chapter');
      Array.prototype.forEach.call(markers, function (m, i) {
        m.classList.toggle('is-passed', t >= CHAPTERS[i].t - 0.01);
      });
    }
  }

  function updateChrome(t) {
    if (trackFill) trackFill.style.transform = 'scaleX(' + (t / DURATION).toFixed(4) + ')';
    if (timeEl) {
      var s = Math.floor(t);
      var total = Math.round(DURATION);
      timeEl.textContent =
        '00:' + (s < 10 ? '0' : '') + s + ' / 00:' + (total < 10 ? '0' : '') + total;
    }
    updateChapter(t);
  }

  function setPlayGlyph(state) {
    if (!playBtn) return;
    playBtn.setAttribute('aria-label', state === 'play' ? '播放演示' : '暂停演示');
    Array.prototype.forEach.call(playBtn.querySelectorAll('[data-glyph]'), function (g) {
      g.classList.toggle('is-shown', g.getAttribute('data-glyph') === state);
    });
  }

  function frame(ts) {
    if (!playing) return;
    if (lastTs === null) lastTs = ts;
    var dt = Math.min(0.1, (ts - lastTs) / 1000);
    lastTs = ts;
    current = Math.min(DURATION, current + dt);
    runStepsUpTo(current, true);
    applyTweens(current);
    updateChrome(current);
    if (current >= DURATION) {
      playing = false;
      finished = true;
      setPlayGlyph('play');
      if (posterHint) posterHint.textContent = '重播 30 秒功能演示';
      if (poster) poster.classList.remove('is-hidden');
      return;
    }
    rafId = window.requestAnimationFrame(frame);
  }

  function play() {
    if (playing) return;
    if (finished || current >= DURATION) {
      finished = false;
      current = 0;
      resetStage();
    }
    playing = true;
    lastTs = null;
    setPlayGlyph('pause');
    if (poster) poster.classList.add('is-hidden');
    rafId = window.requestAnimationFrame(frame);
  }

  function pause() {
    playing = false;
    if (rafId) window.cancelAnimationFrame(rafId);
    setPlayGlyph('play');
  }

  function seek(t) {
    t = Math.max(0, Math.min(DURATION, t));
    finished = false;
    resetStage();
    current = t;
    runStepsUpTo(t, false);
    applyTweens(t);
    updateChrome(t);
    /* 拖到中段时展示指针（第 2 章后出现） */
    var cursor = $('cursor');
    if (cursor && t >= 6.9 && t < 28.4) cursor.classList.add('is-shown');
  }

  function replay() {
    pause();
    seek(0);
    play();
  }

  /* ---------------------------------------------------------------------------
     控件绑定
     ------------------------------------------------------------------------ */
  if (playBtn) {
    playBtn.addEventListener('click', function () {
      if (playing) pause();
      else play();
    });
  }

  if (replayBtn) replayBtn.addEventListener('click', replay);

  if (poster) {
    poster.addEventListener('click', function () {
      play();
    });
  }

  if (track) {
    /* 章节标记 */
    CHAPTERS.forEach(function (ch, i) {
      var marker = document.createElement('span');
      marker.className = 'demo-track__chapter';
      marker.style.left = (ch.t / DURATION) * 100 + '%';
      marker.title = '第 ' + (i + 1) + ' 章 · ' + ch.title;
      track.appendChild(marker);
    });

    function seekFromEvent(event) {
      var rect = track.getBoundingClientRect();
      var ratio = (event.clientX - rect.left) / rect.width;
      seek(ratio * DURATION);
    }

    var dragging = false;
    track.addEventListener('pointerdown', function (event) {
      dragging = true;
      track.setPointerCapture(event.pointerId);
      pause();
      seekFromEvent(event);
    });
    track.addEventListener('pointermove', function (event) {
      if (dragging) seekFromEvent(event);
    });
    track.addEventListener('pointerup', function () {
      dragging = false;
    });
  }

  /* 章节亮点卡点击跳转 */
  document.querySelectorAll('[data-chapter]').forEach(function (card) {
    card.addEventListener('click', function () {
      var idx = parseInt(card.getAttribute('data-chapter'), 10);
      if (isNaN(idx) || !CHAPTERS[idx]) return;
      shell.scrollIntoView({ behavior: motionEnabled() ? 'smooth' : 'auto', block: 'center' });
      seek(CHAPTERS[idx].t);
      play();
    });
  });

  /* 空格键播放/暂停 */
  document.addEventListener('keydown', function (event) {
    if (event.code !== 'Space' || event.target.closest('input, textarea, button, a')) return;
    event.preventDefault();
    if (playing) pause();
    else play();
  });

  /* 页面不可见时自动暂停 */
  document.addEventListener('visibilitychange', function () {
    if (document.hidden && playing) pause();
  });

  /* 进入视口后自动播放一次（尊重动效开关） */
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting && !autoplayed && motionEnabled()) {
            autoplayed = true;
            window.setTimeout(play, 450);
          }
        });
      },
      { threshold: 0.45 }
    ).observe(scaler);
  }

  /* ---------------------------------------------------------------------------
     舞台等比缩放
     ------------------------------------------------------------------------ */
  function fit() {
    var width = scaler.clientWidth;
    var scale = width / 960;
    stage.style.transform = 'scale(' + scale + ')';
    scaler.style.height = 600 * scale + 'px';
  }

  window.addEventListener('resize', fit);
  fit();
  updateChrome(0);
  setCaption(0);
})();
