// Hero halftone chain link — two interlocked tori, raymarched per halftone
// cell against the exact SDF (no mesh, no WebGL, no deps), screened as a
// classic 45-degree rotated-dot halftone. A "transfer pulse" of brighter
// dots periodically runs around one ring, crosses at the interlock, and
// continues around the other — a file handoff, abstracted. Halftone-hero
// technique inspired by solosystems.dev/jcode; form, palette, pulse, and
// implementation are our own.
(function () {
  "use strict";

  var R = 1.32, TUBE = 0.36, D2 = R / 2, K2 = 5.6;
  var BOUND = R + TUBE + D2 + 0.05;
  var MAX_STEPS = 44, EPS = 6e-4;
  var LY = 0.7071, LZ = -0.7071;

  function makeField(cols, rows) {
    var lum = new Float32Array(cols * rows);
    var K1 = (cols * K2 * 3) / (8 * (R + TUBE + D2));

    function render(t, spin, pulsePhase, pulseOn) {
      var A = 0.62 + Math.sin(t * 0.33) * 0.22;
      var B = t * 0.5 + spin;
      var cA = Math.cos(A), sA = Math.sin(A);
      var cB = Math.cos(B), sB = Math.sin(B);
      var M00 = cB,      M01 = 0,   M02 = -sB;
      var M10 = sB * sA, M11 = cA,  M12 = cB * sA;
      var M20 = sB * cA, M21 = -sA, M22 = cB * cA;
      var ox = M02 * -K2, oy = M12 * -K2, oz = M22 * -K2;

      var TAU = Math.PI * 2;
      var headA = pulsePhase < 1 ? pulsePhase * TAU : -1;
      var headB = pulsePhase >= 1 ? Math.PI + (pulsePhase - 1) * TAU : -1;
      var PW = 0.11;
      var CC = K2 * K2 - BOUND * BOUND;

      var idx = 0;
      for (var yc = 0; yc < rows; yc++) {
        var pyw = -(yc + 0.5 - rows / 2) / K1;
        for (var xc = 0; xc < cols; xc++, idx++) {
          var pxw = (xc + 0.5 - cols / 2) / K1;
          var inv = 1 / Math.sqrt(pxw * pxw + pyw * pyw + 1);
          var dwx = pxw * inv, dwy = pyw * inv, dwz = inv;
          var dx = M00 * dwx + M01 * dwy + M02 * dwz;
          var dy = M10 * dwx + M11 * dwy + M12 * dwz;
          var dz = M20 * dwx + M21 * dwy + M22 * dwz;

          var bq = -(dx * ox + dy * oy + dz * oz);
          var disc = bq * bq - CC;
          if (disc <= 0) { lum[idx] = 0; continue; }
          var sq = Math.sqrt(disc);
          var s = bq - sq, sEnd = bq + sq;
          if (s < 0) s = 0;

          var hit = false, isA = false, px = 0, py = 0, pz = 0;
          for (var st = 0; st < MAX_STEPS; st++) {
            px = ox + dx * s; py = oy + dy * s; pz = oz + dz * s;
            var ax = px + D2;
            var la = Math.sqrt(ax * ax + py * py);
            var qa = la - R;
            var dA = Math.sqrt(qa * qa + pz * pz) - TUBE;
            var bx = px - D2;
            var lb = Math.sqrt(bx * bx + pz * pz);
            var qb = lb - R;
            var dB = Math.sqrt(qb * qb + py * py) - TUBE;
            var d = dA < dB ? dA : dB;
            if (d < EPS * s) { hit = true; isA = dA < dB; break; }
            s += d;
            if (s > sEnd) break;
          }
          if (!hit) { lum[idx] = 0; continue; }

          var nx, ny, nz, k, l;
          if (isA) {
            l = Math.sqrt((px + D2) * (px + D2) + py * py) || 1;
            k = R / l;
            nx = (px + D2) * (1 - k); ny = py * (1 - k); nz = pz;
          } else {
            l = Math.sqrt((px - D2) * (px - D2) + pz * pz) || 1;
            k = R / l;
            nx = (px - D2) * (1 - k); ny = py; nz = pz * (1 - k);
          }
          var nl = Math.sqrt(nx * nx + ny * ny + nz * nz) || 1;
          nx /= nl; ny /= nl; nz /= nl;

          var lx = M01 * LY + M02 * LZ;
          var ly = M11 * LY + M12 * LZ;
          var lz = M21 * LY + M22 * LZ;
          var v = nx * lx + ny * ly + nz * lz;
          if (v < 0) v = 0;
          v = 0.07 + v * 0.73;
          var df = 1.08 - 0.55 * ((s - (K2 - BOUND)) / (2 * BOUND));
          v *= df > 1 ? 1 : df;

          if (pulseOn) {
            var ang, head;
            if (isA) { ang = Math.atan2(py, px + D2); head = headA; }
            else     { ang = Math.atan2(pz, px - D2); head = headB; }
            if (head >= 0) {
              var dd = ang - head;
              while (dd > Math.PI) dd -= TAU;
              while (dd < -Math.PI) dd += TAU;
              var boost = Math.exp(-(dd * dd) / PW) + (dd < 0 ? Math.exp(dd * 2.2) * 0.35 : 0);
              v = Math.min(1.25, Math.max(v, boost * 1.15));
            }
          }
          lum[idx] = v;
        }
      }
      return lum;
    }
    return { lum: lum, render: render };
  }

  function start(canvas) {
    var cells = 72;
    var grid = cells * 2;
    var field = makeField(grid, grid);

    var cssW = canvas.clientWidth || 440;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = cssW * dpr;
    canvas.height = cssW * dpr;
    var ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);

    function inkColor() {
      var v = getComputedStyle(document.documentElement).getPropertyValue("--chain-ink").trim();
      return v || "#f2b184";
    }
    var ink = inkColor();
    var pitch = cssW / cells;
    var cosA = Math.SQRT1_2, sinA = Math.SQRT1_2;
    var half = cssW / 2;
    var ext = Math.ceil(cells * 0.7071) + 1;

    function sample(gx, gy) {
      if (gx < 0 || gy < 0 || gx > grid - 2 || gy > grid - 2) return 0;
      var x0 = gx | 0, y0 = gy | 0;
      var fx = gx - x0, fy = gy - y0;
      var l = field.lum;
      var a = l[x0 + y0 * grid], b = l[x0 + 1 + y0 * grid];
      var c = l[x0 + (y0 + 1) * grid], d = l[x0 + 1 + (y0 + 1) * grid];
      return a * (1 - fx) * (1 - fy) + b * fx * (1 - fy) + c * (1 - fx) * fy + d * fx * fy;
    }

    var spin = 0, dragVel = 0, dragging = false, lastX = 0;
    canvas.style.cursor = "grab";
    canvas.style.touchAction = "pan-y";
    canvas.addEventListener("pointerdown", function (e) {
      dragging = true; lastX = e.clientX;
      canvas.setPointerCapture(e.pointerId);
      canvas.style.cursor = "grabbing";
    });
    canvas.addEventListener("pointermove", function (e) {
      if (!dragging) return;
      dragVel += (e.clientX - lastX) * 0.006;
      lastX = e.clientX;
    });
    function endDrag() { dragging = false; canvas.style.cursor = "grab"; }
    canvas.addEventListener("pointerup", endDrag);
    canvas.addEventListener("pointercancel", endDrag);

    var PERIOD = 9, LAPS_TIME = 4.6;
    var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var visible = true;
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting;
      }).observe(canvas);
    }

    function draw(t) {
      var tp = t % PERIOD;
      var pulseOn = tp < LAPS_TIME;
      var pulsePhase = pulseOn ? (tp / LAPS_TIME) * 2 : 0;
      field.render(t, spin, pulsePhase, pulseOn);
      ctx.clearRect(0, 0, cssW, cssW);
      ctx.fillStyle = ink;
      var maxR = pitch * 0.56;
      for (var j = -ext; j <= ext; j++) {
        for (var i = -ext; i <= ext; i++) {
          var x = (i * cosA - j * sinA) * pitch + half;
          var y = (i * sinA + j * cosA) * pitch + half;
          if (x < -pitch || y < -pitch || x > cssW + pitch || y > cssW + pitch) continue;
          var v = sample((x / cssW) * grid, (y / cssW) * grid);
          if (v <= 0.015) continue;
          var rad = Math.sqrt(Math.min(v, 1.25)) * maxR;
          ctx.beginPath();
          ctx.arc(x, y, rad, 0, 6.2832);
          ctx.fill();
        }
      }
    }

    // First paint is synchronous: hidden/throttled tabs and reduced-motion
    // users get a perfect still frame without ever needing rAF.
    var T_HERO = 0.9;
    draw(T_HERO);

    var lastT = T_HERO;
    function reink() { ink = inkColor(); draw(lastT); }
    if (window.matchMedia) {
      var mq = window.matchMedia("(prefers-color-scheme: light)");
      if (mq.addEventListener) mq.addEventListener("change", reink);
    }
    new MutationObserver(reink).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    if (reduced) return;
    var t0 = performance.now();
    function frame(now) {
      if (!visible || document.hidden) { requestAnimationFrame(frame); return; }
      spin += dragVel; dragVel *= 0.92;
      lastT = T_HERO + (now - t0) / 1000;
      draw(lastT);
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function fillStars() {
    var els = document.querySelectorAll("[data-gh-stars]");
    if (!els.length) return;
    fetch("https://api.github.com/repos/shehryarsaroya/agenttransfer")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j || typeof j.stargazers_count !== "number") return;
        els.forEach(function (el) {
          el.textContent = "★ " + j.stargazers_count.toLocaleString();
          el.removeAttribute("hidden");
        });
      })
      .catch(function () {});
  }

  function fillStats() {
    var els = document.querySelectorAll("[data-stat]");
    if (!els.length) return;
    fetch("/v1/stats")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        if (!j) return;
        els.forEach(function (el) {
          var k = el.getAttribute("data-stat");
          if (j[k] === undefined || j[k] === null) return;
          el.textContent = typeof j[k] === "number" ? j[k].toLocaleString() : String(j[k]);
        });
      })
      .catch(function () {});
  }

  function init() {
    var c = document.getElementById("chain");
    if (c) start(c);
    fillStars();
    fillStats();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

