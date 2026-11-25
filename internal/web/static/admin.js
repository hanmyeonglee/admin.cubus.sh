(() => {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const THEME_KEY = "admin_theme";

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
  const page = document.body ? (document.body.getAttribute("data-page") || "") : "";
  const activeService = document.body ? (document.body.getAttribute("data-service") || "") : "";

  // Strict DOM helpers (always build nodes via createElement / createElementNS + textContent).
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function makeSvgIcon(pathDefs, size, cls) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("xmlns", SVG_NS);
    svg.setAttribute("width", String(size || 16));
    svg.setAttribute("height", String(size || 16));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    if (cls) svg.setAttribute("class", cls);
    pathDefs.forEach((d) => {
      const p = document.createElementNS(SVG_NS, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    });
    return svg;
  }

  // ==================== THEME MANAGEMENT ====================
  const SUN_PATHS = [
    "M12 12m-4 0a4 4 0 1 0 8 0a4 4 0 1 0 -8 0",
    "M3 12h1m8 -9v1m8 8h1m-9 8v1m-6.4 -15.4l.7 .7m12.1 -.7l-.7 .7m0 11.4l.7 .7m-12.1 -.7l-.7 .7"
  ];
  const MOON_PATHS = [
    "M12 3c.132 0 .263 0 .393 0a7.5 7.5 0 0 0 7.92 12.446a9 9 0 1 1 -8.313 -12.454z"
  ];

  const themeListeners = [];

  function readStoredTheme() {
    try {
      const v = window.localStorage.getItem(THEME_KEY);
      if (v === "dark" || v === "light") return v;
    } catch {}
    return null;
  }

  function saveTheme(theme) {
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {}
  }

  function resolveInitialTheme() {
    const stored = readStoredTheme();
    if (stored) return stored;
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  }

  function updateThemeToggleButtons(theme) {
    const isDark = theme === "dark";
    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      btn.setAttribute("aria-pressed", isDark ? "true" : "false");
      btn.setAttribute("title", isDark ? "Switch to light mode" : "Switch to dark mode");
      const iconSlot = btn.querySelector(".theme-toggle-icon");
      if (iconSlot) {
        clear(iconSlot);
        iconSlot.appendChild(makeSvgIcon(isDark ? SUN_PATHS : MOON_PATHS, 16, "icon-inline"));
      }
      const labelSlot = btn.querySelector(".theme-toggle-label");
      if (labelSlot) {
        labelSlot.textContent = isDark ? "Light mode" : "Dark mode";
      }
    });
  }

  function applyTheme(theme) {
    const next = theme === "dark" ? "dark" : "light";
    document.documentElement.setAttribute("data-bs-theme", next);
    updateThemeToggleButtons(next);
    themeListeners.forEach((fn) => {
      try { fn(next); } catch {}
    });
  }

  function initTheme() {
    applyTheme(resolveInitialTheme());
    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
        const next = current === "dark" ? "light" : "dark";
        saveTheme(next);
        applyTheme(next);
      });
    });
    if (window.matchMedia) {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      const onMediaChange = (e) => {
        if (!readStoredTheme()) {
          applyTheme(e.matches ? "dark" : "light");
        }
      };
      if (typeof mq.addEventListener === "function") {
        mq.addEventListener("change", onMediaChange);
      }
    }
  }

  // ==================== SIDEBAR NAVIGATION ====================
  function initSidebar() {
    const toggler = document.getElementById("sidebar-toggler");
    const menu = document.getElementById("sidebar-menu");
    if (!toggler || !menu) return;

    function setOpen(open) {
      menu.classList.toggle("show", open);
      toggler.setAttribute("aria-expanded", open ? "true" : "false");
    }

    toggler.addEventListener("click", () => {
      setOpen(!menu.classList.contains("show"));
    });

    menu.querySelectorAll("a.nav-link").forEach((link) => {
      link.addEventListener("click", () => {
        if (window.innerWidth < 992) setOpen(false);
      });
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && menu.classList.contains("show") && window.innerWidth < 992) {
        setOpen(false);
        toggler.focus();
      }
    });
  }

  // ==================== TOASTS & CONFIRM MODAL ====================
  function showToast(msg, isError) {
    const toast = document.getElementById("toast");
    const body = document.getElementById("toast-body");
    const title = document.getElementById("toast-title");
    const dot = document.getElementById("toast-dot");
    if (!toast || !body) return;

    body.textContent = msg;
    if (title) title.textContent = isError ? "Error" : "Success";
    if (dot) {
      dot.className = "toast-status-dot me-2 " + (isError ? "bg-danger" : "bg-green");
    }
    toast.classList.toggle("border-danger", Boolean(isError));
    toast.classList.add("show");
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove("show"), 4000);
  }

  const toastClose = document.getElementById("toast-close");
  if (toastClose) {
    toastClose.addEventListener("click", () => {
      const toast = document.getElementById("toast");
      if (toast) toast.classList.remove("show");
    });
  }

  let activeConfirmCleanup = null;

  function confirmAction(opts) {
    const modal = document.getElementById("confirm-modal");
    const backdrop = document.getElementById("confirm-backdrop");
    const titleEl = document.getElementById("confirm-modal-title");
    const bodyEl = document.getElementById("confirm-modal-body");
    const okBtn = document.getElementById("confirm-modal-ok");
    const cancelBtn = document.getElementById("confirm-modal-cancel");
    const statusBar = document.getElementById("confirm-modal-status");

    if (!modal || !backdrop || !okBtn || !cancelBtn) {
      return Promise.resolve(window.confirm(opts.message || "Are you sure?"));
    }

    if (activeConfirmCleanup) {
      activeConfirmCleanup(false);
    }

    const prevFocus = document.activeElement;
    const variant = opts.variant || "danger";
    if (titleEl) titleEl.textContent = opts.title || "Confirm action";
    if (bodyEl) bodyEl.textContent = opts.message || "";
    okBtn.textContent = opts.confirmLabel || "Confirm";
    okBtn.className = "btn w-100 " + (variant === "warning" ? "btn-warning" : "btn-danger");
    if (statusBar) statusBar.className = "modal-status " + (variant === "warning" ? "bg-warning" : "bg-danger");

    modal.classList.add("show");
    modal.setAttribute("aria-hidden", "false");
    backdrop.classList.add("show");
    cancelBtn.focus();

    return new Promise((resolve) => {
      let settled = false;
      function cleanup(result) {
        if (settled) return;
        settled = true;
        activeConfirmCleanup = null;
        modal.classList.remove("show");
        modal.setAttribute("aria-hidden", "true");
        backdrop.classList.remove("show");
        okBtn.removeEventListener("click", onOk);
        cancelBtn.removeEventListener("click", onCancel);
        modal.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) {
          try { prevFocus.focus(); } catch {}
        }
        resolve(result);
      }

      activeConfirmCleanup = cleanup;

      function onOk() { cleanup(true); }
      function onCancel() { cleanup(false); }
      function onBackdrop(e) {
        if (e.target === modal) cleanup(false);
      }
      function onKey(e) {
        if (e.key === "Escape") {
          e.preventDefault();
          cleanup(false);
          return;
        }
        if (e.key === "Tab") {
          const focusables = [cancelBtn, okBtn].filter((b) => !b.disabled);
          if (focusables.length === 0) return;
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          if (e.shiftKey) {
            if (document.activeElement === first || !modal.contains(document.activeElement)) {
              e.preventDefault();
              last.focus();
            }
          } else if (document.activeElement === last || !modal.contains(document.activeElement)) {
            e.preventDefault();
            first.focus();
          }
        }
      }

      okBtn.addEventListener("click", onOk);
      cancelBtn.addEventListener("click", onCancel);
      modal.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
    });
  }

  // ==================== FORMATTERS & API ====================
  function fmtBytes(n) {
    if (n === undefined || n === null || Number.isNaN(Number(n))) return "—";
    const num = Number(n);
    if (num >= 1024 ** 3) return (num / 1024 ** 3).toFixed(2) + " GiB";
    if (num >= 1024 ** 2) return (num / 1024 ** 2).toFixed(1) + " MiB";
    if (num >= 1024) return (num / 1024).toFixed(1) + " KiB";
    return num + " B";
  }

  function fmtUptime(sec) {
    if (!sec || sec < 0) return "—";
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + "d " + h + "h " + m + "m";
    if (h > 0) return h + "h " + m + "m";
    return m + "m";
  }

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
  }

  function fmtShortHHMM(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    return d.toISOString().slice(11, 16) + "Z";
  }

  async function apiFetch(url, options) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options || {});
    if (opts.method && opts.method !== "GET" && opts.method !== "HEAD") {
      opts.headers["X-CSRF-Token"] = csrfToken;
    }
    const resp = await fetch(url, opts);
    let data = null;
    try { data = await resp.json(); } catch {}
    if (!resp.ok) {
      const msg = (data && data.error) ? data.error : ("HTTP " + resp.status);
      throw new Error(msg);
    }
    return data;
  }

  function progressColorClass(pct) {
    if (pct >= 90) return "bg-red";
    if (pct >= 75) return "bg-yellow";
    return "bg-primary";
  }

  function makeProgress(pct, label, valueText) {
    const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
    const wrap = el("div", "progress progress-sm");
    const bar = el("div", "progress-bar " + progressColorClass(clamped));
    bar.setAttribute("role", "progressbar");
    bar.setAttribute("aria-valuenow", String(Math.round(clamped)));
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    if (label) bar.setAttribute("aria-label", label);
    if (valueText) bar.setAttribute("aria-valuetext", valueText);
    bar.style.width = clamped.toFixed(1) + "%";
    wrap.appendChild(bar);
    return wrap;
  }

  function makeEmptyRow(colSpan, title, subtitle) {
    const tr = el("tr");
    const td = el("td", "text-center py-4 text-secondary");
    td.colSpan = colSpan;
    const t = el("div", "fw-medium", title);
    td.appendChild(t);
    if (subtitle) td.appendChild(el("div", "small text-secondary mt-1", subtitle));
    tr.appendChild(td);
    return tr;
  }

  // ==================== INTERACTIVE TELEMETRY CHARTS ====================
  const chartRegistry = new Map();

  function createChartCard(cfg) {
    const col = el("div", "col-md-6");
    const card = el("div", "card card-sm");

    const hdr = el("div", "card-header py-2");
    const titleWrap = el("div", "d-flex align-items-center gap-2");
    const dot = el("span", "status-dot " + (cfg.dotClass || "status-blue"));
    titleWrap.appendChild(dot);
    titleWrap.appendChild(el("span", "fw-medium", cfg.title));
    hdr.appendChild(titleWrap);

    const meta = el("div", "card-actions text-secondary small tabular-nums");
    const curValEl = el("strong", "text-reset me-2", "—");
    const statsEl = el("span", "text-secondary", "");
    meta.appendChild(curValEl);
    meta.appendChild(statsEl);
    hdr.appendChild(meta);
    card.appendChild(hdr);

    const body = el("div", "card-body p-2");
    const wrap = el("div", "chart-canvas-wrap");
    const canvas = el("canvas", "chart-canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", cfg.title + " 1-hour history chart");
    const tooltip = el("div", "chart-tooltip d-none");
    wrap.appendChild(canvas);
    wrap.appendChild(tooltip);
    body.appendChild(wrap);
    card.appendChild(body);
    col.appendChild(card);

    let ro = null;
    const state = {
      id: cfg.id,
      col: col,
      canvas: canvas,
      wrap: wrap,
      tooltip: tooltip,
      dot: dot,
      curValEl: curValEl,
      statsEl: statsEl,
      unit: cfg.unit || "%",
      fixedMax: cfg.maxVal || null,
      colorClass: cfg.colorClass || "text-primary",
      samples: [],
      validIndices: [],
      hoverIndex: -1,
      draw: draw,
      update: update,
      destroy: () => {
        if (ro) {
          ro.disconnect();
          ro = null;
        }
      }
    };

    function computeScale(vals) {
      if (state.fixedMax) return state.fixedMax;
      const peak = Math.max(10, ...vals);
      return Math.ceil(peak / 10) * 10;
    }

    function draw() {
      const rect = wrap.getBoundingClientRect();
      const width = Math.max(120, Math.floor(rect.width));
      const height = Math.max(100, Math.floor(rect.height));
      const dpr = Math.min(window.devicePixelRatio || 1, 3);
      if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(height * dpr)) {
        canvas.width = Math.floor(width * dpr);
        canvas.height = Math.floor(height * dpr);
      }

      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const strokeColor = getComputedStyle(state.dot).backgroundColor || "#206bc4";
      const mutedColor = getComputedStyle(state.statsEl).color || "#6c7a91";
      const gridColor = getComputedStyle(card).borderTopColor || "rgba(128,128,128,0.2)";
      const surfaceColor = getComputedStyle(card).backgroundColor || "#ffffff";

      const padLeft = 38;
      const padRight = 10;
      const padTop = 10;
      const padBottom = 22;
      const plotW = Math.max(20, width - padLeft - padRight);
      const plotH = Math.max(20, height - padTop - padBottom);

      const samples = state.samples;
      const validIndices = state.validIndices;
      const vals = validIndices.map((idx) => samples[idx].val);
      const yMax = computeScale(vals.length ? vals : [100]);

      // Horizontal gridlines & Y-axis labels
      ctx.font = "11px system-ui, -apple-system, sans-serif";
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      const ticks = [0, 0.25, 0.5, 0.75, 1];
      ticks.forEach((frac) => {
        const y = padTop + plotH * (1 - frac);
        ctx.save();
        ctx.strokeStyle = gridColor;
        ctx.globalAlpha = frac === 0 ? 0.9 : 0.55;
        ctx.setLineDash(frac === 0 ? [] : [3, 3]);
        ctx.beginPath();
        ctx.moveTo(padLeft, y);
        ctx.lineTo(padLeft + plotW, y);
        ctx.stroke();
        ctx.restore();

        const labelVal = Math.round(yMax * frac) + state.unit;
        ctx.fillStyle = mutedColor;
        ctx.fillText(labelVal, padLeft - 6, y);
      });

      if (validIndices.length === 0) {
        tooltip.classList.add("d-none");
        ctx.fillStyle = mutedColor;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("Waiting for telemetry samples...", padLeft + plotW / 2, padTop + plotH / 2);
        return;
      }

      const xFor = (idx) => {
        if (samples.length === 1) return padLeft + plotW / 2;
        return padLeft + (idx / (samples.length - 1)) * plotW;
      };
      const yFor = (val) => {
        const clamped = Math.max(0, Math.min(yMax, val));
        return padTop + plotH - (clamped / yMax) * plotH;
      };

      // X-axis time ticks (start / mid / end)
      ctx.fillStyle = mutedColor;
      ctx.textBaseline = "top";
      const startLbl = fmtShortHHMM(samples[0].ts);
      const endLbl = fmtShortHHMM(samples[samples.length - 1].ts);
      if (startLbl) {
        ctx.textAlign = "left";
        ctx.fillText(startLbl, padLeft, padTop + plotH + 6);
      }
      if (samples.length >= 3) {
        const midLbl = fmtShortHHMM(samples[Math.floor(samples.length / 2)].ts);
        if (midLbl) {
          ctx.textAlign = "center";
          ctx.fillText(midLbl, padLeft + plotW / 2, padTop + plotH + 6);
        }
      }
      if (endLbl && samples.length >= 2) {
        ctx.textAlign = "right";
        ctx.fillText(endLbl, padLeft + plotW, padTop + plotH + 6);
      }

      // Build contiguous non-null runs so missing intervals render as gaps rather than bridged lines
      const runs = [];
      let curRun = null;
      samples.forEach((s, i) => {
        if (s.val !== null) {
          if (!curRun) {
            curRun = { start: i, end: i };
            runs.push(curRun);
          } else {
            curRun.end = i;
          }
        } else {
          curRun = null;
        }
      });

      runs.forEach((run) => {
        if (run.end <= run.start) return;
        ctx.save();
        ctx.beginPath();
        for (let i = run.start; i <= run.end; i++) {
          const x = xFor(i);
          const y = yFor(samples[i].val);
          if (i === run.start) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.lineTo(xFor(run.end), padTop + plotH);
        ctx.lineTo(xFor(run.start), padTop + plotH);
        ctx.closePath();
        ctx.fillStyle = strokeColor;
        ctx.globalAlpha = 0.14;
        ctx.fill();
        ctx.restore();

        ctx.save();
        ctx.beginPath();
        for (let i = run.start; i <= run.end; i++) {
          const x = xFor(i);
          const y = yFor(samples[i].val);
          if (i === run.start) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2;
        ctx.lineJoin = "round";
        ctx.lineCap = "round";
        ctx.stroke();
        ctx.restore();
      });

      // Highlight either hovered valid point or latest valid point
      const activeIdx = (state.hoverIndex >= 0 && state.hoverIndex < samples.length && samples[state.hoverIndex].val !== null)
        ? state.hoverIndex
        : validIndices[validIndices.length - 1];
      const ax = xFor(activeIdx);
      const ay = yFor(samples[activeIdx].val);

      if (state.hoverIndex >= 0 && state.hoverIndex < samples.length && samples[state.hoverIndex].val !== null) {
        ctx.save();
        ctx.strokeStyle = mutedColor;
        ctx.globalAlpha = 0.6;
        ctx.setLineDash([3, 3]);
        ctx.beginPath();
        ctx.moveTo(ax, padTop);
        ctx.lineTo(ax, padTop + plotH);
        ctx.stroke();
        ctx.restore();
      }

      ctx.save();
      ctx.beginPath();
      ctx.arc(ax, ay, state.hoverIndex >= 0 ? 4.5 : 3.2, 0, Math.PI * 2);
      ctx.fillStyle = strokeColor;
      ctx.fill();
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = surfaceColor;
      ctx.stroke();
      ctx.restore();

      if (state.hoverIndex >= 0 && state.hoverIndex < samples.length && samples[state.hoverIndex].val !== null) {
        const pt = samples[state.hoverIndex];
        tooltip.textContent = (pt.ts ? (fmtTime(pt.ts) + " · ") : "") + pt.val.toFixed(1) + state.unit;
        tooltip.classList.remove("d-none");
        const tipW = tooltip.offsetWidth || 120;
        const leftPos = Math.min(Math.max(padLeft, ax - tipW / 2), width - tipW - 6);
        const topPos = Math.max(4, ay - 32);
        tooltip.style.left = leftPos.toFixed(0) + "px";
        tooltip.style.top = topPos.toFixed(0) + "px";
      } else {
        tooltip.classList.add("d-none");
      }
    }

    function handlePointer(clientX) {
      if (state.validIndices.length === 0 || state.samples.length === 0) return;
      const rect = canvas.getBoundingClientRect();
      const padLeft = 38;
      const padRight = 10;
      const plotW = Math.max(20, rect.width - padLeft - padRight);
      const relX = clientX - rect.left - padLeft;
      const ratio = Math.max(0, Math.min(1, relX / plotW));
      const target = Math.round(ratio * (state.samples.length - 1));
      let nearest = state.validIndices[0];
      let bestDist = Math.abs(nearest - target);
      state.validIndices.forEach((idx) => {
        const d = Math.abs(idx - target);
        if (d < bestDist) {
          bestDist = d;
          nearest = idx;
        }
      });
      state.hoverIndex = nearest;
      draw();
    }

    canvas.addEventListener("pointermove", (e) => handlePointer(e.clientX));
    canvas.addEventListener("pointerleave", () => {
      state.hoverIndex = -1;
      draw();
    });

    if (typeof ResizeObserver === "function") {
      ro = new ResizeObserver(() => draw());
      ro.observe(wrap);
    }

    function update(latestText, rawPoints, valueFn) {
      const mapped = [];
      const validIdx = [];
      (rawPoints || []).forEach((p, idx) => {
        const v = valueFn(p);
        const isNum = v !== null && v !== undefined && !Number.isNaN(Number(v));
        mapped.push({ ts: p.ts || "", val: isNum ? Number(v) : null });
        if (isNum) validIdx.push(idx);
      });
      state.samples = mapped;
      state.validIndices = validIdx;
      state.curValEl.textContent = latestText;
      if (validIdx.length > 0) {
        let sum = 0;
        let max = mapped[validIdx[0]].val;
        validIdx.forEach((i) => {
          const val = mapped[i].val;
          sum += val;
          if (val > max) max = val;
        });
        const avg = sum / validIdx.length;
        state.statsEl.textContent = "avg " + avg.toFixed(1) + state.unit + " · max " + max.toFixed(1) + state.unit;
      } else {
        state.statsEl.textContent = "";
      }
      draw();
    }

    return state;
  }

  themeListeners.push(() => {
    chartRegistry.forEach((c) => c.draw());
  });

  // ==================== OVERVIEW PAGE ====================
  function makeKPICard(label, value, badgeText, sub, pct, valueText) {
    const col = el("div", "col-sm-6 col-xl");
    const card = el("div", "card");
    const body = el("div", "card-body");

    const topRow = el("div", "d-flex align-items-center justify-content-between gap-2 mb-1");
    topRow.appendChild(el("div", "subheader", label));
    if (badgeText) topRow.appendChild(el("span", "badge bg-secondary-lt tabular-nums", badgeText));
    body.appendChild(topRow);

    body.appendChild(el("div", "h1 mb-2 tabular-nums", value));
    body.appendChild(el("div", "text-secondary small mb-2", sub));
    if (pct !== null && pct !== undefined) {
      body.appendChild(makeProgress(pct, label, valueText));
    }

    card.appendChild(body);
    col.appendChild(card);
    return col;
  }

  function renderSystem(sys) {
    const hwGrid = document.getElementById("hw-grid");
    const subtitle = document.getElementById("page-subtitle");
    if (!hwGrid || !sys) return;

    if (subtitle && sys.host) {
      subtitle.textContent = [
        sys.host.hostname,
        sys.host.os,
        sys.host.kernel ? ("kernel " + sys.host.kernel) : "",
        "up " + fmtUptime(sys.host.uptime_seconds)
      ].filter(Boolean).join(" · ");
    }

    clear(hwGrid);
    const cpu = sys.cpu || {};
    const mem = sys.memory || {};
    const disk = sys.disk || {};

    hwGrid.appendChild(makeKPICard(
      "CPU Usage",
      (cpu.usage_pct ?? 0).toFixed(1) + "%",
      (cpu.cores || 0) + " cores",
      "Load " + (cpu.load_1 ?? 0).toFixed(2) + " / " + (cpu.load_5 ?? 0).toFixed(2) + " / " + (cpu.load_15 ?? 0).toFixed(2),
      cpu.usage_pct ?? 0
    ));

    hwGrid.appendChild(makeKPICard(
      "Memory",
      (mem.usage_pct ?? 0).toFixed(1) + "%",
      fmtBytes(mem.total_bytes),
      fmtBytes(mem.used_bytes) + " used" + (mem.swap_total_bytes ? (" · swap " + fmtBytes(mem.swap_used_bytes)) : ""),
      mem.usage_pct ?? 0
    ));

    hwGrid.appendChild(makeKPICard(
      "Host Disk",
      (disk.usage_pct ?? 0).toFixed(1) + "%",
      disk.mount_hint || fmtBytes(disk.total_bytes),
      fmtBytes(disk.used_bytes) + " / " + fmtBytes(disk.total_bytes) + " (" + fmtBytes(disk.available_bytes) + " free)",
      disk.usage_pct ?? 0
    ));

    if (sys.docker_df) {
      hwGrid.appendChild(makeKPICard(
        "Docker Disk",
        fmtBytes(sys.docker_df.total_bytes),
        "images + vols",
        "img " + fmtBytes(sys.docker_df.images_bytes) + " · vol " + fmtBytes(sys.docker_df.volumes_bytes) + " · cache " + fmtBytes(sys.docker_df.build_cache_bytes),
        null
      ));
    }

    if (sys.thermals && sys.thermals.length > 0) {
      const top = sys.thermals[0];
      const topTemp = Number(top.temp_c ?? 0);
      hwGrid.appendChild(makeKPICard(
        "Thermals",
        topTemp.toFixed(1) + " °C",
        top.name,
        sys.thermals.slice(0, 3).map((t) => t.name + ": " + Number(t.temp_c ?? 0).toFixed(1) + "°C").join(" · "),
        topTemp,
        topTemp.toFixed(1) + " °C"
      ));
    }

    // NVIDIA GPU card
    const gpuSection = document.getElementById("gpu-section");
    const gpuBody = document.getElementById("gpu-body");
    const gpuDriver = document.getElementById("gpu-driver");
    if (gpuSection && gpuBody) {
      if (sys.gpu && sys.gpu.available && sys.gpu.devices && sys.gpu.devices.length > 0) {
        gpuSection.classList.remove("d-none");
        clear(gpuBody);
        const row = el("div", "row row-cards");
        if (gpuDriver) gpuDriver.textContent = "Driver " + (sys.gpu.devices[0].driver_version || "N/A");

        sys.gpu.devices.forEach((dev) => {
          const col = el("div", sys.gpu.devices.length > 1 ? "col-lg-6" : "col-12");
          const card = el("div", "card card-sm");
          const body = el("div", "card-body");

          const hdr = el("div", "d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3");
          hdr.appendChild(el("div", "fw-semibold", "GPU " + dev.index + " · " + dev.name));
          const badges = el("div", "btn-list");
          if (dev.temp_c != null) {
            const tempCls = dev.temp_c >= 85 ? "bg-red-lt" : (dev.temp_c >= 75 ? "bg-yellow-lt" : "bg-azure-lt");
            badges.appendChild(el("span", "badge tabular-nums " + tempCls, dev.temp_c.toFixed(0) + " °C"));
          }
          if (dev.power_draw_w != null) {
            const pwr = dev.power_draw_w.toFixed(0) + "W" + (dev.power_limit_w ? (" / " + dev.power_limit_w.toFixed(0) + "W") : "");
            badges.appendChild(el("span", "badge bg-secondary-lt tabular-nums", pwr));
          }
          hdr.appendChild(badges);
          body.appendChild(hdr);

          const bars = el("div", "row g-3");
          // Core utilization bar
          const utilCol = el("div", "col-sm-6");
          const utilRow = el("div", "d-flex justify-content-between small mb-1");
          utilRow.appendChild(el("span", "text-secondary", "Core Utilization"));
          utilRow.appendChild(el("strong", "tabular-nums", dev.util_pct != null ? (dev.util_pct.toFixed(0) + "%") : "N/A"));
          utilCol.appendChild(utilRow);
          utilCol.appendChild(makeProgress(dev.util_pct ?? 0, "GPU core utilization"));
          bars.appendChild(utilCol);

          // VRAM bar
          const vramPct = (dev.mem_used_mib != null && dev.mem_total_mib) ? ((dev.mem_used_mib / dev.mem_total_mib) * 100) : 0;
          const vramStr = (dev.mem_used_mib != null && dev.mem_total_mib != null)
            ? (Math.round(dev.mem_used_mib) + " / " + Math.round(dev.mem_total_mib) + " MiB")
            : "N/A";
          const vramCol = el("div", "col-sm-6");
          const vramRow = el("div", "d-flex justify-content-between small mb-1");
          vramRow.appendChild(el("span", "text-secondary", "VRAM Usage"));
          vramRow.appendChild(el("strong", "tabular-nums", vramStr));
          vramCol.appendChild(vramRow);
          vramCol.appendChild(makeProgress(vramPct, "GPU VRAM usage"));
          bars.appendChild(vramCol);

          body.appendChild(bars);
          card.appendChild(body);
          col.appendChild(card);
          row.appendChild(col);
        });
        gpuBody.appendChild(row);
      } else {
        gpuSection.classList.add("d-none");
      }
    }

    // 1-Hour Telemetry History charts
    const charts = document.getElementById("charts-grid");
    const histMeta = document.getElementById("hist-meta");
    if (charts && Array.isArray(sys.history)) {
      if (histMeta) histMeta.textContent = sys.history.length + " samples · 1h rolling window";

      const hasGPUUtilHist = sys.history.some((p) => p.gpu_util_pct !== undefined && p.gpu_util_pct !== null);
      const hasGPUTempHist = sys.history.some((p) => p.gpu_temp_c !== undefined && p.gpu_temp_c !== null);
      const latestOf = (fn) => {
        for (let i = sys.history.length - 1; i >= 0; i--) {
          const v = fn(sys.history[i]);
          if (v !== undefined && v !== null) return Number(v);
        }
        return null;
      };
      const specs = [
        {
          id: "cpu",
          title: "CPU Utilization",
          unit: "%",
          maxVal: 100,
          colorClass: "text-primary",
          dotClass: "status-blue",
          latest: (cpu.usage_pct ?? 0).toFixed(1) + "%",
          valueFn: (p) => p.cpu_pct
        },
        {
          id: "mem",
          title: "Memory Utilization",
          unit: "%",
          maxVal: 100,
          colorClass: "text-green",
          dotClass: "status-green",
          latest: (mem.usage_pct ?? 0).toFixed(1) + "%",
          valueFn: (p) => p.mem_pct
        }
      ];
      if (hasGPUUtilHist) {
        const lastUtil = latestOf((p) => p.gpu_util_pct);
        specs.push({
          id: "gpu_util",
          title: "GPU Utilization",
          unit: "%",
          maxVal: 100,
          colorClass: "text-yellow",
          dotClass: "status-yellow",
          latest: lastUtil !== null ? (lastUtil.toFixed(0) + "%") : "—",
          valueFn: (p) => p.gpu_util_pct
        });
      }
      if (hasGPUTempHist) {
        const lastTemp = latestOf((p) => p.gpu_temp_c);
        specs.push({
          id: "gpu_temp",
          title: "GPU Temperature",
          unit: "°C",
          maxVal: 100,
          colorClass: "text-red",
          dotClass: "status-red",
          latest: lastTemp !== null ? (lastTemp.toFixed(0) + "°C") : "—",
          valueFn: (p) => p.gpu_temp_c
        });
      }

      const desiredIds = new Set(specs.map((s) => s.id));
      Array.from(chartRegistry.keys()).forEach((id) => {
        if (!desiredIds.has(id)) {
          const stale = chartRegistry.get(id);
          if (stale) {
            if (typeof stale.destroy === "function") stale.destroy();
            if (stale.col.parentNode) stale.col.parentNode.removeChild(stale.col);
          }
          chartRegistry.delete(id);
        }
      });

      specs.forEach((spec) => {
        let chart = chartRegistry.get(spec.id);
        if (!chart) {
          chart = createChartCard(spec);
          chartRegistry.set(spec.id, chart);
          charts.appendChild(chart.col);
        }
        chart.update(spec.latest, sys.history, spec.valueFn);
      });
    }
  }

  function renderContainers(payload) {
    const tbl = document.getElementById("containers-table");
    const meta = document.getElementById("containers-meta");
    if (!tbl || !payload || !Array.isArray(payload.containers)) return;
    clear(tbl);
    if (meta) meta.textContent = payload.containers.length + " containers";

    const thead = el("thead");
    const hr = el("tr");
    ["Service", "State / Health", "CPU", "Memory", "Restarts", "Image", "Logs"].forEach((h) => hr.appendChild(el("th", "", h)));
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    if (payload.containers.length === 0) {
      tbody.appendChild(makeEmptyRow(7, "No containers reported", "Verify ops-agent connectivity on the admin network."));
    } else {
      payload.containers.forEach((c) => {
        const tr = el("tr");
        const svcTd = el("td");
        svcTd.appendChild(el("div", "fw-medium", c.service || c.name));
        if (c.name && c.service && c.name !== c.service) {
          svcTd.appendChild(el("div", "text-secondary small font-monospace", c.name));
        }
        tr.appendChild(svcTd);

        const stTd = el("td");
        const badgeCls = (c.state === "running" && (!c.health || c.health === "healthy"))
          ? "badge bg-green-lt"
          : (c.state === "running" ? "badge bg-yellow-lt" : "badge bg-red-lt");
        stTd.appendChild(el("span", badgeCls, c.health ? (c.state + " · " + c.health) : c.state));
        tr.appendChild(stTd);

        tr.appendChild(el("td", "tabular-nums", (c.cpu_pct ?? 0).toFixed(1) + "%"));
        tr.appendChild(el("td", "tabular-nums", fmtBytes(c.mem_usage_bytes) + (c.mem_pct ? (" (" + c.mem_pct.toFixed(1) + "%)") : "")));
        tr.appendChild(el("td", "tabular-nums", String(c.restart_count ?? 0)));

        const imgTd = el("td", "text-secondary col-image-cell text-truncate font-monospace small", c.image || "");
        if (c.image) imgTd.title = c.image;
        tr.appendChild(imgTd);

        const logTd = el("td");
        const link = el("a", "btn btn-sm btn-outline-primary", "Logs");
        link.href = "/logs?service=" + encodeURIComponent(c.service || "");
        logTd.appendChild(link);
        tr.appendChild(logTd);

        tbody.appendChild(tr);
      });
    }
    tbl.appendChild(tbody);
  }

  function renderDBStats(db) {
    const tbl = document.getElementById("db-table");
    const meta = document.getElementById("db-meta");
    if (!tbl) return;
    clear(tbl);

    const thead = el("thead");
    const hr = el("tr");
    ["Database", "Service", "Size", "Connections", "Created"].forEach((h) => hr.appendChild(el("th", "", h)));
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    if (!db || !Array.isArray(db.databases)) {
      if (meta) meta.textContent = "PostgreSQL stats unavailable";
      tbody.appendChild(makeEmptyRow(5, "PostgreSQL stats unavailable", "db-broker stats endpoint not configured or unreachable."));
      tbl.appendChild(tbody);
      return;
    }

    if (meta) {
      meta.textContent = "PostgreSQL " + db.server_version + " · " + db.client_connections + "/" + db.max_connections + " conns · total " + fmtBytes(db.total_size_bytes);
    }

    if (db.databases.length === 0) {
      tbody.appendChild(makeEmptyRow(5, "No databases found", ""));
    } else {
      db.databases.forEach((d) => {
        const tr = el("tr");
        tr.appendChild(el("td", "font-monospace fw-medium", d.name));
        const svcTd = el("td");
        svcTd.appendChild(d.service_name ? el("span", "badge bg-blue-lt", d.service_name) : el("span", "badge bg-secondary-lt", "system"));
        tr.appendChild(svcTd);
        tr.appendChild(el("td", "tabular-nums", fmtBytes(d.size_bytes)));
        tr.appendChild(el("td", "tabular-nums", String(d.connections ?? 0)));
        tr.appendChild(el("td", "text-secondary tabular-nums", d.created_at ? fmtTime(d.created_at) : "—"));
        tbody.appendChild(tr);
      });
    }
    tbl.appendChild(tbody);
  }

  function setStatusPill(statusBox, cls, text, animated) {
    if (!statusBox) return;
    clear(statusBox);
    const pill = el("span", "status " + cls);
    const dot = el("span", "status-dot" + (animated ? " status-dot-animated" : ""));
    pill.appendChild(dot);
    pill.appendChild(document.createTextNode(" " + text));
    statusBox.appendChild(pill);
  }

  async function initOverview() {
    const statusBox = document.getElementById("header-status");

    async function loadOverview() {
      try {
        const data = await apiFetch("/api/overview");
        if (data.system) renderSystem(data.system);
        else if (data.system_error) showToast("System metrics unavailable: " + data.system_error, true);
        if (data.containers) renderContainers(data.containers);
        else if (data.containers_error) showToast("Container list unavailable: " + data.containers_error, true);
        renderDBStats(data.db_stats);
      } catch (err) {
        showToast("Overview load failed: " + err.message, true);
      }
    }

    await loadOverview();

    const es = new EventSource("/api/stream/metrics");
    window.addEventListener("pagehide", () => {
      es.close();
    });
    es.onopen = () => {
      setStatusPill(statusBox, "status-green", "Live · 5s", true);
    };
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.system) renderSystem(msg.system);
        if (msg.containers) renderContainers(msg.containers);
      } catch {}
    };
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setStatusPill(statusBox, "status-red", "Stream closed (reload to reconnect)", false);
      } else {
        setStatusPill(statusBox, "status-yellow", "Reconnecting…", false);
      }
    };
  }

  // ==================== LOG EXPLORER PAGE ====================
  function httpStatusBadgeClass(code) {
    const n = Number(code);
    if (n >= 500) return "badge bg-red-lt tabular-nums";
    if (n >= 400) return "badge bg-yellow-lt tabular-nums";
    if (n >= 300) return "badge bg-azure-lt tabular-nums";
    if (n >= 200) return "badge bg-green-lt tabular-nums";
    return "badge bg-secondary-lt tabular-nums";
  }

  function logLevelBadgeClass(level) {
    switch ((level || "").toLowerCase()) {
      case "error": return "badge bg-red-lt";
      case "warn": return "badge bg-yellow-lt";
      case "info": return "badge bg-green-lt";
      default: return "badge bg-secondary-lt";
    }
  }

  function makeLogRow(entry) {
    const row = el("div", "log-row");
    row.appendChild(el("span", "log-ts tabular-nums", fmtTime(entry.ts)));

    const svcWrap = el("span", "text-truncate");
    svcWrap.appendChild(el("span", "badge bg-azure-lt", entry.service || "unknown"));
    row.appendChild(svcWrap);

    const lvlWrap = el("span");
    const lvl = (entry.level || "info").toUpperCase();
    lvlWrap.appendChild(el("span", logLevelBadgeClass(entry.level), lvl));
    row.appendChild(lvlWrap);

    const msgWrap = el("div", "min-w-0");
    if (entry.structured && entry.structured.request) {
      const st = entry.structured;
      const chips = el("div", "log-msg-chips");
      if (st.status) chips.appendChild(el("span", httpStatusBadgeClass(st.status), String(st.status)));
      if (st.host) chips.appendChild(el("span", "badge bg-secondary-lt", st.host));
      chips.appendChild(el("span", "log-req-text", st.request));
      if (st.request_time !== undefined && st.request_time !== null) {
        chips.appendChild(el("span", "badge bg-secondary-lt tabular-nums", Number(st.request_time).toFixed(3) + "s"));
      }
      if (st.client_ip) {
        chips.appendChild(el("span", "badge bg-secondary-lt tabular-nums", "ip=" + st.client_ip));
      }
      if (st.cf_ray) {
        chips.appendChild(el("span", "badge bg-secondary-lt", "ray=" + st.cf_ray));
      }
      msgWrap.appendChild(chips);
    } else {
      msgWrap.textContent = entry.message || "";
    }
    row.appendChild(msgWrap);
    return row;
  }

  async function initLogs() {
    const svcSelect = document.getElementById("log-service");
    const form = document.getElementById("log-filter-form");
    const out = document.getElementById("log-output");
    const meta = document.getElementById("log-meta");
    const tailBadge = document.getElementById("log-tail-badge");
    const tailBtn = document.getElementById("log-tail-btn");
    const olderBtn = document.getElementById("log-older-btn");
    const clearBtn = document.getElementById("log-clear-btn");
    const copyBtn = document.getElementById("log-copy-btn");

    let nextUntil = "";
    let tailES = null;
    let visibleLines = [];

    const urlParams = new URLSearchParams(window.location.search);
    const initialService = urlParams.get("service") || "all";

    let matchedInitial = initialService === "all";
    try {
      const ov = await apiFetch("/api/overview");
      if (ov.containers && Array.isArray(ov.containers.containers)) {
        const seen = new Set();
        ov.containers.containers.forEach((c) => {
          const val = c.service || c.name;
          if (!val || seen.has(val)) return;
          seen.add(val);
          const opt = el("option", "", val);
          opt.value = val;
          if (val === initialService) {
            opt.selected = true;
            matchedInitial = true;
          }
          svcSelect.appendChild(opt);
        });
      }
    } catch {}

    if (!matchedInitial && initialService) {
      const opt = el("option", "", initialService);
      opt.value = initialService;
      opt.selected = true;
      svcSelect.appendChild(opt);
    }

    function setTailBadge(state, label) {
      if (!tailBadge) return;
      if (!state) {
        tailBadge.classList.add("d-none");
        clear(tailBadge);
        return;
      }
      tailBadge.classList.remove("d-none");
      setStatusPill(tailBadge, state, label, state === "status-green");
    }

    function formatEntryLine(entry) {
      if (entry.structured && entry.structured.request) {
        const st = entry.structured;
        return [
          fmtTime(entry.ts),
          entry.service || "",
          (entry.level || "info").toUpperCase(),
          st.status || "",
          st.host || "",
          st.request || ""
        ].filter(Boolean).join(" ");
      }
      return [fmtTime(entry.ts), entry.service || "", (entry.level || "info").toUpperCase(), entry.message || ""].filter(Boolean).join(" ");
    }

    function renderLogEmpty(msg) {
      clear(out);
      const empty = el("div", "empty py-5");
      empty.appendChild(el("p", "empty-title", msg));
      empty.appendChild(el("p", "empty-subtitle text-secondary", "Adjust your container, time window, or filter query and run Search."));
      out.appendChild(empty);
    }

    function stopTail() {
      if (tailES) {
        tailES.close();
        tailES = null;
      }
      tailBtn.textContent = "Live Tail";
      tailBtn.className = "btn btn-outline-secondary btn-sm";
      setTailBadge(null, "");
    }

    async function runSearch(appendOlder) {
      stopTail();
      const params = new URLSearchParams();
      params.set("service", svcSelect.value || "all");
      const q = document.getElementById("log-query").value.trim();
      if (q) params.set("q", q);
      if (document.getElementById("log-regex").checked) params.set("regex", "1");
      params.set("since", document.getElementById("log-since").value);
      params.set("level", document.getElementById("log-level").value);
      const nh = document.getElementById("log-nginx-host").value.trim();
      if (nh) params.set("nginx_host", nh);
      const ns = document.getElementById("log-nginx-status").value;
      if (ns) params.set("nginx_status", ns);
      if (appendOlder && nextUntil) params.set("until", nextUntil);

      try {
        const res = await apiFetch("/api/logs/search?" + params.toString());
        if (!appendOlder) {
          clear(out);
          visibleLines = [];
        }
        const entries = res.entries || [];
        if (!appendOlder && entries.length === 0) {
          renderLogEmpty("No log lines matched");
        } else {
          entries.forEach((entry) => {
            out.appendChild(makeLogRow(entry));
            visibleLines.push(formatEntryLine(entry));
          });
        }
        nextUntil = res.next_until || "";
        olderBtn.classList.toggle("d-none", !res.truncated || !nextUntil);
        const truncNote = res.truncated ? " (truncated; use Load Older or narrow filters)" : "";
        meta.textContent = (appendOlder ? visibleLines.length + " lines displayed" : (res.count || 0) + " matching lines") + truncNote;
      } catch (err) {
        showToast("Log search failed: " + err.message, true);
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      runSearch(false);
    });
    olderBtn.addEventListener("click", () => runSearch(true));
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        visibleLines = [];
        if (tailES) {
          clear(out);
          meta.textContent = "Streaming live logs (console cleared)…";
        } else {
          renderLogEmpty("Console cleared");
          meta.textContent = "0 lines displayed";
        }
      });
    }
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        if (visibleLines.length === 0) {
          showToast("No visible log lines to copy", true);
          return;
        }
        try {
          await navigator.clipboard.writeText(visibleLines.join("\n"));
          showToast("Copied " + visibleLines.length + " log lines");
        } catch {
          showToast("Clipboard permission unavailable", true);
        }
      });
    }

    tailBtn.addEventListener("click", () => {
      if (tailES) {
        stopTail();
        return;
      }
      const svc = svcSelect.value;
      if (!svc || svc === "all") {
        showToast("Select a specific container to start Live Tail", true);
        return;
      }
      clear(out);
      visibleLines = [];
      olderBtn.classList.add("d-none");
      meta.textContent = "Streaming live logs from " + svc + "…";
      tailBtn.textContent = "Stop Tail";
      tailBtn.className = "btn btn-danger btn-sm";
      setTailBadge("status-yellow", "Connecting…");

      tailES = new EventSource("/api/logs/stream?service=" + encodeURIComponent(svc) + "&tail=100");
      tailES.onopen = () => {
        setTailBadge("status-green", "Streaming · " + svc);
      };
      tailES.onmessage = (ev) => {
        try {
          const entry = JSON.parse(ev.data);
          const emptyEl = out.querySelector(".empty");
          if (emptyEl) emptyEl.remove();
          out.appendChild(makeLogRow(entry));
          visibleLines.push(formatEntryLine(entry));
          while (out.childNodes.length > 1000) out.removeChild(out.firstChild);
          while (visibleLines.length > 1000) visibleLines.shift();
          out.scrollTop = out.scrollHeight;
        } catch {}
      };
      tailES.onerror = () => {
        if (tailES && tailES.readyState === EventSource.CLOSED) {
          stopTail();
          meta.textContent = "Stream closed (session expired or concurrency limit reached).";
          setTailBadge("status-red", "Closed");
        } else {
          meta.textContent = "Stream interrupted; reconnecting…";
          setTailBadge("status-yellow", "Reconnecting…");
        }
      };
    });

    window.addEventListener("pagehide", stopTail);
    runSearch(false);
  }

  // ==================== MANAGED SERVICE PAGE ====================
  async function initService() {
    const banner = document.getElementById("service-banner");
    const tabsEl = document.getElementById("service-tabs");
    const panelEl = document.getElementById("service-panel");
    const sub = document.getElementById("page-subtitle");

    let manifest;
    try {
      manifest = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/manifest");
    } catch (err) {
      if (banner) {
        banner.textContent = "Unable to load service manifest: " + err.message;
        banner.classList.remove("d-none");
      }
      return;
    }

    if (sub) {
      sub.textContent = "Service v" + (manifest.version || "1") + " · capabilities: " + (manifest.capabilities || []).join(", ");
    }

    const caps = Array.isArray(manifest.capabilities) ? manifest.capabilities : [];
    let currentTab = caps[0] || "";
    let activeTabSeq = 0;

    function tabDomId(cap) {
      return "tab-" + String(cap).replace(/[^A-Za-z0-9_-]/g, "_");
    }

    function selectTab(cap, focusBtn) {
      currentTab = cap;
      renderTabs();
      if (focusBtn) {
        const activeBtn = document.getElementById(tabDomId(cap));
        if (activeBtn) activeBtn.focus();
      }
      loadTab(cap);
    }

    function renderTabs() {
      clear(tabsEl);
      if (panelEl && currentTab) {
        panelEl.setAttribute("aria-labelledby", tabDomId(currentTab));
      }
      caps.forEach((cap, idx) => {
        const li = el("li", "nav-item");
        li.setAttribute("role", "presentation");
        const isActive = cap === currentTab;
        const b = el("button", "nav-link" + (isActive ? " active" : ""), cap.toUpperCase());
        b.id = tabDomId(cap);
        b.type = "button";
        b.setAttribute("role", "tab");
        b.setAttribute("aria-selected", isActive ? "true" : "false");
        b.setAttribute("aria-controls", "service-panel");
        b.tabIndex = isActive ? 0 : -1;
        b.addEventListener("click", () => {
          selectTab(cap, false);
        });
        b.addEventListener("keydown", (e) => {
          if (caps.length < 2) return;
          if (e.key === "ArrowRight") {
            e.preventDefault();
            selectTab(caps[(idx + 1) % caps.length], true);
          } else if (e.key === "ArrowLeft") {
            e.preventDefault();
            selectTab(caps[(idx - 1 + caps.length) % caps.length], true);
          } else if (e.key === "Home") {
            e.preventDefault();
            selectTab(caps[0], true);
          } else if (e.key === "End") {
            e.preventDefault();
            selectTab(caps[caps.length - 1], true);
          }
        });
        li.appendChild(b);
        tabsEl.appendChild(li);
      });
    }

    async function loadTab(cap) {
      const seq = ++activeTabSeq;
      const isStale = () => seq !== activeTabSeq;
      clear(panelEl);
      const loading = el("div", "card-body text-secondary", "Loading " + cap + "…");
      panelEl.appendChild(loading);
      try {
        if (cap === "users") await renderUsersTab(panelEl, isStale);
        else if (cap === "settings") await renderSettingsTab(panelEl, manifest.settings_schema || [], isStale);
        else if (cap === "artifacts") await renderArtifactsTab(panelEl, "", isStale, true);
        else {
          if (isStale()) return;
          clear(panelEl);
          panelEl.appendChild(el("div", "card-body text-secondary", "Unsupported capability: " + cap));
        }
      } catch (err) {
        if (isStale()) return;
        clear(panelEl);
        const body = el("div", "card-body");
        body.appendChild(el("div", "alert alert-danger mb-0", "Failed to load " + cap + ": " + err.message));
        panelEl.appendChild(body);
      }
    }

    async function renderUsersTab(container, isStale) {
      const data = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users");
      if (isStale && isStale()) return;
      clear(container);
      const wrap = el("div", "table-responsive");
      const tbl = el("table", "table table-vcenter card-table table-hover");
      const thead = el("thead");
      const hr = el("tr");
      ["Username", "Role", "Status", "Artifacts", "Storage", "Created", "Actions"].forEach((h) => hr.appendChild(el("th", "", h)));
      thead.appendChild(hr);
      tbl.appendChild(thead);

      const tbody = el("tbody");
      const users = data.users || [];
      if (users.length === 0) {
        tbody.appendChild(makeEmptyRow(7, "No users found", ""));
      } else {
        users.forEach((u) => {
          const tr = el("tr");
          tr.appendChild(el("td", "fw-medium", u.username));

          const roleTd = el("td");
          roleTd.appendChild(el("span", "badge bg-secondary-lt", u.role || "user"));
          tr.appendChild(roleTd);

          const stTd = el("td");
          const cls = u.status === "active" ? "badge bg-green-lt" : (u.status === "pending" ? "badge bg-yellow-lt" : "badge bg-red-lt");
          stTd.appendChild(el("span", cls, u.status));
          tr.appendChild(stTd);

          tr.appendChild(el("td", "tabular-nums", String(u.artifact_count ?? 0)));
          tr.appendChild(el("td", "tabular-nums", fmtBytes(u.storage_bytes ?? 0)));
          tr.appendChild(el("td", "text-secondary tabular-nums", fmtTime(u.created_at)));

          const actTd = el("td");
          const btns = el("div", "btn-list");
          if (u.status !== "active") {
            const ap = el("button", "btn btn-sm btn-primary", "Approve");
            ap.type = "button";
            ap.addEventListener("click", async () => {
              try {
                await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users/" + encodeURIComponent(u.id) + "/approve", { method: "POST" });
                showToast("Approved " + u.username);
                loadTab("users");
              } catch (err) { showToast(err.message, true); }
            });
            btns.appendChild(ap);
          }
          if (u.status !== "denied") {
            const dn = el("button", "btn btn-sm btn-outline-danger", "Deny");
            dn.type = "button";
            dn.addEventListener("click", async () => {
              const ok = await confirmAction({
                title: "Deny user account?",
                message: "Deny account '" + u.username + "' and revoke active sessions/tokens?",
                confirmLabel: "Deny account",
                variant: "danger"
              });
              if (!ok) return;
              try {
                await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users/" + encodeURIComponent(u.id) + "/deny", { method: "POST" });
                showToast("Denied " + u.username);
                loadTab("users");
              } catch (err) { showToast(err.message, true); }
            });
            btns.appendChild(dn);
          }
          actTd.appendChild(btns);
          tr.appendChild(actTd);
          tbody.appendChild(tr);
        });
      }
      tbl.appendChild(tbody);
      wrap.appendChild(tbl);
      container.appendChild(wrap);
    }

    async function renderSettingsTab(container, schema, isStale) {
      const current = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/settings");
      if (isStale && isStale()) return;
      clear(container);
      const form = el("form");
      const body = el("div", "card-body service-settings-body");
      const inputs = {};

      const fields = schema.length > 0 ? schema : Object.keys(current).map((k) => ({
        key: k,
        label: k,
        type: Array.isArray(current[k]) ? "string_list"
          : (typeof current[k] === "boolean" ? "bool"
          : (typeof current[k] === "number" ? (Number.isInteger(current[k]) ? "int" : "float") : "string"))
      }));

      fields.forEach((f, idx) => {
        const grp = el("div", idx === fields.length - 1 ? "mb-0" : "mb-3");
        const val = current[f.key];
        const fieldType = f.type || "string";
        const inputID = "setting-" + String(f.key).replace(/[^A-Za-z0-9_-]/g, "_");

        if (fieldType === "bool") {
          const lbl = el("label", "form-check form-switch");
          lbl.setAttribute("for", inputID);
          const cb = el("input", "form-check-input");
          cb.id = inputID;
          cb.type = "checkbox";
          cb.setAttribute("role", "switch");
          cb.checked = Boolean(val);
          lbl.appendChild(cb);
          lbl.appendChild(el("span", "form-check-label fw-medium", f.label || f.key));
          grp.appendChild(lbl);
          inputs[f.key] = { type: "bool", node: cb };
        } else if (fieldType === "string_list") {
          const lbl = el("label", "form-label", f.label || f.key);
          lbl.setAttribute("for", inputID);
          grp.appendChild(lbl);
          const ta = el("textarea", "form-control font-monospace");
          ta.id = inputID;
          ta.rows = 4;
          ta.value = Array.isArray(val) ? val.join("\n") : "";
          grp.appendChild(ta);
          inputs[f.key] = { type: "string_list", node: ta };
        } else if (fieldType === "int" || fieldType === "float") {
          const lblRow = el("div", "d-flex align-items-center justify-content-between gap-2 mb-1");
          const lbl = el("label", "form-label mb-0", f.label || f.key);
          lbl.setAttribute("for", inputID);
          lblRow.appendChild(lbl);
          const hasMin = f.min !== undefined && f.min !== null;
          const hasMax = f.max !== undefined && f.max !== null;
          if (hasMin || hasMax) {
            const rangeText = (hasMin ? String(f.min) : "—") + " – " + (hasMax ? String(f.max) : "—");
            lblRow.appendChild(el("span", "badge bg-secondary-lt tabular-nums", rangeText));
          }
          grp.appendChild(lblRow);
          const inp = el("input", "form-control tabular-nums");
          inp.id = inputID;
          inp.type = "number";
          inp.required = true;
          inp.step = fieldType === "int" ? "1" : "any";
          if (hasMin) inp.min = String(f.min);
          if (hasMax) inp.max = String(f.max);
          inp.value = (val !== undefined && val !== null) ? String(val) : "";
          grp.appendChild(inp);
          inputs[f.key] = { type: fieldType, node: inp };
        } else {
          const lbl = el("label", "form-label", f.label || f.key);
          lbl.setAttribute("for", inputID);
          grp.appendChild(lbl);
          const inp = el("input", "form-control");
          inp.id = inputID;
          inp.type = "text";
          inp.value = (val !== undefined && val !== null) ? String(val) : "";
          grp.appendChild(inp);
          inputs[f.key] = { type: "string", node: inp };
        }

        if (f.help) grp.appendChild(el("div", "form-hint", f.help));
        body.appendChild(grp);
      });

      form.appendChild(body);

      const footer = el("div", "card-footer d-flex flex-wrap align-items-center justify-content-between gap-2");
      footer.appendChild(el("span", "text-secondary small", "Changes take effect immediately and are recorded in the audit log."));
      const saveBtn = el("button", "btn btn-primary", "Save Settings");
      saveBtn.type = "submit";
      footer.appendChild(saveBtn);
      form.appendChild(footer);

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const patch = {};
        for (const k of Object.keys(inputs)) {
          const it = inputs[k];
          if (it.type === "bool") {
            patch[k] = it.node.checked;
          } else if (it.type === "int" || it.type === "float") {
            const raw = it.node.value.trim();
            const num = Number(raw);
            if (raw === "" || Number.isNaN(num) || (it.type === "int" && !Number.isInteger(num))) {
              showToast("Invalid numeric value for " + k, true);
              return;
            }
            patch[k] = num;
          } else if (it.type === "string_list") {
            patch[k] = it.node.value.split("\n").map((s) => s.trim()).filter(Boolean);
          } else {
            patch[k] = it.node.value;
          }
        }

        saveBtn.disabled = true;
        saveBtn.textContent = "Saving…";
        try {
          await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/settings", {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(patch)
          });
          showToast("Settings saved");
          loadTab("settings");
        } catch (err) {
          showToast("Save failed: " + err.message, true);
          saveBtn.disabled = false;
          saveBtn.textContent = "Save Settings";
        }
      });

      container.appendChild(form);
    }

    async function renderArtifactsTab(container, queryStr, isStale, throwOnError) {
      const prevParams = new URLSearchParams(queryStr || "");
      const qs = queryStr ? ("?" + queryStr) : "";
      let data;
      try {
        data = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/artifacts" + qs);
      } catch (err) {
        if (isStale && isStale()) return;
        if (throwOnError) throw err;
        showToast("Failed to load artifacts: " + err.message, true);
        return;
      }
      if (isStale && isStale()) return;
      clear(container);

      const filterWrap = el("div", "card-body border-bottom py-3");
      const bar = el("form", "row g-2 align-items-end");

      const qCol = el("div", "col-12 col-sm-4 col-lg-3");
      const qLbl = el("label", "form-label small text-secondary mb-1", "Title");
      qLbl.setAttribute("for", "art-filter-q");
      const qInp = el("input", "form-control form-control-sm");
      qInp.id = "art-filter-q";
      qInp.type = "text";
      qInp.placeholder = "Search title…";
      qInp.value = prevParams.get("q") || "";
      qCol.appendChild(qLbl);
      qCol.appendChild(qInp);

      const oCol = el("div", "col-12 col-sm-4 col-lg-3");
      const oLbl = el("label", "form-label small text-secondary mb-1", "Owner");
      oLbl.setAttribute("for", "art-filter-owner");
      const ownerInp = el("input", "form-control form-control-sm");
      ownerInp.id = "art-filter-owner";
      ownerInp.type = "text";
      ownerInp.placeholder = "Owner username…";
      ownerInp.value = prevParams.get("owner") || "";
      oCol.appendChild(oLbl);
      oCol.appendChild(ownerInp);

      const vCol = el("div", "col-6 col-sm-4 col-lg-2");
      const vLbl = el("label", "form-label small text-secondary mb-1", "Visibility");
      vLbl.setAttribute("for", "art-filter-vis");
      const visSel = el("select", "form-select form-select-sm");
      visSel.id = "art-filter-vis";
      [["", "All"], ["private", "Private"], ["public", "Public"]].forEach(([v, label]) => {
        const o = el("option", "", label);
        o.value = v;
        if (v === (prevParams.get("visibility") || "")) o.selected = true;
        visSel.appendChild(o);
      });
      vCol.appendChild(vLbl);
      vCol.appendChild(visSel);

      const actCol = el("div", "col-6 col-sm-12 col-lg-4 d-flex flex-wrap align-items-center justify-content-lg-between gap-2");
      const btnGroup = el("div", "btn-list");
      const goBtn = el("button", "btn btn-primary btn-sm", "Filter");
      goBtn.type = "submit";
      const resetBtn = el("button", "btn btn-outline-secondary btn-sm", "Reset");
      resetBtn.type = "button";
      resetBtn.addEventListener("click", () => {
        const nextSeq = ++activeTabSeq;
        renderArtifactsTab(container, "", () => nextSeq !== activeTabSeq, false);
      });
      btnGroup.appendChild(goBtn);
      btnGroup.appendChild(resetBtn);
      actCol.appendChild(btnGroup);
      actCol.appendChild(el("span", "text-secondary small tabular-nums", (data.total_count || 0) + " artifacts · " + fmtBytes(data.total_bytes || 0)));

      bar.appendChild(qCol);
      bar.appendChild(oCol);
      bar.appendChild(vCol);
      bar.appendChild(actCol);
      bar.addEventListener("submit", (e) => {
        e.preventDefault();
        const p = new URLSearchParams();
        if (qInp.value.trim()) p.set("q", qInp.value.trim());
        if (ownerInp.value.trim()) p.set("owner", ownerInp.value.trim());
        if (visSel.value) p.set("visibility", visSel.value);
        const nextSeq = ++activeTabSeq;
        renderArtifactsTab(container, p.toString(), () => nextSeq !== activeTabSeq, false);
      });
      filterWrap.appendChild(bar);
      container.appendChild(filterWrap);

      const wrap = el("div", "table-responsive");
      const tbl = el("table", "table table-vcenter card-table table-hover");
      const thead = el("thead");
      const hr = el("tr");
      ["Title", "Owner", "Visibility", "Type", "Size", "Updated", "Actions"].forEach((h) => hr.appendChild(el("th", "", h)));
      thead.appendChild(hr);
      tbl.appendChild(thead);

      const tbody = el("tbody");
      const artifacts = data.artifacts || [];
      if (artifacts.length === 0) {
        tbody.appendChild(makeEmptyRow(7, "No artifacts matched", ""));
      } else {
        artifacts.forEach((a) => {
          const tr = el("tr");
          const tTd = el("td", "fw-medium");
          if (a.viewer_url && (a.viewer_url.startsWith("https://") || a.viewer_url.startsWith("http://"))) {
            const link = el("a", "", a.title);
            link.href = a.viewer_url;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            tTd.appendChild(link);
          } else {
            tTd.textContent = a.title;
          }
          tr.appendChild(tTd);
          tr.appendChild(el("td", "", a.owner_username || a.owner_id));

          const vTd = el("td");
          vTd.appendChild(el("span", a.visibility === "public" ? "badge bg-green-lt" : "badge bg-secondary-lt", a.visibility));
          tr.appendChild(vTd);

          tr.appendChild(el("td", "text-secondary font-monospace small", a.content_type));
          tr.appendChild(el("td", "tabular-nums", fmtBytes(a.size_bytes)));
          tr.appendChild(el("td", "text-secondary tabular-nums", fmtTime(a.updated_at)));

          const actTd = el("td");
          const del = el("button", "btn btn-sm btn-outline-danger", "Delete");
          del.type = "button";
          del.addEventListener("click", async () => {
            const ok = await confirmAction({
              title: "Delete artifact?",
              message: "Permanently delete artifact '" + a.title + "'?",
              confirmLabel: "Delete permanently",
              variant: "danger"
            });
            if (!ok) return;
            try {
              await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/artifacts/" + encodeURIComponent(a.id), { method: "DELETE" });
              showToast("Deleted artifact " + a.id);
              const nextSeq = ++activeTabSeq;
              renderArtifactsTab(container, queryStr, () => nextSeq !== activeTabSeq, false);
            } catch (err) { showToast(err.message, true); }
          });
          actTd.appendChild(del);
          tr.appendChild(actTd);
          tbody.appendChild(tr);
        });
      }
      tbl.appendChild(tbody);
      wrap.appendChild(tbl);
      container.appendChild(wrap);
    }

    renderTabs();
    if (currentTab) loadTab(currentTab);
  }

  // ==================== AUDIT LOG PAGE ====================
  function auditActionBadgeClass(action) {
    switch (action) {
      case "user_approve": return "badge bg-green-lt";
      case "user_deny":
      case "artifact_delete": return "badge bg-red-lt";
      case "settings_update": return "badge bg-yellow-lt";
      case "login": return "badge bg-azure-lt";
      default: return "badge bg-secondary-lt";
    }
  }

  async function initAudit() {
    const form = document.getElementById("audit-filter-form");
    const resetBtn = document.getElementById("audit-reset-btn");
    const svcInput = document.getElementById("audit-service");
    const actInput = document.getElementById("audit-action");
    const tbl = document.getElementById("audit-table");
    const countEl = document.getElementById("audit-count");

    async function load() {
      const p = new URLSearchParams();
      const s = svcInput.value.trim();
      const a = actInput.value.trim();
      if (s) p.set("service", s);
      if (a) p.set("action", a);
      try {
        const res = await apiFetch("/api/audit?" + p.toString());
        const rows = res.audit_logs || [];
        if (countEl) countEl.textContent = rows.length + " events";

        clear(tbl);
        const thead = el("thead");
        const hr = el("tr");
        ["Time", "Actor", "Auth", "Action", "Service", "Target", "IP", "Details"].forEach((h) => hr.appendChild(el("th", "", h)));
        thead.appendChild(hr);
        tbl.appendChild(thead);

        const tbody = el("tbody");
        if (rows.length === 0) {
          tbody.appendChild(makeEmptyRow(8, "No audit records matched", ""));
        } else {
          rows.forEach((row) => {
            const tr = el("tr");
            tr.appendChild(el("td", "text-secondary tabular-nums small", fmtTime(row.created_at)));
            tr.appendChild(el("td", "fw-medium", row.actor_email));

            const authTd = el("td");
            authTd.appendChild(el("span", "badge bg-blue-lt", row.auth_method));
            tr.appendChild(authTd);

            const actTd = el("td");
            actTd.appendChild(el("span", auditActionBadgeClass(row.action), row.action));
            tr.appendChild(actTd);

            const svcTd = el("td");
            svcTd.appendChild(el("span", "badge bg-secondary-lt", row.target_service));
            tr.appendChild(svcTd);

            tr.appendChild(el("td", "text-secondary font-monospace small", row.target_id || "—"));
            tr.appendChild(el("td", "text-secondary font-monospace small tabular-nums", row.client_ip || "—"));

            const detTd = el("td", "text-secondary small");
            const hasDetails = row.details && typeof row.details === "object" && Object.keys(row.details).length > 0;
            if (hasDetails) {
              const det = el("details");
              const summary = el("summary", "text-primary small", Object.keys(row.details).length + " field(s)");
              const pre = el("pre", "audit-details-pre", JSON.stringify(row.details, null, 2));
              det.appendChild(summary);
              det.appendChild(pre);
              detTd.appendChild(det);
            } else {
              detTd.textContent = "—";
            }
            tr.appendChild(detTd);

            tbody.appendChild(tr);
          });
        }
        tbl.appendChild(tbody);
      } catch (err) {
        showToast("Failed to load audit logs: " + err.message, true);
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      load();
    });
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        svcInput.value = "";
        actInput.value = "";
        load();
      });
    }
    load();
  }

  initTheme();
  initSidebar();

  if (page === "overview") initOverview();
  else if (page === "logs") initLogs();
  else if (page === "service") initService();
  else if (page === "audit") initAudit();
})();
