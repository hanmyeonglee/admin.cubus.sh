(() => {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const THEME_KEY = "admin_theme";

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
  const page = document.body ? (document.body.getAttribute("data-page") || "") : "";
  const activeService = document.body ? (document.body.getAttribute("data-service") || "") : "";

  function getBS() {
    return (window.tabler && window.tabler.bootstrap) || window.bootstrap || window.tabler || null;
  }

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
        iconSlot.appendChild(makeSvgIcon(isDark ? SUN_PATHS : MOON_PATHS, 16, "icon m-0"));
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
      if (typeof mq.addEventListener === "function") {
        mq.addEventListener("change", (e) => {
          if (!readStoredTheme()) {
            applyTheme(e.matches ? "dark" : "light");
          }
        });
      }
    }
  }

  // ==================== TOASTS & CONFIRM MODAL ====================
  function showToast(msg, isError) {
    const toastEl = document.getElementById("toast");
    const bodyEl = document.getElementById("toast-body");
    const titleEl = document.getElementById("toast-title");
    const dotEl = document.getElementById("toast-dot");
    if (!toastEl || !bodyEl) return;

    bodyEl.textContent = msg;
    if (titleEl) titleEl.textContent = isError ? "Error" : "Success";
    if (dotEl) {
      dotEl.className = "status-dot me-2 " + (isError ? "status-red" : "status-green");
    }
    toastEl.classList.toggle("border-danger", Boolean(isError));

    const bs = getBS();
    if (bs && bs.Toast) {
      bs.Toast.getOrCreateInstance(toastEl, { delay: 4000 }).show();
    } else {
      toastEl.classList.add("show");
    }
  }

  let confirmPending = false;

  function confirmAction(opts) {
    const bs = getBS();
    const modalEl = document.getElementById("confirm-modal");
    const titleEl = document.getElementById("confirm-modal-title");
    const bodyEl = document.getElementById("confirm-modal-body");
    const okBtn = document.getElementById("confirm-modal-ok");
    const statusEl = document.getElementById("confirm-modal-status");
    const iconEl = modalEl ? modalEl.querySelector("svg.icon-lg") : null;

    if (!modalEl || !okBtn || !bs || !bs.Modal) {
      return Promise.resolve(window.confirm(opts.message || "Are you sure?"));
    }
    if (confirmPending) {
      return Promise.resolve(false);
    }

    confirmPending = true;
    const variant = opts.variant === "warning" ? "warning" : "danger";
    if (titleEl) titleEl.textContent = opts.title || "Confirm action";
    if (bodyEl) bodyEl.textContent = opts.message || "";
    okBtn.textContent = opts.confirmLabel || "Confirm";
    okBtn.className = "btn w-100 btn-" + variant;
    okBtn.disabled = false;
    if (statusEl) statusEl.className = "modal-status bg-" + variant;
    if (iconEl) iconEl.setAttribute("class", "icon mb-2 icon-lg text-" + variant);

    const prevFocus = document.activeElement;
    const modal = bs.Modal.getOrCreateInstance(modalEl);
    return new Promise((resolve) => {
      let confirmed = false;
      let decided = false;
      let settled = false;
      let isShownDone = false;
      let hideAfterShown = false;

      function decide(val) {
        if (decided) return;
        decided = true;
        confirmed = val;
        okBtn.disabled = true;
        if (isShownDone) {
          modal.hide();
        } else {
          hideAfterShown = true;
        }
      }

      function settle() {
        if (settled) return;
        settled = true;
        confirmPending = false;
        okBtn.disabled = false;
        okBtn.removeEventListener("click", onConfirm);
        modalEl.removeEventListener("click", onDismissClick);
        document.removeEventListener("keydown", onEscKey);
        modalEl.removeEventListener("shown.bs.modal", onShown);
        modalEl.removeEventListener("hidden.bs.modal", onHidden);
        resolve(confirmed);
      }

      function onConfirm() {
        decide(true);
      }

      function onDismissClick(e) {
        if (e.target === modalEl || (e.target && e.target.closest && e.target.closest('[data-bs-dismiss="modal"]'))) {
          decide(false);
        }
      }

      function onEscKey(e) {
        if (e.key === "Escape") {
          decide(false);
        }
      }

      function onShown() {
        isShownDone = true;
        if (hideAfterShown) {
          modal.hide();
        }
      }

      function onHidden() {
        settle();
      }

      okBtn.addEventListener("click", onConfirm);
      modalEl.addEventListener("click", onDismissClick);
      document.addEventListener("keydown", onEscKey);
      modalEl.addEventListener("shown.bs.modal", onShown, { once: true });
      modalEl.addEventListener("hidden.bs.modal", onHidden, { once: true });
      modal.show(prevFocus);
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
    const td = el("td", "p-0 border-0");
    td.colSpan = colSpan;
    const empty = el("div", "empty py-4");
    empty.appendChild(el("p", "empty-title h4 mb-1", title));
    if (subtitle) empty.appendChild(el("p", "empty-subtitle text-secondary small mb-0", subtitle));
    td.appendChild(empty);
    tr.appendChild(td);
    return tr;
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

  // ==================== CHART.JS TELEMETRY HISTORY ====================
  const chartRegistry = new Map();

  function chartPalette() {
    const isDark = document.documentElement.getAttribute("data-bs-theme") === "dark";
    return {
      tickColor: isDark ? "#9aa7b8" : "#6c7a91",
      gridColor: isDark ? "rgba(255, 255, 255, 0.08)" : "rgba(108, 122, 145, 0.16)",
      tooltipBg: isDark ? "#182433" : "#ffffff",
      tooltipText: isDark ? "#f8fafc" : "#182433",
      tooltipBorder: isDark ? "#2c3c50" : "#e6e7e9"
    };
  }

  function createChartCard(spec) {
    const col = el("div", "col-md-6");
    const card = el("div", "card card-sm");

    const hdr = el("div", "card-header py-2");
    const titleWrap = el("div", "d-flex align-items-center gap-2");
    titleWrap.appendChild(el("span", "status-dot " + (spec.dotClass || "status-blue")));
    titleWrap.appendChild(el("span", "fw-medium", spec.title));
    hdr.appendChild(titleWrap);

    const meta = el("div", "card-actions text-secondary small tabular-nums");
    const curValEl = el("strong", "text-reset me-2", "—");
    const statsEl = el("span", "text-secondary", "");
    meta.appendChild(curValEl);
    meta.appendChild(statsEl);
    hdr.appendChild(meta);
    card.appendChild(hdr);

    const body = el("div", "card-body");
    const box = el("div", "chart-box");
    const canvas = el("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", spec.title + " 1-hour history chart");
    box.appendChild(canvas);
    body.appendChild(box);
    card.appendChild(body);
    col.appendChild(card);

    let timestamps = [];
    let chart = null;

    if (typeof window.Chart === "function") {
      const pal = chartPalette();
      chart = new window.Chart(canvas.getContext("2d"), {
        type: "line",
        data: {
          labels: [],
          datasets: [{
            label: spec.title,
            data: [],
            borderColor: spec.strokeColor,
            backgroundColor: spec.fillColor,
            fill: true,
            tension: 0.25,
            borderWidth: 2,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHitRadius: 10,
            spanGaps: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          interaction: {
            mode: "index",
            intersect: false
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: pal.tooltipBg,
              titleColor: pal.tooltipText,
              bodyColor: pal.tooltipText,
              borderColor: pal.tooltipBorder,
              borderWidth: 1,
              displayColors: false,
              callbacks: {
                title: (items) => {
                  if (!items || !items.length) return "";
                  const idx = items[0].dataIndex;
                  return timestamps[idx] ? fmtTime(timestamps[idx]) : (items[0].label || "");
                },
                label: (ctx) => {
                  if (ctx.parsed.y === null || ctx.parsed.y === undefined) return "No sample";
                  return spec.title + ": " + ctx.parsed.y.toFixed(1) + spec.unit;
                }
              }
            }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: {
                maxTicksLimit: 6,
                autoSkip: true,
                color: pal.tickColor,
                font: { size: 11 }
              }
            },
            y: {
              min: 0,
              max: spec.maxVal || undefined,
              suggestedMax: spec.suggestedMax || undefined,
              border: { display: false },
              grid: { color: pal.gridColor },
              ticks: {
                maxTicksLimit: 5,
                color: pal.tickColor,
                font: { size: 11 },
                callback: (v) => v + spec.unit
              }
            }
          }
        }
      });
    }

    function applyChartTheme() {
      if (!chart) return;
      const pal = chartPalette();
      chart.options.scales.x.ticks.color = pal.tickColor;
      chart.options.scales.y.ticks.color = pal.tickColor;
      chart.options.scales.y.grid.color = pal.gridColor;
      chart.options.plugins.tooltip.backgroundColor = pal.tooltipBg;
      chart.options.plugins.tooltip.titleColor = pal.tooltipText;
      chart.options.plugins.tooltip.bodyColor = pal.tooltipText;
      chart.options.plugins.tooltip.borderColor = pal.tooltipBorder;
      chart.update("none");
    }

    function update(latestText, rawPoints, valueFn) {
      const labels = [];
      const values = [];
      const tsList = [];
      const valid = [];

      (rawPoints || []).forEach((pt) => {
        const ts = pt.ts || "";
        tsList.push(ts);
        labels.push(fmtShortHHMM(ts));
        const raw = valueFn(pt);
        const isNum = raw !== null && raw !== undefined && !Number.isNaN(Number(raw));
        if (isNum) {
          const num = Number(raw);
          values.push(num);
          valid.push(num);
        } else {
          values.push(null);
        }
      });

      timestamps = tsList;
      curValEl.textContent = latestText;
      if (valid.length > 0) {
        const sum = valid.reduce((a, b) => a + b, 0);
        const avg = sum / valid.length;
        const max = Math.max(...valid);
        statsEl.textContent = "avg " + avg.toFixed(1) + spec.unit + " · max " + max.toFixed(1) + spec.unit;
      } else {
        statsEl.textContent = "waiting for samples";
      }

      if (chart) {
        chart.data.labels = labels;
        chart.data.datasets[0].data = values;
        chart.update("none");
      }
    }

    function destroy() {
      if (chart) {
        chart.destroy();
        chart = null;
      }
    }

    return {
      col,
      update,
      applyTheme: applyChartTheme,
      destroy
    };
  }

  themeListeners.push(() => {
    chartRegistry.forEach((c) => c.applyTheme());
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

  function makeDatagridItem(title, contentNodeOrText) {
    const item = el("div", "datagrid-item");
    item.appendChild(el("div", "datagrid-title", title));
    const content = el("div", "datagrid-content");
    if (typeof contentNodeOrText === "string") content.textContent = contentNodeOrText;
    else if (contentNodeOrText) content.appendChild(contentNodeOrText);
    item.appendChild(content);
    return item;
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

    // NVIDIA GPU card using Tabler .datagrid + .progress
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
          const cardHdr = el("div", "card-header py-2");
          cardHdr.appendChild(el("div", "card-title h4 mb-0", "GPU " + dev.index + " · " + dev.name));
          const actions = el("div", "card-actions btn-list");
          if (dev.temp_c != null) {
            const tempCls = dev.temp_c >= 85 ? "bg-red-lt" : (dev.temp_c >= 75 ? "bg-yellow-lt" : "bg-azure-lt");
            actions.appendChild(el("span", "badge tabular-nums " + tempCls, dev.temp_c.toFixed(0) + " °C"));
          }
          if (dev.power_draw_w != null) {
            const pwr = dev.power_draw_w.toFixed(0) + "W" + (dev.power_limit_w ? (" / " + dev.power_limit_w.toFixed(0) + "W") : "");
            actions.appendChild(el("span", "badge bg-secondary-lt tabular-nums", pwr));
          }
          cardHdr.appendChild(actions);
          card.appendChild(cardHdr);

          const body = el("div", "card-body");
          const dg = el("div", "datagrid");

          const utilWrap = el("div");
          utilWrap.appendChild(el("div", "fw-medium tabular-nums mb-1", dev.util_pct != null ? (dev.util_pct.toFixed(0) + "%") : "N/A"));
          utilWrap.appendChild(makeProgress(dev.util_pct ?? 0, "GPU core utilization"));
          dg.appendChild(makeDatagridItem("Core Utilization", utilWrap));

          const vramPct = (dev.mem_used_mib != null && dev.mem_total_mib) ? ((dev.mem_used_mib / dev.mem_total_mib) * 100) : 0;
          const vramStr = (dev.mem_used_mib != null && dev.mem_total_mib != null)
            ? (Math.round(dev.mem_used_mib) + " / " + Math.round(dev.mem_total_mib) + " MiB")
            : "N/A";
          const vramWrap = el("div");
          vramWrap.appendChild(el("div", "fw-medium tabular-nums mb-1", vramStr));
          vramWrap.appendChild(makeProgress(vramPct, "GPU VRAM usage"));
          dg.appendChild(makeDatagridItem("VRAM Usage", vramWrap));

          if (dev.uuid) {
            dg.appendChild(makeDatagridItem("Device UUID", el("span", "font-monospace small text-secondary", dev.uuid)));
          }

          body.appendChild(dg);
          card.appendChild(body);
          col.appendChild(card);
          row.appendChild(col);
        });
        gpuBody.appendChild(row);
      } else {
        gpuSection.classList.add("d-none");
      }
    }

    // 1-Hour Telemetry History via Chart.js
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
          dotClass: "status-blue",
          strokeColor: "#066fd1",
          fillColor: "rgba(6, 111, 209, 0.14)",
          latest: (cpu.usage_pct ?? 0).toFixed(1) + "%",
          valueFn: (p) => p.cpu_pct
        },
        {
          id: "mem",
          title: "Memory Utilization",
          unit: "%",
          maxVal: 100,
          dotClass: "status-green",
          strokeColor: "#2fb344",
          fillColor: "rgba(47, 179, 68, 0.14)",
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
          dotClass: "status-yellow",
          strokeColor: "#f59f00",
          fillColor: "rgba(245, 159, 0, 0.14)",
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
          suggestedMax: 100,
          dotClass: "status-red",
          strokeColor: "#d63939",
          fillColor: "rgba(214, 57, 57, 0.14)",
          latest: lastTemp !== null ? (lastTemp.toFixed(0) + "°C") : "—",
          valueFn: (p) => p.gpu_temp_c
        });
      }

      const desiredIds = new Set(specs.map((s) => s.id));
      Array.from(chartRegistry.keys()).forEach((id) => {
        if (!desiredIds.has(id)) {
          const stale = chartRegistry.get(id);
          if (stale) {
            stale.destroy();
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

        const imgTd = el("td", "text-secondary col-image text-truncate font-monospace small", c.image || "");
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

  async function initOverview() {
    const statusBox = document.getElementById("header-status");
    let metricsES = null;

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

    function connectMetricsStream() {
      if (metricsES) {
        metricsES.close();
        metricsES = null;
      }
      const es = new EventSource("/api/stream/metrics");
      metricsES = es;
      es.onopen = () => {
        if (metricsES !== es) return;
        setStatusPill(statusBox, "status-green", "Live · 5s", true);
      };
      es.onmessage = (ev) => {
        if (metricsES !== es) return;
        try {
          const msg = JSON.parse(ev.data);
          if (msg.system) renderSystem(msg.system);
          if (msg.containers) renderContainers(msg.containers);
        } catch {}
      };
      es.onerror = () => {
        if (metricsES !== es) return;
        if (es.readyState === EventSource.CLOSED) {
          setStatusPill(statusBox, "status-red", "Stream closed (reload to reconnect)", false);
        } else {
          setStatusPill(statusBox, "status-yellow", "Reconnecting…", false);
        }
      };
    }

    window.addEventListener("pagehide", () => {
      if (metricsES) {
        metricsES.close();
        metricsES = null;
      }
    });
    window.addEventListener("pageshow", (e) => {
      if (e.persisted) {
        loadOverview();
        connectMetricsStream();
      }
    });

    await loadOverview();
    connectMetricsStream();
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

  function ruleVerdictBadgeClass(verdict) {
    switch ((verdict || "").toLowerCase()) {
      case "critical": return "badge bg-red-lt";
      case "high": return "badge bg-orange-lt";
      case "medium": return "badge bg-yellow-lt";
      case "low": return "badge bg-azure-lt";
      default: return "badge bg-secondary-lt text-secondary";
    }
  }

  function amberChoiceBadgeClass(choice) {
    switch ((choice || "").toLowerCase()) {
      case "malicious_attack": return "badge bg-red-lt";
      case "suspicious_recon": return "badge bg-orange-lt";
      case "operational_error": return "badge bg-yellow-lt";
      case "normal": return "badge bg-green-lt";
      default: return "badge bg-secondary-lt text-secondary";
    }
  }

  function formatRuleCategory(cat) {
    switch (cat) {
      case "sqli": return "SQLi";
      case "xss": return "XSS";
      case "lfi_traversal": return "LFI/Traversal";
      case "rce_injection": return "RCE/Injection";
      case "scanner_recon": return "Scanner/Recon";
      case "auth_abuse": return "Auth Abuse";
      case "db_security": return "DB Security";
      case "service_error": return "Service Error";
      case "protocol_anomaly": return "Protocol Anomaly";
      case "burst_abuse": return "Burst Abuse";
      case "clean": return "Clean";
      default: return cat || "Unknown";
    }
  }

  function formatAmberChoice(choice) {
    switch (choice) {
      case "malicious_attack": return "Attack";
      case "suspicious_recon": return "Recon";
      case "operational_error": return "Error";
      case "normal": return "Normal";
      default: return choice || "Unknown";
    }
  }

  function formatEngineName(eng) {
    switch (eng) {
      case "owasp_crs": return "OWASP CRS v4";
      case "sigma": return "Sigma";
      case "burst": return "Burst";
      default: return eng || "Rule";
    }
  }

  function renderRuleCell(rec) {
    clear(rec.ruleBtn);
    const r = rec.ruleResult;
    if (!r) {
      rec.ruleBtn.appendChild(el("span", "badge bg-secondary-lt text-secondary", "—"));
      rec.ruleBtn.title = "Inspect log entry";
      return;
    }
    if (r.verdict === "clean") {
      rec.ruleBtn.appendChild(el("span", "badge bg-secondary-lt text-secondary", "clean"));
      rec.ruleBtn.title = "No rules matched (click for details)";
      return;
    }
    const label = r.verdict.toUpperCase() + " · " + formatRuleCategory(r.category);
    rec.ruleBtn.appendChild(el("span", ruleVerdictBadgeClass(r.verdict), label));
    rec.ruleBtn.title = "Score " + (r.score || 0) + " · " + ((r.matches && r.matches.length) || 0) + " match(es) — click for details";
  }

  function renderAmberCell(rec) {
    clear(rec.amberBtn);
    const a = rec.amberResult;
    if (!a) {
      rec.amberBtn.appendChild(el("span", "badge bg-secondary-lt text-secondary", "—"));
      rec.amberBtn.title = "Not evaluated by Amber-150M";
      return;
    }
    if (a.error) {
      rec.amberBtn.appendChild(el("span", "badge bg-yellow-lt", "error"));
      rec.amberBtn.title = a.error;
      return;
    }
    if (!a.evaluated || !a.choice) {
      rec.amberBtn.appendChild(el("span", "badge bg-secondary-lt text-secondary", "skipped"));
      rec.amberBtn.title = "Skipped (batch capped at 50 entries)";
      return;
    }
    const pct = Math.round((Number(a.confidence) || 0) * 100);
    rec.amberBtn.appendChild(el("span", amberChoiceBadgeClass(a.choice) + " tabular-nums", formatAmberChoice(a.choice) + " " + pct + "%"));
    rec.amberBtn.title = "Amber-150M: " + a.choice + " (" + pct + "%) — click for details";
  }

  function makeLogRow(entry, onInspect) {
    const tr = el("tr");
    tr.appendChild(el("td", "text-secondary text-nowrap small tabular-nums", fmtTime(entry.ts)));

    const svcTd = el("td", "text-nowrap");
    svcTd.appendChild(el("span", "badge bg-azure-lt", entry.service || "unknown"));
    tr.appendChild(svcTd);

    const lvlTd = el("td", "text-nowrap");
    lvlTd.appendChild(el("span", logLevelBadgeClass(entry.level), (entry.level || "info").toUpperCase()));
    tr.appendChild(lvlTd);

    const ruleTd = el("td", "text-nowrap");
    const ruleBtn = el("button", "btn btn-link p-0 border-0 text-decoration-none");
    ruleBtn.type = "button";
    ruleTd.appendChild(ruleBtn);
    tr.appendChild(ruleTd);

    const amberTd = el("td", "text-nowrap");
    const amberBtn = el("button", "btn btn-link p-0 border-0 text-decoration-none");
    amberBtn.type = "button";
    amberTd.appendChild(amberBtn);
    tr.appendChild(amberTd);

    const msgTd = el("td", "text-break small");
    if (entry.structured && entry.structured.request) {
      const st = entry.structured;
      const wrap = el("div", "d-flex flex-wrap align-items-center gap-1");
      if (st.status) wrap.appendChild(el("span", httpStatusBadgeClass(st.status), String(st.status)));
      if (st.host) wrap.appendChild(el("span", "badge bg-secondary-lt", st.host));
      wrap.appendChild(el("span", "fw-medium", st.request));
      if (st.request_time !== undefined && st.request_time !== null) {
        wrap.appendChild(el("span", "badge bg-secondary-lt tabular-nums", Number(st.request_time).toFixed(3) + "s"));
      }
      if (st.client_ip) wrap.appendChild(el("span", "badge bg-secondary-lt tabular-nums", "ip=" + st.client_ip));
      if (st.cf_ray) wrap.appendChild(el("span", "badge bg-secondary-lt", "ray=" + st.cf_ray));
      msgTd.appendChild(wrap);
    } else {
      msgTd.textContent = entry.message || "";
    }
    tr.appendChild(msgTd);

    const rec = {
      entry: entry,
      tr: tr,
      ruleBtn: ruleBtn,
      amberBtn: amberBtn,
      ruleResult: null,
      amberResult: null
    };
    renderRuleCell(rec);
    renderAmberCell(rec);
    ruleBtn.addEventListener("click", () => onInspect(rec));
    amberBtn.addEventListener("click", () => onInspect(rec));
    return rec;
  }

  function openLogDetailModal(rec) {
    const modalEl = document.getElementById("log-detail-modal");
    const bodyEl = document.getElementById("log-detail-modal-body");
    const titleEl = document.getElementById("log-detail-modal-title");
    if (!modalEl || !bodyEl) return;

    const e = rec.entry || {};
    const st = e.structured || null;
    if (titleEl) {
      titleEl.textContent = "Log Classification · " + (e.service || "unknown");
    }
    clear(bodyEl);

    const dg = el("div", "datagrid mb-3");
    dg.appendChild(makeDatagridItem("Service", el("span", "badge bg-azure-lt", e.service || "unknown")));
    dg.appendChild(makeDatagridItem("Timestamp", el("span", "font-monospace small tabular-nums", fmtTime(e.ts) || "—")));
    dg.appendChild(makeDatagridItem("Level", el("span", logLevelBadgeClass(e.level), (e.level || "info").toUpperCase())));
    if (st) {
      if (st.client_ip) dg.appendChild(makeDatagridItem("Client IP", el("span", "font-monospace small tabular-nums", st.client_ip)));
      if (st.host) dg.appendChild(makeDatagridItem("Host", el("span", "font-monospace small", st.host)));
      if (st.status) dg.appendChild(makeDatagridItem("HTTP Status", el("span", httpStatusBadgeClass(st.status), String(st.status))));
      if (st.request) dg.appendChild(makeDatagridItem("Request", el("span", "font-monospace small text-break", st.request)));
      if (st.user_agent) dg.appendChild(makeDatagridItem("User-Agent", el("span", "font-monospace small text-break", st.user_agent)));
      if (st.referer) dg.appendChild(makeDatagridItem("Referer", el("span", "font-monospace small text-break", st.referer)));
      if (st.cf_ray) dg.appendChild(makeDatagridItem("CF Ray", el("span", "font-monospace small", st.cf_ray)));
    }
    bodyEl.appendChild(dg);

    const msgCard = el("div", "card card-sm mb-3");
    const msgHdr = el("div", "card-header py-2");
    msgHdr.appendChild(el("h4", "card-title mb-0", "Log Message"));
    msgCard.appendChild(msgHdr);
    const msgBody = el("div", "card-body py-2");
    msgBody.appendChild(el("pre", "audit-json mb-0 font-monospace small", e.message || (st && st.request) || ""));
    msgCard.appendChild(msgBody);
    bodyEl.appendChild(msgCard);

    const ruleCard = el("div", "card card-sm mb-3");
    const ruleHdr = el("div", "card-header py-2");
    ruleHdr.appendChild(el("h4", "card-title mb-0", "Rule-Based Detection (OWASP CRS v4 + Sigma + Burst)"));
    const ruleMeta = el("div", "card-actions d-flex flex-wrap gap-1");
    if (rec.ruleResult) {
      ruleMeta.appendChild(el("span", ruleVerdictBadgeClass(rec.ruleResult.verdict), rec.ruleResult.verdict.toUpperCase()));
      ruleMeta.appendChild(el("span", "badge bg-secondary-lt", formatRuleCategory(rec.ruleResult.category)));
      ruleMeta.appendChild(el("span", "badge bg-secondary-lt tabular-nums", "Score " + (rec.ruleResult.score || 0)));
    }
    ruleHdr.appendChild(ruleMeta);
    ruleCard.appendChild(ruleHdr);

    if (!rec.ruleResult) {
      ruleCard.appendChild(el("div", "card-body py-2 text-secondary small", "Not yet evaluated by rule engine."));
    } else if (!rec.ruleResult.matches || rec.ruleResult.matches.length === 0) {
      ruleCard.appendChild(el("div", "card-body py-2 text-secondary small", "No OWASP CRS v4, Sigma, or burst rules triggered."));
    } else {
      const wrap = el("div", "table-responsive");
      const tbl = el("table", "table table-sm table-vcenter card-table mb-0");
      const thead = el("thead");
      const hr = el("tr");
      ["Engine", "Rule ID", "Severity", "Rule / Description", "Tags", "Matched"].forEach((h) => hr.appendChild(el("th", "", h)));
      thead.appendChild(hr);
      tbl.appendChild(thead);

      const tbody = el("tbody");
      rec.ruleResult.matches.forEach((m) => {
        const tr = el("tr");
        tr.appendChild(el("td", "text-nowrap", formatEngineName(m.engine)));
        tr.appendChild(el("td", "font-monospace small text-nowrap", m.rule_id || ""));
        const sevTd = el("td", "text-nowrap");
        sevTd.appendChild(el("span", ruleVerdictBadgeClass(m.severity), (m.severity || "").toUpperCase()));
        tr.appendChild(sevTd);
        tr.appendChild(el("td", "small text-break", m.title || ""));
        const tagTd = el("td", "small");
        const tagWrap = el("div", "d-flex flex-wrap gap-1");
        (m.tags || []).forEach((t) => tagWrap.appendChild(el("span", "badge bg-secondary-lt", t)));
        tagTd.appendChild(tagWrap);
        tr.appendChild(tagTd);
        tr.appendChild(el("td", "font-monospace small text-break", m.matched_data || "—"));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      wrap.appendChild(tbl);
      ruleCard.appendChild(wrap);
    }
    bodyEl.appendChild(ruleCard);

    const amberCard = el("div", "card card-sm mb-0");
    const amberHdr = el("div", "card-header py-2");
    amberHdr.appendChild(el("h4", "card-title mb-0", "Amber-150M AI Classification"));
    if (rec.amberResult && rec.amberResult.evaluated && rec.amberResult.choice) {
      const acts = el("div", "card-actions");
      const confPct = ((Number(rec.amberResult.confidence) || 0) * 100).toFixed(1) + "%";
      acts.appendChild(el("span", amberChoiceBadgeClass(rec.amberResult.choice) + " tabular-nums", formatAmberChoice(rec.amberResult.choice) + " · " + confPct));
      amberHdr.appendChild(acts);
    }
    amberCard.appendChild(amberHdr);

    const amberBody = el("div", "card-body py-2");
    if (!rec.amberResult) {
      amberBody.appendChild(el("div", "text-secondary small", "Not yet evaluated by Amber-150M (click Amber AI or Scan Both)."));
    } else if (rec.amberResult.error) {
      amberBody.appendChild(el("div", "alert alert-warning mb-0 py-2 small", rec.amberResult.error));
    } else if (!rec.amberResult.evaluated) {
      amberBody.appendChild(el("div", "text-secondary small", "Entry was outside the top 50 priority Amber-150M batch."));
    } else {
      const probs = rec.amberResult.probabilities || {};
      const ordered = ["malicious_attack", "suspicious_recon", "operational_error", "normal"];
      ordered.forEach((lbl) => {
        if (probs[lbl] === undefined && lbl !== rec.amberResult.choice) return;
        const pctVal = Math.max(0, Math.min(100, (Number(probs[lbl]) || 0) * 100));
        const row = el("div", "mb-2");
        const top = el("div", "d-flex justify-content-between align-items-center small mb-1");
        top.appendChild(el("span", lbl === rec.amberResult.choice ? "fw-semibold" : "text-secondary", lbl));
        top.appendChild(el("span", "tabular-nums font-monospace", pctVal.toFixed(1) + "%"));
        row.appendChild(top);
        const prog = document.createElement("progress");
        prog.className = "progress progress-sm";
        prog.max = 100;
        prog.value = Math.round(pctVal);
        row.appendChild(prog);
        amberBody.appendChild(row);
      });
    }
    amberCard.appendChild(amberBody);
    bodyEl.appendChild(amberCard);

    const bs = getBS();
    if (bs && bs.Modal) {
      bs.Modal.getOrCreateInstance(modalEl).show();
    }
  }

  async function initLogs() {
    const svcSelect = document.getElementById("log-service");
    const form = document.getElementById("log-filter-form");
    const scrollBox = document.getElementById("log-scroll");
    const out = document.getElementById("log-output");
    const meta = document.getElementById("log-meta");
    const tailBadge = document.getElementById("log-tail-badge");
    const tailBtn = document.getElementById("log-tail-btn");
    const olderBtn = document.getElementById("log-older-btn");
    const clearBtn = document.getElementById("log-clear-btn");
    const copyBtn = document.getElementById("log-copy-btn");
    const ruleStatusBadge = document.getElementById("log-rule-status");
    const amberStatusBadge = document.getElementById("log-amber-status");
    const autoRulesCheck = document.getElementById("log-auto-rules");
    const classFilterSel = document.getElementById("log-class-filter");
    const scanRulesBtn = document.getElementById("log-scan-rules-btn");
    const scanAmberBtn = document.getElementById("log-scan-amber-btn");
    const scanBothBtn = document.getElementById("log-scan-both-btn");
    const summaryBar = document.getElementById("log-classify-summary");

    const CLASSIFY_MAX_ENTRIES = 200;
    const CLASSIFY_MAX_BYTES = 400 * 1024;
    const utf8Encoder = typeof TextEncoder === "function" ? new TextEncoder() : null;

    let nextUntil = "";
    let tailES = null;
    let visibleRecords = [];
    let searchSeq = 0;
    let searchAbort = null;
    let ovAbort = null;
    let classifySeq = 0;
    let classifyAbort = null;
    let infoAbort = null;
    let manualScanRunning = false;
    let autoTailScanRunning = false;
    let tailClassifyPending = false;
    let tailClassifyTimer = null;
    let tailReconnecting = false;
    let tailReconnectTimer = null;
    const tailSeenOrder = [];
    const tailSeenSet = new Set();

    function utf8ByteLength(str) {
      if (typeof str !== "string" || str.length === 0) return 0;
      if (utf8Encoder) return utf8Encoder.encode(str).length;
      let bytes = 0;
      for (let i = 0; i < str.length;) {
        const cp = str.codePointAt(i);
        i += cp > 0xffff ? 2 : 1;
        bytes += cp <= 0x7f ? 1 : (cp <= 0x7ff ? 2 : (cp <= 0xffff ? 3 : 4));
      }
      return bytes;
    }

    function clampUTF8String(str, maxBytes) {
      if (typeof str !== "string" || str.length === 0 || maxBytes <= 0) return "";
      if (utf8ByteLength(str) <= maxBytes) return str;
      let bytes = 0;
      let idx = 0;
      while (idx < str.length) {
        const cp = str.codePointAt(idx);
        const step = cp > 0xffff ? 2 : 1;
        const add = cp <= 0x7f ? 1 : (cp <= 0x7ff ? 2 : (cp <= 0xffff ? 3 : 4));
        if (bytes + add > maxBytes) break;
        bytes += add;
        idx += step;
      }
      return str.slice(0, idx);
    }

    function sanitizeEntryForClassify(entry, scale) {
      const e = entry || {};
      const s = scale || 1;
      const cap = (n) => Math.max(128, Math.floor(n * s));
      const hasStructuredReq = Boolean(e.structured && e.structured.request);
      const out = {
        ts: clampUTF8String(e.ts || "", 64),
        service: clampUTF8String(e.service || "", 128),
        stream: clampUTF8String(e.stream || "", 32),
        level: clampUTF8String(e.level || "", 32),
        message: clampUTF8String(e.message || "", cap(hasStructuredReq ? 4096 : 8192))
      };
      if (e.structured && typeof e.structured === "object") {
        const st = e.structured;
        const cleanSt = {};
        if (st.host) cleanSt.host = clampUTF8String(st.host, Math.min(512, cap(512)));
        if (st.status) cleanSt.status = Number(st.status) || 0;
        if (st.request) cleanSt.request = clampUTF8String(st.request, cap(8192));
        if (st.request_time !== undefined && st.request_time !== null) cleanSt.request_time = Number(st.request_time);
        if (st.client_ip) cleanSt.client_ip = clampUTF8String(st.client_ip, 128);
        if (st.upstream) cleanSt.upstream = clampUTF8String(st.upstream, 256);
        if (st.cf_ray) cleanSt.cf_ray = clampUTF8String(st.cf_ray, 128);
        if (st.user_agent) cleanSt.user_agent = clampUTF8String(st.user_agent, cap(4096));
        if (st.referer) cleanSt.referer = clampUTF8String(st.referer, cap(4096));
        out.structured = cleanSt;
      }
      return out;
    }

    function packClassifyBatches(records, mode) {
      const wrapperOverhead = utf8ByteLength(JSON.stringify({ mode: mode, entries: [] }));
      const maxSingleEntryBytes = Math.max(512, CLASSIFY_MAX_BYTES - wrapperOverhead);
      const batches = [];
      let curBatch = [];
      let curBytes = wrapperOverhead;

      for (const rec of records) {
        let scale = 1;
        let sanitized = sanitizeEntryForClassify(rec.entry, scale);
        let entryBytes = utf8ByteLength(JSON.stringify(sanitized));
        while (entryBytes > maxSingleEntryBytes && scale > 0.02) {
          scale *= 0.5;
          sanitized = sanitizeEntryForClassify(rec.entry, scale);
          entryBytes = utf8ByteLength(JSON.stringify(sanitized));
        }
        const sep = curBatch.length > 0 ? 1 : 0;
        if (curBatch.length >= CLASSIFY_MAX_ENTRIES || (curBatch.length > 0 && curBytes + sep + entryBytes > CLASSIFY_MAX_BYTES)) {
          batches.push(curBatch);
          curBatch = [];
          curBytes = wrapperOverhead;
        }
        const addSep = curBatch.length > 0 ? 1 : 0;
        curBatch.push({ rec: rec, entry: sanitized });
        curBytes += addSep + entryBytes;
      }
      if (curBatch.length > 0) batches.push(curBatch);
      return batches;
    }

    function clearTailReconnectTimer() {
      if (tailReconnectTimer) {
        clearTimeout(tailReconnectTimer);
        tailReconnectTimer = null;
      }
    }

    function setScanButtonsDisabled(disabled) {
      if (scanRulesBtn) scanRulesBtn.disabled = disabled;
      if (scanAmberBtn) scanAmberBtn.disabled = disabled;
      if (scanBothBtn) scanBothBtn.disabled = disabled;
    }

    function cancelClassify(clearSummary) {
      classifySeq++;
      if (tailClassifyTimer) {
        clearTimeout(tailClassifyTimer);
        tailClassifyTimer = null;
      }
      if (classifyAbort) {
        classifyAbort.abort();
        classifyAbort = null;
      }
      manualScanRunning = false;
      autoTailScanRunning = false;
      tailClassifyPending = false;
      setScanButtonsDisabled(false);
      if (clearSummary && summaryBar) {
        summaryBar.classList.add("d-none");
        clear(summaryBar);
      }
    }

    function isRuleFlagged(rec) {
      return Boolean(rec.ruleResult && rec.ruleResult.verdict && rec.ruleResult.verdict !== "clean");
    }

    function isAmberFlagged(rec) {
      return Boolean(
        rec.amberResult &&
        rec.amberResult.evaluated &&
        !rec.amberResult.error &&
        rec.amberResult.choice &&
        rec.amberResult.choice !== "normal"
      );
    }

    function matchesClassFilter(rec, filterVal) {
      switch (filterVal) {
        case "suspicious":
          return isRuleFlagged(rec) || isAmberFlagged(rec);
        case "rule":
          return isRuleFlagged(rec);
        case "amber":
          return isAmberFlagged(rec);
        case "clean":
          return !isRuleFlagged(rec) && !isAmberFlagged(rec);
        default:
          return true;
      }
    }

    function applyClassFilter() {
      const existingEmpty = document.getElementById("log-filter-empty-row");
      if (existingEmpty) existingEmpty.remove();

      const filterVal = classFilterSel ? classFilterSel.value : "all";
      let shown = 0;
      visibleRecords.forEach((rec) => {
        const show = matchesClassFilter(rec, filterVal);
        rec.tr.classList.toggle("d-none", !show);
        if (show) shown++;
      });

      if (visibleRecords.length > 0 && shown === 0) {
        const emptyTr = makeEmptyRow(6, "No matching logs for selected filter", "Switch filter to All logs or run another classification scan.");
        emptyTr.id = "log-filter-empty-row";
        out.appendChild(emptyTr);
      }
    }

    function renderSummary(mode, summaryData, evaluatedCount, amberEvaluated, amberError, durationMs) {
      if (!summaryBar || !summaryData) return;
      clear(summaryBar);
      summaryBar.classList.remove("d-none");

      summaryBar.appendChild(el("span", "badge bg-secondary-lt tabular-nums", "Scanned " + evaluatedCount + (visibleRecords.length > evaluatedCount ? (" / " + visibleRecords.length + " visible") : "")));

      if (mode === "rules" || mode === "both") {
        const ruleCls = summaryData.rule_flagged > 0 ? "badge bg-red-lt tabular-nums" : "badge bg-green-lt tabular-nums";
        summaryBar.appendChild(el("span", ruleCls, "Rule Flagged: " + (summaryData.rule_flagged || 0)));
        ["critical", "high", "medium", "low"].forEach((sev) => {
          const cnt = summaryData.by_verdict ? (summaryData.by_verdict[sev] || 0) : 0;
          if (cnt > 0) {
            summaryBar.appendChild(el("span", ruleVerdictBadgeClass(sev) + " tabular-nums", sev + ": " + cnt));
          }
        });
      }

      if (mode === "amber" || mode === "both") {
        if (amberEvaluated > 0) {
          summaryBar.appendChild(el("span", "badge bg-azure-lt tabular-nums", "Amber AI: " + amberEvaluated + "/" + evaluatedCount));
          ["malicious_attack", "suspicious_recon", "operational_error", "normal"].forEach((lbl) => {
            const cnt = summaryData.by_amber ? (summaryData.by_amber[lbl] || 0) : 0;
            if (cnt > 0) {
              summaryBar.appendChild(el("span", amberChoiceBadgeClass(lbl) + " tabular-nums", formatAmberChoice(lbl) + ": " + cnt));
            }
          });
        }
        if (amberError) {
          summaryBar.appendChild(el("span", "badge bg-yellow-lt text-break", "Amber note: " + amberError));
        }
      }

      if (durationMs !== undefined && durationMs !== null) {
        summaryBar.appendChild(el("span", "badge bg-secondary-lt tabular-nums ms-auto", durationMs + " ms"));
      }
    }

    function buildAggregateSummary(records) {
      const agg = { rule_flagged: 0, by_verdict: {}, by_amber: {} };
      records.forEach((rec) => {
        if (rec.ruleResult) {
          const v = rec.ruleResult.verdict || "clean";
          agg.by_verdict[v] = (agg.by_verdict[v] || 0) + 1;
          if (v !== "clean") agg.rule_flagged++;
        }
        if (rec.amberResult && rec.amberResult.evaluated && !rec.amberResult.error && rec.amberResult.choice) {
          const c = rec.amberResult.choice;
          agg.by_amber[c] = (agg.by_amber[c] || 0) + 1;
        }
      });
      return agg;
    }

    async function runClassify(mode, isAuto, explicitSubset) {
      const isAutoTail = Boolean(isAuto && tailES);
      if (isAutoTail) {
        if (manualScanRunning) return;
        if (autoTailScanRunning) {
          tailClassifyPending = true;
          return;
        }
      }

      const sourceRecords = Array.isArray(explicitSubset) ? explicitSubset : visibleRecords;
      if (sourceRecords.length === 0) {
        if (!isAuto) showToast("No visible log entries to classify", true);
        return;
      }

      // Pack batches strictly within <= 400 KiB UTF-8 serialized JSON and <= 200 entries.
      const list = mode === "rules"
        ? (Array.isArray(explicitSubset) ? sourceRecords : (tailES ? sourceRecords.slice(-CLASSIFY_MAX_ENTRIES) : sourceRecords))
        : (tailES ? sourceRecords.slice(-CLASSIFY_MAX_ENTRIES) : sourceRecords.slice(0, CLASSIFY_MAX_ENTRIES));
      const batches = packClassifyBatches(list, mode);
      if (batches.length === 0) return;

      const seq = ++classifySeq;
      const sSeq = searchSeq;
      const activeTail = tailES;
      if (!isAutoTail && classifyAbort) {
        classifyAbort.abort();
        classifyAbort = null;
      }
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      classifyAbort = ctrl;

      if (isAutoTail) {
        autoTailScanRunning = true;
      }
      if (!isAuto) {
        autoTailScanRunning = false;
        tailClassifyPending = false;
        manualScanRunning = true;
        setScanButtonsDisabled(true);
      }

      let totalDur = 0;
      let lastResp = null;
      let totalEvaluated = 0;
      let totalAmberEvaluated = 0;
      let lastAmberError = "";
      const allUpdatedSet = new Set();

      try {
        for (const chunk of batches) {
          const resp = await apiFetch("/api/logs/classify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              mode: mode,
              entries: chunk.map((item) => item.entry)
            }),
            signal: ctrl ? ctrl.signal : undefined
          });
          if (seq !== classifySeq || sSeq !== searchSeq || (isAuto && tailES !== activeTail)) return;

          (resp.results || []).forEach((res) => {
            const item = chunk[res.index];
            if (!item || !item.rec) return;
            const rec = item.rec;
            allUpdatedSet.add(rec);
            if (res.rule) {
              rec.ruleResult = res.rule;
              renderRuleCell(rec);
            }
            if (res.amber) {
              rec.amberResult = res.amber;
              renderAmberCell(rec);
            }
          });
          totalDur += Number(resp.duration_ms) || 0;
          totalEvaluated += chunk.length;
          totalAmberEvaluated += Number(resp.amber_evaluated) || 0;
          if (resp.amber_error) lastAmberError = resp.amber_error;
          lastResp = resp;
        }

        if (mode === "amber" || mode === "both") {
          visibleRecords.forEach((rec) => {
            if (!allUpdatedSet.has(rec) && rec.amberResult) {
              rec.amberResult = null;
              renderAmberCell(rec);
            }
          });
        }

        applyClassFilter();
        if (lastResp) {
          if (batches.length > 1 || Array.isArray(explicitSubset)) {
            const agg = buildAggregateSummary(visibleRecords);
            const evaluatedAll = mode === "amber"
              ? totalEvaluated
              : visibleRecords.filter((r) => Boolean(r.ruleResult)).length;
            renderSummary(mode, agg, evaluatedAll, totalAmberEvaluated, lastAmberError, totalDur);
          } else {
            renderSummary(lastResp.mode, lastResp.summary, totalEvaluated, totalAmberEvaluated, lastAmberError, totalDur);
          }
          if (!isAuto && lastAmberError && mode === "both") {
            showToast("Rules completed; Amber AI note: " + lastAmberError, true);
          }
        }
      } catch (err) {
        if ((err && err.name === "AbortError") || seq !== classifySeq || sSeq !== searchSeq) return;
        if (totalEvaluated > 0) {
          applyClassFilter();
          const agg = buildAggregateSummary(visibleRecords);
          const evaluatedAll = mode === "amber"
            ? totalEvaluated
            : visibleRecords.filter((r) => Boolean(r.ruleResult)).length;
          renderSummary(mode, agg, evaluatedAll, totalAmberEvaluated, lastAmberError, totalDur);
        }
        if (!isAuto) {
          showToast("Log classification failed: " + err.message, true);
        }
      } finally {
        if (classifyAbort === ctrl) classifyAbort = null;
        if (isAutoTail && seq === classifySeq) {
          autoTailScanRunning = false;
          if (tailClassifyPending && tailES && autoRulesCheck && autoRulesCheck.checked && !manualScanRunning) {
            tailClassifyPending = false;
            scheduleTailRuleScan();
          }
        }
        if (!isAuto && seq === classifySeq) {
          manualScanRunning = false;
          setScanButtonsDisabled(false);
          if (tailES && autoRulesCheck && autoRulesCheck.checked) {
            scheduleTailRuleScan();
          }
        }
      }
    }

    function scheduleTailRuleScan() {
      if (!tailES || !autoRulesCheck || !autoRulesCheck.checked || manualScanRunning) return;
      if (autoTailScanRunning) {
        tailClassifyPending = true;
        return;
      }
      if (tailClassifyTimer) return;
      tailClassifyTimer = setTimeout(() => {
        tailClassifyTimer = null;
        if (!tailES || !autoRulesCheck.checked || manualScanRunning) return;
        if (autoTailScanRunning) {
          tailClassifyPending = true;
          return;
        }
        const pending = visibleRecords.filter((r) => !r.ruleResult);
        if (pending.length === 0) return;
        runClassify("rules", true, pending);
      }, 450);
    }

    async function loadClassifierInfo() {
      if (infoAbort) infoAbort.abort();
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      infoAbort = ctrl;
      try {
        const info = await apiFetch("/api/logs/classifier-info", ctrl ? { signal: ctrl.signal } : undefined);
        if (ruleStatusBadge && info.rule_engine) {
          ruleStatusBadge.textContent = "OWASP CRS v4 + " + (info.rule_engine.sigma_rules || 0) + " Sigma rules";
        }
        if (amberStatusBadge && info.amber) {
          if (info.amber.available) {
            amberStatusBadge.className = "badge bg-green-lt";
            amberStatusBadge.textContent = "Amber-150M: ready (" + (info.amber.service || "choice") + ")";
            amberStatusBadge.title = "Model " + (info.amber.model || "amber-150m") + " reachable";
          } else {
            amberStatusBadge.className = "badge bg-yellow-lt";
            amberStatusBadge.textContent = "Amber-150M: unavailable";
            amberStatusBadge.title = info.amber.error || "No classify service reachable";
          }
        }
      } catch (err) {
        if (err && err.name === "AbortError") return;
        if (amberStatusBadge) {
          amberStatusBadge.className = "badge bg-yellow-lt";
          amberStatusBadge.textContent = "Amber-150M: status unknown";
        }
      } finally {
        if (infoAbort === ctrl) infoAbort = null;
      }
    }

    function resetTailDedup() {
      tailSeenOrder.length = 0;
      tailSeenSet.clear();
    }

    function recordTailKey(entry) {
      const key = [
        entry.ts || "",
        entry.service || "",
        entry.level || "",
        entry.message || "",
        entry.structured ? (entry.structured.request || "") : ""
      ].join("\x00");
      if (tailSeenSet.has(key)) return false;
      tailSeenSet.add(key);
      tailSeenOrder.push(key);
      if (tailSeenOrder.length > 300) {
        tailSeenSet.delete(tailSeenOrder.shift());
      }
      return true;
    }

    const urlParams = new URLSearchParams(window.location.search);
    const initialService = urlParams.get("service") || "all";

    async function loadContainerDropdown() {
      if (ovAbort) ovAbort.abort();
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      ovAbort = ctrl;
      let matchedInitial = initialService === "all";
      try {
        const ov = await apiFetch("/api/overview", ctrl ? { signal: ctrl.signal } : undefined);
        if (ov.containers && Array.isArray(ov.containers.containers)) {
          const seen = new Set();
          ov.containers.containers.forEach((c) => {
            const val = c.service || c.name;
            if (!val || seen.has(val)) return;
            seen.add(val);
            if (Array.from(svcSelect.options).some((o) => o.value === val)) {
              if (val === initialService) matchedInitial = true;
              return;
            }
            const opt = el("option", "", val);
            opt.value = val;
            if (val === initialService) {
              opt.selected = true;
              matchedInitial = true;
            }
            svcSelect.appendChild(opt);
          });
        }
      } catch {} finally {
        if (ovAbort === ctrl) ovAbort = null;
      }
      if (!matchedInitial && initialService && !Array.from(svcSelect.options).some((o) => o.value === initialService)) {
        const opt = el("option", "", initialService);
        opt.value = initialService;
        opt.selected = true;
        svcSelect.appendChild(opt);
      }
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

    function stopTail() {
      if (tailES) {
        tailES.close();
        tailES = null;
      }
      if (tailClassifyTimer) {
        clearTimeout(tailClassifyTimer);
        tailClassifyTimer = null;
      }
      tailClassifyPending = false;
      if (autoTailScanRunning && !manualScanRunning) {
        cancelClassify(false);
      }
      clearTailReconnectTimer();
      tailReconnecting = false;
      resetTailDedup();
      tailBtn.textContent = "Live Tail";
      tailBtn.className = "btn btn-outline-secondary btn-sm";
      setTailBadge(null, "");
    }

    async function runSearch(appendOlder) {
      stopTail();
      cancelClassify(!appendOlder);
      const seq = ++searchSeq;
      if (searchAbort) {
        searchAbort.abort();
        searchAbort = null;
      }
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      searchAbort = ctrl;

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
        const res = await apiFetch("/api/logs/search?" + params.toString(), ctrl ? { signal: ctrl.signal } : undefined);
        if (seq !== searchSeq || tailES) return;
        if (!appendOlder) {
          clear(out);
          visibleRecords = [];
        } else {
          const existingEmpty = document.getElementById("log-filter-empty-row");
          if (existingEmpty) existingEmpty.remove();
        }
        const entries = res.entries || [];
        const addedRecords = [];
        if (!appendOlder && entries.length === 0) {
          out.appendChild(makeEmptyRow(6, "No log lines matched", "Adjust your container, time window, or filter query and run Search."));
        } else {
          entries.forEach((entry) => {
            const rec = makeLogRow(entry, openLogDetailModal);
            out.appendChild(rec.tr);
            visibleRecords.push(rec);
            addedRecords.push(rec);
          });
        }
        applyClassFilter();
        nextUntil = res.next_until || "";
        olderBtn.classList.toggle("d-none", !res.truncated || !nextUntil);
        const truncNote = res.truncated ? " (truncated; use Load Older or narrow filters)" : "";
        meta.textContent = (appendOlder ? visibleRecords.length + " lines displayed" : (res.count || 0) + " matching lines") + truncNote;

        if (addedRecords.length > 0 && autoRulesCheck && autoRulesCheck.checked) {
          runClassify("rules", true, appendOlder ? addedRecords : null);
        }
      } catch (err) {
        if ((err && err.name === "AbortError") || seq !== searchSeq) return;
        showToast("Log search failed: " + err.message, true);
      } finally {
        if (searchAbort === ctrl) searchAbort = null;
      }
    }

    // Register all DOM event listeners synchronously before starting async requests.
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      runSearch(false);
    });
    olderBtn.addEventListener("click", () => runSearch(true));
    if (classFilterSel) {
      classFilterSel.addEventListener("change", applyClassFilter);
    }
    if (scanRulesBtn) {
      scanRulesBtn.addEventListener("click", () => runClassify("rules", false));
    }
    if (scanAmberBtn) {
      scanAmberBtn.addEventListener("click", () => runClassify("amber", false));
    }
    if (scanBothBtn) {
      scanBothBtn.addEventListener("click", () => runClassify("both", false));
    }
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        cancelClassify(true);
        clearTailReconnectTimer();
        tailReconnecting = false;
        resetTailDedup();
        visibleRecords = [];
        nextUntil = "";
        olderBtn.classList.add("d-none");
        clear(out);
        if (tailES) {
          meta.textContent = "Streaming live logs (console cleared)…";
        } else {
          out.appendChild(makeEmptyRow(6, "Console cleared", "Run Search or start Live Tail to view log entries."));
          meta.textContent = "0 lines displayed";
        }
      });
    }
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        const lines = visibleRecords
          .filter((r) => !r.tr.classList.contains("d-none"))
          .map((r) => formatEntryLine(r.entry));
        if (lines.length === 0) {
          showToast("No visible log lines to copy", true);
          return;
        }
        try {
          await navigator.clipboard.writeText(lines.join("\n"));
          showToast("Copied " + lines.length + " log lines");
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
      searchSeq++;
      if (searchAbort) {
        searchAbort.abort();
        searchAbort = null;
      }
      cancelClassify(true);
      resetTailDedup();
      clear(out);
      visibleRecords = [];
      nextUntil = "";
      olderBtn.classList.add("d-none");
      meta.textContent = "Streaming live logs from " + svc + "…";
      tailBtn.textContent = "Stop Tail";
      tailBtn.className = "btn btn-danger btn-sm";
      setTailBadge("status-yellow", "Connecting…");

      clearTailReconnectTimer();
      tailReconnecting = false;
      const es = new EventSource("/api/logs/stream?service=" + encodeURIComponent(svc) + "&tail=100");
      tailES = es;
      es.onopen = () => {
        if (tailES !== es) return;
        meta.textContent = "Streaming live logs from " + svc + "…";
        setTailBadge("status-green", "Streaming · " + svc);
        if (tailReconnecting) {
          clearTailReconnectTimer();
          tailReconnectTimer = setTimeout(() => {
            tailReconnectTimer = null;
            if (tailES === es) tailReconnecting = false;
          }, 1500);
        }
      };
      es.onmessage = (ev) => {
        if (tailES !== es) return;
        try {
          const entry = JSON.parse(ev.data);
          const isNew = recordTailKey(entry);
          if (tailReconnecting) {
            if (!isNew) return;
            tailReconnecting = false;
            clearTailReconnectTimer();
          }
          const emptyRow = out.querySelector(".empty");
          if (emptyRow && emptyRow.closest("tr")) emptyRow.closest("tr").remove();
          const rec = makeLogRow(entry, openLogDetailModal);
          out.appendChild(rec.tr);
          visibleRecords.push(rec);
          while (visibleRecords.length > 1000) {
            const oldest = visibleRecords.shift();
            if (oldest && oldest.tr && oldest.tr.parentNode) oldest.tr.remove();
          }
          applyClassFilter();
          scheduleTailRuleScan();
          if (scrollBox) scrollBox.scrollTop = scrollBox.scrollHeight;
        } catch {}
      };
      es.onerror = () => {
        if (tailES !== es) return;
        if (es.readyState === EventSource.CLOSED) {
          stopTail();
          meta.textContent = "Stream closed (session expired or concurrency limit reached).";
          setTailBadge("status-red", "Closed");
        } else {
          clearTailReconnectTimer();
          tailReconnecting = true;
          meta.textContent = "Stream interrupted; reconnecting…";
          setTailBadge("status-yellow", "Reconnecting…");
        }
      };
    });

    window.addEventListener("pagehide", () => {
      if (searchAbort) {
        searchAbort.abort();
        searchAbort = null;
      }
      if (ovAbort) {
        ovAbort.abort();
        ovAbort = null;
      }
      if (infoAbort) {
        infoAbort.abort();
        infoAbort = null;
      }
      cancelClassify(false);
      stopTail();
    });

    if (initialService && initialService !== "all" && !Array.from(svcSelect.options).some((o) => o.value === initialService)) {
      const opt = el("option", "", initialService);
      opt.value = initialService;
      opt.selected = true;
      svcSelect.appendChild(opt);
    }

    loadContainerDropdown();
    loadClassifierInfo();
    runSearch(false);
  }

  // ==================== MANAGED SERVICE PAGE ====================
  async function initService() {
    const banner = document.getElementById("service-banner");
    const tabsEl = document.getElementById("service-tabs");
    const panelEl = document.getElementById("service-panel");
    const sub = document.getElementById("page-subtitle");
    const bs = getBS();

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
    if (caps.length === 0) {
      clear(panelEl);
      const emptyPane = el("div", "tab-pane active show card-body text-secondary", "This service exposes no interactive capabilities.");
      emptyPane.setAttribute("role", "tabpanel");
      panelEl.appendChild(emptyPane);
      return;
    }

    const paneSeqs = new WeakMap();

    function bumpPaneSeq(pane) {
      const next = (paneSeqs.get(pane) || 0) + 1;
      paneSeqs.set(pane, next);
      return next;
    }

    function isPaneStale(pane, seq) {
      return paneSeqs.get(pane) !== seq;
    }

    async function loadTab(cap, pane) {
      const seq = bumpPaneSeq(pane);
      const isStale = () => isPaneStale(pane, seq);
      clear(pane);
      pane.appendChild(el("div", "card-body text-secondary", "Loading " + cap + "…"));
      try {
        if (cap === "users") await renderUsersTab(pane, isStale);
        else if (cap === "settings") await renderSettingsTab(pane, manifest.settings_schema || [], isStale);
        else if (cap === "artifacts") await renderArtifactsTab(pane, "", isStale, true);
        else {
          if (isStale()) return;
          clear(pane);
          pane.appendChild(el("div", "card-body text-secondary", "Unsupported capability: " + cap));
        }
      } catch (err) {
        if (isStale()) return;
        clear(pane);
        const body = el("div", "card-body");
        body.appendChild(el("div", "alert alert-danger mb-0", "Failed to load " + cap + ": " + err.message));
        pane.appendChild(body);
      }
    }

    clear(tabsEl);
    clear(panelEl);

    let firstPane = null;
    caps.forEach((cap, idx) => {
      const safeId = idx + "-" + String(cap).replace(/[^A-Za-z0-9_-]/g, "_");
      const tabId = "tab-" + safeId;
      const paneId = "pane-" + safeId;
      const isFirst = idx === 0;

      const li = el("li", "nav-item");
      li.setAttribute("role", "presentation");
      const btn = el("button", "nav-link" + (isFirst ? " active" : ""), cap.toUpperCase());
      btn.id = tabId;
      btn.type = "button";
      btn.setAttribute("role", "tab");
      btn.setAttribute("data-bs-toggle", "tab");
      btn.setAttribute("data-bs-target", "#" + paneId);
      btn.setAttribute("aria-controls", paneId);
      btn.setAttribute("aria-selected", isFirst ? "true" : "false");
      if (!isFirst) btn.tabIndex = -1;

      li.appendChild(btn);
      tabsEl.appendChild(li);

      const pane = el("div", "tab-pane" + (isFirst ? " active show" : ""));
      pane.id = paneId;
      pane.setAttribute("role", "tabpanel");
      pane.setAttribute("aria-labelledby", tabId);
      panelEl.appendChild(pane);
      if (isFirst) firstPane = pane;

      btn.addEventListener("shown.bs.tab", () => {
        loadTab(cap, pane);
      });
      if (bs && bs.Tab) {
        bs.Tab.getOrCreateInstance(btn);
      } else {
        btn.addEventListener("click", () => {
          tabsEl.querySelectorAll(".nav-link").forEach((n) => {
            n.classList.remove("active");
            n.setAttribute("aria-selected", "false");
          });
          panelEl.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active", "show"));
          btn.classList.add("active");
          btn.setAttribute("aria-selected", "true");
          pane.classList.add("active", "show");
          loadTab(cap, pane);
        });
      }
    });

    if (firstPane) {
      loadTab(caps[0], firstPane);
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
          let ap = null;
          let dn = null;
          const setRowBusy = (busy) => {
            if (ap) ap.disabled = busy;
            if (dn) dn.disabled = busy;
          };
          if (u.status !== "active") {
            ap = el("button", "btn btn-sm btn-primary", "Approve");
            ap.type = "button";
            ap.addEventListener("click", async () => {
              setRowBusy(true);
              try {
                await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users/" + encodeURIComponent(u.id) + "/approve", { method: "POST" });
                showToast("Approved " + u.username);
                if (container.classList.contains("active")) loadTab("users", container);
              } catch (err) {
                showToast(err.message, true);
                setRowBusy(false);
              }
            });
            btns.appendChild(ap);
          }
          if (u.status !== "denied") {
            dn = el("button", "btn btn-sm btn-outline-danger", "Deny");
            dn.type = "button";
            dn.addEventListener("click", async () => {
              const ok = await confirmAction({
                title: "Deny user account?",
                message: "Deny account '" + u.username + "' and revoke active sessions/tokens?",
                confirmLabel: "Deny account",
                variant: "danger"
              });
              if (!ok) return;
              setRowBusy(true);
              try {
                await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users/" + encodeURIComponent(u.id) + "/deny", { method: "POST" });
                showToast("Denied " + u.username);
                if (container.classList.contains("active")) loadTab("users", container);
              } catch (err) {
                showToast(err.message, true);
                setRowBusy(false);
              }
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
      const body = el("div", "card-body");
      const row = el("div", "row");
      const col = el("div", "col-lg-8");
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
        } else if (Array.isArray(f.options) && f.options.length > 0) {
          const lbl = el("label", "form-label", f.label || f.key);
          lbl.setAttribute("for", inputID);
          grp.appendChild(lbl);
          const sel = el("select", "form-select");
          sel.id = inputID;
          f.options.forEach((optVal) => {
            const opt = el("option", "", String(optVal));
            opt.value = String(optVal);
            if (String(val) === String(optVal)) opt.selected = true;
            sel.appendChild(opt);
          });
          grp.appendChild(sel);
          inputs[f.key] = { type: "string", node: sel };
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
        col.appendChild(grp);
      });

      row.appendChild(col);
      body.appendChild(row);
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
          if (container.classList.contains("active")) {
            loadTab("settings", container);
          } else {
            saveBtn.disabled = false;
            saveBtn.textContent = "Save Settings";
          }
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
        const seq = bumpPaneSeq(container);
        renderArtifactsTab(container, "", () => isPaneStale(container, seq), false);
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
        const seq = bumpPaneSeq(container);
        renderArtifactsTab(container, p.toString(), () => isPaneStale(container, seq), false);
      });
      filterWrap.appendChild(bar);
      container.appendChild(filterWrap);

      function safeViewerURL(raw) {
        if (!raw || typeof raw !== "string") return "";
        const s = raw.trim();
        if (!s) return "";
        if (s.startsWith("/") && !s.startsWith("//") && !s.startsWith("/\\")) {
          return s;
        }
        try {
          const u = new URL(s);
          if (u.protocol === "https:" || u.protocol === "http:") {
            return u.href;
          }
        } catch {}
        return "";
      }

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
          const safeHref = safeViewerURL(a.viewer_url);
          if (safeHref) {
            const link = el("a", "", a.title);
            link.href = safeHref;
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
            del.disabled = true;
            try {
              await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/artifacts/" + encodeURIComponent(a.id), { method: "DELETE" });
              showToast("Deleted artifact " + a.id);
              if (container.classList.contains("active")) {
                const seq = bumpPaneSeq(container);
                renderArtifactsTab(container, queryStr, () => isPaneStale(container, seq), false);
              }
            } catch (err) {
              showToast(err.message, true);
              del.disabled = false;
            }
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
    const footerEl = document.getElementById("audit-footer");
    const footerMetaEl = document.getElementById("audit-footer-meta");
    const olderBtn = document.getElementById("audit-older-btn");

    const PAGE_SIZE = 50;
    let auditSeq = 0;
    let auditAbort = null;
    let currentOffset = 0;
    let totalShown = 0;
    let tbodyRef = null;

    function buildAuditRow(row) {
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
        const pre = el("pre", "audit-json bg-body-tertiary border rounded p-2 mt-1 mb-0 font-monospace small", JSON.stringify(row.details, null, 2));
        det.appendChild(summary);
        det.appendChild(pre);
        detTd.appendChild(det);
      } else {
        detTd.textContent = "—";
      }
      tr.appendChild(detTd);
      return tr;
    }

    async function load(append) {
      const seq = ++auditSeq;
      if (auditAbort) {
        auditAbort.abort();
        auditAbort = null;
      }
      const ctrl = typeof AbortController === "function" ? new AbortController() : null;
      auditAbort = ctrl;

      if (!append) {
        currentOffset = 0;
      }
      const p = new URLSearchParams();
      const s = svcInput.value.trim();
      const a = actInput.value.trim();
      if (s) p.set("service", s);
      if (a) p.set("action", a);
      p.set("limit", String(PAGE_SIZE));
      p.set("offset", String(currentOffset));

      if (olderBtn) olderBtn.disabled = true;
      try {
        const res = await apiFetch("/api/audit?" + p.toString(), ctrl ? { signal: ctrl.signal } : undefined);
        if (seq !== auditSeq) return;
        const rows = res.audit_logs || [];

        if (!append || !tbodyRef) {
          clear(tbl);
          const thead = el("thead");
          const hr = el("tr");
          ["Time", "Actor", "Auth", "Action", "Service", "Target", "IP", "Details"].forEach((h) => hr.appendChild(el("th", "", h)));
          thead.appendChild(hr);
          tbl.appendChild(thead);
          tbodyRef = el("tbody");
          tbl.appendChild(tbodyRef);
          totalShown = 0;
        }

        if (!append && rows.length === 0) {
          tbodyRef.appendChild(makeEmptyRow(8, "No audit records matched", ""));
        } else {
          rows.forEach((row) => {
            tbodyRef.appendChild(buildAuditRow(row));
          });
          totalShown += rows.length;
          currentOffset += rows.length;
        }

        if (countEl) countEl.textContent = totalShown + " events";
        const hasMore = rows.length === PAGE_SIZE;
        if (footerEl) {
          footerEl.classList.toggle("d-none", !hasMore && totalShown <= PAGE_SIZE);
        }
        if (footerMetaEl) {
          footerMetaEl.textContent = "Showing " + totalShown + " event(s)";
        }
        if (olderBtn) {
          olderBtn.classList.toggle("d-none", !hasMore);
          olderBtn.disabled = false;
        }
      } catch (err) {
        if ((err && err.name === "AbortError") || seq !== auditSeq) return;
        if (olderBtn) olderBtn.disabled = false;
        showToast("Failed to load audit logs: " + err.message, true);
      } finally {
        if (auditAbort === ctrl) auditAbort = null;
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      load(false);
    });
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        svcInput.value = "";
        actInput.value = "";
        load(false);
      });
    }
    if (olderBtn) {
      olderBtn.addEventListener("click", () => load(true));
    }
    window.addEventListener("pagehide", () => {
      if (auditAbort) {
        auditAbort.abort();
        auditAbort = null;
      }
    });
    load(false);
  }

  initTheme();

  if (page === "overview") initOverview();
  else if (page === "logs") initLogs();
  else if (page === "service") initService();
  else if (page === "audit") initAudit();
})();
