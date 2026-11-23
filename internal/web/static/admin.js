(() => {
  "use strict";

  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
  const page = document.body.getAttribute("data-page") || "";
  const activeService = document.body.getAttribute("data-service") || "";

  // Strict DOM helpers (always build elements via createElement + textContent).
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function showToast(msg, isError) {
    const t = document.getElementById("toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.remove("hidden");
    t.style.borderColor = isError ? "#f46c6c" : "#3a72c8";
    clearTimeout(t._timer);
    t._timer = setTimeout(() => t.classList.add("hidden"), 3500);
  }

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

  function barClass(pct) {
    if (pct >= 90) return "bar-fill err";
    if (pct >= 75) return "bar-fill warn";
    return "bar-fill";
  }

  function makeMetricCard(label, value, sub, pct) {
    const card = el("div", "metric-card");
    card.appendChild(el("div", "metric-label", label));
    card.appendChild(el("div", "metric-value", value));
    if (pct !== null && pct !== undefined) {
      const track = el("div", "bar-track");
      const fill = el("div", barClass(pct));
      fill.style.width = Math.max(0, Math.min(100, pct)) + "%";
      track.appendChild(fill);
      card.appendChild(track);
    }
    card.appendChild(el("div", "metric-sub", sub));
    return card;
  }

  function makeSparkline(title, latestText, values, maxVal, stroke) {
    const box = el("div", "chart-box");
    const hdr = el("div", "chart-title");
    hdr.appendChild(el("span", "", title));
    hdr.appendChild(el("strong", "", latestText));
    box.appendChild(hdr);

    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("class", "sparkline");
    svg.setAttribute("viewBox", "0 0 300 72");
    svg.setAttribute("preserveAspectRatio", "none");

    const clean = values.filter((v) => v !== null && v !== undefined && !Number.isNaN(Number(v)));
    if (clean.length >= 2) {
      const top = maxVal || Math.max(100, ...clean);
      const pts = clean.map((v, i) => {
        const x = (i / (clean.length - 1)) * 300;
        const y = 68 - (Math.max(0, Math.min(top, v)) / top) * 62;
        return x.toFixed(1) + "," + y.toFixed(1);
      }).join(" ");
      const poly = document.createElementNS(svgNS, "polyline");
      poly.setAttribute("fill", "none");
      poly.setAttribute("stroke", stroke || "#6ea8fe");
      poly.setAttribute("stroke-width", "2");
      poly.setAttribute("points", pts);
      svg.appendChild(poly);
    }
    box.appendChild(svg);
    return box;
  }

  // ==================== OVERVIEW PAGE ====================
  function renderSystem(sys) {
    const hwGrid = document.getElementById("hw-grid");
    const subtitle = document.getElementById("page-subtitle");
    if (!hwGrid || !sys) return;

    if (subtitle && sys.host) {
      subtitle.textContent = [sys.host.hostname, sys.host.os, sys.host.kernel ? ("kernel " + sys.host.kernel) : "", "up " + fmtUptime(sys.host.uptime_seconds)].filter(Boolean).join(" · ");
    }

    clear(hwGrid);
    const cpu = sys.cpu || {};
    const mem = sys.memory || {};
    const disk = sys.disk || {};

    hwGrid.appendChild(makeMetricCard(
      "CPU Usage",
      (cpu.usage_pct ?? 0).toFixed(1) + "%",
      (cpu.cores || 0) + " cores · load " + (cpu.load_1 ?? 0).toFixed(2) + " / " + (cpu.load_5 ?? 0).toFixed(2) + " / " + (cpu.load_15 ?? 0).toFixed(2),
      cpu.usage_pct ?? 0
    ));
    hwGrid.appendChild(makeMetricCard(
      "Memory",
      (mem.usage_pct ?? 0).toFixed(1) + "%",
      fmtBytes(mem.used_bytes) + " / " + fmtBytes(mem.total_bytes) + (mem.swap_total_bytes ? (" · swap " + fmtBytes(mem.swap_used_bytes)) : ""),
      mem.usage_pct ?? 0
    ));
    hwGrid.appendChild(makeMetricCard(
      "Host Disk",
      (disk.usage_pct ?? 0).toFixed(1) + "%",
      fmtBytes(disk.used_bytes) + " / " + fmtBytes(disk.total_bytes) + " (" + fmtBytes(disk.available_bytes) + " free)",
      disk.usage_pct ?? 0
    ));
    if (sys.docker_df) {
      hwGrid.appendChild(makeMetricCard(
        "Docker Disk",
        fmtBytes(sys.docker_df.total_bytes),
        "img " + fmtBytes(sys.docker_df.images_bytes) + " · vol " + fmtBytes(sys.docker_df.volumes_bytes) + " · cache " + fmtBytes(sys.docker_df.build_cache_bytes),
        null
      ));
    }
    if (sys.thermals && sys.thermals.length > 0) {
      const top = sys.thermals[0];
      hwGrid.appendChild(makeMetricCard(
        "Thermal (" + top.name + ")",
        top.temp_c.toFixed(1) + " °C",
        sys.thermals.slice(0, 3).map((t) => t.name + ": " + t.temp_c + "°C").join(" · "),
        top.temp_c
      ));
    }

    // NVIDIA GPU section
    const gpuSection = document.getElementById("gpu-section");
    const gpuBody = document.getElementById("gpu-body");
    const gpuDriver = document.getElementById("gpu-driver");
    if (gpuSection && gpuBody && sys.gpu && sys.gpu.available && sys.gpu.devices && sys.gpu.devices.length > 0) {
      gpuSection.classList.remove("hidden");
      clear(gpuBody);
      const grid = el("div", "grid-cards");
      if (gpuDriver) gpuDriver.textContent = "Driver " + (sys.gpu.devices[0].driver_version || "");
      sys.gpu.devices.forEach((dev) => {
        const vramPct = (dev.mem_used_mib != null && dev.mem_total_mib) ? ((dev.mem_used_mib / dev.mem_total_mib) * 100) : null;
        const utilStr = dev.util_pct != null ? (dev.util_pct.toFixed(0) + "%") : "N/A";
        const vramStr = (dev.mem_used_mib != null && dev.mem_total_mib != null) ? (Math.round(dev.mem_used_mib) + " / " + Math.round(dev.mem_total_mib) + " MiB") : "VRAM N/A";
        const tempStr = dev.temp_c != null ? (dev.temp_c.toFixed(0) + "°C") : "";
        const pwrStr = dev.power_draw_w != null ? (dev.power_draw_w.toFixed(0) + "W" + (dev.power_limit_w ? ("/" + dev.power_limit_w.toFixed(0) + "W") : "")) : "";
        grid.appendChild(makeMetricCard(
          "GPU " + dev.index + " · " + dev.name,
          utilStr + (tempStr ? (" · " + tempStr) : ""),
          [vramStr, pwrStr].filter(Boolean).join(" · "),
          vramPct !== null ? vramPct : dev.util_pct
        ));
      });
      gpuBody.appendChild(grid);
    }

    // 1-hour history sparklines
    const charts = document.getElementById("charts-grid");
    const histMeta = document.getElementById("hist-meta");
    if (charts && Array.isArray(sys.history)) {
      clear(charts);
      if (histMeta) histMeta.textContent = sys.history.length + " samples";
      charts.appendChild(makeSparkline("CPU %", (cpu.usage_pct ?? 0).toFixed(1) + "%", sys.history.map((p) => p.cpu_pct), 100, "#6ea8fe"));
      charts.appendChild(makeSparkline("Memory %", (mem.usage_pct ?? 0).toFixed(1) + "%", sys.history.map((p) => p.mem_pct), 100, "#3dd68c"));
      const hasGPUHist = sys.history.some((p) => p.gpu_util_pct !== undefined && p.gpu_util_pct !== null);
      if (hasGPUHist) {
        const last = sys.history[sys.history.length - 1];
        charts.appendChild(makeSparkline("GPU Util %", (last.gpu_util_pct != null ? last.gpu_util_pct.toFixed(0) + "%" : "—"), sys.history.map((p) => p.gpu_util_pct), 100, "#f5b942"));
        charts.appendChild(makeSparkline("GPU Temp °C", (last.gpu_temp_c != null ? last.gpu_temp_c.toFixed(0) + "°C" : "—"), sys.history.map((p) => p.gpu_temp_c), 100, "#f46c6c"));
      }
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
    payload.containers.forEach((c) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", c.service || c.name));

      const stTd = el("td");
      const pillCls = (c.state === "running" && (!c.health || c.health === "healthy")) ? "pill pill-ok" : (c.state === "running" ? "pill pill-warn" : "pill pill-err");
      stTd.appendChild(el("span", pillCls, c.health ? (c.state + " (" + c.health + ")") : c.state));
      tr.appendChild(stTd);

      tr.appendChild(el("td", "", (c.cpu_pct ?? 0).toFixed(1) + "%"));
      tr.appendChild(el("td", "", fmtBytes(c.mem_usage_bytes) + (c.mem_pct ? (" (" + c.mem_pct.toFixed(1) + "%)") : "")));
      tr.appendChild(el("td", "", String(c.restart_count ?? 0)));
      tr.appendChild(el("td", "muted", c.image || ""));

      const logTd = el("td");
      const link = el("a", "btn btn-sm", "Logs");
      link.href = "/logs?service=" + encodeURIComponent(c.service || "");
      logTd.appendChild(link);
      tr.appendChild(logTd);

      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
  }

  function renderDBStats(db) {
    const tbl = document.getElementById("db-table");
    const meta = document.getElementById("db-meta");
    if (!tbl) return;
    clear(tbl);
    if (!db || !Array.isArray(db.databases)) {
      if (meta) meta.textContent = "PostgreSQL stats unavailable";
      return;
    }
    if (meta) {
      meta.textContent = "PostgreSQL " + db.server_version + " · " + db.client_connections + "/" + db.max_connections + " conns · total " + fmtBytes(db.total_size_bytes);
    }

    const thead = el("thead");
    const hr = el("tr");
    ["Database", "Service", "Size", "Connections", "Created"].forEach((h) => hr.appendChild(el("th", "", h)));
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = el("tbody");
    db.databases.forEach((d) => {
      const tr = el("tr");
      tr.appendChild(el("td", "", d.name));
      tr.appendChild(el("td", "", d.service_name || "system"));
      tr.appendChild(el("td", "", fmtBytes(d.size_bytes)));
      tr.appendChild(el("td", "", String(d.connections ?? 0)));
      tr.appendChild(el("td", "muted", d.created_at ? fmtTime(d.created_at) : "—"));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
  }

  async function initOverview() {
    const statusBox = document.getElementById("header-status");
    try {
      const data = await apiFetch("/api/overview");
      if (data.system) renderSystem(data.system);
      if (data.containers) renderContainers(data.containers);
      renderDBStats(data.db_stats);
    } catch (err) {
      showToast("Overview load failed: " + err.message, true);
    }

    const es = new EventSource("/api/stream/metrics");
    es.onopen = () => {
      if (statusBox) {
        clear(statusBox);
        statusBox.appendChild(el("span", "pill pill-ok", "Live (5s)"));
      }
    };
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.system) renderSystem(msg.system);
        if (msg.containers) renderContainers(msg.containers);
      } catch {}
    };
    es.onerror = () => {
      if (statusBox) {
        clear(statusBox);
        statusBox.appendChild(el("span", "pill pill-warn", "Reconnecting..."));
      }
    };
  }

  // ==================== LOG EXPLORER PAGE ====================
  function makeLogRow(entry) {
    const row = el("div", "log-row");
    row.appendChild(el("span", "log-ts", fmtTime(entry.ts)));
    row.appendChild(el("span", "log-svc", entry.service || ""));
    row.appendChild(el("span", "log-lvl-" + (entry.level || "info"), (entry.level || "info").toUpperCase()));
    const msgWrap = el("span", "");
    if (entry.structured && entry.structured.request) {
      const st = entry.structured;
      const parts = [String(st.status || ""), st.host || "", st.request || ""];
      if (st.request_time !== undefined && st.request_time !== null) parts.push("(" + Number(st.request_time).toFixed(3) + "s)");
      if (st.client_ip) parts.push("ip=" + st.client_ip);
      msgWrap.textContent = parts.filter(Boolean).join(" ");
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
    const tailBtn = document.getElementById("log-tail-btn");
    const olderBtn = document.getElementById("log-older-btn");

    let nextUntil = "";
    let tailES = null;

    const urlParams = new URLSearchParams(window.location.search);
    const initialService = urlParams.get("service") || "all";

    try {
      const ov = await apiFetch("/api/overview");
      if (ov.containers && Array.isArray(ov.containers.containers)) {
        ov.containers.containers.forEach((c) => {
          const opt = el("option", "", c.service || c.name);
          opt.value = c.service || c.name;
          if (opt.value === initialService) opt.selected = true;
          svcSelect.appendChild(opt);
        });
      }
    } catch {}

    function stopTail() {
      if (tailES) {
        tailES.close();
        tailES = null;
      }
      tailBtn.textContent = "Live Tail";
      tailBtn.classList.remove("btn-danger");
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
        if (!appendOlder) clear(out);
        (res.entries || []).forEach((entry) => out.appendChild(makeLogRow(entry)));
        nextUntil = res.next_until || "";
        olderBtn.classList.toggle("hidden", !res.truncated || !nextUntil);
        meta.textContent = (res.count || 0) + " matching lines" + (res.truncated ? " (truncated; use Load Older or narrow filters)" : "");
      } catch (err) {
        showToast("Log search failed: " + err.message, true);
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      runSearch(false);
    });
    olderBtn.addEventListener("click", () => runSearch(true));
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
      olderBtn.classList.add("hidden");
      meta.textContent = "Streaming live logs from " + svc + "...";
      tailBtn.textContent = "Stop Tail";
      tailBtn.classList.add("btn-danger");
      tailES = new EventSource("/api/logs/stream?service=" + encodeURIComponent(svc) + "&tail=100");
      tailES.onmessage = (ev) => {
        try {
          const entry = JSON.parse(ev.data);
          out.appendChild(makeLogRow(entry));
          while (out.childNodes.length > 1000) out.removeChild(out.firstChild);
          out.scrollTop = out.scrollHeight;
        } catch {}
      };
      tailES.onerror = () => {
        meta.textContent = "Stream interrupted; reconnecting...";
      };
    });

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
      banner.textContent = "Unable to load service manifest: " + err.message;
      banner.classList.remove("hidden");
      return;
    }

    if (sub) sub.textContent = "Service v" + (manifest.version || "1") + " · capabilities: " + (manifest.capabilities || []).join(", ");

    const caps = Array.isArray(manifest.capabilities) ? manifest.capabilities : [];
    let currentTab = caps[0] || "";

    function renderTabs() {
      clear(tabsEl);
      caps.forEach((cap) => {
        const b = el("button", "tab-btn" + (cap === currentTab ? " active" : ""), cap.toUpperCase());
        b.type = "button";
        b.addEventListener("click", () => {
          currentTab = cap;
          renderTabs();
          loadTab(cap);
        });
        tabsEl.appendChild(b);
      });
    }

    async function loadTab(cap) {
      clear(panelEl);
      panelEl.appendChild(el("div", "muted", "Loading " + cap + "..."));
      try {
        if (cap === "users") await renderUsersTab(panelEl);
        else if (cap === "settings") await renderSettingsTab(panelEl, manifest.settings_schema || []);
        else if (cap === "artifacts") await renderArtifactsTab(panelEl);
        else {
          clear(panelEl);
          panelEl.appendChild(el("div", "muted", "Unsupported capability: " + cap));
        }
      } catch (err) {
        clear(panelEl);
        panelEl.appendChild(el("div", "alert", "Failed to load " + cap + ": " + err.message));
      }
    }

    async function renderUsersTab(container) {
      const data = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users");
      clear(container);
      const wrap = el("div", "table-wrap");
      const tbl = el("table", "table");
      const thead = el("thead");
      const hr = el("tr");
      ["Username", "Role", "Status", "Artifacts", "Storage", "Created", "Actions"].forEach((h) => hr.appendChild(el("th", "", h)));
      thead.appendChild(hr);
      tbl.appendChild(thead);

      const tbody = el("tbody");
      (data.users || []).forEach((u) => {
        const tr = el("tr");
        tr.appendChild(el("td", "", u.username));
        tr.appendChild(el("td", "", u.role));
        const stTd = el("td");
        const cls = u.status === "active" ? "pill pill-ok" : (u.status === "pending" ? "pill pill-warn" : "pill pill-err");
        stTd.appendChild(el("span", cls, u.status));
        tr.appendChild(stTd);
        tr.appendChild(el("td", "", String(u.artifact_count ?? 0)));
        tr.appendChild(el("td", "", fmtBytes(u.storage_bytes ?? 0)));
        tr.appendChild(el("td", "muted", fmtTime(u.created_at)));

        const actTd = el("td", "actions-cell");
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
          actTd.appendChild(ap);
        }
        if (u.status !== "denied") {
          const dn = el("button", "btn btn-sm btn-danger", "Deny");
          dn.type = "button";
          dn.addEventListener("click", async () => {
            if (!window.confirm("Deny account '" + u.username + "' and revoke active sessions/tokens?")) return;
            try {
              await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/users/" + encodeURIComponent(u.id) + "/deny", { method: "POST" });
              showToast("Denied " + u.username);
              loadTab("users");
            } catch (err) { showToast(err.message, true); }
          });
          actTd.appendChild(dn);
        }
        tr.appendChild(actTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      wrap.appendChild(tbl);
      container.appendChild(wrap);
    }

    async function renderSettingsTab(container, schema) {
      const current = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/settings");
      clear(container);
      const form = el("form");
      const inputs = {};

      const fields = schema.length > 0 ? schema : Object.keys(current).map((k) => ({
        key: k,
        label: k,
        type: Array.isArray(current[k]) ? "string_list" : (typeof current[k] === "boolean" ? "bool" : "int")
      }));

      fields.forEach((f) => {
        const grp = el("div", "form-field");
        const val = current[f.key];
        if (f.type === "bool") {
          const lbl = el("label", "check-inline");
          const cb = el("input");
          cb.type = "checkbox";
          cb.checked = Boolean(val);
          lbl.appendChild(cb);
          lbl.appendChild(el("span", "", f.label || f.key));
          grp.appendChild(lbl);
          inputs[f.key] = { type: "bool", node: cb };
        } else if (f.type === "string_list") {
          grp.appendChild(el("label", "", f.label || f.key));
          const ta = el("textarea");
          ta.value = Array.isArray(val) ? val.join("\n") : "";
          grp.appendChild(ta);
          inputs[f.key] = { type: "string_list", node: ta };
        } else {
          grp.appendChild(el("label", "", f.label || f.key));
          const inp = el("input");
          inp.type = "number";
          if (f.min !== undefined) inp.min = String(f.min);
          if (f.max !== undefined) inp.max = String(f.max);
          inp.value = val !== undefined ? String(val) : "";
          grp.appendChild(inp);
          inputs[f.key] = { type: "int", node: inp };
        }
        if (f.help) grp.appendChild(el("div", "form-help", f.help));
        form.appendChild(grp);
      });

      const saveBtn = el("button", "btn btn-primary", "Save Settings");
      saveBtn.type = "submit";
      form.appendChild(saveBtn);

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const patch = {};
        Object.keys(inputs).forEach((k) => {
          const it = inputs[k];
          if (it.type === "bool") patch[k] = it.node.checked;
          else if (it.type === "int") patch[k] = Number(it.node.value);
          else if (it.type === "string_list") {
            patch[k] = it.node.value.split("\n").map((s) => s.trim()).filter(Boolean);
          }
        });
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
        }
      });

      container.appendChild(form);
    }

    async function renderArtifactsTab(container, queryStr) {
      const qs = queryStr ? ("?" + queryStr) : "";
      const data = await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/artifacts" + qs);
      clear(container);

      const bar = el("form", "filter-row");
      const qInp = el("input");
      qInp.type = "text";
      qInp.placeholder = "Search title...";
      const ownerInp = el("input");
      ownerInp.type = "text";
      ownerInp.placeholder = "Owner username...";
      const visSel = el("select");
      [["", "All visibility"], ["private", "Private"], ["public", "Public"]].forEach(([v, label]) => {
        const o = el("option", "", label);
        o.value = v;
        visSel.appendChild(o);
      });
      const goBtn = el("button", "btn btn-primary", "Filter");
      goBtn.type = "submit";
      bar.appendChild(qInp);
      bar.appendChild(ownerInp);
      bar.appendChild(visSel);
      bar.appendChild(goBtn);
      bar.appendChild(el("span", "muted", (data.total_count || 0) + " artifacts · " + fmtBytes(data.total_bytes || 0)));
      bar.addEventListener("submit", (e) => {
        e.preventDefault();
        const p = new URLSearchParams();
        if (qInp.value.trim()) p.set("q", qInp.value.trim());
        if (ownerInp.value.trim()) p.set("owner", ownerInp.value.trim());
        if (visSel.value) p.set("visibility", visSel.value);
        renderArtifactsTab(container, p.toString());
      });
      container.appendChild(bar);

      const wrap = el("div", "table-wrap");
      const tbl = el("table", "table");
      const thead = el("thead");
      const hr = el("tr");
      ["Title", "Owner", "Visibility", "Type", "Size", "Updated", "Actions"].forEach((h) => hr.appendChild(el("th", "", h)));
      thead.appendChild(hr);
      tbl.appendChild(thead);

      const tbody = el("tbody");
      (data.artifacts || []).forEach((a) => {
        const tr = el("tr");
        const tTd = el("td");
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
        vTd.appendChild(el("span", a.visibility === "public" ? "pill pill-ok" : "pill", a.visibility));
        tr.appendChild(vTd);
        tr.appendChild(el("td", "muted", a.content_type));
        tr.appendChild(el("td", "", fmtBytes(a.size_bytes)));
        tr.appendChild(el("td", "muted", fmtTime(a.updated_at)));

        const actTd = el("td", "actions-cell");
        const del = el("button", "btn btn-sm btn-danger", "Delete");
        del.type = "button";
        del.addEventListener("click", async () => {
          if (!window.confirm("Permanently delete artifact '" + a.title + "'?")) return;
          try {
            await apiFetch("/api/services/" + encodeURIComponent(activeService) + "/artifacts/" + encodeURIComponent(a.id), { method: "DELETE" });
            showToast("Deleted artifact " + a.id);
            renderArtifactsTab(container, queryStr);
          } catch (err) { showToast(err.message, true); }
        });
        actTd.appendChild(del);
        tr.appendChild(actTd);
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      wrap.appendChild(tbl);
      container.appendChild(wrap);
    }

    renderTabs();
    if (currentTab) loadTab(currentTab);
  }

  // ==================== AUDIT LOG PAGE ====================
  async function initAudit() {
    const form = document.getElementById("audit-filter-form");
    const tbl = document.getElementById("audit-table");

    async function load() {
      const p = new URLSearchParams();
      const s = document.getElementById("audit-service").value.trim();
      const a = document.getElementById("audit-action").value.trim();
      if (s) p.set("service", s);
      if (a) p.set("action", a);
      try {
        const res = await apiFetch("/api/audit?" + p.toString());
        clear(tbl);
        const thead = el("thead");
        const hr = el("tr");
        ["Time", "Actor", "Auth", "Action", "Service", "Target", "IP", "Details"].forEach((h) => hr.appendChild(el("th", "", h)));
        thead.appendChild(hr);
        tbl.appendChild(thead);

        const tbody = el("tbody");
        (res.audit_logs || []).forEach((row) => {
          const tr = el("tr");
          tr.appendChild(el("td", "muted", fmtTime(row.created_at)));
          tr.appendChild(el("td", "", row.actor_email));
          tr.appendChild(el("td", "", row.auth_method));
          tr.appendChild(el("td", "", row.action));
          tr.appendChild(el("td", "", row.target_service));
          tr.appendChild(el("td", "muted", row.target_id || "—"));
          tr.appendChild(el("td", "muted", row.client_ip || "—"));
          tr.appendChild(el("td", "muted", row.details ? JSON.stringify(row.details) : "{}"));
          tbody.appendChild(tr);
        });
        tbl.appendChild(tbody);
      } catch (err) {
        showToast("Failed to load audit logs: " + err.message, true);
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      load();
    });
    load();
  }

  if (page === "overview") initOverview();
  else if (page === "logs") initLogs();
  else if (page === "service") initService();
  else if (page === "audit") initAudit();
})();
