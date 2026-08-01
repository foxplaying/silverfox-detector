/**
 * 扩展设置页：VirusTotal API Key + 自动提交/打开开关（与 popup 风险报告分离）。
 */
;(function () {
  "use strict";

  function $(id) {
    return document.getElementById(id);
  }

  function setStatus(el, text, cls) {
    if (!el) return;
    el.textContent = text || "";
    el.className = "status" + (cls ? " " + cls : "");
  }

  function notifyKeyUpdated() {
    try {
      chrome.runtime.sendMessage({ type: "vt-api-key-updated" }, () => {
        void chrome.runtime.lastError;
      });
    } catch { /* ignore */ }
  }

  function initApiKey() {
    const input = $("vt-api-key");
    const saveBtn = $("vt-api-save");
    const clearBtn = $("vt-api-clear");
    const toggleBtn = $("vt-api-toggle");
    const status = $("vt-api-status");
    if (!input || !saveBtn) return;

    try {
      chrome.storage.local.get(["vtApiKey", "virusTotalApiKey"], (r) => {
        const k = String((r && (r.vtApiKey || r.virusTotalApiKey)) || "").trim();
        if (k) {
          input.value = k;
          setStatus(status, "已配置", "ok");
        } else {
          setStatus(status, "未配置", "");
        }
      });
    } catch {
      setStatus(status, "读取失败", "err");
    }

    saveBtn.addEventListener("click", () => {
      const key = String(input.value || "").trim();
      if (!key) {
        setStatus(status, "请输入 Key", "err");
        return;
      }
      if (key.length < 32) {
        setStatus(status, "Key 太短", "err");
        return;
      }
      chrome.storage.local.set({ vtApiKey: key }, () => {
        if (chrome.runtime.lastError) {
          setStatus(status, "保存失败", "err");
          return;
        }
        setStatus(status, "已保存", "ok");
        notifyKeyUpdated();
      });
    });

    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        input.value = "";
        chrome.storage.local.remove(["vtApiKey", "virusTotalApiKey"], () => {
          setStatus(status, "已清除", "");
          notifyKeyUpdated();
        });
      });
    }

    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        toggleBtn.textContent = show ? "隐藏" : "显示";
      });
    }
  }

  function initFeedToggles() {
    const submitEl = $("vt-auto-submit");
    const status = $("vt-feed-status");
    if (!submitEl) return;

    // 默认：自动提交开（无「自动打开」开关）
    try {
      chrome.storage.local.get(["vtAutoSubmitUrl"], (r) => {
        submitEl.checked = r.vtAutoSubmitUrl === undefined ? true : !!r.vtAutoSubmitUrl;
      });
    } catch {
      setStatus(status, "读取失败", "err");
    }

    submitEl.addEventListener("change", () => {
      const autoSubmit = !!submitEl.checked;
      chrome.storage.local.set({ vtAutoSubmitUrl: autoSubmit }, () => {
        if (chrome.runtime.lastError) {
          setStatus(status, "保存失败", "err");
          return;
        }
        setStatus(
          status,
          autoSubmit ? "已保存：自动上传文件开启" : "已保存：自动上传文件关闭",
          "ok"
        );
      });
    });
  }

  function init() {
    initApiKey();
    initFeedToggles();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
