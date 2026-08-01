const MESSAGE_TYPE = "silverfox-archive-extract";
const MESSAGE_TARGET = "archive-offscreen";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.target !== MESSAGE_TARGET || message.type !== MESSAGE_TYPE) return false;
  const taskId = String(message.taskId || "");
  const worker = new Worker(chrome.runtime.getURL("offscreen/archive-worker.js"));
  let answered = false;
  const finish = (response) => {
    if (answered) return;
    answered = true;
    try { worker.terminate(); } catch { /* already stopped */ }
    sendResponse(response);
  };
  worker.addEventListener("message", (event) => {
    const response = event && event.data;
    finish(response && typeof response === "object"
      ? response
      : { ok: false, error: "archive-worker-invalid-response" });
  }, { once: true });
  worker.addEventListener("error", (event) => {
    finish({
      ok: false,
      error: String(event && event.message || "archive-worker-failed")
    });
  }, { once: true });
  worker.postMessage({ taskId });
  return true;
});
