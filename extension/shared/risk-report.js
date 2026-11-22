// Merge reports only AFTER the caller has verified the same document/transaction.
// A progress message is not a verdict. Keep the selected verdict's sequence
// (not the arrival time of an enrichment) so late terminal results can be ordered.
;(function (root) {
  "use strict";
  const terminal = r => r.analysisComplete === true || r.identityVerificationUnavailable === true;
  const blocked = r => !!(r.downloadGuardInstalled || r.packageBlocked);
  function merge(previous, incoming, chooseSsl) {
    const a = Number(previous.reportSequence), b = Number(incoming.reportSequence);
    const diff = a > 0 && b > 0 ? b - a : (Number(incoming.timestamp) || 0) - (Number(previous.timestamp) || 0);
    const older = diff < 0 ? incoming : previous, newer = diff < 0 ? previous : incoming;
    let verdict = newer;
    if (!terminal(newer) && (terminal(older) || blocked(older))
      && !(blocked(newer) && !blocked(older))) verdict = older;
    const merged = { ...verdict, sslInfo: /^https:/i.test(incoming.url || previous.url || "")
      ? chooseSsl(older.sslInfo, newer.sslInfo) : null };
    if (merged.identityVerificationUnavailable === true) merged.analysisComplete = false;
    return merged;
  }
  root.SilverfoxRiskReport = Object.freeze({ merge });
})(globalThis);
