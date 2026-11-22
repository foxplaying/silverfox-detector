/** Shared by the service worker, content script and popup. A validation grade
 * describes one certificate, not a permanent property of its hostname. */
;(function (root) {
  "use strict";

  const host = (info) => String((info && (info.host || info.queriedHost)) || "")
    .trim().toLowerCase().replace(/\.$/, "");
  const rank = (info) => {
    if (/internet\s*widgits|some[-\s]?state|default\s+company/i.test(String(info && info.organization || ""))) return 0;
    return ({ DV: 1, OV: 2, EV: 3 })[String(info && info.validation || "").toUpperCase()] || 0;
  };
  const identity = (info) => {
    const fp = String(info && (info.fingerprintSha256 || info.fingerprint || info.sha256) || "")
      .toLowerCase().replace(/[^a-f0-9]/g, "");
    if (fp.length === 64) return `sha256:${fp}`;
    const id = String(info && (info.certId || info.certificateId) || "").trim();
    return id ? `id:${id}` : "";
  };
  const sameCertificate = (a, b) => !!identity(a) && identity(a) === identity(b);
  const isLive = (info) => {
    if (!info || !(info.sniChainVerified === true || info.liveTlsLeafVerified === true)) return false;
    const queried = String(info.queriedHost || "").toLowerCase().replace(/\.$/, "");
    // A live certificate on a parent host is not a live observation of this host.
    return !queried || !host(info) || queried === host(info);
  };
  const observedAt = (info) => Number(info && (info.observedAt || info.at)) || 0;
  const certTime = (info) => {
    const raw = info && info.notBefore;
    const value = Number(raw) || Date.parse(String(raw || "")) || 0;
    return value > 0 && value < 1e11 ? value * 1000 : value;
  };
  const evidence = (info) => {
    if (!info || !rank(info)) return -1;
    if (isLive(info)) return 3;
    if (/^(?:https-assumed|https-reachability|page-https)$/i.test(String(info.source || ""))) return 0;
    return info.unexpiredHostVerified === true ? 2 : 1;
  };

  function choose(previous, incoming) {
    if (!previous) return incoming || null;
    if (!incoming) return previous;
    if (host(previous) && host(incoming) && host(previous) !== host(incoming)) return incoming;

    if (sameCertificate(previous, incoming)) {
      // A DER/CT lookup can enrich the exact live leaf, but never another leaf.
      const primary = rank(incoming) > rank(previous) ? incoming
        : rank(incoming) < rank(previous) ? previous
          : evidence(incoming) > evidence(previous) ? incoming
            : evidence(incoming) < evidence(previous) ? previous
              : observedAt(incoming) >= observedAt(previous) ? incoming : previous;
      const secondary = primary === incoming ? previous : incoming;
      const live = isLive(incoming) ? incoming : isLive(previous) ? previous : null;
      return {
        ...secondary,
        ...primary,
        organization: rank(primary) >= 2 ? String(primary.organization || secondary.organization || "") : "",
        sniChainVerified: previous.sniChainVerified === true || incoming.sniChainVerified === true,
        liveTlsLeafVerified: previous.liveTlsLeafVerified === true || incoming.liveTlsLeafVerified === true,
        unexpiredHostVerified: previous.unexpiredHostVerified === true || incoming.unexpiredHostVerified === true,
        queriedHost: live ? (live.queriedHost || host(live)) : (primary.queriedHost || secondary.queriedHost),
        observedAt: live ? Math.max(isLive(previous) ? observedAt(previous) : 0,
          isLive(incoming) ? observedAt(incoming) : 0) : Math.max(observedAt(previous), observedAt(incoming))
      };
    }

    const previousEvidence = evidence(previous), incomingEvidence = evidence(incoming);
    if (previousEvidence !== incomingEvidence) return incomingEvidence > previousEvidence ? incoming : previous;
    // A newer live observation may legitimately lower the displayed grade.
    // CT retrieval time alone cannot make an older issued certificate current.
    const pa = observedAt(previous), ia = observedAt(incoming);
    const pn = certTime(previous), inb = certTime(incoming);
    if (previousEvidence === 3 && pa && ia && pa !== ia) return ia > pa ? incoming : previous;
    if (pn && inb && pn !== inb) return inb > pn ? incoming : previous;
    if (pa && ia && pa !== ia) return ia > pa ? incoming : previous;
    // No identity/time proof: keep whole records, never borrow an old org or
    // use EV > OV > DV to override the newest observation of a different leaf.
    return incoming;
  }

  // Presentation only: EV is not proof of an ICP registration. Keep actual
  // licenses, claims, contradictions and provider errors available to the user.
  const hidesMissingIcp = (info, text) => String(info?.validation || "").toUpperCase() === "EV"
    && String(text || "").trim() === "未查询到备案信息";
  root.SilverfoxSslEvidence = Object.freeze({ choose, sameCertificate, identity, isLive, host, observedAt, hidesMissingIcp });
})(globalThis);
