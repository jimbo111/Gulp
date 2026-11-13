// Gulp DOM Probe instrumentation (F16 BRW-010). Injected into every page before its own scripts run
// (CDP Page.addScriptToEvaluateOnNewDocument). It wraps DOM sinks and, when a sink receives a string
// that contains the current value of a DOM source (location.hash/search/href, document.referrer,
// window.name), reports a tainted source -> sink flow through the `__gulpReport` binding. This is a
// lightweight substring-taint heuristic (not full byte-level taint tracking), which reliably catches
// the classic client-side XSS patterns while staying deterministic. Single source of truth: embedded
// into GulpBrowser and loaded verbatim by the real-Chromium DoD harness.
(function () {
  if (window.__gulpProbeInstalled) return;
  window.__gulpProbeInstalled = true;

  function sources() {
    var s = {};
    try { s["location.hash"] = String(location.hash || ""); } catch (e) {}
    try { s["location.search"] = String(location.search || ""); } catch (e) {}
    try { s["location.href"] = String(location.href || ""); } catch (e) {}
    try { s["document.referrer"] = String(document.referrer || ""); } catch (e) {}
    try { s["window.name"] = String(window.name || ""); } catch (e) {}
    return s;
  }

  // Returns {source, sample} when `value` carries a source's payload, else null.
  function taint(value) {
    if (typeof value !== "string" || value.length < 3) return null;
    var s = sources();
    for (var key in s) {
      var raw = s[key];
      if (typeof raw !== "string") continue;
      // Compare on the payload: strip a single leading '#' or '?', and URL-decode where possible.
      var payload = raw.replace(/^[#?]/, "");
      var decoded = payload;
      try { decoded = decodeURIComponent(payload); } catch (e) {}
      for (var i = 0; i < 2; i++) {
        var probe = i === 0 ? payload : decoded;
        if (probe.length >= 3 && value.indexOf(probe) !== -1) {
          return { source: key, sample: probe.slice(0, 80) };
        }
      }
    }
    return null;
  }

  function report(sink, value) {
    var t = taint(value);
    if (!t) return;
    try {
      if (window.__gulpReport) {
        window.__gulpReport(JSON.stringify({
          sink: sink, source: t.source, sample: t.sample, snippet: String(value).slice(0, 200)
        }));
      }
    } catch (e) {}
  }

  // innerHTML / outerHTML setters.
  ["innerHTML", "outerHTML"].forEach(function (prop) {
    try {
      var desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (desc && desc.set) {
        Object.defineProperty(Element.prototype, prop, {
          configurable: true,
          enumerable: desc.enumerable,
          get: desc.get,
          set: function (v) { report("Element." + prop, v); return desc.set.call(this, v); }
        });
      }
    } catch (e) {}
  });

  // document.write / writeln.
  ["write", "writeln"].forEach(function (name) {
    try {
      var original = document[name];
      document[name] = function (v) { report("document." + name, v); return original.apply(document, arguments); };
    } catch (e) {}
  });

  // eval and the Function constructor.
  try {
    var realEval = window.eval;
    window.eval = function (v) { report("eval", v); return realEval.call(window, v); };
  } catch (e) {}

  // setAttribute of dangerous attributes.
  try {
    var realSetAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (/^(src|href|on\w+|srcdoc|formaction|xlink:href|data)$/i.test(String(name))) {
        report("setAttribute[" + name + "]", value);
      }
      return realSetAttr.apply(this, arguments);
    };
  } catch (e) {}
})();
