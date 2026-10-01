// conduitscope manual -- small vanilla-JS helpers, no external dependencies.
// Runs entirely client-side against static content already in the page; nothing is fetched.
(function () {
  "use strict";

  // Mobile sidebar toggle
  var toggle = document.querySelector(".nav-toggle");
  var sidebar = document.querySelector(".sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      sidebar.classList.toggle("is-open");
      var open = sidebar.classList.contains("is-open");
      toggle.textContent = open ? "✕ Close menu" : "☰ Menu";
    });
  }

  // OS tab switching (Linux/Windows panels). Remembers the last choice in this tab only
  // (sessionStorage, not shared across visitors/devices) -- a light convenience, never load-bearing.
  var STORE_KEY = "conduitscope-manual-os";
  var saved = null;
  try { saved = sessionStorage.getItem(STORE_KEY); } catch (e) { /* ignore */ }

  function setOs(os) {
    document.querySelectorAll(".os-tabs").forEach(function (tabs) {
      tabs.querySelectorAll(".os-tab-btn").forEach(function (btn) {
        btn.classList.toggle("is-active", btn.getAttribute("data-os") === os);
      });
    });
    document.querySelectorAll(".os-panel").forEach(function (panel) {
      panel.classList.toggle("is-active", panel.getAttribute("data-os") === os);
    });
    try { sessionStorage.setItem(STORE_KEY, os); } catch (e) { /* ignore */ }
  }

  document.querySelectorAll(".os-tab-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      setOs(btn.getAttribute("data-os"));
    });
  });

  if (document.querySelector(".os-tabs")) {
    setOs(saved === "windows" || saved === "linux" ? saved : "linux");
  }

  // Copy-to-clipboard on terminal blocks: copies only the command lines (.ln-cmd),
  // not the surrounding captured output, so the clipboard holds a runnable command.
  document.querySelectorAll(".term-wrap").forEach(function (wrap) {
    var pre = wrap.querySelector("pre.term");
    if (!pre) return;
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    btn.type = "button";
    btn.textContent = "Copy";
    btn.addEventListener("click", function () {
      var cmdLines = pre.querySelectorAll(".ln-cmd");
      var text;
      if (cmdLines.length) {
        text = Array.prototype.map.call(cmdLines, function (el) {
          var clone = el.cloneNode(true);
          var mark = clone.querySelector(".prompt-mark");
          if (mark) mark.remove();
          return clone.textContent.trim();
        }).join("\n");
      } else {
        text = pre.textContent;
      }
      var done = function () {
        btn.textContent = "Copied";
        btn.classList.add("copied");
        setTimeout(function () {
          btn.textContent = "Copy";
          btn.classList.remove("copied");
        }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        try {
          var ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          document.body.removeChild(ta);
        } catch (e) { /* ignore */ }
        done();
      }
    });
    wrap.appendChild(btn);
  });
})();
