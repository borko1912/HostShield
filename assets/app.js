// HostShield dashboard behaviour (no inline scripts: the CSP forbids them).
(function () {
  'use strict';

  // Confirm dialogs on forms and buttons.
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var btn = e.submitter;
    var msg = (btn && btn.getAttribute('data-confirm')) || f.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
    }
  });

  // Copy buttons: data-copy="<id of the element to copy>".
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.getAttribute('data-copy'));
    if (!el) return;
    var text = el.textContent;
    var done = function () { var t = b.textContent; b.textContent = '✓'; setTimeout(function () { b.textContent = t; }, 1200); };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(done);
    } else {
      var r = document.createRange(); r.selectNodeContents(el);
      var s = getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand('copy'); done();
    }
  });

  // "Select all" checkbox: data-check-all="<name of the checkboxes>".
  document.querySelectorAll('[data-check-all]').forEach(function (all) {
    all.addEventListener('change', function () {
      document.querySelectorAll('input[name="' + all.getAttribute('data-check-all') + '"]').forEach(function (c) { c.checked = all.checked; });
    });
  });

  // Show a block depending on a select: <div data-switch="field"> ... <div data-when="value">.
  document.querySelectorAll('[data-switch]').forEach(function (box) {
    var sel = box.querySelector('[name="' + box.getAttribute('data-switch') + '"]');
    if (!sel) return;
    var apply = function () {
      box.querySelectorAll('[data-when]').forEach(function (d) { d.classList.toggle('show', d.getAttribute('data-when') === sel.value); });
    };
    sel.addEventListener('change', apply);
    apply();
  });

  // Submit on change (filters).
  document.querySelectorAll('[data-autosubmit]').forEach(function (s) {
    s.addEventListener('change', function () { s.form.submit(); });
  });

  // Auto refresh while a task runs.
  var r = document.querySelector('[data-refresh]');
  if (r) {
    setTimeout(function () { location.reload(); }, 1000 * (parseInt(r.getAttribute('data-refresh'), 10) || 5));
  }

  // Installer: send the browser's time zone.
  document.querySelectorAll('[data-timezone]').forEach(function (i) {
    try { i.value = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
  });

  // 2FA QR code (qrcodejs from cdnjs, loaded only on that page).
  var qr = document.querySelector('[data-qr]');
  if (qr) {
    var s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    s.onload = function () {
      /* global QRCode */
      new QRCode(qr, { text: qr.getAttribute('data-qr'), width: 180, height: 180 });
    };
    document.head.appendChild(s);
  }
})();
