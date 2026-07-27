() => {
    function isVisible(el) {
        if (!el || el.nodeType !== 1) return false;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }
    function inViewport(el) {
        const rect = el.getBoundingClientRect();
        return rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth;
    }

    // ── page text (title + headings + progress) ────────────────────────
    const pageText = [];
    const title = document.title?.trim();
    if (title) pageText.push({ type: 'title', text: title.substring(0, 150) });

    document.querySelectorAll('h1, h2, h3, h4, [role="heading"]').forEach(el => {
        if (!isVisible(el)) return;
        const text = el.textContent.trim().substring(0, 120);
        if (!text) return;
        const rawLevel = el.tagName?.match(/H(\d)/)?.[1] || el.getAttribute('aria-level') || '2';
        // CLAMP to 1..6 — same reason as js/accessibility_tree.js: this feeds a Rust
        // `Option<u8>` (models::dom::PageTextSection.level), so an unbounded
        // page-controlled `aria-level` ("300", "-1", "x") would fail deserialization
        // for the ENTIRE page-context payload and silently blind the AI agent.
        const parsed = parseInt(rawLevel, 10);
        const level = Number.isFinite(parsed) ? Math.min(6, Math.max(1, parsed)) : 2;
        pageText.push({ type: 'heading', level: level, text: text, inViewport: inViewport(el) });
    });

    const stepMatch = document.body?.innerText?.match(/(?:step|page|section|étape)\s*(\d+)\s*(?:of|on|\/)\s*(\d+)/i);
    if (stepMatch) pageText.push({ type: 'progress', text: 'Step ' + stepMatch[1] + ' of ' + stepMatch[3] });

    // ── validation errors (linked to nearest field index) ──────────────
    const fieldSelector = 'input, select, textarea, [role="checkbox"], [role="radio"], [role="option"], [role="textbox"], [role="listbox"], [role="combobox"], [aria-haspopup="listbox"], [contenteditable="true"], [data-params], [data-qa*="choice"], .ps-select-trigger, .ps-select-option';
    const allVisibleFields = Array.from(document.querySelectorAll(fieldSelector)).filter(f => {
        if (f.tagName === 'INPUT' && f.type === 'hidden') return false;
        if (f.tagName === 'SELECT' && f.dataset?.psAbstracted === 'true') return false;
        const r = f.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return false;
        const s = window.getComputedStyle(f);
        return s.display !== 'none' && s.visibility !== 'hidden';
    });

    function nearestFieldIndex(el) {
        if (!el) return null;
        const rect = el.getBoundingClientRect();
        const cy = rect.top + rect.height / 2;
        let bestDist = Infinity, bestIdx = null;
        allVisibleFields.forEach((f, i) => {
            const fr = f.getBoundingClientRect();
            const fy = fr.top + fr.height / 2;
            const dist = Math.abs(cy - fy) + (el.closest('form, .form-group, [class*="form-item"]') === f.closest('form, .form-group, [class*="form-item"]') ? 0 : 500);
            if (dist < bestDist) { bestDist = dist; bestIdx = i; }
        });
        return bestDist < 200 ? bestIdx : null;
    }

    function getAccessibleName(el) {
        if (el.getAttribute('aria-label')) return el.getAttribute('aria-label').substring(0, 60);
        if (el.id) { const l = document.querySelector('label[for="'+CSS.escape(el.id)+'"]'); if (l) return l.textContent.trim().substring(0, 60); }
        const p = el.closest('label'); if (p) return p.textContent.trim().substring(0, 60);
        return el.name || el.id || '';
    }

    const errors = [];
    const seenErr = new Set();

    // aria-invalid fields
    document.querySelectorAll('[aria-invalid="true"]').forEach(el => {
        const errId = el.getAttribute('aria-errormessage') || el.getAttribute('aria-describedby');
        if (errId) {
            const errEl = document.getElementById(errId.split(/\s+/)[0]);
            if (errEl && isVisible(errEl)) {
                const text = errEl.textContent.trim().substring(0, 120);
                if (text && !seenErr.has(text)) {
                    seenErr.add(text);
                    const fi = allVisibleFields.indexOf(el);
                    errors.push({ fieldIndex: fi >= 0 ? fi : null, field: getAccessibleName(el), message: text });
                }
            }
        }
    });

    // error-class elements
    document.querySelectorAll('.error-message, .field-error, .invalid-feedback, [class*="error-msg"], [class*="validation-error"], .alert-danger, [role="alert"], .text-danger, .Mui-error, .ant-form-item-explain-error').forEach(el => {
        if (!isVisible(el)) return;
        const text = el.textContent.trim().substring(0, 120);
        if (text && text.length > 2 && !seenErr.has(text)) {
            seenErr.add(text);
            errors.push({ fieldIndex: nearestFieldIndex(el), field: '', message: text });
        }
    });

    // ── toasts ─────────────────────────────────────────────────────────
    const toasts = [];
    const seenToast = new Set();
    document.querySelectorAll('[class*="toast"], [class*="Toast"], [class*="snackbar"], [class*="Snackbar"], .Toastify__toast, [role="status"]').forEach(el => {
        if (!isVisible(el)) return;
        const text = el.textContent.trim().substring(0, 150);
        if (text && !seenToast.has(text)) {
            seenToast.add(text);
            const isError = /error|danger|fail/i.test(el.className);
            const isSuccess = /success|done|complete/i.test(el.className);
            toasts.push({ message: text, type: isError ? 'error' : isSuccess ? 'success' : 'info' });
        }
    });

    // ── field values & states ──────────────────────────────────────────
    const fieldValues = {};
    allVisibleFields.forEach((el, idx) => {
        const tag = el.tagName.toLowerCase();
        const type = (el.type || el.getAttribute('role') || tag).toLowerCase();
        const entry = {};

        if (tag === 'select') {
            entry.value = el.options[el.selectedIndex]?.text || el.value || '';
        } else if (type === 'checkbox' || type === 'radio' || el.getAttribute('role') === 'checkbox' || el.getAttribute('role') === 'radio') {
            entry.checked = el.checked || el.getAttribute('aria-checked') === 'true';
        } else if (el.getAttribute('contenteditable') === 'true') {
            entry.value = (el.textContent || '').substring(0, 100);
        } else if (type !== 'hidden') {
            entry.value = (el.value || '').substring(0, 100);
        }

        // dropdown expanded state
        const expanded = el.getAttribute('aria-expanded');
        if (expanded !== null) entry.expanded = expanded === 'true';

        // filled heuristic
        if ('checked' in entry) {
            entry.filled = !!entry.checked;
        } else if ('value' in entry) {
            entry.filled = entry.value.length > 0;
        }

        fieldValues[idx] = entry;
    });

    // ── iframes (payment only) ─────────────────────────────────────────
    const iframes = [];
    document.querySelectorAll('iframe').forEach((iframe, idx) => {
        if (!isVisible(iframe)) return;
        const src = iframe.src || '';
        if (/stripe|braintree|paypal|adyen|square/i.test(src)) {
            const rect = iframe.getBoundingClientRect();
            iframes.push({ index: idx, purpose: 'payment', x: Math.round(rect.left + rect.width/2), y: Math.round(rect.top + rect.height/2) });
        }
    });

    return {
        pageText: pageText,
        errors: errors,
        toasts: toasts,
        fieldValues: fieldValues,
        iframes: iframes,
        hasMoreBelow: (window.scrollY + window.innerHeight) < (document.documentElement.scrollHeight - 50),
        hasMoreAbove: window.scrollY > 50,
        scrollPosition: { x: window.scrollX, y: window.scrollY },
    };
}
