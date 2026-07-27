([fieldIndex]) => {
    const allFields = document.querySelectorAll('input, select, textarea, [role="checkbox"], [role="radio"], [role="option"], [role="textbox"], [role="listbox"], [role="combobox"], [aria-haspopup="listbox"], [contenteditable="true"], [data-params], [data-qa*="choice"], .ps-select-trigger, .ps-select-option');
    const visible = Array.from(allFields).filter(f => {
        if (f.tagName === 'INPUT' && f.type === 'hidden') return false;
        if (f.tagName === 'SELECT' && f.dataset.psAbstracted === 'true') return false;
        const rect = f.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return false;
        const style = window.getComputedStyle(f);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });
    if (fieldIndex < 0 || fieldIndex >= visible.length) return { error: 'field_index out of range', total_fields: visible.length };

    const el = visible[fieldIndex];
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    const tag = el.tagName.toLowerCase();
    const type = (el.type || el.getAttribute('role') || tag).toLowerCase();

    const result = {
        index: fieldIndex,
        tag: tag,
        type: type,
        name: el.name || null,
        id: el.id || null,
        visible: true,
        inViewport: rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth,
        coordinates: { x: Math.round(rect.left + rect.width / 2), y: Math.round(rect.top + rect.height / 2) },
        size: { width: Math.round(rect.width), height: Math.round(rect.height) },
    };

    // value
    if (tag === 'select') {
        result.value = el.options[el.selectedIndex]?.text || el.value || '';
        result.options = Array.from(el.options).slice(0, 20).map(o => ({ value: o.value, text: o.text, selected: o.selected }));
    } else if (type === 'checkbox' || type === 'radio' || el.getAttribute('role') === 'checkbox' || el.getAttribute('role') === 'radio') {
        result.checked = el.checked || el.getAttribute('aria-checked') === 'true';
        result.value = el.value || '';
    } else if (el.getAttribute('contenteditable') === 'true') {
        result.value = el.textContent?.substring(0, 500) || '';
    } else {
        result.value = (el.value || '').substring(0, 500);
    }

    // states
    result.disabled = el.disabled || el.getAttribute('aria-disabled') === 'true';
    result.required = el.required || el.getAttribute('aria-required') === 'true';
    result.readOnly = el.readOnly || false;
    result.focused = document.activeElement === el;
    result.placeholder = el.placeholder || null;

    // aria attributes
    result.ariaLabel = el.getAttribute('aria-label') || null;
    result.ariaExpanded = el.getAttribute('aria-expanded');
    result.ariaHasPopup = el.getAttribute('aria-haspopup') || null;

    // validation
    if (el.validity) {
        result.validity = {
            valid: el.validity.valid,
            valueMissing: el.validity.valueMissing,
            typeMismatch: el.validity.typeMismatch,
            patternMismatch: el.validity.patternMismatch,
            tooLong: el.validity.tooLong,
            tooShort: el.validity.tooShort,
            rangeUnderflow: el.validity.rangeUnderflow,
            rangeOverflow: el.validity.rangeOverflow,
        };
        result.validationMessage = el.validationMessage || '';
    }
    result.ariaInvalid = el.getAttribute('aria-invalid');

    // nearby error text
    const errId = el.getAttribute('aria-errormessage') || el.getAttribute('aria-describedby');
    if (errId) {
        const errEl = document.getElementById(errId.split(/\s+/)[0]);
        if (errEl) result.errorMessage = errEl.textContent.trim().substring(0, 150);
    }

    // label (accessible name)
    let label = el.getAttribute('aria-label') || el.placeholder || '';
    if (!label && el.id) {
        const lbl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (lbl) label = lbl.textContent.trim();
    }
    if (!label) {
        const parentLabel = el.closest('label');
        if (parentLabel) label = parentLabel.textContent.trim();
    }
    result.label = label.substring(0, 100);

    return result;
}
