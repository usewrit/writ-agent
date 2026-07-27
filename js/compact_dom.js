() => {
    const fields = [];
    let fieldIndex = 0;

    document.querySelectorAll('input, select, textarea').forEach((el) => {
        // Skip hidden inputs entirely
        if (el.type === 'hidden') return;
        // Skip elements not visible in the viewport
        if (!el.offsetParent) return;
        // Skip elements with zero dimensions
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;

        const type = el.type || el.tagName.toLowerCase();
        const label = getLabel(el);
        const selector = getSelector(el);
        const required = el.required || el.getAttribute('aria-required') === 'true';

        fields.push(`${fieldIndex}. [${type}] "${label}" → ${selector}${required ? ' (required)' : ''}`);
        fieldIndex++;
    });

    const buttons = [];
    document.querySelectorAll('button, input[type="submit"], a[class*="btn"], [role="button"]').forEach(el => {
        if (!el.offsetParent) return;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const text = (el.textContent || el.value || '').trim().substring(0, 30);
        if (text) buttons.push(`"${text}" → ${getSelector(el)}`);
    });

    // Check for success/error/captcha
    // IMPORTANT: Only mark as success if there are NO form fields remaining
    // A page with form fields is NOT a success page, even if it has "success" in class names
    const hasFormFields = fieldIndex > 0;  // Any visible form fields means it's still a form page
    const successIndicators = !!(
        document.querySelector('.freebirdFormviewerViewResponseConfirmationMessage') || // Google Forms success
        document.querySelector('[class*="thank-you"], [class*="thankyou"]') ||
        ((document.body?.innerText || '').toLowerCase().match(/thank you for (your |)submitting|your (form|submission|response) (has been|was) (received|submitted|recorded)/) && !hasFormFields)
    );
    const hasSuccess = successIndicators && !hasFormFields;

    const hasError = !!(
        document.querySelector('[class*="error"]:not([class*="error-boundary"]), [class*="invalid"], .alert-danger, .invalid-feedback')
    );

    const hasCaptcha = !!(
        document.querySelector('[class*="captcha"], iframe[src*="recaptcha"], iframe[src*="hcaptcha"], .g-recaptcha, .h-captcha, .cf-turnstile')
    );

    // Try to detect step indicator
    const stepMatch = (document.body?.innerText || '').match(/step\s*(\d+)\s*(of|\/)\s*(\d+)/i);
    const stepInfo = stepMatch ? `Step ${stepMatch[1]} of ${stepMatch[3]}` : null;

    return {
        fields_text: fields.join('\n') || 'No form fields found',
        buttons_text: buttons.join('\n') || 'No buttons found',
        has_success: hasSuccess,
        has_error: hasError,
        has_captcha: hasCaptcha,
        step_info: stepInfo,
        field_count: fieldIndex
    };

    function getLabel(el) {
        // Try to find label text from various sources
        // 1. Try label[for]
        if (el.id) {
            const lbl = document.querySelector(`label[for="${el.id}"]`);
            if (lbl) return lbl.textContent.trim().substring(0, 40);
        }
        // 2. Try aria-labelledby
        if (el.getAttribute('aria-labelledby')) {
            const lblEl = document.getElementById(el.getAttribute('aria-labelledby'));
            if (lblEl) return lblEl.textContent.trim().substring(0, 40);
        }
        // 3. Try parent or ancestor with label-like text
        const parentLabel = el.closest('label');
        if (parentLabel) return parentLabel.textContent.trim().substring(0, 40);
        // 4. Look for nearby label-like elements (Google Forms pattern)
        const parent = el.closest('[role="listitem"], .freebirdFormviewerComponentsQuestionBaseRoot, [data-params]');
        if (parent) {
            const labelEl = parent.querySelector('[role="heading"], .freebirdFormviewerComponentsQuestionBaseTitle, [dir="auto"]');
            if (labelEl) return labelEl.textContent.trim().substring(0, 40);
        }
        // 5. Try aria-label
        if (el.getAttribute('aria-label')) return el.getAttribute('aria-label').substring(0, 40);
        // 6. Try placeholder
        if (el.placeholder) return el.placeholder.substring(0, 40);
        // 7. Use name or id
        return el.name || el.id || '(unlabeled)';
    }

    function getSelector(el) {
        // Priority order for selectors (most specific first)
        // 1. ID is most specific
        if (el.id) return '#' + CSS.escape(el.id);
        // 2. Name attribute for form fields
        if (el.name) return `[name="${el.name}"]`;
        // 3. Data-testid for testing-friendly sites
        if (el.dataset.testid) return `[data-testid="${el.dataset.testid}"]`;
        // 4. Aria-label for accessible elements
        if (el.getAttribute('aria-label')) return `[aria-label="${el.getAttribute('aria-label')}"]`;
        // 5. Type + placeholder combo for inputs
        if (el.placeholder && el.type) {
            return `input[type="${el.type}"][placeholder="${el.placeholder}"]`;
        }
        // 6. Generate a unique selector using visible siblings only
        const tag = el.tagName.toLowerCase();
        const parent = el.parentElement;
        if (parent) {
            // Only count visible siblings of the same type
            const visibleSiblings = Array.from(parent.querySelectorAll(':scope > ' + tag)).filter(sib => {
                if (sib.type === 'hidden') return false;
                const r = sib.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            });
            const idx = visibleSiblings.indexOf(el);
            if (idx >= 0 && visibleSiblings.length > 1) {
                return `${tag}:visible:nth(${idx})`;
            }
        }
        // 7. Last resort: use role if available
        if (el.getAttribute('role')) {
            return `[role="${el.getAttribute('role')}"]`;
        }
        return tag;
    }
}
