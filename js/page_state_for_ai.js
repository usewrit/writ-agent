() => {
    // Get visible text content (limited)
    const bodyText = document.body?.innerText?.substring(0, 3000) || '';

    // Get all interactive elements
    const interactiveElements = [];
    const selectors = 'a, button, input, select, textarea, [role="button"], [onclick]';

    document.querySelectorAll(selectors).forEach((el, idx) => {
        if (idx > 50) return; // Limit elements

        const rect = el.getBoundingClientRect();
        const isVisible = rect.width > 0 && rect.height > 0 &&
                         rect.top < window.innerHeight && rect.bottom > 0;

        if (!isVisible) return;

        const elem = {
            tag: el.tagName.toLowerCase(),
            type: el.type || null,
            id: el.id || null,
            name: el.name || null,
            className: el.className?.toString()?.substring(0, 100) || null,
            text: (el.innerText || el.value || el.placeholder || '')?.substring(0, 100),
            href: el.href || null,
            required: el.required || false,
            disabled: el.disabled || false,
            ariaLabel: el.getAttribute('aria-label'),
            placeholder: el.placeholder || null,
        };

        // Build a unique selector
        if (el.id) {
            elem.selector = '#' + el.id;
        } else if (el.name) {
            elem.selector = `${el.tagName.toLowerCase()}[name="${el.name}"]`;
        } else if (el.className && typeof el.className === 'string') {
            const firstClass = el.className.split(' ')[0];
            if (firstClass) elem.selector = '.' + firstClass;
        }

        // For inputs, get label if available
        if (el.id) {
            const label = document.querySelector(`label[for="${el.id}"]`);
            if (label) elem.label = label.innerText?.substring(0, 50);
        }

        // For select, get options
        if (el.tagName === 'SELECT') {
            elem.options = Array.from(el.options).slice(0, 10).map(o => ({
                value: o.value,
                text: o.text?.substring(0, 50)
            }));
        }

        interactiveElements.push(elem);
    });

    // Get forms
    const forms = Array.from(document.querySelectorAll('form')).slice(0, 5).map(form => ({
        id: form.id,
        action: form.action,
        method: form.method,
        fieldCount: form.querySelectorAll('input, select, textarea').length,
    }));

    // Check for common success/error indicators
    const indicators = {
        hasSuccessMessage: !!document.querySelector('.success, .alert-success, [class*="success"], [class*="confirmation"], [class*="thank"]'),
        hasErrorMessage: !!document.querySelector('.error, .alert-error, .alert-danger, [class*="error"], .invalid-feedback, [class*="invalid"]'),
        hasLoadingSpinner: !!document.querySelector('.loading, .spinner, [class*="loading"], [class*="spinner"]'),
        successMessages: [],
        errorMessages: [],
    };

    // Extract actual success/error message text
    document.querySelectorAll('.success, .alert-success, [class*="success"], [class*="confirmation"]').forEach(el => {
        const text = el.innerText?.trim();
        if (text && text.length < 200) indicators.successMessages.push(text.substring(0, 100));
    });
    document.querySelectorAll('.error, .alert-error, .alert-danger, [class*="error"], .invalid-feedback').forEach(el => {
        const text = el.innerText?.trim();
        if (text && text.length < 200 && text.length > 0) indicators.errorMessages.push(text.substring(0, 100));
    });

    // Look for success/confirmation text patterns in page
    const successPatterns = ['thank you', 'success', 'confirmed', 'complete', 'submitted', 'received', 'registration successful', 'order placed', 'account created', 'signed up'];
    const failurePatterns = ['error', 'failed', 'invalid', 'incorrect', 'wrong', 'try again', 'problem', 'issue'];
    const pageTextLower = bodyText.toLowerCase();
    indicators.successTextFound = successPatterns.some(pattern => pageTextLower.includes(pattern));
    indicators.failureTextFound = failurePatterns.some(pattern => pageTextLower.includes(pattern));

    // Detect checkboxes and their states
    const checkboxes = [];
    document.querySelectorAll('input[type="checkbox"]').forEach(cb => {
        let selector = '';
        if (cb.id) selector = '#' + cb.id;
        else if (cb.name) selector = `input[name="${cb.name}"]`;

        let label = '';
        if (cb.id) {
            const labelEl = document.querySelector(`label[for="${cb.id}"]`);
            if (labelEl) label = labelEl.innerText?.trim()?.substring(0, 50);
        }
        if (!label && cb.parentElement?.tagName === 'LABEL') {
            label = cb.parentElement.innerText?.trim()?.substring(0, 50);
        }

        checkboxes.push({
            selector: selector,
            name: cb.name || null,
            checked: cb.checked,
            required: cb.required,
            label: label || null,
            disabled: cb.disabled,
        });
    });
    indicators.checkboxes = checkboxes.slice(0, 10);

    // Detect multi-step form wizard indicators
    const wizardInfo = {
        hasProgressBar: !!document.querySelector('[class*="progress"], [class*="stepper"], [class*="wizard"], [role="progressbar"]'),
        hasStepIndicator: !!document.querySelector('[class*="step"], [class*="stage"], .breadcrumb'),
        currentStep: null,
        totalSteps: null,
    };

    // Try to extract step info from text (e.g., "Step 2 of 4")
    const stepMatch = bodyText.match(/step\s*(\d+)\s*(of|\/)\s*(\d+)/i);
    if (stepMatch) {
        wizardInfo.currentStep = parseInt(stepMatch[1]);
        wizardInfo.totalSteps = parseInt(stepMatch[3]);
    }

    // Find navigation buttons (Next, Continue, Submit, etc.)
    const navButtons = [];
    document.querySelectorAll('button, input[type="submit"], a[class*="btn"], [role="button"]').forEach(btn => {
        const text = (btn.innerText || btn.value || '').toLowerCase().trim();
        if (['next', 'continue', 'proceed', 'submit', 'send', 'finish', 'complete', 'save', 'register', 'sign up', 'create account'].some(t => text.includes(t))) {
            let selector = '';
            if (btn.id) selector = '#' + btn.id;
            else if (btn.name) selector = `[name="${btn.name}"]`;
            else if (btn.className) selector = '.' + btn.className.split(' ')[0];

            navButtons.push({
                text: text.substring(0, 30),
                tag: btn.tagName.toLowerCase(),
                selector: selector,
                type: btn.type || null,
            });
        }
    });

    return {
        title: document.title,
        url: window.location.href,
        bodyTextPreview: bodyText.substring(0, 1500),
        interactiveElements,
        forms,
        indicators,
        wizardInfo,
        navButtons: navButtons.slice(0, 5),
    };
}
