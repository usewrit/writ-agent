() => {
    function getLabel(el) {
        const role = el.getAttribute('role');
        const tag = el.tagName.toLowerCase();

        // For Typeform/choice buttons - clean up keyboard shortcut prefixes
        function cleanLabel(text) {
            if (!text) return text;
            // Remove Typeform keyboard shortcuts like "KeyA", "KeyB", "A ", "B " at start
            return text.replace(/^Key[A-Z]\s*/i, '').replace(/^[A-Z]\s+(?=[A-Z])/i, '').trim();
        }

        // For radio/checkbox options or choice buttons, get the OPTION label
        // This is what AI needs to decide which option to click
        if (role === 'radio' || role === 'checkbox' || role === 'option' ||
            (tag === 'button' && el.closest('[role="listbox"], [role="group"], [data-qa]'))) {
            // Try aria-label first
            if (el.getAttribute('aria-label')) return cleanLabel(el.getAttribute('aria-label'));
            if (el.getAttribute('data-value')) return cleanLabel(el.getAttribute('data-value'));
            // Try to find text content within the option
            const optionText = el.textContent?.trim();
            if (optionText && optionText.length < 100) return cleanLabel(optionText.substring(0, 50));
            // Try sibling/child span with the option text
            const span = el.querySelector('span') || el.nextElementSibling;
            if (span?.textContent) return cleanLabel(span.textContent.trim().substring(0, 50));
        }

        // Try aria-label first
        if (el.getAttribute('aria-label')) return el.getAttribute('aria-label');
        // Try placeholder
        if (el.placeholder) return el.placeholder;
        // Try aria-labelledby
        const labelledBy = el.getAttribute('aria-labelledby');
        if (labelledBy) {
            const labelEl = document.getElementById(labelledBy.split(' ')[0]);
            if (labelEl) return labelEl.textContent?.trim().substring(0, 50);
        }
        // Try associated label
        if (el.id) {
            const label = document.querySelector(`label[for="${el.id}"]`);
            if (label) return label.textContent?.trim().substring(0, 50);
        }
        // Try parent label
        const parentLabel = el.closest('label');
        if (parentLabel) {
            const text = parentLabel.textContent?.trim().substring(0, 50);
            if (text) return text;
        }
        // Try nearby text
        const prev = el.previousElementSibling;
        if (prev && prev.textContent) return prev.textContent.trim().substring(0, 30);

        // For wizard forms (Typeform, etc.) - look for question text in parent containers
        // The question text is often in a heading or paragraph above the input
        let parent = el.parentElement;
        for (let i = 0; i < 5 && parent; i++) {
            // Look for headings
            const heading = parent.querySelector('h1, h2, h3, h4, [role="heading"], [data-qa="question-title"]');
            if (heading) {
                const headingText = heading.textContent?.trim();
                if (headingText && headingText.length > 3 && headingText.length < 100) {
                    return headingText.substring(0, 50);
                }
            }
            // Look for question text in Typeform format
            const questionText = parent.querySelector('[class*="Question"], [class*="question"]');
            if (questionText && !questionText.contains(el)) {
                const qText = questionText.textContent?.trim();
                if (qText && qText.length > 3 && qText.length < 100) {
                    return qText.substring(0, 50);
                }
            }
            parent = parent.parentElement;
        }

        return el.name || el.id || 'unknown';
    }

    const fields = [];
    let fieldIndex = 0;
    const processedDatePickers = new Set();  // Track processed date picker containers

    // Get all form inputs (including Google Forms and Typeform specific elements)
    // Google Forms dropdowns use [role="listbox"], [role="combobox"], or [aria-haspopup="listbox"]
    // Typeform uses [role="option"] buttons and [data-qa] attributes for choices
    // Also include our abstracted select elements (.ps-select-trigger, .ps-select-option)
    document.querySelectorAll('input, select, textarea, [role="checkbox"], [role="radio"], [role="option"], [role="textbox"], [role="listbox"], [role="combobox"], [aria-haspopup="listbox"], [contenteditable="true"], [data-params], [data-qa*="choice"], .ps-select-trigger, .ps-select-option').forEach((el) => {
        // Skip hidden inputs
        if (el.tagName === 'INPUT' && el.type === 'hidden') return;
        // Skip native selects that have been abstracted (replaced by custom dropdown)
        if (el.tagName === 'SELECT' && el.dataset.psAbstracted === 'true') return;
        // Skip invisible elements
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return;

        const tag = el.tagName.toLowerCase();
        let type = el.type || el.getAttribute('role') || tag;
        let label = getLabel(el);
        const required = el.required || el.getAttribute('aria-required') === 'true';

        // Handle our abstracted select elements
        const isPsSelectTrigger = el.classList.contains('ps-select-trigger');
        const isPsSelectOption = el.classList.contains('ps-select-option');
        if (isPsSelectTrigger) {
            type = 'combobox';
            // Get label from data attribute or underlying select
            const selectName = el.dataset.selectName;
            if (selectName) {
                const originalSelect = document.querySelector(`select[name="${selectName}"]`);
                if (originalSelect) {
                    label = getLabel(originalSelect);
                }
            }
            if (!label || label === 'unknown') {
                label = el.textContent?.trim() || 'Select';
            }
        }
        if (isPsSelectOption) {
            type = 'option';
            label = el.textContent?.trim() || el.dataset.value || 'Option';
        }

        // Detect Google Forms date picker (has _year, _month, _day suffix in name)
        const elName = el.name || '';
        const isDatePart = elName.match(/^(.+)_(year|month|day)$/);
        if (isDatePart) {
            const datePickerBase = isDatePart[1];
            // Only process once per date picker - skip individual year/month/day inputs
            if (processedDatePickers.has(datePickerBase)) return;
            processedDatePickers.add(datePickerBase);

            // Find the container and get proper label
            // Try multiple container selectors for Google Forms
            let container = el.closest('[data-params]');
            if (!container) container = el.closest('.freebirdFormviewerComponentsQuestionDateRoot');
            if (!container) container = el.closest('.freebirdFormviewerComponentsQuestionDateInputsWrapper');
            if (!container) container = el.closest('[role="group"]');
            if (!container) container = el.parentElement?.parentElement?.parentElement; // Fallback

            // Get coordinates - use container if found, otherwise use the input itself
            const targetRect = container ? container.getBoundingClientRect() : rect;

            // Try to get label from various sources
            let dateLabel = label;
            if (container) {
                const ariaLabelledBy = container.getAttribute('aria-labelledby');
                if (ariaLabelledBy) {
                    const labelEl = document.getElementById(ariaLabelledBy.split(' ')[0]);
                    if (labelEl) dateLabel = labelEl.textContent?.trim().substring(0, 50) || dateLabel;
                }
                // Also try data-item-id for label lookup
                const dataItemId = container.getAttribute('data-item-id');
                if (dataItemId && !dateLabel) {
                    const headerEl = container.querySelector('[role="heading"]');
                    if (headerEl) dateLabel = headerEl.textContent?.trim().substring(0, 50) || dateLabel;
                }
            }
            // If still no label, try to find nearby heading
            if (!dateLabel || dateLabel === 'unknown') {
                const parent = el.closest('[data-params]') || el.parentElement?.parentElement?.parentElement?.parentElement;
                if (parent) {
                    const heading = parent.querySelector('[role="heading"]');
                    if (heading) dateLabel = heading.textContent?.trim().substring(0, 50) || dateLabel;
                }
            }

            console.log('[DatePicker Debug] Found date picker:', datePickerBase, 'label:', dateLabel, 'container:', container?.className);

            // Build selector for date picker
            let dateSelector = null;
            if (container?.id) {
                dateSelector = '#' + CSS.escape(container.id);
            } else if (datePickerBase) {
                dateSelector = `[name="${datePickerBase}_year"]`;
            }

            fields.push({
                index: fieldIndex,
                type: 'date',
                inputType: 'date',
                tag: 'input',
                label: dateLabel || 'Date',
                x: Math.round(targetRect.left + targetRect.width / 2),
                y: Math.round(targetRect.top + targetRect.height / 2),
                required: required,
                id: container?.id || null,
                name: datePickerBase,
                selector: dateSelector,
                recognition: {
                    tagName: 'input',
                    formIndex: 0,
                    fieldIndex: fieldIndex,
                    isGoogleFormsDate: true
                },
                isGoogleFormsDate: true,
                isEditable: true,
                dateInputs: {
                    year: datePickerBase + '_year',
                    month: datePickerBase + '_month',
                    day: datePickerBase + '_day'
                }
            });
            fieldIndex++;
            return; // Skip adding individual date inputs
        }

        // Also detect native date inputs
        if (type === 'date' || type === 'datetime-local') {
            // Native date picker - handle normally
        }

        // Calculate center coordinates
        const centerX = Math.round(rect.left + rect.width / 2);
        const centerY = Math.round(rect.top + rect.height / 2);

        // Build selector for the field
        let selector = null;
        if (el.id) {
            selector = '#' + CSS.escape(el.id);
        } else if (el.name) {
            selector = `[name="${el.name}"]`;
        } else if (el.getAttribute('aria-label')) {
            // Escape embedded double-quotes so a page-controlled value can't break the selector.
            selector = `[aria-label="${el.getAttribute('aria-label').replace(/"/g, '\\"')}"]`;
        } else if (el.getAttribute('aria-labelledby')) {
            selector = `[aria-labelledby="${el.getAttribute('aria-labelledby').replace(/"/g, '\\"')}"]`;
        } else if (el.placeholder) {
            selector = `${tag}[placeholder="${el.placeholder.replace(/"/g, '\\"')}"]`;
        } else {
            // Fallback to nth-of-type
            const allOfType = document.querySelectorAll(tag);
            const idx = Array.from(allOfType).indexOf(el);
            if (idx >= 0) {
                selector = `${tag}:nth-of-type(${idx + 1})`;
            }
        }

        // Build recognition data
        const recognition = {
            tagName: tag,
            formIndex: 0,
            fieldIndex: fieldIndex,
            ariaLabel: el.getAttribute('aria-label'),
            stableAttributes: {
                'aria-labelledby': el.getAttribute('aria-labelledby'),
                'aria-label': el.getAttribute('aria-label'),
                'role': el.getAttribute('role'),
                'required': required
            }
        };

        fields.push({
            index: fieldIndex,
            type: type,
            inputType: type,
            tag: tag,
            label: label,
            x: centerX,
            y: centerY,
            required: required,
            id: el.id || null,
            name: el.name || null,
            selector: selector,
            placeholder: el.placeholder || null,
            recognition: recognition,
            isCheckable: type === 'checkbox' || type === 'radio' || type === 'option' || el.getAttribute('role') === 'checkbox' || el.getAttribute('role') === 'radio' || el.getAttribute('role') === 'option' || el.hasAttribute('data-qa'),
            isEditable: ['text', 'email', 'password', 'tel', 'number', 'url', 'search', 'date', 'time', 'textarea', 'textbox'].includes(type)
        });
        fieldIndex++;
    });

    // Get buttons with selectors for reliable clicking
    const buttons = [];
    document.querySelectorAll('button, input[type="submit"], [role="button"], a[class*="btn"]').forEach((el, idx) => {
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return;

        const text = (el.textContent || el.value || '').trim().substring(0, 30);
        if (!text) return;

        const centerX = Math.round(rect.left + rect.width / 2);
        const centerY = Math.round(rect.top + rect.height / 2);

        // Build a selector for the button
        let selector = null;
        const tag = el.tagName.toLowerCase();
        const role = el.getAttribute('role');

        if (el.id) {
            selector = '#' + CSS.escape(el.id);
        } else if (tag === 'input' && el.type === 'submit') {
            if (el.value) {
                selector = `input[type="submit"][value="${el.value.replace(/"/g, '\\"')}"]`;
            } else {
                selector = 'input[type="submit"]';
            }
        } else if (el.getAttribute('data-testid')) {
            selector = `[data-testid="${el.getAttribute('data-testid')}"]`;
        } else if (tag === 'button') {
            // Try to build a unique selector
            const allButtons = document.querySelectorAll('button');
            const btnIndex = Array.from(allButtons).indexOf(el);
            if (btnIndex >= 0) {
                selector = `button:nth-of-type(${btnIndex + 1})`;
            }
        } else if (role === 'button') {
            // Google Forms and other sites use div[role="button"]
            // Try to find by aria-label or text content
            const ariaLabel = el.getAttribute('aria-label');
            if (ariaLabel) {
                selector = `[role="button"][aria-label="${ariaLabel.replace(/"/g, '\\"')}"]`;
            } else {
                // Use jsname attribute if present (Google-specific)
                const jsname = el.getAttribute('jsname');
                if (jsname) {
                    selector = `[role="button"][jsname="${jsname}"]`;
                } else {
                    // Fallback to nth-of-type
                    const allRoleButtons = document.querySelectorAll('[role="button"]');
                    const roleIdx = Array.from(allRoleButtons).indexOf(el);
                    if (roleIdx >= 0) {
                        selector = `[role="button"]:nth-of-type(${roleIdx + 1})`;
                    }
                }
            }
        }

        buttons.push({
            text: text,
            x: centerX,
            y: centerY,
            id: el.id || null,
            selector: selector,
            tag: tag
        });
    });

    // Check for success/captcha
    // IMPORTANT: Only mark as success if there are NO form fields (or very few)
    // A page with form fields is not a success page, even if it has "success" text
    const hasFormFields = fields.length > 0;
    const successIndicators = !!(
        document.querySelector('.freebirdFormviewerViewResponseConfirmationMessage') || // Google Forms success
        document.querySelector('[class*="thank-you"], [class*="thankyou"]') ||
        ((document.body?.innerText || '').toLowerCase().match(/thank you for (your |)submitting|your (form|submission|response) (has been|was) (received|submitted|recorded)/) && !hasFormFields)
    );
    // Only treat as success if success indicators found AND no form fields present
    const hasSuccess = successIndicators && !hasFormFields;

    // Detect captcha with details (type, position, selector)
    let captchaInfo = null;
    const captchaSelectors = [
        { sel: '.cf-turnstile', type: 'turnstile' },
        { sel: '#cf-turnstile', type: 'turnstile' },
        { sel: 'iframe[src*="challenges.cloudflare.com"]', type: 'turnstile' },
        { sel: '.g-recaptcha', type: 'recaptcha_v2' },
        { sel: 'iframe[src*="recaptcha"]', type: 'recaptcha_v2' },
        { sel: '.h-captcha', type: 'hcaptcha' },
        { sel: 'iframe[src*="hcaptcha"]', type: 'hcaptcha' },
        { sel: '[class*="captcha"]', type: 'unknown' }
    ];
    for (const {sel, type} of captchaSelectors) {
        const captchaEl = document.querySelector(sel);
        if (captchaEl && captchaEl.offsetParent !== null) {
            const rect = captchaEl.getBoundingClientRect();
            // For turnstile, find the checkbox inside
            let clickTarget = captchaEl;
            const iframe = captchaEl.querySelector('iframe') || (captchaEl.tagName === 'IFRAME' ? captchaEl : null);
            captchaInfo = {
                type: type,
                selector: sel,
                x: Math.round(rect.left + rect.width / 2),
                y: Math.round(rect.top + rect.height / 2),
                width: Math.round(rect.width),
                height: Math.round(rect.height),
                has_iframe: !!iframe
            };
            break;
        }
    }
    const hasCaptcha = captchaInfo !== null;

    // Build text summary for prompt
    const fieldsText = fields.map(f =>
        `  - ${f.type.toUpperCase()} "${f.label}" at (${f.x}, ${f.y})${f.required ? ' [required]' : ''}`
    ).join('\n');

    const buttonsText = buttons.map(b =>
        `  - "${b.text}" button at (${b.x}, ${b.y})`
    ).join('\n');

    return {
        fields: fields,
        buttons: buttons,
        fields_text: fieldsText || '  No fields found',
        buttons_text: buttonsText || '  No buttons found',
        has_success: hasSuccess,
        has_captcha: hasCaptcha,
        captcha_info: captchaInfo
    };
}
