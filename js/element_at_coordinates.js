// Called as page.evaluate with (x, y) passed in.
// Usage: page.evaluate(thisScript, { x, y })
//
// SECURITY: the selectors built below are derived from PAGE-CONTROLLED attribute
// values (aria-label, aria-labelledby, link/button text). They are embedded in
// double-quoted selector strings, so BOTH `"` and `\` must be escaped — escaping
// only `"` (the previous behaviour) let a value ending in a backslash swallow the
// escape and close the string, producing a selector whose tail is attacker-chosen.
// The Rust side additionally never interpolates a selector into JS source (it passes
// it as an evaluate argument — see recorder::helpers::eval_selector_probe), so this
// is defence in depth rather than the only barrier.
(({x, y}) => {
    let el = document.elementFromPoint(x, y);
    if (!el) return null;

    // Helper to check if element is visible and interactive
    function isVisibleInput(inp) {
        if (!inp) return false;
        // Skip hidden inputs
        if (inp.tagName === 'INPUT' && inp.type === 'hidden') return false;
        // Check visibility
        const rect = inp.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return false;
        const style = window.getComputedStyle(inp);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        return true;
    }

    // All form input element types we want to find (excluding hidden)
    const inputSelector = 'input:not([type="hidden"]), textarea, select, button, [contenteditable="true"], [role="textbox"], [role="combobox"], [role="listbox"], [role="spinbutton"], [role="slider"], [role="checkbox"], [role="radio"], [role="switch"]';

    // Interactive element tags
    const interactiveTags = ['input', 'textarea', 'select', 'button', 'a'];
    const tag = el.tagName.toLowerCase();

    // Skip if we landed on a hidden input - look for visible one nearby
    if (tag === 'input' && el.type === 'hidden') {
        const parent = el.parentElement;
        if (parent) {
            const visibleInput = parent.querySelector('input:not([type="hidden"]), textarea');
            if (visibleInput && isVisibleInput(visibleInput)) {
                el = visibleInput;
            }
        }
    }

    // Check if element has interactive role
    const role = el.getAttribute('role');
    const isInteractiveRole = ['textbox', 'combobox', 'listbox', 'spinbutton', 'slider', 'checkbox', 'radio', 'switch', 'button', 'link'].includes(role);
    const isContentEditable = el.getAttribute('contenteditable') === 'true';

    // If not already an interactive element, look for one inside or nearby
    if (!interactiveTags.includes(el.tagName.toLowerCase()) && !isInteractiveRole && !isContentEditable) {
        // First, check if there's a VISIBLE input element inside this element
        const innerInputs = el.querySelectorAll(inputSelector);
        let foundInput = null;
        for (const inp of innerInputs) {
            if (isVisibleInput(inp)) {
                foundInput = inp;
                break;
            }
        }
        if (foundInput) {
            el = foundInput;
        } else {
            // Check parent elements for a visible input (clicked on label or wrapper)
            let parent = el.parentElement;
            let depth = 0;
            while (parent && depth < 5) {
                const parentInputs = parent.querySelectorAll(inputSelector);
                for (const inp of parentInputs) {
                    if (isVisibleInput(inp)) {
                        foundInput = inp;
                        break;
                    }
                }
                if (foundInput) {
                    el = foundInput;
                    break;
                }
                parent = parent.parentElement;
                depth++;
            }
        }
    }

    // Refresh tag after potential element change
    const finalTag = el.tagName.toLowerCase();
    const finalRole = el.getAttribute('role');

    // ========================================
    // BUILD SELECTOR (same logic as manual recording)
    // Priority: ID > name > aria-labelledby > type-specific > role+aria > nth-of-type
    // ========================================
    let selector = null;

    // Helper to check selector uniqueness
    const isUnique = (sel) => {
        try { return document.querySelectorAll(sel).length === 1; } catch(e) { return false; }
    };

    // 1. ID (best, if unique)
    if (el.id && isUnique('#' + CSS.escape(el.id))) {
        selector = '#' + CSS.escape(el.id);
    }

    // 2. Name attribute (very reliable for form inputs)
    if (!selector && el.name && !/^(f_|entry\.)/.test(el.name)) {
        // Avoid dynamic names (f_xxx, entry.xxx are Google Forms dynamic IDs)
        const nameSelector = finalTag + '[name="' + el.name + '"]';
        if (isUnique(nameSelector)) {
            selector = nameSelector;
        }
    }

    // 3. For inputs: Try type-specific selectors first
    if (!selector && finalTag === 'input') {
        const inputType = el.type || 'text';

        // Unique type selectors
        if (inputType === 'email' && isUnique('input[type="email"]')) {
            selector = 'input[type="email"]';
        } else if (inputType === 'tel' && isUnique('input[type="tel"]')) {
            selector = 'input[type="tel"]';
        } else if (inputType === 'password' && isUnique('input[type="password"]')) {
            selector = 'input[type="password"]';
        } else if (inputType === 'url' && isUnique('input[type="url"]')) {
            selector = 'input[type="url"]';
        } else if (inputType === 'search' && isUnique('input[type="search"]')) {
            selector = 'input[type="search"]';
        } else if (inputType === 'date' && isUnique('input[type="date"]')) {
            selector = 'input[type="date"]';
        } else if (inputType === 'number' && isUnique('input[type="number"]')) {
            selector = 'input[type="number"]';
        }

        // For checkbox/radio, try value attribute
        if (!selector && (inputType === 'checkbox' || inputType === 'radio')) {
            const value = el.value;
            if (value) {
                const valueSelector = 'input[type="' + inputType + '"][value="' + value + '"]';
                if (isUnique(valueSelector)) {
                    selector = valueSelector;
                }
            }
            // Try name + value combination
            if (!selector && el.name && value) {
                const nameValueSelector = 'input[name="' + el.name + '"][value="' + value + '"]';
                if (isUnique(nameValueSelector)) {
                    selector = nameValueSelector;
                }
            }
        }

        // Try aria-labelledby (Google Forms uses this)
        if (!selector) {
            const ariaLabelledby = el.getAttribute('aria-labelledby');
            if (ariaLabelledby && isUnique('input[aria-labelledby="' + ariaLabelledby + '"]')) {
                selector = 'input[aria-labelledby="' + ariaLabelledby + '"]';
            }
        }

        // Fallback: use Playwright's >> nth= operator (0-indexed)
        if (!selector) {
            const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"])')).filter(inp => {
                const rect = inp.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) return false;
                const style = window.getComputedStyle(inp);
                return style.display !== 'none' && style.visibility !== 'hidden';
            });
            const index = allInputs.indexOf(el);
            if (index >= 0) {
                selector = 'input:visible >> nth=' + index;
            }
        }
    }

    // 4. For textarea
    if (!selector && finalTag === 'textarea') {
        // Try aria-labelledby first
        const ariaLabelledby = el.getAttribute('aria-labelledby');
        if (ariaLabelledby && isUnique('textarea[aria-labelledby="' + ariaLabelledby + '"]')) {
            selector = 'textarea[aria-labelledby="' + ariaLabelledby + '"]';
        }
        // Fallback: use Playwright's >> nth= operator (0-indexed)
        if (!selector) {
            const allTextareas = Array.from(document.querySelectorAll('textarea')).filter(t => {
                const rect = t.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            });
            const index = allTextareas.indexOf(el);
            if (index >= 0) {
                selector = 'textarea:visible >> nth=' + index;
            }
        }
    }

    // 5. For select elements
    if (!selector && finalTag === 'select') {
        // Try aria-labelledby
        const ariaLabelledby = el.getAttribute('aria-labelledby');
        if (ariaLabelledby && isUnique('select[aria-labelledby="' + ariaLabelledby + '"]')) {
            selector = 'select[aria-labelledby="' + ariaLabelledby + '"]';
        }
        // Fallback: nth-of-type
        if (!selector) {
            const allSelects = Array.from(document.querySelectorAll('select'));
            const index = allSelects.indexOf(el) + 1;
            if (index > 0) {
                selector = 'select:nth-of-type(' + index + ')';
            }
        }
    }

    // 6. For buttons
    if (!selector && (finalTag === 'button' || (finalTag === 'input' && ['submit', 'button', 'reset'].includes(el.type)))) {
        // Try text content for buttons
        const buttonText = el.textContent?.trim() || el.value;
        if (buttonText && buttonText.length < 50) {
            if (finalTag === 'button') {
                const textSelector = 'button:has-text("' + buttonText.replace(/["\\]/g, '\\$&') + '")';
                // Playwright supports :has-text, but check with standard selector for uniqueness
                const altSelector = 'button';
                const allButtons = Array.from(document.querySelectorAll(altSelector)).filter(b => b.textContent?.trim() === buttonText);
                if (allButtons.length === 1) {
                    selector = textSelector;
                }
            } else {
                // input[type="submit"]
                const valueSelector = 'input[type="' + el.type + '"][value="' + buttonText + '"]';
                if (isUnique(valueSelector)) {
                    selector = valueSelector;
                }
            }
        }
        // Fallback for buttons
        if (!selector && finalTag === 'button') {
            const allButtons = Array.from(document.querySelectorAll('button'));
            const index = allButtons.indexOf(el) + 1;
            if (index > 0) {
                selector = 'button:nth-of-type(' + index + ')';
            }
        }
    }

    // 7. data-testid (very reliable)
    if (!selector && el.getAttribute('data-testid')) {
        selector = '[data-testid="' + el.getAttribute('data-testid') + '"]';
    }

    // 8. For role-based elements (Google Forms), use role + aria-label
    if (!selector && finalRole) {
        const ariaLabel = el.getAttribute('aria-label');
        if (ariaLabel) {
            // Escape embedded double-quotes so a page-controlled value can't break the selector.
            const roleSelector = '[role="' + finalRole + '"][aria-label="' + ariaLabel.replace(/["\\]/g, '\\$&') + '"]';
            if (isUnique(roleSelector)) {
                selector = roleSelector;
            }
        }
        // Try role + aria-labelledby
        if (!selector) {
            const ariaLabelledby = el.getAttribute('aria-labelledby');
            if (ariaLabelledby) {
                const roleSelector = '[role="' + finalRole + '"][aria-labelledby="' + ariaLabelledby.replace(/["\\]/g, '\\$&') + '"]';
                if (isUnique(roleSelector)) {
                    selector = roleSelector;
                }
            }
        }
        // Fallback: role + nth-of-type (only if few elements)
        if (!selector) {
            const allWithRole = document.querySelectorAll('[role="' + finalRole + '"]');
            if (allWithRole.length <= 10) {
                const idx = Array.from(allWithRole).indexOf(el) + 1;
                if (idx > 0) {
                    selector = '[role="' + finalRole + '"]:nth-of-type(' + idx + ')';
                }
            }
        }
    }

    // 9. aria-label (if unique)
    if (!selector) {
        const ariaLabel = el.getAttribute('aria-label');
        const ariaLabelSel = '[aria-label="' + (ariaLabel || '').replace(/["\\]/g, '\\$&') + '"]';
        if (ariaLabel && isUnique(ariaLabelSel)) {
            selector = ariaLabelSel;
        }
    }

    // 10. aria-labelledby (very reliable for Google Forms)
    if (!selector) {
        const ariaLabelledby = el.getAttribute('aria-labelledby');
        if (ariaLabelledby) {
            const tagSelector = finalTag + '[aria-labelledby="' + ariaLabelledby.replace(/["\\]/g, '\\$&') + '"]';
            if (isUnique(tagSelector)) {
                selector = tagSelector;
            }
        }
    }

    // 11. For anchor tags (links)
    if (!selector && finalTag === 'a') {
        const href = el.getAttribute('href');
        if (href && href !== '#' && !href.startsWith('javascript:')) {
            const hrefSelector = 'a[href="' + href + '"]';
            if (isUnique(hrefSelector)) {
                selector = hrefSelector;
            }
        }
        // Try text content
        if (!selector) {
            const linkText = el.textContent?.trim();
            if (linkText && linkText.length < 50) {
                const allLinks = Array.from(document.querySelectorAll('a')).filter(a => a.textContent?.trim() === linkText);
                if (allLinks.length === 1) {
                    selector = 'a:has-text("' + linkText.replace(/["\\]/g, '\\$&') + '")';
                }
            }
        }
    }

    // 12. For non-generic elements, try tag + nth-of-type
    // IMPORTANT: Only for meaningful tags, NOT div/span which are too generic
    if (!selector && !['div', 'span', 'section', 'article', 'main', 'header', 'footer', 'nav', 'aside', 'p', 'li', 'ul', 'ol'].includes(finalTag)) {
        const parent = el.parentElement;
        if (parent) {
            const siblings = Array.from(parent.children).filter(c => c.tagName === el.tagName);
            const index = siblings.indexOf(el) + 1;
            selector = finalTag + ':nth-of-type(' + index + ')';
        }
    }

    // 13. LAST RESORT: Set to N/A (rely on coordinates + recognition)
    if (!selector) {
        selector = 'N/A';
    }

    // ========================================
    // BUILD RECOGNITION DATA (same as manual recording)
    // ========================================
    // Find form context
    const form = el.closest('form');
    const allForms = Array.from(document.querySelectorAll('form'));
    const formIndex = form ? allForms.indexOf(form) : 0;

    // Get field index within form/page
    // Include all interactive elements, not just input/textarea/select
    const allInteractive = (form || document).querySelectorAll('input:not([type="hidden"]), textarea, select, [role="checkbox"], [role="radio"], [role="textbox"], [role="combobox"]');
    let fieldIndex = Array.from(allInteractive).indexOf(el);
    // If not found directly, try to find the closest ancestor that matches
    if (fieldIndex === -1) {
        for (let i = 0; i < allInteractive.length; i++) {
            if (allInteractive[i].contains(el) || el.contains(allInteractive[i])) {
                fieldIndex = i;
                break;
            }
        }
    }

    // Build parent path (CSS classes breadcrumb) - go deeper for better matching
    const parentPath = [];
    let p = el.parentElement;
    let depth = 0;
    while (p && depth < 5) {
        if (p.className && typeof p.className === 'string') {
            const classes = p.className.split(' ').filter(c => c && c.length > 2 && !c.includes(':')).slice(0, 2);
            if (classes.length > 0) {
                parentPath.push(classes.join('.'));
            }
        }
        p = p.parentElement;
        depth++;
    }

    // Stable attributes for recognition fallback
    const stableAttributes = {
        'aria-labelledby': el.getAttribute('aria-labelledby'),
        'aria-describedby': el.getAttribute('aria-describedby'),
        'aria-label': el.getAttribute('aria-label'),
        'role': el.getAttribute('role'),
        'required': el.required || false,
        'readonly': el.readOnly || false,
        'pattern': el.pattern || null,
        'inputmode': el.inputMode || null,
        'maxlength': el.maxLength > 0 ? el.maxLength : null,
        'minlength': el.minLength > 0 ? el.minLength : null,
    };

    // Data attributes
    const dataAttributes = {};
    for (const attr of el.attributes) {
        if (attr.name.startsWith('data-')) {
            dataAttributes[attr.name] = attr.value;
        }
    }

    // Build recognition object (same structure as manual recording)
    const recognition = {
        tagName: finalTag,
        formIndex: formIndex,
        fieldIndex: fieldIndex,
        parentPath: parentPath,
        ariaLabel: el.getAttribute('aria-label'),
        nearbyText: [],
        stableAttributes: stableAttributes,
        dataAttributes: dataAttributes,
    };

    // Detect element type and capabilities
    let inputType = null;
    let isCheckable = false;
    let isEditable = false;
    let isSelectable = false;

    if (finalTag === 'input') {
        inputType = el.type || 'text';
        isCheckable = ['checkbox', 'radio'].includes(inputType);
        isEditable = ['text', 'email', 'password', 'tel', 'number', 'url', 'search', 'date', 'time', 'datetime-local', 'month', 'week'].includes(inputType);
    } else if (finalTag === 'textarea') {
        inputType = 'textarea';
        isEditable = true;
    } else if (finalTag === 'select') {
        inputType = 'select';
        isSelectable = true;
    } else if (el.getAttribute('contenteditable') === 'true') {
        inputType = 'contenteditable';
        isEditable = true;
    } else if (finalRole === 'textbox') {
        inputType = 'textbox';
        isEditable = true;
    } else if (finalRole === 'combobox') {
        inputType = 'combobox';
        isSelectable = true;
    } else if (['checkbox', 'radio', 'switch'].includes(finalRole)) {
        inputType = finalRole;
        isCheckable = true;
    } else if (finalRole === 'slider' || finalRole === 'spinbutton') {
        inputType = finalRole;
        isEditable = true;
    }

    // Check if clicking on a label for a checkbox/radio
    const labelFor = el.closest('label');
    let associatedInput = null;
    if (labelFor) {
        const inputEl = labelFor.querySelector('input[type="checkbox"], input[type="radio"]');
        if (inputEl) {
            associatedInput = {
                type: inputEl.type,
                name: inputEl.name,
                value: inputEl.value,
                checked: inputEl.checked,
                selector: inputEl.id ? '#' + CSS.escape(inputEl.id) :
                          inputEl.name ? 'input[name="' + inputEl.name + '"]' : null
            };
            isCheckable = true;
            if (!inputType) inputType = inputEl.type;
        }
    }

    // Get label text from various sources
    let labelText = null;
    if (el.getAttribute('aria-label')) {
        labelText = el.getAttribute('aria-label');
    } else if (el.placeholder) {
        labelText = el.placeholder;
    } else if (el.getAttribute('aria-labelledby')) {
        const labelEl = document.getElementById(el.getAttribute('aria-labelledby'));
        if (labelEl) labelText = labelEl.textContent?.trim();
    } else if (el.id) {
        const labelEl = document.querySelector('label[for="' + el.id + '"]');
        if (labelEl) labelText = labelEl.textContent?.trim();
    }

    return {
        tag: finalTag,
        text: el.textContent?.trim().substring(0, 100) || '',
        selector: selector,
        inputType: inputType,
        isCheckable: isCheckable,
        isEditable: isEditable,
        isSelectable: isSelectable,
        associatedInput: associatedInput,
        ariaLabel: el.getAttribute('aria-label'),
        placeholder: el.placeholder || null,
        name: el.name || null,
        id: el.id || null,
        type: el.type || null,
        // Same resilience data as manual recording
        recognition: recognition,
        fieldCategory: inputType === 'email' ? 'email' :
                      inputType === 'tel' ? 'phone' :
                      inputType === 'password' ? 'password' : 'text',
        role: finalRole,
        label: labelText
    };
})
