(criteria) => {
    // Include both native inputs AND role-based elements (for Google Forms, etc.)
    const roleBasedSelector = '[role="radio"], [role="checkbox"], [role="listbox"], [role="combobox"], [role="textbox"]';
    const inputs = Array.from(document.querySelectorAll('input, textarea, select, ' + roleBasedSelector));
    const forms = Array.from(document.querySelectorAll('form'));

    let bestScore = 0;
    let bestSelector = null;
    let bestDebug = null;

    inputs.forEach((el, globalIndex) => {
        const matches = {};  // Track which factors matched
        const tagName = el.tagName.toLowerCase();
        const inputType = el.type || 'text';
        const role = el.getAttribute('role');  // For role-based elements (Google Forms)

        // Get element's form context
        const form = el.closest('form');
        const formIndex = form ? forms.indexOf(form) : -1;
        const formInputs = form ? Array.from(form.querySelectorAll('input, textarea, select, [role="radio"], [role="checkbox"]')) : inputs;
        const fieldIndex = formInputs.indexOf(el);

        // Get associated label - for role-based elements, use aria-label
        const labelEl = el.labels?.[0] || document.querySelector(`label[for="${el.id}"]`);
        let labelText = labelEl ? labelEl.textContent.trim().toLowerCase() : '';
        if (!labelText && role) {
            // For role-based elements, use aria-label as the label
            labelText = (el.getAttribute('aria-label') || '').toLowerCase();
        }

        // Get placeholder
        const placeholder = (el.placeholder || '').toLowerCase();

        // === CHECK EACH FACTOR ===

        // 1. Input type / role MUST match if specified (strict filter)
        const stableRole = criteria.stable_attributes?.role;
        if (stableRole) {
            // For role-based elements, check role matches
            if (role !== stableRole) {
                return; // Skip - role mismatch
            }
            matches.role = true;
        } else if (criteria.field_type && criteria.field_type !== 'text') {
            if (inputType !== criteria.field_type) {
                return; // Skip this element - type mismatch
            }
            matches.type = true;
        }

        // 2. Tag name matching - be flexible for role-based elements
        if (criteria.tag_name && criteria.tag_name !== 'input') {
            // If looking for a div with a role, match the role instead of tag
            if (criteria.tag_name === 'div' && role) {
                // It's a role-based element, tag match is ok
                matches.tag = true;
            } else if (tagName !== criteria.tag_name) {
                return; // Skip - tag mismatch
            } else {
                matches.tag = true;
            }
        }

        // 3. Label match (exact preferred)
        if (criteria.label && labelText) {
            const criteriaLabel = criteria.label.toLowerCase().trim();
            if (labelText === criteriaLabel) {
                matches.label = 'exact';
            } else if (labelText.includes(criteriaLabel) || criteriaLabel.includes(labelText)) {
                matches.label = 'partial';
            }
        }

        // 4. Placeholder match (exact preferred)
        if (criteria.placeholder && placeholder) {
            const criteriaPlaceholder = criteria.placeholder.toLowerCase().trim();
            if (placeholder === criteriaPlaceholder) {
                matches.placeholder = 'exact';
            } else if (placeholder.includes(criteriaPlaceholder) || criteriaPlaceholder.includes(placeholder)) {
                matches.placeholder = 'partial';
            }
        }

        // 5. Field index match (important for forms with similar fields)
        if (criteria.field_index >= 0) {
            if (fieldIndex === criteria.field_index) {
                matches.fieldIndex = 'exact';
            } else if (Math.abs(fieldIndex - criteria.field_index) <= 1) {
                matches.fieldIndex = 'close'; // Allow 1 off for dynamic forms
            }
        }

        // 6. Form index match
        if (criteria.form_index >= 0 && formIndex === criteria.form_index) {
            matches.formIndex = true;
        }

        // 7. Autocomplete match (very reliable)
        if (criteria.autocomplete && el.autocomplete === criteria.autocomplete) {
            matches.autocomplete = true;
        }

        // 8. Aria-label match
        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
        if (criteria.aria_label && ariaLabel) {
            if (ariaLabel === criteria.aria_label.toLowerCase()) {
                matches.ariaLabel = 'exact';
            } else if (ariaLabel.includes(criteria.aria_label.toLowerCase())) {
                matches.ariaLabel = 'partial';
            }
        }

        // 9. Data attributes (very reliable)
        if (criteria.data_attributes && Object.keys(criteria.data_attributes).length > 0) {
            let dataMatches = 0;
            for (const [attrName, attrValue] of Object.entries(criteria.data_attributes)) {
                if (el.getAttribute(attrName) === attrValue) {
                    dataMatches++;
                }
            }
            if (dataMatches > 0) {
                matches.dataAttrs = dataMatches;
            }
        }

        // 10. Field category semantic match
        if (criteria.field_category) {
            const cat = criteria.field_category.toLowerCase();
            const allText = (labelText + ' ' + placeholder + ' ' + ariaLabel + ' ' + (el.name || '')).toLowerCase();

            const categoryMatches = {
                'email': () => allText.includes('email') || inputType === 'email',
                'password': () => allText.includes('password') || inputType === 'password',
                'phone': () => allText.includes('phone') || allText.includes('tel') || inputType === 'tel',
                'date': () => allText.includes('date') || ['date', 'datetime-local', 'month', 'week'].includes(inputType),
                'time': () => allText.includes('time') || inputType === 'time',
                'number': () => allText.includes('number') || inputType === 'number',
                'url': () => allText.includes('url') || allText.includes('website') || inputType === 'url',
            };

            if (categoryMatches[cat] && categoryMatches[cat]()) {
                matches.category = true;
            }
        }

        // 11. Stable attributes matching (aria-labelledby, aria-describedby - very reliable for Google Forms)
        if (criteria.stable_attributes) {
            const sa = criteria.stable_attributes;
            const elAriaLabelledBy = el.getAttribute('aria-labelledby');
            const elAriaDescribedBy = el.getAttribute('aria-describedby');

            if (sa['aria-labelledby'] && elAriaLabelledBy === sa['aria-labelledby']) {
                matches.ariaLabelledBy = true;  // Exact match - very high confidence
            }
            if (sa['aria-describedby'] && elAriaDescribedBy === sa['aria-describedby']) {
                matches.ariaDescribedBy = true;
            }
        }

        // === CALCULATE SCORE based on COMBINATION of matches ===
        let score = 0;
        const matchCount = Object.keys(matches).length;

        // Base scores for individual matches
        if (matches.label === 'exact') score += 40;
        else if (matches.label === 'partial') score += 20;

        if (matches.placeholder === 'exact') score += 40;
        else if (matches.placeholder === 'partial') score += 20;

        if (matches.fieldIndex === 'exact') score += 30;
        else if (matches.fieldIndex === 'close') score += 15;

        if (matches.formIndex) score += 15;
        if (matches.autocomplete) score += 35;
        if (matches.type) score += 20;
        if (matches.role) score += 30;  // Role match is strong (for Google Forms elements)
        if (matches.tag) score += 5;
        if (matches.category) score += 20;

        if (matches.ariaLabel === 'exact') score += 50;  // Increased - aria-label is very reliable for role-based elements
        else if (matches.ariaLabel === 'partial') score += 25;

        // aria-labelledby/describedby are VERY reliable (unique per field in Google Forms)
        if (matches.ariaLabelledBy) score += 80;  // Almost guaranteed match
        if (matches.ariaDescribedBy) score += 60;

        if (matches.dataAttrs) score += matches.dataAttrs * 40;  // Data attrs are very reliable

        // BONUS: Multiple factors matching together is more reliable
        if (matchCount >= 3) score += 30;  // 3+ factors = strong match
        if (matchCount >= 4) score += 20;  // 4+ factors = very strong
        if (matchCount >= 5) score += 20;  // 5+ factors = excellent

        // BONUS: Label/placeholder + index is very reliable combination
        if ((matches.label || matches.placeholder) && matches.fieldIndex) {
            score += 25;
        }

        // BONUS: Type + index + (label OR placeholder) = almost certain
        if (matches.type && matches.fieldIndex && (matches.label || matches.placeholder)) {
            score += 30;
        }

        // Update best match
        if (score > bestScore) {
            bestScore = score;
            bestDebug = { matches, fieldIndex, inputType, labelText: labelText.substring(0, 30), placeholder: placeholder.substring(0, 30) };

            // Generate a UNIQUE selector - check that it matches only 1 element
            bestSelector = null;

            const trySelector = (sel) => {
                try {
                    const matches = document.querySelectorAll(sel);
                    return matches.length === 1 ? sel : null;
                } catch(e) { return null; }
            };

            // 1. First try ID (always unique)
            if (el.id) {
                bestSelector = trySelector('#' + CSS.escape(el.id));
            }

            // 2. Try role + aria-label (unique for Google Forms role-based elements)
            if (!bestSelector && role) {
                const ariaLabel = el.getAttribute('aria-label');
                if (ariaLabel) {
                    bestSelector = trySelector('[role="' + role + '"][aria-label="' + ariaLabel + '"]');
                }
            }

            // 3. Try aria-labelledby (unique in forms like Google Forms)
            if (!bestSelector) {
                const ariaLabelledBy = el.getAttribute('aria-labelledby');
                if (ariaLabelledBy) {
                    // For role-based elements, include the role in selector
                    const prefix = role ? '[role="' + role + '"]' : tagName;
                    bestSelector = trySelector(prefix + '[aria-labelledby="' + ariaLabelledBy + '"]');
                }
            }

            // 4. Try aria-describedby (also unique in Google Forms)
            if (!bestSelector) {
                const ariaDescribedBy = el.getAttribute('aria-describedby');
                if (ariaDescribedBy) {
                    const prefix = role ? '[role="' + role + '"]' : tagName;
                    bestSelector = trySelector(prefix + '[aria-describedby="' + ariaDescribedBy + '"]');
                }
            }

            // 5. Try name if not dynamic
            if (!bestSelector && el.name && !/^f_[a-z0-9]{6,}$/i.test(el.name)) {
                bestSelector = trySelector(tagName + '[name="' + el.name + '"]');
            }

            // 5. Try data-testid or data-test (usually unique)
            if (!bestSelector) {
                for (const attr of ['data-testid', 'data-test', 'data-cy', 'data-id']) {
                    const val = el.getAttribute(attr);
                    if (val) {
                        bestSelector = trySelector('[' + attr + '="' + val + '"]');
                        if (bestSelector) break;
                    }
                }
            }

            // 6. Use form context + fieldIndex (reliable for consistent forms)
            if (!bestSelector && formIndex >= 0) {
                const formSelector = form.id ? '#' + CSS.escape(form.id) : 'form:nth-of-type(' + (formIndex + 1) + ')';
                bestSelector = trySelector(formSelector + ' ' + tagName + ':nth-of-type(' + (fieldIndex + 1) + ')');
            }

            // 7. Last resort - parent context + nth-of-type
            if (!bestSelector) {
                const parent = el.parentElement;
                if (parent) {
                    const siblings = Array.from(parent.querySelectorAll(':scope > ' + tagName));
                    const idx = siblings.indexOf(el) + 1;
                    const parentSelector = parent.id ? '#' + CSS.escape(parent.id) : parent.tagName.toLowerCase();
                    bestSelector = parentSelector + ' > ' + tagName + ':nth-of-type(' + idx + ')';
                }
            }
        }
    });

    // Require minimum score of 40 (data attr alone = 40+5=45, needs tag match too)
    return bestScore >= 40 ? { selector: bestSelector, score: bestScore, debug: bestDebug, totalInputs: inputs.length } : { selector: null, score: bestScore, debug: bestDebug, totalInputs: inputs.length };
}
