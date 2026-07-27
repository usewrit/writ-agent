(criteria) => {
    // Find all clickable elements
    const clickables = Array.from(document.querySelectorAll(
        'button, a, input[type="submit"], input[type="button"], [role="button"], [onclick], [tabindex]'
    ));

    let bestScore = 0;
    let bestSelector = null;

    clickables.forEach((el, index) => {
        let score = 0;
        const tagName = el.tagName.toLowerCase();

        // Get text content
        const text = (el.textContent || el.value || '').trim().toLowerCase();

        // Get aria-label
        const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();

        // Text match (highest priority for buttons)
        if (criteria.text) {
            const criteriaText = criteria.text.toLowerCase();
            if (text === criteriaText) score += 60;
            else if (text.includes(criteriaText) || criteriaText.includes(text)) score += 40;
        }

        // Aria-label match
        if (criteria.aria_label && ariaLabel) {
            if (ariaLabel === criteria.aria_label.toLowerCase()) score += 50;
            else if (ariaLabel.includes(criteria.aria_label.toLowerCase())) score += 30;
        }

        // Role match
        const role = el.getAttribute('role');
        if (criteria.role && role === criteria.role) {
            score += 20;
        }

        // Tag name match
        if (criteria.tag_name && tagName === criteria.tag_name) {
            score += 10;
        }

        // Element ID match (very high priority)
        if (criteria.element_id && el.id === criteria.element_id) {
            score += 70;
        }

        // Element name match
        if (criteria.element_name && el.name === criteria.element_name) {
            score += 60;
        }

        // Data attribute matching (high priority - often stable)
        if (criteria.data_attributes && Object.keys(criteria.data_attributes).length > 0) {
            for (const [attrName, attrValue] of Object.entries(criteria.data_attributes)) {
                const elValue = el.getAttribute(attrName);
                if (elValue === attrValue) {
                    // data-testid, data-test, data-cy are very reliable
                    if (attrName.includes('test') || attrName.includes('cy')) {
                        score += 55;
                    } else {
                        score += 30;
                    }
                }
            }
        }

        // Stable attributes matching
        if (criteria.stable_attributes) {
            const sa = criteria.stable_attributes;
            if (sa.role && el.getAttribute('role') === sa.role) score += 15;
            if (sa.type && el.getAttribute('type') === sa.type) score += 10;
        }

        // Nearby text match
        if (criteria.nearby_text && criteria.nearby_text.length > 0) {
            const parent = el.parentElement;
            const parentText = parent ? parent.textContent.toLowerCase() : '';
            criteria.nearby_text.forEach(nearText => {
                if (parentText.includes(nearText.toLowerCase())) {
                    score += 15;
                }
            });
        }

        // Update best match
        if (score > bestScore) {
            bestScore = score;
            // Generate a reliable selector for this element
            if (el.id) {
                bestSelector = '#' + CSS.escape(el.id);
            } else if (el.name) {
                bestSelector = tagName + '[name="' + el.name + '"]';
            } else {
                // Try data attributes first
                for (const attr of ['data-testid', 'data-test', 'data-cy']) {
                    const val = el.getAttribute(attr);
                    if (val) {
                        bestSelector = `[${attr}="${val}"]`;
                        break;
                    }
                }
                if (!bestSelector) {
                    // Use nth-of-type as fallback
                    const siblings = Array.from(el.parentElement.querySelectorAll(':scope > ' + tagName));
                    const idx = siblings.indexOf(el) + 1;
                    const parentSelector = el.parentElement.id ? '#' + el.parentElement.id : el.parentElement.tagName.toLowerCase();
                    bestSelector = parentSelector + ' > ' + tagName + ':nth-of-type(' + idx + ')';
                }
            }
        }
    });

    // Return only if score is above threshold
    return bestScore >= 30 ? { selector: bestSelector, score: bestScore } : null;
}
