() => {
    const result = {
        status: 'unknown',
        message: '',
        selector: null,
        success_indicators: [],
        error_indicators: []
    };

    // Success patterns (classes, IDs, text patterns)
    const successPatterns = {
        classes: ['success', 'thank', 'confirm', 'complete', 'submitted', 'done', 'checked', 'valid'],
        ids: ['success', 'thank-you', 'confirmation', 'complete'],
        text: [
            /thank\s*you/i,
            /success(ful(ly)?)?/i,
            /confirm(ed|ation)?/i,
            /submit(ted)?/i,
            /complet(ed|e)/i,
            /votre\s*(réponse|demande|inscription)\s*(a\s*été\s*)?(enregistrée|reçue|confirmée)/i,  // French
            /merci/i,  // French thank you
            /we('ve| have)\s*received/i,
            /your (response|submission|form) (has been|was)/i,
            /application\s*(received|submitted)/i
        ]
    };

    // Error patterns
    const errorPatterns = {
        classes: ['error', 'invalid', 'fail', 'alert-danger', 'validation-error', 'form-error', 'field-error'],
        ids: ['error', 'errors', 'validation-errors'],
        text: [
            /error/i,
            /invalid/i,
            /required/i,
            /please\s*(fill|complete|enter|correct)/i,
            /failed/i,
            /must\s*be/i,
            /cannot\s*be\s*(empty|blank)/i,
            /champ\s*(obligatoire|requis)/i,  // French required field
            /veuillez/i  // French please
        ]
    };

    // Check for success elements
    const successSelectors = [
        '[class*="success"]',
        '[class*="thank"]',
        '[class*="confirm"]',
        '[class*="complete"]',
        '[class*="submitted"]',
        '[class*="freebirdFormviewerViewResponseConfirmationMessage"]',  // Google Forms
        '.freebirdFormviewerViewResponseLinkedPageMessage',  // Google Forms linked page
        '[data-success]',
        '#success',
        '#thank-you',
        '#confirmation'
    ];

    for (const selector of successSelectors) {
        const el = document.querySelector(selector);
        if (el && el.offsetParent !== null) {
            const text = el.textContent?.trim().substring(0, 500) || '';
            if (text) {
                result.status = 'success';
                result.message = text;
                result.selector = selector;
                result.success_indicators.push({selector, text: text.substring(0, 100)});
            }
        }
    }

    // Check for error elements if no success found
    if (result.status !== 'success') {
        const errorSelectors = [
            '[class*="error"]',
            '[class*="invalid"]',
            '.alert-danger',
            '.validation-error',
            '.form-error',
            '.field-error',
            '[role="alert"]',
            '#error',
            '#errors'
        ];

        for (const selector of errorSelectors) {
            const el = document.querySelector(selector);
            if (el && el.offsetParent !== null) {
                const text = el.textContent?.trim().substring(0, 500) || '';
                if (text) {
                    result.status = 'error';
                    result.message = text;
                    result.selector = selector;
                    result.error_indicators.push({selector, text: text.substring(0, 100)});
                }
            }
        }
    }

    // Check page text for success/error patterns if no specific element found
    if (result.status === 'unknown') {
        const bodyText = document.body.innerText || '';

        // Check success text patterns
        for (const pattern of successPatterns.text) {
            const match = bodyText.match(pattern);
            if (match) {
                result.status = 'success';
                // Try to get surrounding context
                const matchIndex = bodyText.toLowerCase().indexOf(match[0].toLowerCase());
                if (matchIndex >= 0) {
                    const start = Math.max(0, matchIndex - 20);
                    const end = Math.min(bodyText.length, matchIndex + match[0].length + 100);
                    result.message = bodyText.substring(start, end).trim();
                } else {
                    result.message = match[0];
                }
                result.success_indicators.push({pattern: pattern.toString(), match: match[0]});
                break;
            }
        }

        // Check error text patterns if no success
        if (result.status === 'unknown') {
            for (const pattern of errorPatterns.text) {
                const match = bodyText.match(pattern);
                if (match) {
                    // Only mark as error if there are still form fields visible (not submitted successfully)
                    const hasVisibleInputs = document.querySelector('input:not([type="hidden"]), textarea, select');
                    if (hasVisibleInputs) {
                        result.status = 'error';
                        const matchIndex = bodyText.toLowerCase().indexOf(match[0].toLowerCase());
                        if (matchIndex >= 0) {
                            const start = Math.max(0, matchIndex - 20);
                            const end = Math.min(bodyText.length, matchIndex + match[0].length + 100);
                            result.message = bodyText.substring(start, end).trim();
                        } else {
                            result.message = match[0];
                        }
                        result.error_indicators.push({pattern: pattern.toString(), match: match[0]});
                        break;
                    }
                }
            }
        }
    }

    // If still unknown but URL changed (from form page), assume success
    // This will be handled by comparing with original URL in caller

    return result;
}
