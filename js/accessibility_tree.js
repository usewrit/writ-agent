() => {
    const MAX_TEXT_LENGTH = 120;
    const MAX_TREE_DEPTH = 12;
    const MAX_NODES = 300;

    let nodeCount = 0;

    // ── helpers ──────────────────────────────────────────────────────────
    function isVisible(el) {
        if (!el || el.nodeType !== 1) return false;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function inViewport(el) {
        const rect = el.getBoundingClientRect();
        const vw = window.innerWidth || document.documentElement.clientWidth;
        const vh = window.innerHeight || document.documentElement.clientHeight;
        return rect.bottom > 0 && rect.top < vh && rect.right > 0 && rect.left < vw;
    }

    function getRole(el) {
        const explicit = el.getAttribute('role');
        if (explicit) return explicit;
        const tag = el.tagName.toLowerCase();
        const roleMap = {
            'a': el.href ? 'link' : null,
            'button': 'button',
            'input': _inputRole(el),
            'select': 'combobox',
            'textarea': 'textbox',
            'img': 'img',
            'nav': 'navigation',
            'main': 'main',
            'header': 'banner',
            'footer': 'contentinfo',
            'aside': 'complementary',
            'section': 'region',
            'article': 'article',
            'form': 'form',
            'table': 'table',
            'thead': 'rowgroup',
            'tbody': 'rowgroup',
            'tr': 'row',
            'th': 'columnheader',
            'td': 'cell',
            'ul': 'list',
            'ol': 'list',
            'li': 'listitem',
            'dialog': 'dialog',
            'details': 'group',
            'summary': 'button',
            'h1': 'heading', 'h2': 'heading', 'h3': 'heading',
            'h4': 'heading', 'h5': 'heading', 'h6': 'heading',
        };
        return roleMap[tag] || null;
    }

    function _inputRole(el) {
        const t = (el.type || 'text').toLowerCase();
        const map = {
            'text': 'textbox', 'email': 'textbox', 'password': 'textbox',
            'search': 'searchbox', 'tel': 'textbox', 'url': 'textbox',
            'number': 'spinbutton', 'range': 'slider',
            'checkbox': 'checkbox', 'radio': 'radio',
            'submit': 'button', 'reset': 'button', 'button': 'button',
            'date': 'textbox', 'time': 'textbox', 'datetime-local': 'textbox',
            'file': 'button', 'color': 'button', 'hidden': null,
        };
        return map[t] || 'textbox';
    }

    function getAccessibleName(el) {
        const aria = el.getAttribute('aria-label');
        if (aria) return aria.substring(0, MAX_TEXT_LENGTH);
        const labelledBy = el.getAttribute('aria-labelledby');
        if (labelledBy) {
            const parts = labelledBy.split(/\s+/).map(id => {
                const ref = document.getElementById(id);
                return ref ? ref.textContent.trim() : '';
            }).filter(Boolean);
            if (parts.length) return parts.join(' ').substring(0, MAX_TEXT_LENGTH);
        }
        const tag = el.tagName.toLowerCase();
        if (['input', 'select', 'textarea'].includes(tag)) {
            if (el.id) {
                const lbl = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
                if (lbl) return lbl.textContent.trim().substring(0, MAX_TEXT_LENGTH);
            }
            const parentLabel = el.closest('label');
            if (parentLabel) {
                const clone = parentLabel.cloneNode(true);
                clone.querySelectorAll('input, select, textarea').forEach(c => c.remove());
                const txt = clone.textContent.trim();
                if (txt) return txt.substring(0, MAX_TEXT_LENGTH);
            }
            if (el.placeholder) return el.placeholder.substring(0, MAX_TEXT_LENGTH);
            if (el.title) return el.title.substring(0, MAX_TEXT_LENGTH);
        }
        if (tag === 'img') return (el.alt || el.title || '').substring(0, MAX_TEXT_LENGTH);
        if (tag === 'a') return el.textContent.trim().substring(0, MAX_TEXT_LENGTH);
        if (['button', 'summary'].includes(tag) || el.getAttribute('role') === 'button') {
            return el.textContent.trim().substring(0, MAX_TEXT_LENGTH);
        }
        return '';
    }

    function getFieldState(el) {
        const tag = el.tagName.toLowerCase();
        const state = {};
        if (['input', 'select', 'textarea'].includes(tag) || el.getAttribute('contenteditable') === 'true') {
            if (tag === 'select') {
                state.value = el.options[el.selectedIndex]?.text || el.value || '';
            } else if (tag === 'textarea' || el.getAttribute('contenteditable') === 'true') {
                state.value = (el.value || el.textContent || '').substring(0, 200);
            } else {
                const t = (el.type || '').toLowerCase();
                if (t === 'checkbox' || t === 'radio' || el.getAttribute('role') === 'checkbox' || el.getAttribute('role') === 'radio') {
                    state.checked = el.checked || el.getAttribute('aria-checked') === 'true';
                } else if (t !== 'hidden') {
                    state.value = (el.value || '').substring(0, 200);
                }
            }
            state.disabled = el.disabled || el.getAttribute('aria-disabled') === 'true';
            state.required = el.required || el.getAttribute('aria-required') === 'true';
            state.readOnly = el.readOnly || false;

            // validation
            if (el.validity && !el.validity.valid) {
                state.validationMessage = el.validationMessage || '';
                state.invalid = true;
            }
            if (el.getAttribute('aria-invalid') === 'true') {
                state.invalid = true;
            }
        }
        return Object.keys(state).length ? state : null;
    }

    // ── error detection ─────────────────────────────────────────────────
    function getVisibleErrors() {
        const errors = [];
        const seen = new Set();

        // 1. aria-invalid fields with nearby error text
        document.querySelectorAll('[aria-invalid="true"]').forEach(el => {
            const errId = el.getAttribute('aria-errormessage') || el.getAttribute('aria-describedby');
            if (errId) {
                const errEl = document.getElementById(errId.split(/\s+/)[0]);
                if (errEl && isVisible(errEl)) {
                    const text = errEl.textContent.trim().substring(0, 150);
                    if (text && !seen.has(text)) { seen.add(text); errors.push({ field: getAccessibleName(el) || el.name || el.id, message: text, type: 'aria' }); }
                }
            }
        });

        // 2. Elements with error-like classes
        const errorSelectors = [
            '.error-message', '.field-error', '.form-error', '.invalid-feedback',
            '.error-text', '.help-block.error', '[class*="error-msg"]',
            '[class*="field-error"]', '[class*="validation-error"]',
            '.alert-danger', '.alert-error', '[role="alert"]',
            '.text-danger', '.text-error', '.Mui-error',
            '.ant-form-item-explain-error',
        ];
        document.querySelectorAll(errorSelectors.join(',')).forEach(el => {
            if (!isVisible(el)) return;
            const text = el.textContent.trim().substring(0, 150);
            if (text && text.length > 2 && !seen.has(text)) {
                seen.add(text);
                let fieldName = '';
                const formGroup = el.closest('.form-group, .form-field, .field, [class*="form-item"], [class*="FormField"]');
                if (formGroup) {
                    const lbl = formGroup.querySelector('label');
                    if (lbl) fieldName = lbl.textContent.trim().substring(0, 50);
                }
                errors.push({ field: fieldName, message: text, type: 'class' });
            }
        });

        // 3. Red-colored visible text near form fields (heuristic)
        document.querySelectorAll('span, div, p, small, label').forEach(el => {
            if (!isVisible(el) || !inViewport(el)) return;
            const style = window.getComputedStyle(el);
            const color = style.color;
            const match = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
            if (!match) return;
            const [r, g, b] = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
            if (r > 180 && g < 80 && b < 80) {
                const text = el.textContent.trim().substring(0, 150);
                if (text && text.length > 2 && text.length < 120 && !seen.has(text)) {
                    const nearField = el.closest('form, .form-group, .field, [class*="form-item"]');
                    if (nearField) {
                        seen.add(text);
                        errors.push({ field: '', message: text, type: 'red_text' });
                    }
                }
            }
        });

        return errors;
    }

    // ── toast/notification detection ────────────────────────────────────
    function getToasts() {
        const toasts = [];
        const seen = new Set();
        const toastSelectors = [
            '[class*="toast"]', '[class*="Toast"]', '[class*="snackbar"]', '[class*="Snackbar"]',
            '[class*="notification"]', '[class*="Notification"]', '.Toastify__toast',
            '[class*="notistack"]', '[role="status"]', '[role="alert"]',
            '[class*="flash"]', '.notice', '[class*="banner-message"]',
        ];
        document.querySelectorAll(toastSelectors.join(',')).forEach(el => {
            if (!isVisible(el)) return;
            const text = el.textContent.trim().substring(0, 200);
            if (text && !seen.has(text)) {
                seen.add(text);
                const isError = el.classList.toString().match(/error|danger|fail|critical/i) ||
                                el.querySelector('[class*="error"], [class*="danger"]');
                const isSuccess = el.classList.toString().match(/success|done|complete/i) ||
                                  el.querySelector('[class*="success"], [class*="check"]');
                toasts.push({
                    message: text,
                    type: isError ? 'error' : isSuccess ? 'success' : 'info'
                });
            }
        });
        return toasts;
    }

    // ── page text extraction ────────────────────────────────────────────
    function getPageText() {
        const sections = [];

        // page title
        const title = document.title?.trim();
        if (title) sections.push({ type: 'title', text: title.substring(0, 150) });

        // visible headings
        document.querySelectorAll('h1, h2, h3, h4, h5, h6, [role="heading"]').forEach(el => {
            if (!isVisible(el)) return;
            const text = el.textContent.trim().substring(0, 150);
            if (!text) return;
            const rawLevel = el.tagName?.match(/H(\d)/)?.[1] || el.getAttribute('aria-level') || '2';
            // CLAMP to 1..6. `aria-level` is page-controlled and unbounded, and the
            // agent deserializes this into a Rust `Option<u8>`
            // (models::dom::PageTextSection.level). `<div role="heading"
            // aria-level="300">` (or a negative / non-numeric value) failed
            // deserialization for the WHOLE payload, so the AI agent silently lost
            // ALL page context for that turn.
            const parsed = parseInt(rawLevel, 10);
            const level = Number.isFinite(parsed) ? Math.min(6, Math.max(1, parsed)) : 2;
            sections.push({
                type: 'heading',
                level: level,
                text: text,
                inViewport: inViewport(el)
            });
        });

        // paragraphs and descriptive text in viewport (limited)
        let paraCount = 0;
        document.querySelectorAll('p, [class*="description"], [class*="subtitle"], [class*="helper-text"], .lead, .intro').forEach(el => {
            if (paraCount >= 8) return;
            if (!isVisible(el) || !inViewport(el)) return;
            const text = el.textContent.trim();
            if (text && text.length > 10 && text.length < 500) {
                sections.push({ type: 'text', text: text.substring(0, 200) });
                paraCount++;
            }
        });

        // step/progress indicators
        const stepEl = document.querySelector('[class*="step-indicator"], [class*="progress-step"], [class*="stepper"], .breadcrumb, [aria-label*="step"], [aria-label*="progress"]');
        if (stepEl && isVisible(stepEl)) {
            const text = stepEl.textContent.trim().substring(0, 100);
            if (text) sections.push({ type: 'progress', text: text });
        }
        const stepMatch = document.body.innerText.match(/(?:step|page|section)\s*(\d+)\s*(?:of|\/)\s*(\d+)/i);
        if (stepMatch) sections.push({ type: 'progress', text: 'Step ' + stepMatch[1] + ' of ' + stepMatch[3] });

        return sections;
    }

    // ── iframe detection ────────────────────────────────────────────────
    function getIframeInfo() {
        const iframes = [];
        document.querySelectorAll('iframe').forEach((iframe, idx) => {
            if (!isVisible(iframe)) return;
            const rect = iframe.getBoundingClientRect();
            const src = iframe.src || '';
            let purpose = 'unknown';
            if (src.match(/recaptcha|hcaptcha|turnstile|captcha/i)) purpose = 'captcha';
            else if (src.match(/stripe|braintree|paypal|adyen|square/i)) purpose = 'payment';
            else if (src.match(/youtube|vimeo|wistia/i)) purpose = 'video';
            else if (src.match(/maps\.google|mapbox/i)) purpose = 'map';
            else if (iframe.title) purpose = iframe.title.substring(0, 60);

            let crossOrigin = false;
            try { iframe.contentDocument; } catch(e) { crossOrigin = true; }

            const info = {
                index: idx,
                purpose: purpose,
                src: src.substring(0, 200),
                x: Math.round(rect.left + rect.width / 2),
                y: Math.round(rect.top + rect.height / 2),
                width: Math.round(rect.width),
                height: Math.round(rect.height),
                inViewport: inViewport(iframe),
                crossOrigin: crossOrigin,
            };

            // try to extract fields from same-origin iframes
            if (!crossOrigin) {
                try {
                    const doc = iframe.contentDocument;
                    const iframeFields = [];
                    doc.querySelectorAll('input, select, textarea').forEach(el => {
                        if (el.type === 'hidden') return;
                        const r = el.getBoundingClientRect();
                        if (r.width === 0 || r.height === 0) return;
                        iframeFields.push({
                            type: el.type || el.tagName.toLowerCase(),
                            label: el.getAttribute('aria-label') || el.placeholder || el.name || el.id || '',
                            name: el.name || '',
                        });
                    });
                    if (iframeFields.length) info.fields = iframeFields;
                } catch(e) {}
            }

            iframes.push(info);
        });
        return iframes;
    }

    // ── semantic tree builder ───────────────────────────────────────────
    function buildTree(el, depth) {
        if (!el || depth > MAX_TREE_DEPTH || nodeCount > MAX_NODES) return null;
        if (el.nodeType !== 1) return null;
        if (!isVisible(el)) return null;

        const tag = el.tagName.toLowerCase();
        // skip noise tags
        if (['script', 'style', 'noscript', 'svg', 'path', 'meta', 'link', 'br', 'hr', 'wbr'].includes(tag)) return null;

        const role = getRole(el);
        const name = getAccessibleName(el);
        const fieldState = getFieldState(el);

        // decide if this node is "interesting" enough to include
        const isInteractive = !!fieldState || ['button', 'link', 'textbox', 'searchbox', 'combobox',
            'checkbox', 'radio', 'slider', 'spinbutton', 'switch', 'tab', 'menuitem', 'option'].includes(role);
        const isLandmark = ['navigation', 'main', 'banner', 'contentinfo', 'complementary',
            'region', 'form', 'dialog', 'article', 'list'].includes(role);
        const isHeading = role === 'heading';
        const isTable = ['table', 'row', 'cell', 'columnheader', 'rowgroup'].includes(role);

        // collect children
        const children = [];
        for (const child of el.children) {
            const subtree = buildTree(child, depth + 1);
            if (subtree) children.push(subtree);
        }

        // if node is not interesting and has no interesting children, skip it
        // except: keep nodes that have direct text content
        const hasDirectText = !isInteractive && Array.from(el.childNodes).some(
            n => n.nodeType === 3 && n.textContent.trim().length > 2
        );

        if (!isInteractive && !isLandmark && !isHeading && !isTable && !hasDirectText && children.length === 0) {
            return null;
        }

        // if node just wraps a single child with no extra info, flatten
        if (!isInteractive && !isLandmark && !isHeading && !role && !name && !fieldState && children.length === 1) {
            return children[0];
        }

        nodeCount++;
        const node = {};
        if (role) node.role = role;
        else node.tag = tag;
        if (name) node.name = name;
        if (isHeading) node.level = parseInt(tag.replace('h', '')) || parseInt(el.getAttribute('aria-level')) || 2;

        if (fieldState) node.state = fieldState;

        // bounding box for interactive elements
        if (isInteractive || isHeading) {
            const rect = el.getBoundingClientRect();
            node.bbox = [Math.round(rect.left), Math.round(rect.top), Math.round(rect.right), Math.round(rect.bottom)];
        }

        if (hasDirectText && !name) {
            const directText = Array.from(el.childNodes)
                .filter(n => n.nodeType === 3)
                .map(n => n.textContent.trim())
                .filter(Boolean)
                .join(' ')
                .substring(0, MAX_TEXT_LENGTH);
            if (directText) node.text = directText;
        }

        if (children.length) node.children = children;

        return node;
    }

    // ── main ────────────────────────────────────────────────────────────
    const body = document.body || document.documentElement;
    const tree = buildTree(body, 0);

    return {
        tree: tree,
        pageText: getPageText(),
        errors: getVisibleErrors(),
        toasts: getToasts(),
        iframes: getIframeInfo(),
        url: location.href,
        title: document.title || '',
        viewport: { width: window.innerWidth, height: window.innerHeight },
        scrollPosition: { x: window.scrollX, y: window.scrollY },
        scrollHeight: document.documentElement.scrollHeight,
        hasMoreBelow: (window.scrollY + window.innerHeight) < (document.documentElement.scrollHeight - 50),
        hasMoreAbove: window.scrollY > 50,
        timestamp: Date.now(),
    };
}
