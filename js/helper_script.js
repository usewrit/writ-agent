            window.__psRecorder = {
                // Escape a value for use inside a DOUBLE-QUOTED selector string
                // (`[attr="…"]`, `:has-text("…")`).
                // This file used to carry Rust/Python-style DOUBLE escaping: the
                // replacement string had four backslashes rather than two, so it
                // inserted two literal backslashes before the match. A quote then came
                // out as an escaped backslash followed by an UNESCAPED quote — which
                // terminates the selector string, making the tail of a page-controlled
                // attribute value part of the selector. Insert exactly ONE backslash,
                // in a single pass so the inserted backslashes are not re-escaped.
                escapeCSS: function(str) {
                    return String(str).replace(/["\\]/g, '\\$&');
                },

                // Clean text for use in selectors.
                // The whitespace regex was ALSO double-escaped (an extra backslash
                // before the "s"), so it matched a literal backslash followed by "s"
                // rather than whitespace and runs of spaces/newlines were never
                // collapsed. `/\s+/` is the intended character class.
                cleanText: function(text) {
                    if (!text) return '';
                    return text.trim().replace(/\s+/g, ' ').substring(0, 80);
                },

                // Check if selector is unique on page
                isUnique: function(selector) {
                    try {
                        return document.querySelectorAll(selector).length === 1;
                    } catch(e) {
                        return false;
                    }
                },

                // Get role for element
                getRole: function(el) {
                    const explicitRole = el.getAttribute('role');
                    if (explicitRole) return explicitRole;

                    // Implicit roles
                    const tag = el.tagName.toLowerCase();
                    const type = el.type ? el.type.toLowerCase() : '';

                    if (tag === 'button' || (tag === 'input' && type === 'button')) return 'button';
                    if (tag === 'a' && el.href) return 'link';
                    if (tag === 'input' && type === 'checkbox') return 'checkbox';
                    if (tag === 'input' && type === 'radio') return 'radio';
                    if (tag === 'input' && ['text', 'email', 'password', 'tel', 'url', 'search'].includes(type)) return 'textbox';
                    if (tag === 'textarea') return 'textbox';
                    if (tag === 'select') return 'combobox';
                    if (tag === 'img') return 'img';
                    if (tag === 'nav') return 'navigation';
                    if (tag === 'main') return 'main';
                    if (tag === 'header') return 'banner';
                    if (tag === 'footer') return 'contentinfo';

                    return null;
                },

                getSelector: function(el) {
                    if (!el || el === document.body || el === document.documentElement) return 'body';

                    const tag = el.tagName.toLowerCase();

                    // 1. ID (most reliable if present and stable)
                    if (el.id && !/^[0-9]/.test(el.id) && !/[:.]/.test(el.id)) {
                        const idSel = '#' + el.id;
                        if (this.isUnique(idSel)) return idSel;
                    }

                    // 2. Testing attributes (data-testid, data-test, data-cy)
                    for (const attr of ['data-testid', 'data-test', 'data-cy', 'data-test-id']) {
                        const val = el.getAttribute(attr);
                        if (val) {
                            const sel = '[' + attr + '="' + this.escapeCSS(val) + '"]';
                            if (this.isUnique(sel)) return sel;
                        }
                    }

                    // 3. Name attribute (great for forms)
                    if (el.name) {
                        const sel = tag + '[name="' + this.escapeCSS(el.name) + '"]';
                        if (this.isUnique(sel)) return sel;
                    }

                    // 4. aria-label
                    const ariaLabel = el.getAttribute('aria-label');
                    if (ariaLabel) {
                        const sel = '[aria-label="' + this.escapeCSS(ariaLabel) + '"]';
                        if (this.isUnique(sel)) return sel;
                        // Try with tag
                        const tagSel = tag + sel;
                        if (this.isUnique(tagSel)) return tagSel;
                    }

                    // 5. Text-based selectors for clickable elements
                    const text = this.cleanText(el.textContent);
                    if (text && text.length > 0 && text.length < 50) {
                        const clickable = ['a', 'button', 'input', 'label'].includes(tag) ||
                                          el.getAttribute('role') === 'button' ||
                                          el.onclick !== null;

                        if (clickable) {
                            // For links, use text selector
                            if (tag === 'a') {
                                const sel = 'a:has-text("' + this.escapeCSS(text) + '")';
                                // Playwright text selectors - check with querySelectorAll won't work
                                // but we know this is a good selector
                                return sel;
                            }
                            // For buttons
                            if (tag === 'button' || (tag === 'input' && (el.type === 'submit' || el.type === 'button'))) {
                                if (tag === 'button') {
                                    return 'button:has-text("' + this.escapeCSS(text) + '")';
                                }
                                // input[type=submit] with value
                                if (el.value) {
                                    const sel = 'input[type="' + el.type + '"][value="' + this.escapeCSS(el.value) + '"]';
                                    if (this.isUnique(sel)) return sel;
                                }
                            }
                        }
                    }

                    // 6. Placeholder for inputs
                    if (el.placeholder) {
                        const sel = tag + '[placeholder="' + this.escapeCSS(el.placeholder) + '"]';
                        if (this.isUnique(sel)) return sel;
                    }

                    // 7. Title attribute
                    if (el.title) {
                        const sel = tag + '[title="' + this.escapeCSS(el.title) + '"]';
                        if (this.isUnique(sel)) return sel;
                    }

                    // 8. href for links (partial match with contains)
                    if (tag === 'a' && el.href) {
                        try {
                            const url = new URL(el.href);
                            const path = url.pathname;
                            if (path && path !== '/') {
                                const sel = 'a[href*="' + this.escapeCSS(path) + '"]';
                                if (this.isUnique(sel)) return sel;
                            }
                        } catch(e) {}
                    }

                    // 9. Unique class combination
                    if (el.className && typeof el.className === 'string') {
                        // `/\s+/` — class lists are whitespace-separated. The
                        // double-escaped form here split on a literal backslash.
                        const classes = el.className.trim().split(/\s+/).filter(c => c && !c.startsWith('_'));
                        if (classes.length > 0) {
                            // Try single class first
                            for (const cls of classes.slice(0, 3)) {
                                const sel = tag + '.' + cls;
                                if (this.isUnique(sel)) return sel;
                            }
                            // Try class combinations
                            if (classes.length >= 2) {
                                const sel = tag + '.' + classes.slice(0, 2).join('.');
                                if (this.isUnique(sel)) return sel;
                            }
                        }
                    }

                    // 10. Type attribute for inputs
                    if (tag === 'input' && el.type) {
                        const sel = 'input[type="' + el.type + '"]';
                        if (this.isUnique(sel)) return sel;
                    }

                    // 11. Role-based selector with accessible name
                    const role = this.getRole(el);
                    if (role && text && text.length < 30) {
                        // Playwright role selector format
                        return 'role=' + role + '[name="' + this.escapeCSS(text) + '"]';
                    }

                    // 12. nth-of-type (better than nth-child - counts only same tag)
                    // Build a more contextual selector
                    const parent = el.parentElement;
                    if (parent && parent !== document.body) {
                        const parentSelector = this.getSelector(parent);
                        if (parentSelector && !parentSelector.includes(':nth-of-type')) {
                            const siblings = Array.from(parent.children).filter(c => c.tagName === el.tagName);
                            if (siblings.length > 1) {
                                const index = siblings.indexOf(el) + 1;
                                const sel = parentSelector + ' > ' + tag + ':nth-of-type(' + index + ')';
                                if (this.isUnique(sel)) return sel;
                            } else {
                                // Only one of this type - simpler selector
                                const sel = parentSelector + ' > ' + tag;
                                if (this.isUnique(sel)) return sel;
                            }
                        }
                    }

                    // 13. Final fallback - tag with text filter
                    if (text && text.length > 0 && text.length < 30) {
                        return tag + ':has-text("' + this.escapeCSS(text) + '")';
                    }

                    // 14. Use form context + nth-of-type for form elements
                    // Avoid :visible pseudo-class as it's not standard CSS
                    if (['input', 'textarea', 'select', 'button'].includes(tag)) {
                        // Try to find within a form context
                        const form = el.closest('form');
                        if (form) {
                            const formSelector = form.id ? '#' + CSS.escape(form.id) :
                                                 form.name ? 'form[name="' + form.name + '"]' : 'form';
                            const formElements = Array.from(form.querySelectorAll(tag));
                            const formIndex = formElements.indexOf(el);
                            if (formIndex >= 0) {
                                return formSelector + ' ' + tag + ':nth-of-type(' + (formIndex + 1) + ')';
                            }
                        }
                    }

                    // Last resort - tag with nth-of-type based on DOM position
                    const allOfType = document.querySelectorAll(tag);
                    if (allOfType.length > 1) {
                        const index = Array.from(allOfType).indexOf(el) + 1;
                        return tag + ':nth-of-type(' + index + ')';
                    }

                    return tag;
                },

                getText: function(el) {
                    // Get meaningful text from element
                    if (el.value !== undefined && el.value !== '') return el.value.substring(0, 100);

                    // For inputs, try placeholder
                    if (el.placeholder) return el.placeholder.substring(0, 100);

                    // Get direct text content (not from children)
                    const text = el.textContent;
                    if (text) {
                        // `/\s+/` — see cleanText: the double-escaped form matched a
                        // literal backslash, so multi-line text was never normalized.
                        const cleaned = text.trim().replace(/\s+/g, ' ');
                        if (cleaned.length > 0 && cleaned.length < 200) {
                            return cleaned.substring(0, 100);
                        }
                    }

                    // Aria label
                    if (el.getAttribute('aria-label')) return el.getAttribute('aria-label');

                    // Title
                    if (el.title) return el.title.substring(0, 100);

                    // Alt for images
                    if (el.alt) return el.alt.substring(0, 100);

                    return '';
                },

                // Get additional element info for debugging
                getElementInfo: function(el) {
                    return {
                        tag: el.tagName.toLowerCase(),
                        id: el.id || null,
                        classes: el.className || null,
                        name: el.name || null,
                        type: el.type || null,
                        role: this.getRole(el),
                        text: this.getText(el),
                        href: el.href || null,
                        placeholder: el.placeholder || null,
                    };
                },

                // Abstract native <select> elements into custom clickable dropdowns
                // This allows AI to interact with dropdowns without OS-native UI
                abstractNativeSelects: function() {
                    const self = this;
                    let abstractedCount = 0;
                    const selects = document.querySelectorAll('select:not([data-ps-abstracted])');
                    console.log('[PS] Found ' + selects.length + ' unprocessed select elements');

                    selects.forEach((select) => {
                        // Skip if already processed or if it's hidden
                        if (select.dataset.psAbstracted) return;
                        const rect = select.getBoundingClientRect();
                        if (rect.width === 0 || rect.height === 0) return;
                        const style = window.getComputedStyle(select);
                        if (style.display === 'none' || style.visibility === 'hidden') return;

                        // Mark as processed
                        select.dataset.psAbstracted = 'true';

                        // Get computed styles to match appearance
                        const selectStyle = window.getComputedStyle(select);

                        // Create wrapper positioned over the select
                        const wrapper = document.createElement('div');
                        wrapper.className = 'ps-select-wrapper';
                        wrapper.dataset.psSelectWrapper = 'true';
                        wrapper.style.cssText = `
                            position: relative;
                            display: inline-block;
                            width: ${rect.width}px;
                            min-width: ${rect.width}px;
                            font-family: ${selectStyle.fontFamily};
                            font-size: ${selectStyle.fontSize};
                        `;

                        // Create trigger button showing current value
                        const trigger = document.createElement('div');
                        trigger.className = 'ps-select-trigger';
                        trigger.dataset.psSelectTrigger = 'true';
                        trigger.setAttribute('role', 'combobox');
                        trigger.setAttribute('aria-haspopup', 'listbox');
                        trigger.setAttribute('aria-expanded', 'false');
                        trigger.setAttribute('tabindex', '0');
                        if (select.id) trigger.dataset.forSelect = select.id;
                        if (select.name) trigger.dataset.selectName = select.name;

                        const selectedOpt = select.options[select.selectedIndex];
                        trigger.textContent = selectedOpt ? selectedOpt.text : 'Select...';
                        trigger.style.cssText = `
                            padding: 6px 30px 6px 10px;
                            border: 1px solid #ccc;
                            border-radius: 4px;
                            background: white url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23333' d='M2 4l4 4 4-4z'/%3E%3C/svg%3E") no-repeat right 10px center;
                            cursor: pointer;
                            width: 100%;
                            box-sizing: border-box;
                            white-space: nowrap;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            min-height: ${Math.max(rect.height, 32)}px;
                            line-height: ${Math.max(rect.height - 14, 18)}px;
                        `;

                        // Create options container (hidden initially)
                        const optionsList = document.createElement('div');
                        optionsList.className = 'ps-select-options';
                        optionsList.dataset.psSelectOptions = 'true';
                        optionsList.setAttribute('role', 'listbox');
                        optionsList.style.cssText = `
                            display: none;
                            position: absolute;
                            top: 100%;
                            left: 0;
                            right: 0;
                            max-height: 200px;
                            overflow-y: auto;
                            background: white;
                            border: 1px solid #ccc;
                            border-radius: 4px;
                            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                            z-index: 99999;
                            margin-top: 2px;
                        `;

                        // Create option elements for each <option>
                        Array.from(select.options).forEach((opt, optIdx) => {
                            const optDiv = document.createElement('div');
                            optDiv.className = 'ps-select-option';
                            optDiv.dataset.psSelectOption = 'true';
                            optDiv.setAttribute('role', 'option');
                            optDiv.setAttribute('data-value', opt.value);
                            optDiv.setAttribute('data-index', optIdx.toString());
                            if (select.name) optDiv.dataset.selectName = select.name;
                            optDiv.textContent = opt.text || opt.value;
                            optDiv.style.cssText = `
                                padding: 8px 12px;
                                cursor: pointer;
                                white-space: nowrap;
                                overflow: hidden;
                                text-overflow: ellipsis;
                            `;

                            // Hover effect
                            optDiv.addEventListener('mouseenter', () => {
                                optDiv.style.background = '#f0f0f0';
                            });
                            optDiv.addEventListener('mouseleave', () => {
                                optDiv.style.background = 'white';
                            });

                            // Click handler - select option and sync to native select
                            optDiv.addEventListener('click', (e) => {
                                e.stopPropagation();
                                select.selectedIndex = optIdx;
                                select.value = opt.value;
                                select.dispatchEvent(new Event('change', { bubbles: true }));
                                select.dispatchEvent(new Event('input', { bubbles: true }));
                                trigger.textContent = opt.text || opt.value;
                                optionsList.style.display = 'none';
                                trigger.setAttribute('aria-expanded', 'false');
                            });

                            optionsList.appendChild(optDiv);
                        });

                        // Toggle dropdown on trigger click
                        trigger.addEventListener('click', (e) => {
                            e.stopPropagation();
                            const isOpen = optionsList.style.display !== 'none';
                            // Close all other open dropdowns first
                            document.querySelectorAll('.ps-select-options').forEach(ol => {
                                ol.style.display = 'none';
                            });
                            document.querySelectorAll('.ps-select-trigger').forEach(t => {
                                t.setAttribute('aria-expanded', 'false');
                            });
                            if (!isOpen) {
                                optionsList.style.display = 'block';
                                trigger.setAttribute('aria-expanded', 'true');
                            }
                        });

                        // Keyboard support
                        trigger.addEventListener('keydown', (e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                trigger.click();
                            } else if (e.key === 'Escape') {
                                optionsList.style.display = 'none';
                                trigger.setAttribute('aria-expanded', 'false');
                            }
                        });

                        // Hide original select and insert wrapper
                        select.style.position = 'absolute';
                        select.style.opacity = '0';
                        select.style.pointerEvents = 'none';
                        select.style.width = '1px';
                        select.style.height = '1px';
                        select.parentNode.insertBefore(wrapper, select);
                        wrapper.appendChild(trigger);
                        wrapper.appendChild(optionsList);

                        // Update trigger when native select changes (from other code)
                        select.addEventListener('change', () => {
                            const newOpt = select.options[select.selectedIndex];
                            if (newOpt) trigger.textContent = newOpt.text || newOpt.value;
                        });

                        abstractedCount++;
                        console.log('[PS] Abstracted select:', select.name || select.id || 'unnamed');
                    });

                    // Set up click outside handler (once)
                    if (abstractedCount > 0 && !window.__psSelectClickHandler) {
                        window.__psSelectClickHandler = true;
                        document.addEventListener('click', (e) => {
                            if (!e.target.closest('.ps-select-wrapper')) {
                                document.querySelectorAll('.ps-select-options').forEach(ol => {
                                    ol.style.display = 'none';
                                });
                                document.querySelectorAll('.ps-select-trigger').forEach(t => {
                                    t.setAttribute('aria-expanded', 'false');
                                });
                            }
                        });
                    }

                    return abstractedCount;
                },

                // Initialize and watch for new selects
                initSelectAbstraction: function() {
                    const self = this;
                    console.log('[PS] initSelectAbstraction called');

                    // Abstract existing selects
                    const count = self.abstractNativeSelects();
                    console.log('[PS] Abstracted ' + count + ' native selects');

                    // Watch for dynamically added selects
                    if (!window.__psSelectObserver) {
                        window.__psSelectObserver = new MutationObserver((mutations) => {
                            let hasNewSelects = false;
                            for (const mutation of mutations) {
                                if (mutation.addedNodes.length > 0) {
                                    for (const node of mutation.addedNodes) {
                                        if (node.nodeType === 1) {
                                            if (node.tagName === 'SELECT' || node.querySelector?.('select')) {
                                                hasNewSelects = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (hasNewSelects) break;
                            }
                            if (hasNewSelects) {
                                setTimeout(() => self.abstractNativeSelects(), 100);
                            }
                        });
                        window.__psSelectObserver.observe(document.body, {
                            childList: true,
                            subtree: true
                        });
                        console.log('[PS] MutationObserver set up for new selects');
                    }

                    return count;
                }
            };

            // NOTE: Select abstraction is NOT auto-initialized here
            // It will be manually triggered only in intelligent mode via:
            // page.evaluate('window.__psRecorder && window.__psRecorder.initSelectAbstraction()')
            // This keeps manual recording mode using the frontend overlay for native selects
