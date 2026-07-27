(() => {
    // SECURITY (same-origin-policy bypass) — MAIN FRAME ONLY.
    // Playwright installs both exposed bindings and page init scripts into EVERY
    // frame of a page, but the Rust side of these bridges (Page.locator /
    // Page.screenshot / Page.evaluate) resolves against the MAIN frame. A
    // streaming target is by design a logged-in site, so a third-party iframe (ad,
    // embedded widget, an iframe planted by XSS) that could reach a bridge would
    // read and drive the TOP document — e.g. textContent('input[type=password]')
    // or a full-page screenshot — and could fabricate a command_response back to
    // the coordinator. So the runtime installs NOTHING in a subframe and, crucially,
    // never learns the capability token there: every bridge requires that token, so
    // a subframe is locked out even though the binding globals exist in it.
    // This runs as an init script (before ANY page script in this frame), so
    // window.top cannot have been shadowed by the time we read it.
    if (window.top !== window) return;

    // Remove old ps if exists (page may have partially survived navigation)
    if (window.ps) delete window.ps;

    const _handlers = {};

    // SECURITY: the two per-session secrets, substituted by the Rust runtime bridge
    // at injection time. Both live ONLY in this closure — deliberately not on
    // window.ps — so untrusted page script / XSS can read neither.
    //   _ns          → namespaces the binding globals so they have no guessable
    //                  name (a drive-by script cannot just call __ps_pw_click).
    //                  NOT sufficient alone: Object.getOwnPropertyNames(window)
    //                  still discloses the name, which is why the token exists.
    //   _bridgeToken → required as argument 0 of EVERY bridge (see check_token in
    //                  src/streaming/runtime_bridge.rs). Distinct from _ns, so
    //                  disclosing a binding name never discloses the token.
    const _ns = "__PS_BRIDGE_NS__";
    const _bridgeToken = "__PS_BRIDGE_TOKEN__";

    // Base names of the bridges the Rust side exposes. MUST stay in sync with
    // BRIDGE_BASE_NAMES in src/streaming/runtime_bridge.rs (a unit test asserts it).
    const _names = [
        'emit', 'respond', 'stream', 'log',
        'pw_click', 'pw_fill', 'pw_type', 'pw_press', 'pw_wait_for',
        'pw_text_content', 'pw_evaluate', 'pw_select_option', 'pw_screenshot',
        'pw_upload_file', 'pw_upload_files_to_input',
    ];

    // SECURITY: capture the GENUINE binding functions into this closure now, while
    // we are still ahead of every page script, and lock the properties down.
    // Playwright installs bindings as ordinary writable/configurable window
    // properties, so page script could otherwise replace one, wait for the first
    // legitimate call, and read argument 0 — the capability token. Calling through
    // _bound (never through window[...]) means a wrapper installed later is simply
    // bypassed; the defineProperty also makes the globals non-enumerable so plain
    // Object.keys(window) / for..in scans do not list them.
    const _bound = {};
    for (const base of _names) {
        const key = '__ps_' + _ns + '_' + base;
        const fn = window[key];
        if (typeof fn !== 'function') continue;
        _bound[base] = fn;
        try {
            Object.defineProperty(window, key, {
                value: fn, writable: false, configurable: false, enumerable: false,
            });
        } catch (e) { /* already locked by a previous injection — fine */ }
    }

    // Helper: call a bridge and throw on failure. EVERY bridge (not just eval and
    // file upload) takes the capability token as argument 0.
    const _pw = async (base, ...args) => {
        const fn = _bound[base];
        if (typeof fn !== 'function') throw new Error('bridge unavailable: ' + base);
        const r = JSON.parse(await fn(_bridgeToken, ...args));
        if (!r.ok) throw new Error(r.error || base + ' failed');
        return r.value !== undefined ? r.value : undefined;
    };

    // Helper: fire-and-forget relay bridge (emit/respond/stream/log). Same token.
    const _relay = (base, ...args) => {
        const fn = _bound[base];
        if (typeof fn !== 'function') throw new Error('bridge unavailable: ' + base);
        return fn(_bridgeToken, ...args);
    };

    window.ps = {
        url: location.href,

        // Event system
        on(event, handler) {
            _handlers[event] = _handlers[event] || [];
            _handlers[event].push(handler);
            console.log('[ps] handler registered for event:', event, '(total ' + _handlers[event].length + ')');
        },
        // Alias for on() — register a named callable handler (e.g. ps.fn("get_user", h)).
        // The action/function name routes directly to this handler at dispatch time;
        // "message" remains the catch-all when no named handler is registered.
        fn(event, handler) { return this.on(event, handler); },
        emit(name, data) {
            try {
                _relay('emit', String(name), JSON.stringify(data || {}));
            } catch(e) { console.error('[ps.emit error]', e); }
        },
        respond(requestId, data) {
            try {
                _relay('respond', String(requestId), JSON.stringify(data || {}));
            } catch(e) { console.error('[ps.respond error]', e); }
        },
        stream(requestId, chunk) {
            try {
                const payload = typeof chunk === 'string' ? {content: chunk} : chunk;
                _relay('stream', String(requestId), JSON.stringify(payload));
            } catch(e) { console.error('[ps.stream error]', e); }
        },
        log(...args) {
            try {
                const msg = args.map(a =>
                    typeof a === 'object' ? JSON.stringify(a) : String(a)
                ).join(' ');
                _relay('log', msg);
            } catch(e) { console.error('[ps.log error]', e); }
        },

        // Playwright page automation — bridged to real Playwright.
        // NOTE every one of these resolves against the MAIN frame on the agent side.
        page: {
            click: (sel) => _pw('pw_click', sel),
            fill: (sel, val) => _pw('pw_fill', sel, String(val)),
            type: (sel, text) => _pw('pw_type', sel, String(text)),
            press: (key) => _pw('pw_press', key),
            waitForSelector: (sel) => _pw('pw_wait_for', sel),
            textContent: (sel) => _pw('pw_text_content', sel),
            selectOption: (sel, val) => _pw('pw_select_option', sel, String(val)),
            screenshot: () => _pw('pw_screenshot'),
            evaluate: (fn) => {
                if (typeof fn === 'function') return Promise.resolve(fn());
                return _pw('pw_evaluate', fn);
            },
            $: (sel) => Promise.resolve(document.querySelector(sel)),
            $$: (sel) => Promise.resolve([...document.querySelectorAll(sel)]),
            keyboard: {
                press: (key) => _pw('pw_press', key),
                type: (text) => _pw('pw_type', 'body', String(text)),
            },
            url: () => location.href,
            // File upload: clicks trigger, intercepts file chooser, uploads file
            // triggerSelector: CSS selector of the button that opens the file dialog
            // file: {name: "file.png", mime: "image/png", base64: "iVBOR..."}
            uploadFile: (triggerSelector, file) => _pw('pw_upload_file', triggerSelector, JSON.stringify(file)),
            // Direct file input: sets files on an input[type="file"] element
            // selector: CSS selector of the file input
            // files: [{name, mime, base64}, ...]
            setInputFiles: (selector, files) => _pw('pw_upload_files_to_input', selector, JSON.stringify(files)),
        },

        // ── Utilities ──
        util: {
            htmlToMarkdown(input) {
                const el = typeof input === 'string'
                    ? Object.assign(document.createElement('div'), {innerHTML: input})
                    : input;
                if (!el) return '';

                function proc(node, li) {
                    if (node.nodeType === 3) return node.textContent;
                    if (node.nodeType !== 1) return '';
                    const t = node.tagName.toLowerCase();
                    const kids = () => [...node.childNodes].map(n => proc(n, li)).join('');
                    if ('script style svg noscript'.split(' ').includes(t)) return '';
                    const m = t.match(/^h([1-6])$/);
                    if (m) return '\n' + '#'.repeat(+m[1]) + ' ' + kids().trim() + '\n\n';
                    switch (t) {
                        case 'p': return '\n' + kids().trim() + '\n\n';
                        case 'br': return '\n';
                        case 'hr': return '\n---\n\n';
                        case 'strong': case 'b': return '**' + kids() + '**';
                        case 'em': case 'i': return '*' + kids() + '*';
                        case 'del': case 's': return '~~' + kids() + '~~';
                        case 'a': {
                            const h = node.getAttribute('href');
                            const txt = kids();
                            return h ? '[' + txt + '](' + h + ')' : txt;
                        }
                        case 'img': return '![' + (node.alt || '') + '](' + (node.src || '') + ')';
                        case 'code': {
                            if (node.parentElement?.tagName?.toLowerCase() === 'pre') return node.textContent;
                            const c = node.textContent;
                            return c.includes('`') ? '`` ' + c + ' ``' : '`' + c + '`';
                        }
                        case 'pre': {
                            const ce = node.querySelector('code');
                            const lang = (ce?.className?.match(/(?:language|lang|hljs)-([\w+-]+)/) || ['',''])[1];
                            const txt = (ce || node).textContent;
                            return '\n```' + lang + '\n' + txt.trimEnd() + '\n```\n\n';
                        }
                        case 'ul': return '\n' + [...node.children]
                            .filter(c => c.tagName?.toLowerCase() === 'li')
                            .map(c => li + '- ' + proc(c, li + '  ').trim()).join('\n') + '\n\n';
                        case 'ol': {
                            const s = +(node.getAttribute('start') || 1);
                            return '\n' + [...node.children]
                                .filter(c => c.tagName?.toLowerCase() === 'li')
                                .map((c, i) => li + (s+i) + '. ' + proc(c, li + '   ').trim()).join('\n') + '\n\n';
                        }
                        case 'li': {
                            let out = '';
                            for (const ch of node.childNodes) {
                                const ct = ch.tagName?.toLowerCase();
                                if (ct === 'ul' || ct === 'ol') out += '\n' + proc(ch, li);
                                else out += proc(ch, li);
                            }
                            return out;
                        }
                        case 'blockquote': return '\n' + kids().trim().split('\n').map(l => '> ' + l).join('\n') + '\n\n';
                        case 'table': {
                            const rows = [...node.querySelectorAll('tr')];
                            if (!rows.length) return kids();
                            const mx = rows.map(r => [...r.querySelectorAll('th,td')].map(c => proc(c,'').trim().replace(/\|/g,'\\|')));
                            const cols = Math.max(...mx.map(r => r.length));
                            mx.forEach(r => { while(r.length < cols) r.push(''); });
                            const w = Array(cols).fill(0).map((_,i) => Math.max(3, ...mx.map(r => r[i].length)));
                            let md = '\n';
                            mx.forEach((row, i) => {
                                md += '| ' + row.map((c,j) => c.padEnd(w[j])).join(' | ') + ' |\n';
                                if (i === 0) md += '| ' + w.map(v => '-'.repeat(v)).join(' | ') + ' |\n';
                            });
                            return md + '\n';
                        }
                        default: return kids();
                    }
                }
                return proc(el, '').replace(/\n{3,}/g, '\n\n').trim();
            },
        },

        // Expose handlers for external inspection
        _handlers: _handlers,

        // Per-DOCUMENT marker for the caller-supplied "advanced script".
        // The runtime itself is re-installed automatically on every document by
        // page.add_init_script, so `window.ps` alone can no longer tell the agent
        // whether the advanced script still needs (re-)injecting after a navigation.
        // reinject_runtime() reads this flag and sets it after a successful inject.
        _advInjected: false,

        // Internal dispatch
        _dispatch(event, payload) {
            const fns = _handlers[event] || [];
            console.log('[ps] _dispatch event=' + event + ' handlers=' + fns.length, payload);
            if (fns.length === 0) {
                console.warn('[ps] _dispatch: NO handler registered for event=' + event);
            }
            for (const fn of fns) {
                // Catch BOTH synchronous throws AND async rejections. An async handler
                // (e.g. `ps.on('message', async ...)`) that throws would otherwise be a
                // SILENT unhandled rejection — the handler "runs" but never responds,
                // which looks exactly like nothing happening. Surface it to the browser
                // console AND the agent log (via ps.log).
                try {
                    const r = fn(payload);
                    if (r && typeof r.then === 'function') {
                        r.then(
                            () => console.log('[ps] handler resolved for event=' + event),
                            (e) => {
                                console.error('[ps] ASYNC handler error:', e);
                                ps.log('async handler error:', (e && (e.stack || e.message)) || String(e));
                            }
                        );
                    }
                } catch(e) {
                    console.error('[ps] handler error:', e);
                    ps.log('handler error:', (e && (e.stack || e.message)) || String(e));
                }
            }
        }
    };

    // Catch-all diagnostics: a handler written as a fire-and-forget async IIFE
    // (`ps.on('message', () => { (async()=>{ ... })(); })`) returns undefined, so its
    // rejection escapes _dispatch's per-handler .catch above. These global listeners
    // surface ANY unhandled error/rejection in the page to BOTH the browser console
    // and the agent log (via ps.log → the `log` bridge), so a handler that throws is
    // never silent. (A handler that simply HANGS on an await fires neither — only the
    // agent's per-turn watchdog catches that.)
    window.addEventListener('unhandledrejection', (ev) => {
        const r = ev.reason;
        console.error('[ps] UNHANDLED PROMISE REJECTION:', r);
        try { ps.log('unhandled rejection:', (r && (r.stack || r.message)) || String(r)); } catch (_) {}
    });
    window.addEventListener('error', (ev) => {
        console.error('[ps] WINDOW ERROR:', ev.message, (ev.filename || '') + ':' + (ev.lineno || ''));
        try { ps.log('window error:', (ev.message || 'error') + ' @ ' + (ev.filename || '') + ':' + (ev.lineno || '')); } catch (_) {}
    });

    console.log('[ps] runtime injected at', location.href, '— ps.on/_dispatch ready');
})();
