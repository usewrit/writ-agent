// Browser-fingerprint evasion script.
//
// The evasion techniques below (webdriver removal, navigator/window property
// masking, Function.prototype.toString spoofing, etc.) derive from the lineage
// of puppeteer-extra-plugin-stealth (https://github.com/berstend/puppeteer-extra),
// which is distributed under the MIT License. This is an independent
// reimplementation for the writ agent, not a copy of that source.
(function() {
    if (window.__stealth_injected) return;
    window.__stealth_injected = true;

    // --- 1. Remove webdriver property (primary bot signal) ---
    const removeWebdriver = () => {
        try {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined, configurable: true
            });
        } catch(e) {}
        try { delete navigator.__proto__.webdriver; } catch(e) {}
        try { delete Object.getPrototypeOf(navigator).webdriver; } catch(e) {}
    };
    removeWebdriver();

    // --- 2. Hide all automation-related window properties ---
    [
        'webdriver', '__webdriver_script_fn', '__driver_evaluate',
        '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate',
        '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped',
        '__fxdriver_unwrapped', '_Selenium_IDE_Recorder', '_selenium',
        'calledSelenium', '_WEBDRIVER_ELEM_CACHE', 'ChromeDriverw',
        '__nightmare', '__puppeteer_evaluation_script__',
        '__playwright_evaluation_script__', 'playwright'
    ].forEach(prop => {
        try { delete window[prop]; } catch(e) {}
        try { Object.defineProperty(window, prop, { get: () => undefined, configurable: true }); } catch(e) {}
    });

    // --- 3. Fix plugins array ---
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const plugins = [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '' },
                { name: 'Native Client', filename: 'internal-nacl-plugin', description: '' }
            ];
            plugins.item = (i) => plugins[i];
            plugins.namedItem = (name) => plugins.find(p => p.name === name);
            plugins.refresh = () => {};
            return plugins;
        },
        configurable: true
    });

    // --- 4. Fix mimeTypes ---
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => {
            const mimeTypes = [
                { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
                { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' }
            ];
            mimeTypes.item = (i) => mimeTypes[i];
            mimeTypes.namedItem = (name) => mimeTypes.find(m => m.type === name);
            return mimeTypes;
        },
        configurable: true
    });

    // --- 5. Fix languages ---
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: true
    });

    // --- 6. Fix permissions API ---
    if (navigator.permissions) {
        const originalQuery = navigator.permissions.query;
        navigator.permissions.query = (parameters) => {
            if (parameters.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission || 'default', onchange: null });
            }
            return originalQuery.call(navigator.permissions, parameters);
        };
    }

    // --- 7. Fix chrome runtime + CDP detection ---
    if (!window.chrome) window.chrome = {};
    window.chrome.runtime = window.chrome.runtime || {};
    window.chrome.app = window.chrome.app || {};
    window.chrome.csi = function() { return {}; };
    window.chrome.loadTimes = function() {
        return {
            requestTime: Date.now() / 1000 - Math.random() * 10,
            startLoadTime: Date.now() / 1000 - Math.random() * 5,
            commitLoadTime: Date.now() / 1000 - Math.random() * 2,
            finishDocumentLoadTime: Date.now() / 1000 - Math.random(),
            finishLoadTime: Date.now() / 1000,
            firstPaintTime: Date.now() / 1000 - Math.random() * 3,
            firstPaintAfterLoadTime: 0,
            navigationType: 'Other',
            wasFetchedViaSpdy: false,
            wasNpnNegotiated: true,
            npnNegotiatedProtocol: 'h2',
            wasAlternateProtocolAvailable: false,
            connectionInfo: 'h2'
        };
    };

    // --- 8. Fix iframe contentWindow ---
    try {
        const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (originalContentWindow) {
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
                get: function() {
                    const win = originalContentWindow.get.call(this);
                    try {
                        if (win && !win.chrome) win.chrome = window.chrome;
                    } catch(e) {}
                    return win;
                }
            });
        }
    } catch(e) {}

    // --- 9. Spoof WebGL vendor and renderer ---
    const getParameterProxyHandler = {
        apply: function(target, thisArg, args) {
            const param = args[0];
            if (param === 37445) return 'Google Inc. (Apple)';
            if (param === 37446) return 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)';
            return Reflect.apply(target, thisArg, args);
        }
    };
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (gl) {
            WebGLRenderingContext.prototype.getParameter = new Proxy(
                WebGLRenderingContext.prototype.getParameter, getParameterProxyHandler
            );
            if (typeof WebGL2RenderingContext !== 'undefined') {
                WebGL2RenderingContext.prototype.getParameter = new Proxy(
                    WebGL2RenderingContext.prototype.getParameter, getParameterProxyHandler
                );
            }
        }
    } catch(e) {}

    // --- 10. Canvas fingerprint noise ---
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {
        if (type === 'image/png' && this.width > 16 && this.height > 16) {
            try {
                const context = this.getContext('2d');
                if (context) {
                    const imageData = context.getImageData(0, 0, this.width, this.height);
                    for (let i = 0; i < imageData.data.length; i += 4) {
                        imageData.data[i] = imageData.data[i] ^ (Math.random() > 0.5 ? 1 : 0);
                    }
                    context.putImageData(imageData, 0, 0);
                }
            } catch(e) {}
        }
        return originalToDataURL.apply(this, arguments);
    };

    // --- 11. Hardware properties ---
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: true });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8, configurable: true });
    Object.defineProperty(navigator, 'platform', { get: () => 'MacIntel', configurable: true });

    // --- 12. Headless detection fixes ---
    try { Object.defineProperty(screen, 'availHeight', { get: () => screen.height }); } catch(e) {}
    try { Object.defineProperty(screen, 'availWidth', { get: () => screen.width }); } catch(e) {}
    if (window.outerWidth === 0) {
        Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth });
    }
    if (window.outerHeight === 0) {
        Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight + 85 });
    }

    // --- 13. Notification constructor (headless detection) ---
    if (!window.Notification) {
        window.Notification = {
            permission: 'default',
            requestPermission: () => Promise.resolve('default')
        };
    }

    // --- 14. Connection type (bots often have unusual values) ---
    if (navigator.connection) {
        try {
            Object.defineProperty(navigator.connection, 'rtt', { get: () => 50 });
            Object.defineProperty(navigator.connection, 'downlink', { get: () => 10 });
            Object.defineProperty(navigator.connection, 'effectiveType', { get: () => '4g' });
        } catch(e) {}
    }

    // --- 15. Prevent toString leaks from proxy objects ---
    try {
        const nativeToString = Function.prototype.toString;
        Function.prototype.toString = function() {
            if (this === Function.prototype.toString) {
                return 'function toString() { [native code] }';
            }
            return nativeToString.call(this);
        };
    } catch(e) {}
})();
