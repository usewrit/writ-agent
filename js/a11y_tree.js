() => {
    const sel = (el) => {
        if (el.id && /^[A-Za-z][\w-]*$/.test(el.id)) return '#' + el.id;
        const parts = []; let n = el;
        while (n && n.nodeType === 1 && parts.length < 5) {
            if (n.id && /^[A-Za-z][\w-]*$/.test(n.id)) { parts.unshift(n.tagName.toLowerCase() + '#' + n.id); break; }
            let part = n.tagName.toLowerCase();
            const p = n.parentElement;
            if (p) { const sibs = Array.from(p.children).filter(c => c.tagName === n.tagName);
                     if (sibs.length > 1) part += ':nth-of-type(' + (sibs.indexOf(n) + 1) + ')'; }
            parts.unshift(part); n = n.parentElement;
        }
        return parts.join(' > ');
    };
    const roleOf = (el) => {
        const r = el.getAttribute('role'); if (r) return r;
        const t = el.tagName.toLowerCase();
        if (t === 'a') return el.getAttribute('href') ? 'link' : null;
        if (t === 'button') return 'button';
        if (t === 'select') return 'combobox';
        if (t === 'textarea') return 'textbox';
        if (t === 'img') return 'img';
        if (/^h[1-6]$/.test(t)) return 'heading';
        if (t === 'input') { const it = (el.type || 'text').toLowerCase();
            if (it === 'checkbox') return 'checkbox'; if (it === 'radio') return 'radio';
            if (it === 'submit' || it === 'button' || it === 'reset') return 'button';
            if (it === 'search') return 'searchbox'; if (it === 'hidden') return null;
            return 'textbox'; }
        if (el.hasAttribute('onclick')) return 'button';
        return null;
    };
    const nameOf = (el) => {
        let n = el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('alt') || el.getAttribute('title') || '';
        if (!n) n = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim();
        return n.slice(0, 80);
    };
    const out = [];
    for (const el of document.querySelectorAll('a,button,input,select,textarea,img[alt],[role],h1,h2,h3,h4,[onclick]')) {
        const role = roleOf(el); if (!role) continue;
        const r = el.getBoundingClientRect();
        if (r.width < 3 || r.height < 3) continue;
        if (r.bottom < -50 || r.top > window.innerHeight * 2) continue;
        const st = getComputedStyle(el);
        if (st.visibility === 'hidden' || st.display === 'none' || parseFloat(st.opacity) === 0) continue;
        const name = nameOf(el);
        if (!name && !['textbox','checkbox','radio','combobox','searchbox','img'].includes(role)) continue;
        out.push({ role, name, tag: el.tagName.toLowerCase(),
            x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height),
            cx: Math.round(r.x + r.width / 2), cy: Math.round(r.y + r.height / 2), selector: sel(el) });
        if (out.length >= 120) break;
    }
    return { viewport: { w: window.innerWidth, h: window.innerHeight,
                         scrollY: Math.round(window.scrollY),
                         docHeight: Math.round((document.body && document.body.scrollHeight) || 0) },
             elements: out };
}
