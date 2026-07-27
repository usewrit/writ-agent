([selector, regionBox]) => {
    // mode 1: by CSS selector
    if (selector) {
        let els;
        try { els = document.querySelectorAll(selector); } catch(e) {
            return { error: 'invalid_selector', selector: selector, detail: e.message };
        }
        if (els.length === 0) return { error: 'no_elements_found', selector: selector };
        const results = [];
        els.forEach((el, i) => {
            if (i >= 10) return;
            const rect = el.getBoundingClientRect();
            const visible = rect.width > 0 && rect.height > 0;
            results.push({
                index: i,
                text: el.textContent.trim().substring(0, 1000),
                tag: el.tagName.toLowerCase(),
                visible: visible,
                coordinates: visible ? { x: Math.round(rect.left + rect.width/2), y: Math.round(rect.top + rect.height/2) } : null,
            });
        });
        return { selector: selector, count: els.length, results: results };
    }

    // mode 2: by viewport region [x1, y1, x2, y2]
    if (regionBox && regionBox.length === 4) {
        const [x1, y1, x2, y2] = regionBox;
        const texts = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        let node;
        const seen = new Set();
        while ((node = walker.nextNode()) && texts.length < 30) {
            const range = document.createRange();
            range.selectNodeContents(node);
            const rects = range.getClientRects();
            for (const rect of rects) {
                if (rect.right < x1 || rect.left > x2 || rect.bottom < y1 || rect.top > y2) continue;
                const text = node.textContent.trim();
                if (text && text.length > 1 && !seen.has(text)) {
                    seen.add(text);
                    texts.push(text.substring(0, 200));
                }
                break;
            }
        }
        return { region: regionBox, texts: texts };
    }

    // mode 3: whole page visible text (fallback)
    const body = document.body;
    const text = body?.innerText || '';
    return { fullText: text.substring(0, 3000) };
}
