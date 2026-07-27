([fieldIndex]) => {
    const allFields = document.querySelectorAll('input, select, textarea, [role="checkbox"], [role="radio"], [role="option"], [role="textbox"], [role="listbox"], [role="combobox"], [aria-haspopup="listbox"], [contenteditable="true"], [data-params], [data-qa*="choice"], .ps-select-trigger, .ps-select-option');
    const visible = Array.from(allFields).filter(f => {
        if (f.tagName === 'INPUT' && f.type === 'hidden') return false;
        if (f.tagName === 'SELECT' && f.dataset.psAbstracted === 'true') return false;
        const rect = f.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return false;
        const style = window.getComputedStyle(f);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });
    if (fieldIndex < 0 || fieldIndex >= visible.length) return { error: 'field_index out of range', total_fields: visible.length };

    const el = visible[fieldIndex];
    el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'nearest' });
    const rect = el.getBoundingClientRect();
    return {
        success: true,
        field_index: fieldIndex,
        newCoordinates: { x: Math.round(rect.left + rect.width/2), y: Math.round(rect.top + rect.height/2) },
        inViewport: rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth,
        label: el.getAttribute('aria-label') || el.placeholder || el.name || el.id || '',
    };
}
