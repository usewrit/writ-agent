use tracing::debug;

/// Manages multiple browser tabs (pages) within a single browser context.
///
/// Tracks which tab is currently active and provides an index for switching
/// between them. Page identifiers are stored as strings (target IDs from CDP).
pub struct TabManager {
    active_page_index: usize,
    pages: Vec<String>,
}

impl TabManager {
    /// Create a new TabManager with no pages.
    pub fn new() -> Self {
        Self {
            active_page_index: 0,
            pages: Vec::new(),
        }
    }

    /// Add a page by its target ID. Returns the index of the new page.
    pub fn add_page(&mut self, target_id: String) -> usize {
        let idx = self.pages.len();
        self.pages.push(target_id);
        debug!(idx, "Tab added");
        idx
    }

    /// Remove a page by index. Returns the removed target ID, if valid.
    pub fn remove_page(&mut self, index: usize) -> Option<String> {
        if index >= self.pages.len() {
            return None;
        }
        let removed = self.pages.remove(index);
        // Adjust active index if needed
        if self.active_page_index >= self.pages.len() && !self.pages.is_empty() {
            self.active_page_index = self.pages.len() - 1;
        }
        debug!(index, "Tab removed");
        Some(removed)
    }

    /// Switch to the tab at the given index. Returns `true` if the index was
    /// valid.
    pub fn switch_to(&mut self, index: usize) -> bool {
        if index < self.pages.len() {
            self.active_page_index = index;
            debug!(index, "Switched to tab");
            true
        } else {
            false
        }
    }

    /// Get the target ID of the currently active page.
    pub fn active_page(&self) -> Option<&str> {
        self.pages.get(self.active_page_index).map(|s| s.as_str())
    }

    /// Index of the currently active tab.
    pub fn active_index(&self) -> usize {
        self.active_page_index
    }

    /// Total number of tracked tabs.
    pub fn count(&self) -> usize {
        self.pages.len()
    }

    /// All tracked target IDs.
    pub fn page_ids(&self) -> &[String] {
        &self.pages
    }
}

impl Default for TabManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_active() {
        let mut tm = TabManager::new();
        assert!(tm.active_page().is_none());
        tm.add_page("page-1".to_string());
        assert_eq!(tm.active_page(), Some("page-1"));
        assert_eq!(tm.count(), 1);
    }

    #[test]
    fn test_switch() {
        let mut tm = TabManager::new();
        tm.add_page("a".to_string());
        tm.add_page("b".to_string());
        assert!(tm.switch_to(1));
        assert_eq!(tm.active_page(), Some("b"));
        assert!(!tm.switch_to(5));
    }

    #[test]
    fn test_remove() {
        let mut tm = TabManager::new();
        tm.add_page("x".to_string());
        tm.add_page("y".to_string());
        tm.switch_to(1);
        tm.remove_page(1);
        assert_eq!(tm.count(), 1);
        assert_eq!(tm.active_page(), Some("x"));
    }
}
