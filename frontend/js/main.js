// Huntrs modular frontend loader
// Handles view fetching, template injection, tool lifecycle, and hash routing.

const DEFAULT_VIEW = 'subdomain';
const viewCache = new Map();
const currentState = {
    view: null,
    module: null,
    styles: []
};

const mainContent = document.getElementById('main-content');
const template = document.getElementById('view-template');
const navButtons = Array.from(document.querySelectorAll('[data-view]'));
const yearEl = document.getElementById('current-year');

if (yearEl) {
    yearEl.textContent = String(new Date().getFullYear());
}

navButtons.forEach((button) => {
    button.addEventListener('click', () => {
        const targetView = button.dataset.view;
        if (targetView) {
            navigateTo(targetView);
        }
    });
});

window.addEventListener('hashchange', () => {
    const hashView = getViewFromHash();
    navigateTo(hashView, { updateHash: false });
});

// Kick-off on load using hash router fallback
navigateTo(getViewFromHash(), { updateHash: false });

/**
 * Resolve the desired view name from the current URL hash.
 * @returns {string}
 */
function getViewFromHash() {
    const hash = window.location.hash.replace(/^#/, '').trim();
    return hash || DEFAULT_VIEW;
}

/**
 * Navigate to a specific view, loading HTML, CSS, and JS dynamically.
 * @param {string} viewName
 * @param {{updateHash?: boolean}} [options]
 */
async function navigateTo(viewName, { updateHash = true } = {}) {
    const targetView = viewName || DEFAULT_VIEW;

    if (currentState.view === targetView) {
        return;
    }

    if (updateHash) {
        const expectedHash = `#${targetView}`;
        if (window.location.hash !== expectedHash) {
            window.location.hash = expectedHash;
        }
    }

    setActiveNavigation(targetView);
    showLoadingState();

    try {
        const html = await loadViewTemplate(targetView);
        injectView(html, targetView);
        await initialiseTool(targetView);
        focusMainContent();
    } catch (error) {
        displayError(`Failed to load "${targetView}". ${error.message || error}`);
    }
}

/**
 * Fetch and cache view templates located in /views.
 * @param {string} viewName
 * @returns {Promise<string>}
 */
async function loadViewTemplate(viewName) {
    if (viewCache.has(viewName)) {
        return viewCache.get(viewName);
    }

    const viewPath = `views/${encodeURIComponent(viewName)}.html`;
    const response = await fetch(viewPath, { cache: 'no-cache' });

    if (!response.ok) {
        throw new Error(`View template not found (${response.status})`);
    }

    const html = await response.text();
    viewCache.set(viewName, html);
    return html;
}

/**
 * Inject HTML into the main container via <template> for safe parsing.
 * Moves any linked styles into the document head and tracks them for cleanup.
 * @param {string} html
 * @param {string} viewName
 */
function injectView(html, viewName) {
    template.innerHTML = html;

    const fragment = template.content.cloneNode(true);
    const fragmentRoot = fragment.querySelector('[data-view-root]') || fragment;

    detachActiveStyles();
    attachFragmentStyles(fragment, viewName);

    mainContent.replaceChildren();
    const rootElement = fragmentRoot.cloneNode(true);

    // Add entry animation helper classes
    if (rootElement.classList && rootElement.classList.contains('fade-enter')) {
        requestAnimationFrame(() => {
            rootElement.classList.add('fade-enter-active');
        });
    }

    mainContent.appendChild(rootElement);
    currentState.view = viewName;
}

/**
 * Extract stylesheet links from the fragment and move them to <head>.
 * @param {DocumentFragment} fragment
 * @param {string} viewName
 */
function attachFragmentStyles(fragment, viewName) {
    const styleLinks = Array.from(fragment.querySelectorAll('link[rel="stylesheet"]'));

    styleLinks.forEach((link) => {
        const clone = link.cloneNode(true);
        clone.dataset.viewStyle = viewName;
        document.head.appendChild(clone);
        currentState.styles.push(clone);
        link.remove();
    });
}

/**
 * Remove any styles previously injected for a view.
 */
function detachActiveStyles() {
    currentState.styles.forEach((styleLink) => styleLink.remove());
    currentState.styles = [];
}

/**
 * Import the tool script dynamically and call its lifecycle hooks.
 * @param {string} viewName
 */
async function initialiseTool(viewName) {
    teardownCurrentTool();

    try {
        const module = await import(`./tools/${viewName}.js`);
        if (typeof module.init === 'function') {
            const cleanup = module.init();
            currentState.module = module;
            // Allow tools to return a cleanup callback from init.
            if (typeof cleanup === 'function') {
                currentState.module.destroy = cleanup;
            }
        } else {
            currentState.module = module;
        }
    } catch (error) {
        console.warn(`Optional tool script missing or failed for "${viewName}":`, error);
        currentState.module = null;
    }
}

/**
 * Execute destroy hooks for the currently active tool.
 */
function teardownCurrentTool() {
    if (currentState.module) {
        try {
            if (typeof currentState.module.destroy === 'function') {
                currentState.module.destroy();
            }
        } catch (error) {
            console.warn('Tool cleanup failed:', error);
        }
    }
    currentState.module = null;
}

/**
 * Display a loading message while the view is being fetched.
 */
function showLoadingState() {
    mainContent.textContent = 'Loading…';
}

/**
 * Render an error message in the main container.
 * @param {string} message
 */
function displayError(message) {
    detachActiveStyles();
    mainContent.innerHTML = '';
    const errorPanel = document.createElement('div');
    errorPanel.className = 'panel error';
    errorPanel.textContent = message;
    mainContent.appendChild(errorPanel);
    currentState.view = null;
}

/**
 * Highlight the active navigation button.
 * @param {string} activeView
 */
function setActiveNavigation(activeView) {
    navButtons.forEach((button) => {
        button.classList.toggle('active', button.dataset.view === activeView);
    });
}

/**
 * Move focus to the main content container after a view change.
 */
function focusMainContent() {
    requestAnimationFrame(() => {
        mainContent.focus({ preventScroll: false });
    });
}
