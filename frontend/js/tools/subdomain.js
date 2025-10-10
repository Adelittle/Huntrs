// Subdomain Finder tool module
// Provides a simulated async workflow and exposes init/destroy hooks.

let abortController = null;

export function init() {
    const form = document.getElementById('subdomain-form');
    const results = document.getElementById('subdomain-results');

    if (!form || !results) {
        return;
    }

    abortController = new AbortController();

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (abortController?.signal.aborted) {
            abortController = new AbortController();
        }

        const formData = new FormData(form);
        const domain = String(formData.get('target') || '').trim().toLowerCase();

        if (!domain) {
            results.textContent = 'Please provide a valid domain.';
            return;
        }

        results.textContent = `Searching subdomains for ${domain}…`;

        try {
            const discovered = await simulateSubdomainDiscovery(domain, abortController.signal);
            renderSubdomainResults(results, domain, discovered);
        } catch (error) {
            if (error.name === 'AbortError') {
                results.textContent = 'Subdomain search cancelled.';
            } else {
                results.textContent = `Unable to complete search: ${error.message}`;
            }
        }
    };

    form.addEventListener('submit', handleSubmit);

    return () => {
        form.removeEventListener('submit', handleSubmit);
        abortController?.abort();
    };
}

export function destroy() {
    abortController?.abort();
}

async function simulateSubdomainDiscovery(domain, signal) {
    await delay(700, signal);

    const dictionary = ['app', 'api', 'dev', 'staging', 'cdn', 'assets', 'beta', 'dashboard'];
    const randomised = shuffle(dictionary).slice(0, 5);
    const timestamp = Date.now().toString(36);

    return randomised.map((prefix, index) => `${prefix}${index}-${timestamp}.${domain}`);
}

function renderSubdomainResults(container, domain, results) {
    container.innerHTML = '';

    const heading = document.createElement('p');
    heading.textContent = `${results.length} potential subdomains discovered for ${domain}:`;
    container.appendChild(heading);

    const list = document.createElement('ul');
    list.className = 'subdomain__results-list';

    results.forEach((entry) => {
        const item = document.createElement('li');
        item.textContent = entry;
        list.appendChild(item);
    });

    container.appendChild(list);
}

function delay(ms, signal) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }, ms);

        const onAbort = () => {
            clearTimeout(timeout);
            reject(new DOMException('Aborted', 'AbortError'));
        };

        signal?.addEventListener('abort', onAbort, { once: true });
    });
}

function shuffle(array) {
    const copy = array.slice();
    for (let i = copy.length - 1; i > 0; i -= 1) {
        const j = Math.floor(Math.random() * (i + 1));
        [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
}
