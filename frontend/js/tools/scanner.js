// Port Scanner tool module
// Simulates scanning of a port range with basic lifecycle hooks.

let abortController = null;

export function init() {
    const form = document.getElementById('port-scanner-form');
    const results = document.querySelector('[data-results]');
    const status = document.querySelector('[data-status]');

    if (!form || !results || !status) {
        return;
    }

    abortController = new AbortController();

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (abortController?.signal.aborted) {
            abortController = new AbortController();
        }

        const formData = new FormData(form);
        const target = String(formData.get('target') || '').trim();
        const range = String(formData.get('range') || '').trim();

        if (!target) {
            results.textContent = 'Please provide a target host or IP address.';
            return;
        }

        const [start, end] = parseRange(range);
        if (Number.isNaN(start) || Number.isNaN(end)) {
            results.textContent = 'Invalid port range. Use the format start-end.';
            return;
        }

        status.hidden = false;
        status.textContent = `Scanning ${target} (${start}-${end})…`;
        results.textContent = '';

        try {
            const scanResults = await simulatePortScan(target, start, end, abortController.signal);
            renderPortResults(results, target, scanResults);
            status.textContent = `Scan complete. ${scanResults.filter((item) => item.open).length} open ports found.`;
        } catch (error) {
            if (error.name === 'AbortError') {
                status.textContent = 'Scan cancelled.';
            } else {
                status.textContent = 'Scan failed.';
                results.textContent = `Unable to scan target: ${error.message}`;
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

function parseRange(range) {
    const [start, end] = range.split('-').map((value) => Number.parseInt(value, 10));
    return [start, end];
}

async function simulatePortScan(target, start, end, signal) {
    await delay(600, signal);

    const services = new Map([
        [22, 'SSH'],
        [80, 'HTTP'],
        [135, 'RPC'],
        [443, 'HTTPS'],
        [3306, 'MySQL'],
        [5432, 'PostgreSQL'],
        [6379, 'Redis'],
        [8080, 'HTTP-Alt']
    ]);

    const total = Math.min(end - start + 1, 50);
    const ports = Array.from({ length: total }, (_, index) => start + index);

    return ports.map((port) => {
        const open = Math.random() > 0.6;
        return {
            host: target,
            port,
            open,
            service: services.get(port) || 'unknown'
        };
    });
}

function renderPortResults(container, target, rows) {
    container.innerHTML = '';

    const heading = document.createElement('p');
    heading.textContent = `Results for ${target}`;
    container.appendChild(heading);

    if (!rows.length) {
        const empty = document.createElement('p');
        empty.textContent = 'No ports in the specified range.';
        container.appendChild(empty);
        return;
    }

    const table = document.createElement('table');
    table.className = 'scanner__results-table';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    ['Port', 'Status', 'Service'].forEach((label) => {
        const th = document.createElement('th');
        th.textContent = label;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    rows.forEach((row) => {
        const tr = document.createElement('tr');
        tr.dataset.open = String(row.open);

        const portCell = document.createElement('td');
        portCell.textContent = String(row.port);
        tr.appendChild(portCell);

        const statusCell = document.createElement('td');
        statusCell.textContent = row.open ? 'open' : 'closed';
        tr.appendChild(statusCell);

        const serviceCell = document.createElement('td');
        serviceCell.textContent = row.service;
        tr.appendChild(serviceCell);

        tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    container.appendChild(table);
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
