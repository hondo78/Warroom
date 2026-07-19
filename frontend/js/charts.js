// Language-aware number/date formatting (en-US unless UI is German).
const CHT_LOCALE = (typeof currentLang === 'function' && currentLang() === 'de') ? 'de-DE' : 'en-US';
let timelineChart = null;
let severityChart = null;
let categoriesChart = null;
let attackersChart = null;
let fwAlertsChart = null;
let fwGroupChart = null;

const chartDefaults = {
    color: '#94a3b8',
    borderColor: '#2a3a4e',
};

Chart.defaults.color = chartDefaults.color;
Chart.defaults.borderColor = chartDefaults.borderColor;

function initCharts() {
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Alerts',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    fill: true,
                    tension: 0.3,
                },
                {
                    label: 'Events',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.3,
                },
                {
                    label: 'Detections',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.3,
                },
            ],
        },
        options: {
            responsive: true,
            aspectRatio: 2.5,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: { grid: { color: 'rgba(42,58,78,0.5)' } },
                y: { beginAtZero: true, grid: { color: 'rgba(42,58,78,0.5)' } },
            },
            plugins: { legend: { position: 'top' } },
        },
    });

    const severityCtx = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
            }],
        },
        options: {
            responsive: true,
            aspectRatio: 1.8,
            plugins: {
                legend: { position: 'right' },
            },
        },
    });

    const categoriesCtx = document.getElementById('categoriesChart').getContext('2d');
    categoriesChart = new Chart(categoriesCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Anzahl',
                data: [],
                backgroundColor: 'rgba(139, 92, 246, 0.6)',
                borderColor: '#8b5cf6',
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            aspectRatio: 2.5,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true, grid: { color: 'rgba(42,58,78,0.5)' } },
                y: { grid: { color: 'rgba(42,58,78,0.5)' } },
            },
            plugins: { legend: { display: false } },
        },
    });

    const attackersCtx = document.getElementById('attackersChart').getContext('2d');
    attackersChart = new Chart(attackersCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Angriffe',
                data: [],
                backgroundColor: 'rgba(239, 68, 68, 0.6)',
                borderColor: '#ef4444',
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            aspectRatio: 2.5,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true, grid: { color: 'rgba(42,58,78,0.5)' } },
                y: { grid: { color: 'rgba(42,58,78,0.5)' } },
            },
            plugins: { legend: { display: false } },
        },
    });
    const fwAlertsCtx = document.getElementById('fwAlertsChart').getContext('2d');
    fwAlertsChart = new Chart(fwAlertsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alarme',
                data: [],
                backgroundColor: 'rgba(245, 158, 11, 0.6)',
                borderColor: '#f59e0b',
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            aspectRatio: 2.5,
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true, grid: { color: 'rgba(42,58,78,0.5)' } },
                y: { grid: { color: 'rgba(42,58,78,0.5)' } },
            },
            plugins: { legend: { display: false } },
        },
    });

    const fwGroupCtx = document.getElementById('fwGroupChart').getContext('2d');
    fwGroupChart = new Chart(fwGroupCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#22c55e', '#8b5cf6', '#ec4899', '#06b6d4'],
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'right' },
            },
        },
    });
}

const severityColors = {
    critical: '#ef4444',
    high: '#f59e0b',
    medium: '#3b82f6',
    low: '#22c55e',
    unknown: '#94a3b8',
};

async function updateTimeline(days) {
    try {
        const resp = await fetch(`/api/stats/timeline?days=${days}`);
        const data = await resp.json();

        const formatDate = (d) => {
            if (!d) return '';
            return new Date(d).toLocaleDateString(CHT_LOCALE, { day: '2-digit', month: '2-digit' });
        };

        const allDates = new Set();
        [data.alerts, data.events, data.detections].forEach(arr => {
            arr.forEach(item => allDates.add(item.date));
        });
        const sortedDates = [...allDates].sort();

        const makeMap = (arr) => {
            const m = {};
            arr.forEach(item => { m[item.date] = item.count; });
            return m;
        };

        const alertMap = makeMap(data.alerts);
        const eventMap = makeMap(data.events);
        const detectionMap = makeMap(data.detections);

        timelineChart.data.labels = sortedDates.map(formatDate);
        timelineChart.data.datasets[0].data = sortedDates.map(d => alertMap[d] || 0);
        timelineChart.data.datasets[1].data = sortedDates.map(d => eventMap[d] || 0);
        timelineChart.data.datasets[2].data = sortedDates.map(d => detectionMap[d] || 0);
        timelineChart.update();
    } catch (err) {
        console.error('Timeline update failed:', err);
    }
}

async function updateSeverity(days) {
    try {
        const resp = await fetch(`/api/stats/severity?days=${days}`);
        const data = await resp.json();

        severityChart.data.labels = data.map(d => d.severity);
        severityChart.data.datasets[0].data = data.map(d => d.count);
        severityChart.data.datasets[0].backgroundColor = data.map(d => severityColors[d.severity] || severityColors.unknown);
        severityChart.update();
    } catch (err) {
        console.error('Severity update failed:', err);
    }
}

async function updateCategories(days) {
    try {
        const resp = await fetch(`/api/stats/categories?days=${days}`);
        const data = await resp.json();

        categoriesChart.data.labels = data.map(d => d.category);
        categoriesChart.data.datasets[0].data = data.map(d => d.count);
        categoriesChart.update();
    } catch (err) {
        console.error('Categories update failed:', err);
    }
}

async function updateAttackers(days) {
    try {
        const resp = await fetch(`/api/stats/top-attackers?days=${days}&limit=10`);
        const data = await resp.json();

        attackersChart.data.labels = data.map(d => `${d.ip} (${d.country || '?'})`);
        attackersChart.data.datasets[0].data = data.map(d => d.count);
        attackersChart.update();
    } catch (err) {
        console.error('Attackers update failed:', err);
    }
}

async function updateFirewallStats(days) {
    try {
        const resp = await fetch(`/api/stats/firewall-events?days=${days}`);
        const data = await resp.json();

        // Alerts per firewall
        fwAlertsChart.data.labels = data.by_firewall.map(d => d.firewall);
        fwAlertsChart.data.datasets[0].data = data.by_firewall.map(d => d.count);
        fwAlertsChart.update();

        // Events by group
        fwGroupChart.data.labels = data.by_group.map(d => d.group);
        fwGroupChart.data.datasets[0].data = data.by_group.map(d => d.count);
        fwGroupChart.update();
    } catch (err) {
        console.error('Firewall stats update failed:', err);
    }
}
