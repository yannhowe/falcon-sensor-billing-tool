// Chart instances
let hourlyChart = null;
let dailyChart = null;
let complianceChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadProductCounts();  // Load product counts first (top of page)
    loadStats();
    loadCharts();
    loadTagBreakdown();
    loadCloudBreakdown();  // Load cloud provider breakdown
    loadRecentSensors();
    loadProductTrendChart();  // Load product trend chart

    // Set up event listeners
    document.getElementById('days-selector').addEventListener('change', (e) => {
        loadCharts(parseInt(e.target.value));
    });

    // Set up table filtering
    document.getElementById('tag-filter').addEventListener('input', (e) => {
        filterTable('tag-table', e.target.value);
    });

    document.getElementById('sensor-filter').addEventListener('input', (e) => {
        filterTable('sensors-table', e.target.value);
    });

    // Set up table sorting
    setupTableSorting('tag-table');
    setupTableSorting('cloud-table');  // Add cloud table sorting
    setupTableSorting('sensors-table');

    // Auto-calculate compliance on load if licenses configured
    const reservedAvg = parseInt(document.getElementById('reserved-hourly-avg').value);
    if (reservedAvg > 0) {
        setTimeout(calculateCompliance, 1000);
    }
});

// Load product counts (FCSC, FMC, FCS, EPP)
async function loadProductCounts() {
    try {
        const response = await fetch('/api/product_breakdown?days=28');
        const data = await response.json();

        // Create a map for easy access
        const products = {
            'FCSC': { count: 0, avg: 0 },
            'FMC': { count: 0, avg: 0 },
            'FCS': { count: 0, avg: 0 },
            'EPP': { count: 0, avg: 0 }
        };

        // Populate from API response
        data.products.forEach(p => {
            products[p.product_type] = {
                count: p.unique_sensors,
                avg: p.avg_28day
            };
        });

        // Update UI - make 28-day average the PRIMARY number (billing number)
        document.getElementById('fcsc-avg').textContent = `${products['FCSC'].avg.toFixed(1)} Hosts`;
        document.getElementById('fcsc-count').textContent = `${products['FCSC'].count.toLocaleString()} Unique Hosts`;

        document.getElementById('fmc-avg').textContent = `${products['FMC'].avg.toFixed(1)} Hosts`;
        document.getElementById('fmc-count').textContent = `${products['FMC'].count.toLocaleString()} Unique Hosts`;

        document.getElementById('fcs-avg').textContent = `${products['FCS'].avg.toFixed(1)} Hosts`;
        document.getElementById('fcs-count').textContent = `${products['FCS'].count.toLocaleString()} Unique Hosts`;

        document.getElementById('epp-avg').textContent = `${products['EPP'].avg.toFixed(1)} Hosts`;
        document.getElementById('epp-count').textContent = `${products['EPP'].count.toLocaleString()} Unique Hosts`;

        // Calculate and display total 28-day average
        const totalAvg = data.total_avg_28day || 0;
        document.getElementById('avg-28day').textContent = totalAvg.toFixed(1);

    } catch (error) {
        console.error('Error loading product counts:', error);
    }
}

// Load overall statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        document.getElementById('total-sensors').textContent = data.total_sensors.toLocaleString();
        document.getElementById('total-hours').textContent = data.total_hours.toLocaleString();
        document.getElementById('avg-28day').textContent = data.avg_28day.toLocaleString();
        document.getElementById('unique-tags').textContent = data.unique_tags.toLocaleString();
        document.getElementById('cached-hosts').textContent = data.cached_hosts.toLocaleString();

        // Format date range
        const startDate = new Date(data.date_start).toLocaleDateString();
        const endDate = new Date(data.date_end).toLocaleDateString();
        document.getElementById('date-range').textContent = `${startDate} - ${endDate}`;

    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load charts
async function loadCharts(days = 7) {
    try {
        // Load hourly trend
        const hourlyResponse = await fetch(`/api/hourly_trend?days=${days}`);
        const hourlyData = await hourlyResponse.json();

        // Load daily averages
        const dailyResponse = await fetch(`/api/daily_averages?days=${days}`);
        const dailyData = await dailyResponse.json();

        renderHourlyChart(hourlyData);
        renderDailyChart(dailyData);

    } catch (error) {
        console.error('Error loading charts:', error);
    }
}

// Render hourly trend chart
function renderHourlyChart(data) {
    const ctx = document.getElementById('hourly-chart').getContext('2d');

    if (hourlyChart) {
        hourlyChart.destroy();
    }

    hourlyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => new Date(d.timestamp).toLocaleString()),
            datasets: [{
                label: 'Sensor Count',
                data: data.map(d => d.count),
                borderColor: '#e01f3d',
                backgroundColor: 'rgba(224, 31, 61, 0.1)',
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Render daily averages chart
function renderDailyChart(data) {
    const ctx = document.getElementById('daily-chart').getContext('2d');

    if (dailyChart) {
        dailyChart.destroy();
    }

    // Prepare data for min-max range visualization
    const labels = data.map(d => new Date(d.date).toLocaleDateString());
    const averages = data.map(d => d.avg);
    const mins = data.map(d => d.min);
    const maxs = data.map(d => d.max);

    dailyChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Max',
                    data: maxs,
                    borderColor: '#f39c12',
                    backgroundColor: 'rgba(243, 156, 18, 0.05)',
                    borderWidth: 1,
                    borderDash: [5, 5],
                    fill: false,
                    pointRadius: 3,
                    pointHoverRadius: 5
                },
                {
                    label: 'Average',
                    data: averages,
                    borderColor: '#e01f3d',
                    backgroundColor: 'rgba(224, 31, 61, 0.1)',
                    borderWidth: 3,
                    fill: '+1',
                    pointRadius: 4,
                    pointHoverRadius: 6
                },
                {
                    label: 'Min',
                    data: mins,
                    borderColor: '#27ae60',
                    backgroundColor: 'rgba(39, 174, 96, 0.05)',
                    borderWidth: 1,
                    borderDash: [5, 5],
                    fill: false,
                    pointRadius: 3,
                    pointHoverRadius: 5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                },
                tooltip: {
                    callbacks: {
                        afterBody: function(context) {
                            const index = context[0].dataIndex;
                            const range = maxs[index] - mins[index];
                            return [`Range: ${range} sensors`];
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Sensor Count'
                    }
                },
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}

// Load tag breakdown table
async function loadTagBreakdown() {
    try {
        const response = await fetch('/api/tag_breakdown?days=28&limit=20');
        const data = await response.json();

        const tbody = document.querySelector('#tag-table tbody');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No tag data available</td></tr>';
            return;
        }

        // Get total for percentage calculation
        const stats = await fetch('/api/stats').then(r => r.json());
        const total = stats.avg_28day;

        tbody.innerHTML = data.map(row => `
            <tr>
                <td><strong>${escapeHtml(row.tag)}</strong></td>
                <td>${row.avg_count.toFixed(2)}</td>
                <td>${row.hours_active}</td>
                <td>${((row.avg_count / total) * 100).toFixed(1)}%</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading tag breakdown:', error);
    }
}

// Load cloud provider breakdown table
async function loadCloudBreakdown() {
    try {
        const response = await fetch('/api/cloud_breakdown');
        const data = await response.json();

        const tbody = document.querySelector('#cloud-table tbody');

        if (!data.providers || data.providers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="loading">No cloud provider data available</td></tr>';
            return;
        }

        const total = data.total_avg_28day;

        tbody.innerHTML = data.providers.map(row => `
            <tr>
                <td><strong>${escapeHtml(row.cloud_provider || 'Unknown')}</strong></td>
                <td>${row.unique_sensors.toLocaleString()}</td>
                <td>${row.avg_28day.toFixed(2)}</td>
                <td>${row.fcs_avg.toFixed(2)}</td>
                <td>${row.fcsc_avg.toFixed(2)}</td>
                <td>${row.fmc_avg.toFixed(2)}</td>
                <td>${row.epp_avg.toFixed(2)}</td>
                <td>${total > 0 ? ((row.avg_28day / total) * 100).toFixed(1) : '0.0'}%</td>
            </tr>
        `).join('');

        // Update date range info if available
        if (data.date_range) {
            const startDate = new Date(data.date_range.start).toLocaleDateString();
            const endDate = new Date(data.date_range.end).toLocaleDateString();
            const totalDays = data.date_range.total_days;

            // Update the description text
            const cloudSection = document.querySelector('#cloud-table').closest('section');
            const description = cloudSection.querySelector('p');
            if (description) {
                description.innerHTML = `
                    Sensor distribution across cloud providers and on-premise environments by product type.<br>
                    <strong>Data range:</strong> ${startDate} to ${endDate} (${totalDays} days, ${data.date_range.total_hours} hours)
                `;
            }
        }

    } catch (error) {
        console.error('Error loading cloud breakdown:', error);
    }
}

// Load recent sensors table
async function loadRecentSensors() {
    try {
        const response = await fetch('/api/recent_sensors?limit=50');
        const data = await response.json();

        const tbody = document.querySelector('#sensors-table tbody');

        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No sensor data available</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(row => `
            <tr>
                <td><strong>${escapeHtml(row.hostname)}</strong></td>
                <td>${escapeHtml(row.platform)}</td>
                <td>${escapeHtml(row.tags)}</td>
                <td>${new Date(row.last_seen).toLocaleString()}</td>
            </tr>
        `).join('');

    } catch (error) {
        console.error('Error loading recent sensors:', error);
    }
}

// Export data as CSV
function exportData(type) {
    const days = document.getElementById('days-selector').value;
    window.location.href = `/api/export/csv?type=${type}&days=${days}`;
}

// Calculate licensing compliance
async function calculateCompliance() {
    const reservedAvg = document.getElementById('reserved-hourly-avg').value;

    try {
        const response = await fetch(
            `/api/licensing/compliance?reserved_hourly_avg=${reservedAvg}&days=28`
        );
        const data = await response.json();

        // Update status card
        const statusCard = document.getElementById('compliance-card');
        const statusIcon = document.getElementById('status-icon');
        const statusText = document.getElementById('compliance-status');
        const statusMessage = document.getElementById('compliance-message');

        // Reset classes
        statusCard.className = 'compliance-card';

        // Set status based on overall_status
        if (data.overall_status === 'compliant') {
            statusCard.classList.add('success');
            statusIcon.textContent = '✅';
            statusText.textContent = 'Compliant';
        } else if (data.overall_status === 'over_reserved') {
            statusCard.classList.add('error');
            statusIcon.textContent = '❌';
            statusText.textContent = 'Exceeds Reserved Limit';
        } else {
            statusCard.classList.add('warning');
            statusIcon.textContent = 'ℹ️';
            statusText.textContent = 'No Licenses Configured';
        }

        statusMessage.textContent = data.compliance_message;

        // Update detail cards - match product card format
        document.getElementById('rolling-avg').textContent = data.rolling_avg_28day.toFixed(1);
        document.getElementById('reserved-limit-text').textContent = `vs ${data.reserved_hourly_avg_license || 0} reserved`;
        document.getElementById('max-usage').textContent = data.max_hourly_usage;

        // Calculate percentage for hours over reserved
        const hoursOverPct = data.hours_analyzed > 0
            ? ((data.hours_over_reserved / data.hours_analyzed) * 100).toFixed(1)
            : '0.0';
        document.getElementById('hours-over-pct').textContent = hoursOverPct + '%';
        document.getElementById('hours-over-detail').textContent =
            `${data.hours_over_reserved}/${data.hours_analyzed} hours`;

        // Render compliance chart
        renderComplianceChart(data);

        // Scroll to compliance section
        document.getElementById('compliance-section').scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (error) {
        console.error('Error calculating compliance:', error);
        alert('Failed to calculate compliance. Please try again.');
    }
}

// Render compliance chart
function renderComplianceChart(data) {
    const ctx = document.getElementById('compliance-chart').getContext('2d');

    if (complianceChart) {
        complianceChart.destroy();
    }

    const labels = data.hourly_compliance.map(d => new Date(d.timestamp).toLocaleString());
    const rollingAvgs = data.hourly_compliance.map(d => d.rolling_avg);
    const counts = data.hourly_compliance.map(d => d.count);

    // Calculate smart Y-axis range using both rolling averages and hourly counts
    // Combine both datasets to ensure all data points are visible
    const allValues = [...rollingAvgs, ...counts];
    const sortedValues = [...allValues].sort((a, b) => a - b);

    // Use interquartile range (IQR) method to identify outliers
    const q1Index = Math.floor(sortedValues.length * 0.25);
    const q3Index = Math.floor(sortedValues.length * 0.75);
    const q1 = sortedValues[q1Index];
    const q3 = sortedValues[q3Index];
    const iqr = q3 - q1;

    // Define outlier boundaries (values beyond 1.5 * IQR are outliers)
    const lowerBound = q1 - 1.5 * iqr;
    const upperBound = q3 + 1.5 * iqr;

    // Filter out extreme outliers but keep the rest
    const cleanData = allValues.filter(val => val >= lowerBound && val <= upperBound);

    // Get the actual min/max from clean data
    const dataMin = Math.min(...cleanData);
    const dataMax = Math.max(...cleanData);
    const dataRange = dataMax - dataMin;

    // Add generous 25% buffer to ensure all data points are comfortably visible
    let yMin = Math.max(0, dataMin - dataRange * 0.25);
    let yMax = dataMax + dataRange * 0.25;

    // Determine license limit line
    const licenseLimit = data.reserved_hourly_avg_license > 0 ?
        data.reserved_hourly_avg_license : data.reserved_hourly_license;

    // Ensure license limit is visible in the chart
    if (licenseLimit > 0) {
        yMin = Math.min(yMin, licenseLimit - dataRange * 0.15);
        yMax = Math.max(yMax, licenseLimit + dataRange * 0.15);
    }

    // Final safety check: ensure yMax is at least slightly higher than the highest value
    const absoluteMax = Math.max(...allValues);
    const absoluteMin = Math.min(...allValues);
    if (absoluteMax > yMax) {
        yMax = absoluteMax * 1.05; // Add 5% above the absolute max
    }
    if (absoluteMin < yMin) {
        yMin = Math.max(0, absoluteMin * 0.95); // Subtract 5% below absolute min
    }

    const datasets = [
        {
            label: '28-Day Rolling Average',
            data: rollingAvgs,
            borderColor: '#2980b9',
            backgroundColor: 'rgba(41, 128, 185, 0.1)',
            tension: 0.3,
            fill: true,
            borderWidth: 3
        },
        {
            label: 'Hourly Sensor Count',
            data: counts,
            borderColor: '#e01f3d',
            backgroundColor: 'rgba(224, 31, 61, 0.05)',
            tension: 0.3,
            fill: false,
            borderWidth: 1,
            borderDash: [2, 2]
        }
    ];

    // Add license limit line if configured
    if (licenseLimit > 0) {
        datasets.push({
            label: 'Reserved License Limit',
            data: Array(counts.length).fill(licenseLimit),
            borderColor: '#27ae60',
            borderDash: [5, 5],
            borderWidth: 2,
            fill: false,
            pointRadius: 0
        });
    }

    complianceChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: true
                },
                tooltip: {
                    callbacks: {
                        afterLabel: function(context) {
                            const index = context.dataIndex;
                            const dataPoint = data.hourly_compliance[index];
                            return [
                                `Hourly: ${dataPoint.count}`,
                                `Rolling Avg: ${dataPoint.rolling_avg}`,
                                dataPoint.overage > 0 ? `Overage: ${dataPoint.overage}` : ''
                            ].filter(line => line !== '');
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                },
                y: {
                    min: yMin,
                    max: yMax,
                    title: {
                        display: true,
                        text: 'Sensor Count'
                    }
                }
            }
        }
    });
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Filter table rows based on search text
function filterTable(tableId, filterText) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows = tbody.querySelectorAll('tr:not(.loading)');

    const filter = filterText.toLowerCase();

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? '' : 'none';
    });
}

// Set up table sorting for sortable columns
function setupTableSorting(tableId) {
    const table = document.getElementById(tableId);
    const headers = table.querySelectorAll('th[data-sort]');

    headers.forEach((header, index) => {
        header.addEventListener('click', () => {
            sortTable(tableId, index, header.dataset.sort);
        });
    });
}

// Sort table by column
function sortTable(tableId, columnIndex, sortType) {
    const table = document.getElementById(tableId);
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr:not(.loading)'));

    // Determine sort direction
    const header = table.querySelectorAll('th')[columnIndex];
    const isAscending = header.classList.contains('sort-asc');

    // Remove sort indicators from all headers
    table.querySelectorAll('th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
    });

    // Sort rows
    rows.sort((a, b) => {
        const aValue = a.cells[columnIndex].textContent.trim();
        const bValue = b.cells[columnIndex].textContent.trim();

        let comparison = 0;

        if (sortType === 'number') {
            const aNum = parseFloat(aValue.replace(/[^0-9.-]/g, ''));
            const bNum = parseFloat(bValue.replace(/[^0-9.-]/g, ''));
            comparison = aNum - bNum;
        } else {
            comparison = aValue.localeCompare(bValue);
        }

        return isAscending ? -comparison : comparison;
    });

    // Update sort indicator
    header.classList.add(isAscending ? 'sort-desc' : 'sort-asc');

    // Reorder rows in DOM
    rows.forEach(row => tbody.appendChild(row));
}

// Load product breakdown statistics

// Load product trend chart
async function loadProductTrendChart() {
    try {
        const response = await fetch('/api/product_trend?days=7');
        const data = await response.json();

        const ctx = document.getElementById('product-trend-chart').getContext('2d');

        // Destroy existing chart if it exists
        if (window.productTrendChart) {
            window.productTrendChart.destroy();
        }

        // Prepare data for stacked area chart
        const labels = data.map(d => {
            const date = new Date(d.timestamp);
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit'
            });
        });

        window.productTrendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'FCSC (Container Hosts)',
                        data: data.map(d => d.FCSC),
                        borderColor: 'rgb(54, 162, 235)',
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'FMC (Fargate/Sidecars)',
                        data: data.map(d => d.FMC),
                        borderColor: 'rgb(255, 99, 132)',
                        backgroundColor: 'rgba(255, 99, 132, 0.5)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'FCS (Cloud VMs)',
                        data: data.map(d => d.FCS),
                        borderColor: 'rgb(75, 192, 192)',
                        backgroundColor: 'rgba(75, 192, 192, 0.5)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'EPP (Endpoints)',
                        data: data.map(d => d.EPP),
                        borderColor: 'rgb(153, 102, 255)',
                        backgroundColor: 'rgba(153, 102, 255, 0.5)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        position: 'top'
                    },
                    tooltip: {
                        callbacks: {
                            footer: function(context) {
                                let sum = 0;
                                context.forEach(item => sum += item.parsed.y);
                                return 'Total: ' + sum;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        ticks: {
                            maxRotation: 45,
                            minRotation: 45
                        }
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Sensor Count'
                        }
                    }
                }
            }
        });

    } catch (error) {
        console.error('Error loading product trend chart:', error);
    }
}
