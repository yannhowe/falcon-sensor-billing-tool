// Load FCS licensing data on page load
document.addEventListener('DOMContentLoaded', () => {
    loadFCSData();
});

// Global data storage for filtering
let allData = null;

// Sorting state
let cidSortColumn = null;
let cidSortDirection = 'asc';
let tagSortColumn = null;
let tagSortDirection = 'asc';

// Load FCS licensing summary
async function loadFCSData() {
    try {
        const response = await fetch('/api/fcs/summary');
        const data = await response.json();

        // Store for filtering
        allData = data;

        // Populate CID filter dropdown
        const cidFilter = document.getElementById('cid-filter');
        cidFilter.innerHTML = '<option value="">All CIDs</option>' +
            data.cids.map(cid => `<option value="${escapeHtml(cid.cid)}">${escapeHtml(cid.cid)}</option>`).join('');

        // Display data
        displayData(data);

    } catch (error) {
        console.error('Error loading FCS data:', error);
        document.getElementById('overall-avg').textContent = 'Error';
        document.getElementById('overall-max').textContent = 'Error';
        document.getElementById('hours-collected').textContent = 'Error';
    }
}

// Apply CID filter
function applyFilters() {
    if (!allData) return;

    const cidFilter = document.getElementById('cid-filter').value;

    let filteredData = {...allData};

    if (cidFilter) {
        // Filter CIDs
        filteredData.cids = allData.cids.filter(cid => cid.cid === cidFilter);

        // Filter tags for selected CID (would need API support)
        // For now, show all tags with note
        filteredData.tags = allData.tags;

        // Recalculate overall stats
        if (filteredData.cids.length > 0) {
            const selectedCid = filteredData.cids[0];
            filteredData.overall_avg_sensors = selectedCid.avg_sensors;
            filteredData.overall_max_sensors = selectedCid.max_sensors;
            filteredData.hours_in_window = selectedCid.hours_collected;
        }
    }

    displayData(filteredData);
}

// Filter tags by search
function filterTags() {
    const search = document.getElementById('tag-search').value.toLowerCase();
    const rows = document.querySelectorAll('#tag-table tbody tr');

    let visibleTotal = 0;
    let visibleCount = 0;

    rows.forEach(row => {
        // Skip total row - always keep it visible
        if (row.classList.contains('total-row')) {
            return;
        }

        const tagCell = row.cells[0];
        if (tagCell && !tagCell.classList.contains('loading')) {
            const tagText = tagCell.textContent.toLowerCase();
            const isVisible = tagText.includes(search);
            row.style.display = isVisible ? '' : 'none';

            // Sum allocation units for visible rows
            if (isVisible) {
                visibleCount++;
                const allocationCell = row.cells[4];
                if (allocationCell) {
                    const allocation = parseInt(allocationCell.textContent.replace(/,/g, '')) || 0;
                    visibleTotal += allocation;
                }
            }
        }
    });

    // Update visible total and count
    updateTagTotal(visibleTotal, visibleCount);
}

// Sort data array
function sortData(data, column, direction, type = 'number') {
    return [...data].sort((a, b) => {
        let valA = a[column];
        let valB = b[column];

        // Handle string comparison (for CID)
        if (type === 'string') {
            valA = String(valA).toLowerCase();
            valB = String(valB).toLowerCase();
            return direction === 'asc'
                ? valA.localeCompare(valB)
                : valB.localeCompare(valA);
        }

        // Handle numeric comparison
        const numA = parseFloat(valA) || 0;
        const numB = parseFloat(valB) || 0;
        return direction === 'asc' ? numA - numB : numB - numA;
    });
}

// Sort CID table
function sortCIDTable(column, type = 'number') {
    if (!allData) return;

    // Toggle direction if same column, otherwise default to descending
    if (cidSortColumn === column) {
        cidSortDirection = cidSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        cidSortColumn = column;
        cidSortDirection = 'desc';
    }

    // Sort the data
    const sortedCids = sortData(allData.cids, column, cidSortDirection, type);

    // Update data and redisplay
    const filteredData = {...allData, cids: sortedCids};
    displayData(filteredData);

    // Update sort indicators
    updateSortIndicators('cid-table', column, cidSortDirection);
}

// Sort tag table
function sortTagTable(column, type = 'number') {
    if (!allData) return;

    // Toggle direction if same column, otherwise default to descending
    if (tagSortColumn === column) {
        tagSortDirection = tagSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        tagSortColumn = column;
        tagSortDirection = 'desc';
    }

    // Sort the data
    const sortedTags = sortData(allData.tags, column, tagSortDirection, type);

    // Update data and redisplay
    const filteredData = {...allData, tags: sortedTags};
    displayData(filteredData);

    // Update sort indicators
    updateSortIndicators('tag-table', column, tagSortDirection);
}

// Update sort indicators in table headers
function updateSortIndicators(tableId, activeColumn, direction) {
    const headers = document.querySelectorAll(`#${tableId} th[data-sort]`);
    headers.forEach(header => {
        const column = header.getAttribute('data-sort');
        header.classList.remove('sort-asc', 'sort-desc');
        if (column === activeColumn) {
            header.classList.add(`sort-${direction}`);
        }
    });
}

// Display data in UI
function displayData(data) {
    // Update overall summary
    document.getElementById('overall-avg').textContent = data.overall_avg_sensors.toLocaleString();
    document.getElementById('overall-max').textContent = data.overall_max_sensors.toLocaleString();
    document.getElementById('hours-collected').textContent = `${data.hours_in_window} / ${data.target_hours}`;

    // Populate CID table
    const cidTable = document.querySelector('#cid-table tbody');
    if (data.cids.length === 0) {
        cidTable.innerHTML = '<tr><td colspan="6" class="loading">No data available</td></tr>';
    } else {
        cidTable.innerHTML = data.cids.map(cid => `
            <tr>
                <td><strong>${escapeHtml(cid.cid)}</strong></td>
                <td>${cid.avg_sensors.toFixed(2)}</td>
                <td>${cid.max_sensors}</td>
                <td>${cid.min_sensors}</td>
                <td>${cid.hours_collected} / ${data.target_hours}</td>
                <td class="licenses-cell">${cid.licenses_required}</td>
            </tr>
        `).join('');

        // Add total row
        const totalLicenses = data.cids.reduce((sum, cid) => sum + cid.licenses_required, 0);
        cidTable.innerHTML += `
            <tr class="total-row">
                <td><strong>TOTAL (${data.cids.length} CID${data.cids.length > 1 ? 's' : ''})</strong></td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td class="licenses-cell"><strong>${totalLicenses.toLocaleString()}</strong></td>
            </tr>
        `;
    }

    // Populate tag table
    const tagTable = document.querySelector('#tag-table tbody');
    if (data.tags.length === 0) {
        tagTable.innerHTML = '<tr><td colspan="5" class="loading">No tag data available</td></tr>';
    } else {
        tagTable.innerHTML = data.tags.map(tag => `
            <tr>
                <td><strong>${escapeHtml(tag.tag)}</strong></td>
                <td>${tag.avg_sensors.toFixed(2)}</td>
                <td>${tag.max_sensors}</td>
                <td>${tag.hours_active}</td>
                <td class="licenses-cell">${tag.allocation_units}</td>
            </tr>
        `).join('');

        // Add total row
        const totalAllocation = data.tags.reduce((sum, tag) => sum + tag.allocation_units, 0);
        tagTable.innerHTML += `
            <tr class="total-row">
                <td><strong>TOTAL (<span id="tag-count">${data.tags.length}</span> tag${data.tags.length > 1 ? 's' : ''})</strong></td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
                <td class="licenses-cell"><strong id="tag-total">${totalAllocation.toLocaleString()}</strong></td>
            </tr>
        `;
    }

    // Apply tag search filter if active
    const tagSearch = document.getElementById('tag-search');
    if (tagSearch && tagSearch.value) {
        filterTags();
    } else {
        // Initialize total without filter
        const totalAllocation = data.tags.reduce((sum, tag) => sum + tag.allocation_units, 0);
        updateTagTotal(totalAllocation, data.tags.length);
    }
}

// Update tag total display
function updateTagTotal(total, count) {
    const tagTotalElement = document.getElementById('tag-total');
    if (tagTotalElement) {
        tagTotalElement.textContent = total.toLocaleString();
    }

    const tagCountElement = document.getElementById('tag-count');
    if (tagCountElement) {
        tagCountElement.textContent = count;
    }
}

// Export data as CSV
function exportData(type) {
    window.location.href = `/api/fcs/export?type=${type}`;
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
