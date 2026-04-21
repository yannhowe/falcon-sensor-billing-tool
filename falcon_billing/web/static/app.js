// ===== FCS LICENSING FUNCTIONS =====

let fcsAllData = null;
let cidSortColumn = null;
let cidSortDirection = 'asc';
let tagSortColumn = null;
let tagSortDirection = 'asc';

async function loadFCSData() {
    try {
        const response = await apiFetch('/api/fcs/summary');
        const data = await response.json();

        fcsAllData = data;

        const cidFilter = document.getElementById('cid-filter');
        if (cidFilter) {
            cidFilter.innerHTML = '<option value="">All CIDs</option>' +
                data.cids.map(cid => `<option value="${escapeHtml(cid.cid)}">${escapeHtml(cid.cid)}</option>`).join('');
        }

        displayFCSData(data);

    } catch (error) {
        console.error('Error loading FCS data:', error);
        const el = document.getElementById('overall-avg');
        if (el) el.textContent = 'Error';
    }
}

function applyFilters() {
    if (!fcsAllData) return;

    const cidFilter = document.getElementById('cid-filter').value;
    let filteredData = {...fcsAllData};

    if (cidFilter) {
        filteredData.cids = fcsAllData.cids.filter(cid => cid.cid === cidFilter);
        filteredData.tags = fcsAllData.tags;

        if (filteredData.cids.length > 0) {
            const selectedCid = filteredData.cids[0];
            filteredData.overall_avg_sensors = selectedCid.avg_sensors;
            filteredData.overall_max_sensors = selectedCid.max_sensors;
            filteredData.hours_in_window = selectedCid.hours_collected;
        }
    }

    displayFCSData(filteredData);
}

function filterFCSTags() {
    const search = document.getElementById('tag-search').value.toLowerCase();
    const rows = document.querySelectorAll('#tag-table-fcs tbody tr');

    let visibleCount = 0;
    let visibleAllocation = 0;

    rows.forEach(row => {
        if (row.classList.contains('total-row')) return;
        const tagCell = row.cells[0];
        if (tagCell && !tagCell.classList.contains('loading')) {
            const tagText = tagCell.textContent.toLowerCase();
            const visible = tagText.includes(search);
            row.style.display = visible ? '' : 'none';
            if (visible) {
                visibleCount++;
                const allocCell = row.cells[row.cells.length - 1];
                visibleAllocation += parseInt(allocCell.textContent) || 0;
            }
        }
    });

    // Update total row to reflect visible rows only
    const totalRow = document.querySelector('#tag-table-fcs tbody tr.total-row');
    if (totalRow) {
        totalRow.cells[0].innerHTML = `<strong>TOTAL (${visibleCount} tags)</strong>`;
        totalRow.cells[totalRow.cells.length - 1].innerHTML = `<strong>${visibleAllocation.toLocaleString()}</strong>`;
    }
}

function sortCIDTable(column, type = 'number') {
    if (!fcsAllData) return;

    if (cidSortColumn === column) {
        cidSortDirection = cidSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        cidSortColumn = column;
        cidSortDirection = 'desc';
    }

    const sortedCids = sortFCSData(fcsAllData.cids, column, cidSortDirection, type);
    const filteredData = {...fcsAllData, cids: sortedCids};
    displayFCSData(filteredData);

    updateFCSSortIndicators('cid-table', column, cidSortDirection);
}

function sortTagTable(column, type = 'number') {
    if (!fcsAllData) return;

    if (tagSortColumn === column) {
        tagSortDirection = tagSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        tagSortColumn = column;
        tagSortDirection = 'desc';
    }

    const sortedTags = sortFCSData(fcsAllData.tags, column, tagSortDirection, type);
    const filteredData = {...fcsAllData, tags: sortedTags};
    displayFCSData(filteredData);

    updateFCSSortIndicators('tag-table-fcs', column, tagSortDirection);
}

function sortFCSData(data, column, direction, type = 'number') {
    return [...data].sort((a, b) => {
        let valA = a[column];
        let valB = b[column];

        if (type === 'string') {
            valA = String(valA).toLowerCase();
            valB = String(valB).toLowerCase();
            return direction === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
        }

        const numA = parseFloat(valA) || 0;
        const numB = parseFloat(valB) || 0;
        return direction === 'asc' ? numA - numB : numB - numA;
    });
}

function updateFCSSortIndicators(tableId, activeColumn, direction) {
    const headers = document.querySelectorAll(`#${tableId} th[data-sort]`);
    headers.forEach(header => {
        const column = header.getAttribute('data-sort');
        header.classList.remove('sort-asc', 'sort-desc');
        if (column === activeColumn) {
            header.classList.add(`sort-${direction}`);
        }
    });
}

function displayFCSData(data) {
    const overallAvg = document.getElementById('overall-avg');
    if (overallAvg) overallAvg.textContent = data.overall_avg_sensors.toLocaleString();

    const overallMax = document.getElementById('overall-max');
    if (overallMax) overallMax.textContent = data.overall_max_sensors.toLocaleString();

    const hoursCollected = document.getElementById('hours-collected');
    if (hoursCollected) hoursCollected.textContent = `${data.hours_in_window} / ${data.target_hours}`;

    // CID table
    const cidTable = document.querySelector('#cid-table tbody');
    if (cidTable) {
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

            const totalLicenses = data.cids.reduce((sum, cid) => sum + cid.licenses_required, 0);
            cidTable.innerHTML += `
                <tr class="total-row">
                    <td><strong>TOTAL (${data.cids.length} CID${data.cids.length > 1 ? 's' : ''})</strong></td>
                    <td>-</td><td>-</td><td>-</td><td>-</td>
                    <td class="licenses-cell"><strong>${totalLicenses.toLocaleString()}</strong></td>
                </tr>
            `;
        }
    }

    // Tag table
    const tagTable = document.querySelector('#tag-table-fcs tbody');
    if (tagTable) {
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

            const totalAllocation = data.tags.reduce((sum, tag) => sum + tag.allocation_units, 0);
            tagTable.innerHTML += `
                <tr class="total-row">
                    <td><strong>TOTAL (${data.tags.length} tags)</strong></td>
                    <td>-</td><td>-</td><td>-</td>
                    <td class="licenses-cell"><strong>${totalAllocation.toLocaleString()}</strong></td>
                </tr>
            `;
        }
    }
}

// ===== EXPORT =====

function exportFCSData(type) {
    const key = apiKey ? `&api_key=${encodeURIComponent(apiKey)}` : '';
    window.location.href = `/api/fcs/export?type=${type}${key}`;
}
