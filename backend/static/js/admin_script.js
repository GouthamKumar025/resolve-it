let zoomed = false;

// Function to display the image in the modal
function showImage(imageData, mimeType) {
const modal = document.getElementById('imageModal');
const modalImage = document.getElementById('modalImage');
const downloadLink = document.getElementById('downloadImage');

// Reset zoom on a new image
modalImage.style.transform = 'scale(1)';
modalImage.style.cursor = 'zoom-in';
zoomed = false;

// Set the modal image source
modalImage.src = `data:${mimeType};base64,${imageData}`;
downloadLink.href = `data:${mimeType};base64,${imageData}`;
modal.style.display = 'flex';
} 

// Function to close the modal
function closeImage() {
const modal = document.getElementById('imageModal');
modal.style.display = 'none';
zoomed = false; 
}
// Function to zoom the image
function zoomImage() {
    const modalImage = document.getElementById('modalImage');
    if (!zoomed) {
        modalImage.style.transform = 'scale(1.5)';
        modalImage.style.maxWidth = '85vh'; // Limit width when zoomed
        modalImage.style.maxHeight = '85vh';
        modalImage.style.cursor = 'zoom-out';
        zoomed = true;
    } else {
        modalImage.style.transform = 'scale(1)';
        modalImage.style.cursor = 'zoom-in';
        zoomed = false;
    }
}

// JavaScript function to confirm delete action
function confirmDelete() {
    return confirm("Are you sure you want to delete this query?");
}

// Close modal when clicking outside the modal content
window.onclick = function(event) {
const modal = document.getElementById('imageModal');
if (event.target === modal) {
    modal.style.display = 'none';
}
};

// Search box 
document.addEventListener("DOMContentLoaded", function () {
    let searchBox = document.getElementById("searchBox");

    if (searchBox) {
        searchBox.addEventListener("keyup", function () {
            let filter = searchBox.value.toUpperCase().trim();
            let rows = document.querySelectorAll("tbody tr");

            rows.forEach(row => {
                let text = row.innerText.toUpperCase();
                row.style.display = text.includes(filter) ? "" : "none";
            });
        });
    }
});

// Update Status function with dynamic text update
function updateStatus(button) {
    let selectElement = button.previousElementSibling; // Get the dropdown next to the button
    let queryId = selectElement.getAttribute('data-query-id');
    let userId = selectElement.getAttribute('data-user-id');
    let newStatus = selectElement.value;

    fetch('/update_status', {
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
        body: JSON.stringify({ query_id: queryId, user_id: userId, status: newStatus })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // ✅ Update the text in the column dynamically
            let statusText = document.querySelector(`#status-${queryId}`);
            if (statusText) {
                statusText.textContent = newStatus;
            }
            alert('✅ Status updated successfully!');
        } else {
            alert('❌ Error updating status.');
        }
    })
    .catch(error => console.error('❌ Error:', error));
}

// Update Severity function
function updateSeverity(button) {
let selectElement = button.previousElementSibling; // Get the dropdown
let queryId = selectElement.getAttribute('data-query-id');
let userId = selectElement.getAttribute('data-user-id');
let newSeverity = selectElement.value;

fetch('/update_severity', {
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    body: JSON.stringify({ query_id: queryId, user_id: userId, severity: newSeverity })
})
.then(response => response.json()) 
.then(data => {
    if (data.success) {
        // Instantly update severity in the table
        let severityCell = document.querySelector(`#severity-${queryId}`);
        if (severityCell) {
            severityCell.innerHTML = newSeverity; // Update text content
        }

        // Hide the dropdown and button after updating
        selectElement.style.display = 'none';
        button.style.display = 'none';

        alert('Severity updated successfully!');
    } else {
        alert('Error updating severity.');
    }
})
.catch(error => console.error('Error:', error));
}

function updateScenario(button) {
    let row = button.closest('tr');
    let dropdown = row.querySelector('.scenario-dropdown');
    
    let queryId = dropdown.getAttribute('data-query-id');
    let userId = dropdown.getAttribute('data-user-id');  
    let newScenario = dropdown.value;

    if (!queryId || !userId || !newScenario) {
        alert("Error: Missing parameters in request.");
        console.error("Missing Parameters:", { queryId, userId, newScenario });
        return;
    }

    fetch('/update_scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query_id: queryId, user_id: userId, scenario: newScenario }) 
    })
    .then(response => response.json()) 
    .then(data => {
        if (data.success) {
            alert('Scenario updated successfully!');
            // Hide the dropdown and button after updating
            dropdown.style.display = 'none';
            button.style.display = 'none';

        } else { 
            alert('Error updating scenario: ' + data.error);
        }
    })
    .catch(error => console.error('Fetch Error:', error));
}

// Sort Function
document.addEventListener("DOMContentLoaded", function () {
    const sortBy = document.getElementById("sortBy");
    const table = document.querySelector("table tbody");
    let sortDirection = 1; // 1 = Ascending, -1 = Descending

    sortBy.addEventListener("change", function () {
        let columnIndex = parseInt(this.value);
        let rows = Array.from(table.querySelectorAll("tr"));

        rows.sort((rowA, rowB) => {
            let cellA = rowA.cells[columnIndex]?.textContent.trim().toLowerCase() || "";
            let cellB = rowB.cells[columnIndex]?.textContent.trim().toLowerCase() || "";

            // ✅ Sort by Date (Newest → Oldest & Oldest → Newest)
            if (columnIndex === 4) {  
                let dateA = new Date(cellA) || new Date(0);
                let dateB = new Date(cellB) || new Date(0);
                return (dateB - dateA) * sortDirection;
            }

            // ✅ Sort by Severity (High → Low & vice versa)
            else if (columnIndex === 6) {  
                const severityOrder = { "high severity": 3, "medium severity": 2, "low severity": 1 };
                return ((severityOrder[cellB] || 0) - (severityOrder[cellA] || 0)) * sortDirection;
            }

            // ✅ Sort by Status (Pending → Done & vice versa)
            else if (columnIndex === 8) {  
                const statusOrder = { "done": 3, "in progress": 2, "pending": 1 };
                return ((statusOrder[cellB] || 0) - (statusOrder[cellA] || 0)) * sortDirection;
            }

            // ✅ Default: Sort Alphabetically (A → Z & Z → A)
            else {  
                return cellA.localeCompare(cellB) * sortDirection;
            }
        });

        // 🔄 Toggle Sorting Direction for Next Click
        sortDirection *= -1;

        // 🚀 Optimize Performance: Use DocumentFragment
        let fragment = document.createDocumentFragment();
        rows.forEach(row => fragment.appendChild(row));
        table.innerHTML = ""; // Clear table before inserting
        table.appendChild(fragment);
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const userChartCanvas = document.getElementById("userChart").getContext("2d");
    const queryChartCanvas = document.getElementById("queryChart").getContext("2d");

    // Convert JSON Data
    let userData = JSON.parse('{{ user_data | tojson | safe }}'); 
    let queryData = JSON.parse('{{ query_data | tojson | safe }}');

    // Initial Render
    let userChart = new Chart(userChartCanvas, {
        type: 'bar',
        data: generateUserChartData(userData)
    });

    let queryChart = new Chart(queryChartCanvas, {
        type: 'pie',
        data: generateQueryChartData(queryData)
    });

    // Filter Button Event
    document.getElementById("filterBtn").addEventListener("click", function () {
        let startDate = document.getElementById("startDate").value;
        let endDate = document.getElementById("endDate").value;

        if (!startDate || !endDate) {
            alert("Please select both start and end dates.");
            return;
        }

        let filteredUserData = userData.filter(item => item.date >= startDate && item.date <= endDate);
        let filteredQueryData = queryData.filter(item => item.date >= startDate && item.date <= endDate);

        userChart.destroy();
        queryChart.destroy();

        userChart = new Chart(userChartCanvas, {
            type: "bar",
            data: generateUserChartData(filteredUserData)
        });

        queryChart = new Chart(queryChartCanvas, {
            type: "pie",
            data: generateQueryChartData(filteredQueryData)
        });
    });

    // Function to Generate User Chart Data
    function generateUserChartData(data) {
        let userCounts = {};
        data.forEach(item => {
            if (!userCounts[item.user]) {
                userCounts[item.user] = 0;
            }
            userCounts[item.user] += item.queries;
        });

        return {
            labels: Object.keys(userCounts),
            datasets: [{
                label: 'Queries per User',
                data: Object.values(userCounts),
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        };
    }

    // Function to Generate Query Chart Data
    function generateQueryChartData(data) {
        let statusCounts = { "Pending": 0, "In Progress": 0, "Resolved": 0 };
        data.forEach(item => {
            if (statusCounts[item.status] !== undefined) {
                statusCounts[item.status]++;
            }
        });

        return {
            labels: Object.keys(statusCounts),
            datasets: [{
                label: 'Issue Status',
                data: Object.values(statusCounts),
                backgroundColor: ['#ffcc00', '#007bff', '#28a745'],
                borderColor: ['#d4a400', '#0056b3', '#1e7e34'],
                borderWidth: 1
            }]
        };
    }
});
