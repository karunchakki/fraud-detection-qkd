// static/js/qkd.js

/**
 * Initializes the QBER history chart using Chart.js.
 * Expects data arrays (labels, QBER values) and threshold value
 * to be injected into global `window` variables by the Flask template (qkd.html).
 */
document.addEventListener('DOMContentLoaded', function () {
    const canvasElement = document.getElementById('qberChart');
    const simulationDataExists = typeof window.qkdChartLabels !== 'undefined'; // Basic check if data was injected

    if (!canvasElement) {
        // console.log("QBER Chart canvas not found on this page.");
        return; // Exit if canvas doesn't exist
    }

    // --- Get Data (Safely access potentially undefined global vars) ---
    const labels = window.qkdChartLabels || ['No Data'];
    const qberData = window.qkdChartQberData || [0];
    const qberThreshold = typeof window.qkdChartQberThreshold === 'number'
        ? window.qkdChartQberThreshold // Expecting percentage value
        : 15.0; // Default to 15%

    // Basic validation
    if (!Array.isArray(labels) || !Array.isArray(qberData) || labels.length !== qberData.length) {
        console.error("Invalid or mismatched chart data provided.", { labels, qberData });
        canvasElement.parentElement.innerHTML = '<p class="text-red-500 text-center text-sm p-4">Error: Invalid data for QBER chart.</p>';
        return;
    }
     if (labels.length === 0 || (labels.length === 1 && labels[0] === 'N/A')) { // Check for empty or default 'N/A'
         console.log("No QBER history data provided for chart.");
         canvasElement.parentElement.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-center text-sm p-4">No QBER history data available to display.</p>';
         return;
     }

    // --- Chart Configuration ---
    try {
        // Ensure thresholdData array matches the length of actual data labels
        const thresholdData = Array(labels.length).fill(qberThreshold);

        new Chart(canvasElement, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'QBER (%)', // Simplified label
                    data: qberData,
                    borderColor: 'rgb(59, 130, 246)', // Tailwind blue-500
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.1,
                    pointBackgroundColor: 'rgb(59, 130, 246)',
                    pointRadius: 3,
                    pointHoverRadius: 5
                 },
                 { // Threshold Line
                    label: 'Threshold (%)', // Simplified label
                    data: thresholdData,
                    borderColor: 'rgb(239, 68, 68)', // Tailwind red-500
                    borderWidth: 2,
                    borderDash: [6, 6],
                    pointRadius: 0,
                    fill: false,
                    tension: 0
                 }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: { display: true, text: 'QBER (%)' },
                        suggestedMax: Math.max(25, qberThreshold * 1.2), // Ensure threshold is visible
                        grid: { color: 'rgba(200, 200, 200, 0.1)'} // Lighter grid lines
                    },
                    x: {
                        title: {display: true, text: 'Transaction Log ID'}, // Updated label
                        grid: { display: false } // Hide vertical grid lines
                    }
                },
                 plugins: {
                     legend: {
                         position: 'top', // Changed from bottom for potentially better layout
                         labels: { padding: 15 }
                     },
                     tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                        titleFont: { weight: 'bold' },
                        bodySpacing: 4,
                        padding: 10,
                        // --- UPDATED TOOLTIP CALLBACK ---
                        callbacks: {
                            label: function(context) {
                                let lineLabel = context.dataset.label || ''; // e.g., 'QBER (%)' or 'Threshold (%)'
                                const pointLabel = context.label || ''; // e.g., 'Log 123'
                                const value = context.parsed.y; // The numerical y-value

                                if (value === null || typeof value === 'undefined') {
                                    return lineLabel; // Don't show value if null/undefined
                                }

                                let finalLabel = '';
                                // Add Log ID prefix for QBER points, but not for the threshold line
                                if (!lineLabel.includes('Threshold')) {
                                    finalLabel += `${pointLabel} - `; // Add 'Log XXX - ' prefix
                                }

                                // Add the specific metric and formatted value
                                if (lineLabel.includes('Threshold')) {
                                    finalLabel += `Threshold: ${value.toFixed(1)}%`;
                                } else {
                                    finalLabel += `QBER: ${value.toFixed(2)}%`;
                                }
                                return finalLabel;
                            }
                        } // --- END UPDATED TOOLTIP CALLBACK ---
                     }
                }
            }
        });
        console.log("QBER history chart initialized successfully.");

    } catch (error) {
        console.error("Failed to create Chart.js instance:", error);
        canvasElement.parentElement.innerHTML = '<p class="text-red-500 text-center text-sm p-4">Error loading chart.</p>';
    }
});