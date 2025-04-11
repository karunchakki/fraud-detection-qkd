// static/js/qkd.js

/**
 * Initializes the QBER history chart using Chart.js.
 * Expects data arrays (labels, QBER values) and threshold value
 * to be injected into global `window` variables by the Flask template (qkd.html).
 * e.g., window.qkdChartLabels, window.qkdChartQberData, window.qkdChartQberThreshold
 */
document.addEventListener('DOMContentLoaded', function () {
    const canvasElement = document.getElementById('qberChart');

    if (!canvasElement) {
        // console.log("QBER Chart canvas not found on this page.");
        return; // Exit if canvas doesn't exist
    }

    // --- Get Data (Safely access potentially undefined global vars) ---
    const labels = window.qkdChartLabels || ['No Data'];
    const qberData = window.qkdChartQberData || [0];
    // Default threshold to a reasonable value if not provided
    const qberThreshold = typeof window.qkdChartQberThreshold === 'number'
        ? window.qkdChartQberThreshold
        : 15.0; // Default to 15%

    // Basic validation
    if (!Array.isArray(labels) || !Array.isArray(qberData) || labels.length !== qberData.length) {
        console.error("Invalid or mismatched chart data provided.", { labels, qberData });
        canvasElement.parentElement.innerHTML = '<p class="text-red-500 text-center text-sm p-4">Error: Invalid data for QBER chart.</p>';
        return;
    }
     if (labels.length === 1 && labels[0] === 'No Data') {
         console.log("No QBER history data provided for chart.");
         // Optionally display a message instead of an empty chart
          canvasElement.parentElement.innerHTML = '<p class="text-gray-500 text-center text-sm p-4">No QBER history data available to display.</p>';
         return;
     }


    // --- Chart Configuration ---
    try {
        new Chart(canvasElement, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Simulated QBER (%)',
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
                    label: 'QBER Threshold (%)',
                    data: Array(labels.length).fill(qberThreshold),
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
                        title: {display: true, text: 'Simulation Run / Log Entry'},
                        grid: { display: false } // Hide vertical grid lines
                    }
                },
                 plugins: {
                     legend: {
                         position: 'bottom',
                         labels: { padding: 15 }
                     },
                     tooltip: {
                        mode: 'index',
                        intersect: false,
                        backgroundColor: 'rgba(0, 0, 0, 0.7)',
                        titleFont: { weight: 'bold' },
                        bodySpacing: 4,
                        padding: 10,
                        callbacks: { // Custom tooltip labels
                            label: function(context) {
                                let label = context.dataset.label || '';
                                const value = context.parsed.y;
                                if (label.includes('Threshold')) {
                                    label = value !== null ? `Threshold: ${value.toFixed(1)}%` : 'Threshold';
                                } else {
                                    label = value !== null ? `QBER: ${value.toFixed(2)}%` : 'QBER';
                                }
                                return label;
                            }
                        }
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