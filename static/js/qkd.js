// static/js/qkd.js

/**
 * Initializes the QBER history chart using Chart.js.
 * Expects data arrays (labels, QBER values) and threshold value
 * to be injected into global `window` variables by the Flask template (qkd.html).
 */
document.addEventListener('DOMContentLoaded', function () {
    const canvasElement = document.getElementById('qberChart');

    if (!canvasElement) {
        // console.log("QBER Chart canvas not found on this page.");
        return; // Exit if canvas doesn't exist
    }

    // --- Get Data ---
    const labels = window.qkdChartLabels || ['No Data'];
    const qberData = window.qkdChartQberData || [0];
    const qberThreshold = typeof window.qkdChartQberThreshold === 'number'
        ? window.qkdChartQberThreshold : 15.0; // Default to 15%

    // --- Validation ---
    if (!Array.isArray(labels) || !Array.isArray(qberData) || labels.length !== qberData.length) {
        console.error("Invalid or mismatched chart data provided.", { labels, qberData });
        canvasElement.parentElement.innerHTML = '<p class="text-red-500 dark:text-red-400 text-center text-sm p-4">Error: Invalid data for QBER chart.</p>';
        return;
    }
     if (labels.length === 0 || (labels.length === 1 && labels[0] === 'N/A')) { // Check for empty or placeholder
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
                labels: labels, // e.g., ['Log 101', 'Log 105', ...]
                datasets: [{
                    label: 'QBER (%)',
                    data: qberData, // e.g., [1.2, 0.5, ...]
                    borderColor: 'rgb(59, 130, 246)', // Tailwind blue-500
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.1,
                    pointBackgroundColor: 'rgb(59, 130, 246)',
                    pointRadius: 3,
                    pointHoverRadius: 5
                 },
                 { // Threshold Line
                    label: 'Threshold (%)',
                    data: thresholdData, // e.g., [15.0, 15.0, ...]
                    borderColor: 'rgb(239, 68, 68)', // Tailwind red-500
                    borderWidth: 2,
                    borderDash: [6, 6],
                    pointRadius: 0, // No circles on threshold line
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
                        grid: { color: 'rgba(200, 200, 200, 0.2)'} // Slightly more visible grid
                    },
                    x: {
                        title: {display: true, text: 'Transaction Log ID / Run'},
                        grid: { display: false }
                    }
                },
                 plugins: {
                     legend: {
                         position: 'top', // Move legend back to top maybe? Or keep 'bottom'
                         labels: { padding: 15 }
                     },
                     tooltip: {
                        mode: 'index', // Show all datasets for that x-axis point
                        intersect: false, // Show tooltip when hovering near the point
                        backgroundColor: 'rgba(0, 0, 0, 0.8)', // Darker tooltip
                        titleFont: { weight: 'bold' },
                        bodySpacing: 5, // Slightly more spacing
                        padding: 12, // More padding
                        boxPadding: 3, // Padding inside the box
                        borderColor: 'rgba(255,255,255,0.2)', // Optional border
                        borderWidth: 1,
                        callbacks: {
                            // --- MODIFIED: Use label for Title ---
                            title: function(tooltipItems) {
                                // tooltipItems is an array, usually one item per dataset for index mode
                                if (tooltipItems.length > 0) {
                                    return tooltipItems[0].label; // Use the x-axis label (e.g., "Log 101")
                                }
                                return '';
                            },
                            // --- Refined Label Display ---
                            label: function(context) {
                                let label = context.dataset.label || '';
                                const value = context.parsed.y;
                                let output = '';

                                if (label.includes('Threshold')) {
                                    // Just show threshold value cleanly
                                    output = value !== null ? ` Threshold: ${value.toFixed(1)}%` : '';
                                } else {
                                    // Show QBER value
                                    output = value !== null ? ` QBER: ${value.toFixed(2)}%` : '';
                                    // Optional: Add comparison to threshold
                                    if (value !== null) {
                                        output += (value > qberThreshold) ? ' (Above!)' : ' (OK)';
                                    }
                                }
                                return output;
                            },
                            // Optional: Customize label color
                            // labelColor: function(tooltipItem, chart) {
                            //     return {
                            //         borderColor: 'rgba(0, 0, 0, 0)',
                            //         backgroundColor: tooltipItem.dataset.borderColor // Match line color
                            //     };
                            // },
                        }
                     }
                }
            }
        });
        console.log("QBER history chart initialized successfully.");

    } catch (error) {
        console.error("Failed to create Chart.js instance:", error);
        canvasElement.parentElement.innerHTML = '<p class="text-red-500 dark:text-red-400 text-center text-sm p-4">Error loading chart.</p>';
    }
});