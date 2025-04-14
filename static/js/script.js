// static/js/script.js
// Basic global JavaScript for the QSB Demo

document.addEventListener('DOMContentLoaded', function () {
    console.log("QSB Demo Global JS Loaded");

    // Set current year in footer
    const yearSpan = document.getElementById('current-year');
    if (yearSpan) {
        yearSpan.textContent = new Date().getFullYear();
    }

    // Mobile menu toggle functionality
    const menuButton = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    const openIcon = document.getElementById('menu-icon-open');
    const closeIcon = document.getElementById('menu-icon-close');

    if (menuButton && mobileMenu && openIcon && closeIcon) {
        menuButton.addEventListener('click', () => {
            const isExpanded = menuButton.getAttribute('aria-expanded') === 'true';
            menuButton.setAttribute('aria-expanded', !isExpanded);
            mobileMenu.classList.toggle('hidden'); // Toggle visibility
            // Toggle icons
            openIcon.classList.toggle('hidden');
            openIcon.classList.toggle('block');
            closeIcon.classList.toggle('hidden');
            closeIcon.classList.toggle('block');
        });
    } else {
        // Log warning if elements aren't found, helps debugging missing IDs
        console.warn('Mobile menu elements (button, menu, icons) not all found.');
    }

    // You could add other global initializations here if needed

}); // End DOMContentLoaded