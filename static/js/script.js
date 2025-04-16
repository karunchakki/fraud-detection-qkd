/**
 * QSB Portal Global JavaScript
 * Includes:
 * - Theme Toggling (Light/Dark Mode) with localStorage persistence
 * - Mobile Sidebar Toggling
 */

(function () {
  'use strict';

  // --- Theme Toggle ---
  const themeToggleButton = document.getElementById('theme-toggle');
  const lightIcon = document.getElementById('theme-toggle-light-icon');
  const darkIcon = document.getElementById('theme-toggle-dark-icon');
  const htmlElement = document.documentElement; // The <html> tag

  // Function to apply the theme (called on load and on toggle)
  function applyTheme(theme) {
    if (theme === 'dark') {
      htmlElement.classList.add('dark');
      if (darkIcon) darkIcon.classList.add('hidden'); // Hide moon
      if (lightIcon) lightIcon.classList.remove('hidden'); // Show sun
    } else {
      htmlElement.classList.remove('dark');
      if (darkIcon) darkIcon.classList.remove('hidden'); // Show moon
      if (lightIcon) lightIcon.classList.add('hidden'); // Hide sun
    }
  }

  // Check localStorage on initial load
  // The initial class is set inline in base.html's <html> tag to prevent FOUC,
  // but we sync the button icon state here.
  const storedTheme = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  // Determine initial theme based on storage or system preference
  const initialTheme = storedTheme ? storedTheme : (prefersDark ? 'dark' : 'light');
  applyTheme(initialTheme); // Apply theme and set icon visibility

  // Add click listener to the toggle button
  if (themeToggleButton) {
    themeToggleButton.addEventListener('click', () => {
      const currentTheme = htmlElement.classList.contains('dark') ? 'dark' : 'light';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

      // Apply the new theme
      applyTheme(newTheme);

      // Store the preference in localStorage
      localStorage.setItem('theme', newTheme);
    });
  } else {
    console.warn('Theme toggle button (#theme-toggle) not found.');
  }


  // --- Mobile Sidebar Toggle ---
  const mobileSidebarButton = document.getElementById('mobile-sidebar-button');
  const desktopSidebar = document.getElementById('desktop-sidebar'); // The sidebar itself
  const sidebarOverlay = document.getElementById('sidebar-overlay');
  // Also target the "More" button on mobile nav if it should open the sidebar
  const mobileMoreButton = document.getElementById('mobile-more-button');


  function openSidebar() {
    if (desktopSidebar) {
      desktopSidebar.classList.remove('-translate-x-full'); // Slide in
      desktopSidebar.classList.add('translate-x-0');
    }
    if (sidebarOverlay) {
      sidebarOverlay.classList.remove('opacity-0', 'invisible'); // Show overlay
      sidebarOverlay.classList.add('opacity-100', 'visible');
    }
     // Optional: Prevent body scrolling when sidebar is open
     document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    if (desktopSidebar) {
      desktopSidebar.classList.remove('translate-x-0');
      desktopSidebar.classList.add('-translate-x-full'); // Slide out
    }
    if (sidebarOverlay) {
      sidebarOverlay.classList.remove('opacity-100', 'visible');
      sidebarOverlay.classList.add('opacity-0', 'invisible'); // Hide overlay
    }
     // Optional: Restore body scrolling
     document.body.style.overflow = '';
  }

  // Listener for the main hamburger button
  if (mobileSidebarButton) {
    mobileSidebarButton.addEventListener('click', (e) => {
      e.stopPropagation(); // Prevent event bubbling
      // Check current state based on transform class
      if (desktopSidebar && desktopSidebar.classList.contains('-translate-x-full')) {
        openSidebar();
      } else {
        closeSidebar();
      }
    });
  } else {
    console.warn('Mobile sidebar button (#mobile-sidebar-button) not found.');
  }

   // Listener for the "More" button on the bottom nav (if it exists)
   if (mobileMoreButton) {
       mobileMoreButton.addEventListener('click', (e) => {
           e.stopPropagation();
           openSidebar(); // Always open when "More" is clicked
       });
   }

  // Listener for the overlay (to close sidebar when clicking outside)
  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', () => {
      closeSidebar();
    });
  } else {
    console.warn('Sidebar overlay (#sidebar-overlay) not found.');
  }

  // Optional: Close sidebar if user clicks on a link inside it (on mobile)
  if (desktopSidebar) {
      const sidebarLinks = desktopSidebar.querySelectorAll('a');
      sidebarLinks.forEach(link => {
          link.addEventListener('click', () => {
              // Only close if sidebar is currently open in its mobile state
              // Check screen size or if overlay is visible
               if (sidebarOverlay && sidebarOverlay.classList.contains('visible')) {
                    closeSidebar();
               }
          });
      });
  }


  // --- Add any other global JS like form validation helpers, etc. below ---


})(); // Immediately Invoked Function Expression (IIFE) to avoid polluting global scope