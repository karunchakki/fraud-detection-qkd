// static/js/particles.js

/**
 * Initializes particle animations using the particles.js library.
 * Requires particles.js library (e.g., CDN) and HTML element '#particles-js'.
 */
document.addEventListener('DOMContentLoaded', function() {
  const containerId = 'particles-js';
  const particlesContainer = document.getElementById(containerId);

  if (particlesContainer) {
    // Ensure particles.js library function is available
    if (typeof particlesJS === 'function') {
        console.log(`Initializing particles.js on #${containerId}...`);
        particlesJS(containerId, {
        "particles": {
            "number": { "value": 60, "density": { "enable": true, "value_area": 800 } },
            "color": { "value": "#a5b4fc" }, // Lighter Indigo particles
            "shape": { "type": "circle", "stroke": { "width": 0, "color": "#000000" }, "polygon": { "nb_sides": 5 } },
            "opacity": { "value": 0.6, "random": true, "anim": { "enable": true, "speed": 0.2, "opacity_min": 0.1, "sync": false } },
            "size": { "value": 2.5, "random": true, "anim": { "enable": false, "speed": 40, "size_min": 0.1, "sync": false } },
            "line_linked": { "enable": true, "distance": 160, "color": "#818cf8", "opacity": 0.3, "width": 1 }, // Indigo lines
            "move": { "enable": true, "speed": 1.5, "direction": "none", "random": true, "straight": false, "out_mode": "out", "bounce": false, "attract": { "enable": false, "rotateX": 600, "rotateY": 1200 } }
        },
        "interactivity": {
            "detect_on": "canvas",
            "events": { "onhover": { "enable": true, "mode": "grab" }, "onclick": { "enable": true, "mode": "push" }, "resize": true }, // Grab on hover, push on click
            "modes": {
                "grab": { "distance": 120, "line_linked": { "opacity": 0.7 } },
                "bubble": { "distance": 400, "size": 40, "duration": 2, "opacity": 8, "speed": 3 },
                "repulse": { "distance": 150, "duration": 0.4 },
                "push": { "particles_nb": 4 },
                "remove": { "particles_nb": 2 }
            }
        },
        "retina_detect": true
        });
    } else {
        console.error("particlesJS function not found. Ensure the library is loaded before this script.");
        particlesContainer.innerHTML = '<p class="text-center text-red-500 text-xs p-2">Error: Particle library not loaded.</p>';
    }
  } else {
    // console.log(`Particles container #${containerId} not found.`);
  }
});