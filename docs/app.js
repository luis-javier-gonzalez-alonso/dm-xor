// Tab Switching Logic
function switchTab(event, tabId) {
    // Hide all tab contents
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.remove('active'));

    // Deactivate all tab buttons
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));

    // Show selected tab content and activate button
    document.getElementById(tabId).classList.add('active');
    event.currentTarget.classList.add('active');
}

// Copy Code to Clipboard
function copyCode(buttonElement) {
    const wrapper = buttonElement.closest('.code-block-wrapper');
    const code = wrapper.querySelector('code').innerText;

    navigator.clipboard.writeText(code).then(() => {
        buttonElement.innerText = 'Copied!';
        buttonElement.classList.add('copied');

        setTimeout(() => {
            buttonElement.innerText = 'Copy';
            buttonElement.classList.remove('copied');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

// ScrollSpy: Highlight active section in sidebar on scroll
document.addEventListener('DOMContentLoaded', () => {
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('.nav-link');

    window.addEventListener('scroll', () => {
        let currentSection = '';

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.clientHeight;
            // Scroll trigger point (adjust offset for header/margins)
            if (window.scrollY >= (sectionTop - 120)) {
                currentSection = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${currentSection}`) {
                link.classList.add('active');
            }
        });
    });

    // Dynamic Mobile Toggle Button (created on the fly if on smaller screens)
    const toggleButton = document.createElement('button');
    toggleButton.className = 'mobile-menu-toggle';
    toggleButton.innerHTML = '☰ Menu';
    document.body.appendChild(toggleButton);

    // Apply mobile toggle styling dynamically
    const style = document.createElement('style');
    style.innerHTML = `
        .mobile-menu-toggle {
            display: none;
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--primary);
            border: none;
            color: var(--text-bright);
            padding: 0.8rem 1.2rem;
            font-size: 1rem;
            font-weight: 700;
            border-radius: 50px;
            box-shadow: 0 5px 15px var(--primary-glow);
            cursor: pointer;
            z-index: 1000;
            transition: var(--transition-smooth);
        }
        .mobile-menu-toggle:hover {
            transform: scale(1.05);
        }
        @media (max-width: 1024px) {
            .mobile-menu-toggle {
                display: block;
            }
        }
    `;
    document.head.appendChild(style);

    // Sidebar toggle click listener
    const sidebar = document.querySelector('.sidebar');
    toggleButton.addEventListener('click', (e) => {
        e.stopPropagation();
        sidebar.classList.toggle('open');
        toggleButton.innerHTML = sidebar.classList.contains('open') ? '✕ Close' : '☰ Menu';
    });

    // Close mobile sidebar if clicking outside or on a nav link
    document.addEventListener('click', () => {
        if (sidebar.classList.contains('open')) {
            sidebar.classList.remove('open');
            toggleButton.innerHTML = '☰ Menu';
        }
    });

    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            sidebar.classList.remove('open');
            toggleButton.innerHTML = '☰ Menu';
        });
    });

    sidebar.addEventListener('click', (e) => {
        e.stopPropagation();
    });
});
