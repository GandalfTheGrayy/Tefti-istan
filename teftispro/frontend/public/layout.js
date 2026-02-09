/* ========================================
   TeftişPro Layout System
   Shared sidebar, header, theme & palette management
   ======================================== */

const LAYOUT = {
    menuItems: [
        { title: 'Kontrol Paneli', icon: 'dashboard', path: '/public/kontrol_paneli.html', roles: ['admin', 'field', 'planlamacı', 'gözden_geçiren', 'firma_sahibi', 'sube_kullanici'] },
        { title: 'Denetimler', icon: 'fact_check', path: '/public/denetim_listesi.html', roles: ['admin', 'field', 'planlamacı', 'gözden_geçiren', 'firma_sahibi', 'sube_kullanici'] },
        { title: 'Raporlar', icon: 'bar_chart', path: '/public/raporlar.html', roles: ['admin', 'planlamacı', 'gözden_geçiren', 'firma_sahibi'] },
        { title: 'Şirketler', icon: 'business', path: '/public/sirket_yonetimi.html', roles: ['admin'] },
        { title: 'Bölgeler', icon: 'map', path: '/public/bolge_yonetimi.html', roles: ['admin'] },
        { title: 'Şubeler', icon: 'store', path: '/public/sube_yonetimi.html', roles: ['admin'] },
        { title: 'Kategoriler', icon: 'category', path: '/public/kategori_yonetimi.html', roles: ['admin', 'planlamacı'] },
        { title: 'Kullanıcılar', icon: 'group', path: '/public/admin_yonetimi.html', roles: ['admin'] },
    ],

    init: function () {
        this.applyTheme();
        this.applyPalette();
        this.applyCSSVarTailwind();
        this.renderSidebar();
        if (!document.body.hasAttribute('data-custom-header')) {
            this.renderHeader();
        }
        this.highlightCurrentPage();
        this.initToastContainer();
    },

    // ---------- Theme Management ----------
    getTheme: function () {
        const saved = localStorage.getItem('tp-theme');
        if (saved) return saved;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    },

    setTheme: function (theme) {
        localStorage.setItem('tp-theme', theme);
        document.documentElement.setAttribute('data-theme', theme);
        // Update all theme icons
        document.querySelectorAll('.tp-theme-icon').forEach(el => {
            el.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
        });
    },

    toggleTheme: function () {
        const next = this.getTheme() === 'dark' ? 'light' : 'dark';
        this.setTheme(next);
    },

    applyTheme: function () {
        const theme = this.getTheme();
        document.documentElement.setAttribute('data-theme', theme);
        document.documentElement.classList.remove('dark');
    },

    // ---------- Palette Management ----------
    getPalette: function () {
        return localStorage.getItem('tp-palette') || 'emerald';
    },

    setPalette: function (palette) {
        localStorage.setItem('tp-palette', palette);
        if (palette === 'corporate') {
            document.documentElement.setAttribute('data-palette', 'corporate');
        } else {
            document.documentElement.removeAttribute('data-palette');
        }
        // Update palette dots
        document.querySelectorAll('.tp-palette-dot').forEach(d => {
            d.classList.toggle('active', d.dataset.palette === palette);
        });
    },

    togglePalette: function () {
        const next = this.getPalette() === 'emerald' ? 'corporate' : 'emerald';
        this.setPalette(next);
    },

    applyPalette: function () {
        const palette = this.getPalette();
        if (palette === 'corporate') {
            document.documentElement.setAttribute('data-palette', 'corporate');
        }
    },

    applyCSSVarTailwind: function () {
        if (typeof tailwind !== 'undefined') {
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            accent: {
                                DEFAULT: '#10b981', 50: '#ecfdf5', 100: '#d1fae5',
                                200: '#a7f3d0', 500: '#10b981', 600: '#059669', 700: '#047857'
                            }
                        },
                        fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] }
                    }
                }
            };
        }
    },

    // ---------- User ----------
    getUser: function () {
        const userStr = localStorage.getItem('user');
        if (!userStr) return null;
        try { return JSON.parse(userStr); } catch { return null; }
    },

    getUserRole: function () {
        const user = this.getUser();
        if (!user) return '';
        return typeof user.role === 'object' ? user.role.name : user.role;
    },

    getUserInitials: function () {
        const user = this.getUser();
        if (!user || !user.email) return '??';
        return user.email.substring(0, 2).toUpperCase();
    },

    getUserName: function () {
        const user = this.getUser();
        if (!user || !user.email) return 'Kullanıcı';
        return user.email.split('@')[0];
    },

    getRoleDisplayName: function (role) {
        const names = {
            'admin': 'Yönetici', 'planlamacı': 'Planlamacı', 'field': 'Saha Denetçisi',
            'gözden_geçiren': 'Gözden Geçiren', 'firma_sahibi': 'Firma Sahibi', 'sube_kullanici': 'Şube Kullanıcı'
        };
        return names[role] || role;
    },

    getGreeting: function () {
        const h = new Date().getHours();
        if (h < 12) return 'Günaydın';
        if (h < 18) return 'İyi Günler';
        return 'İyi Akşamlar';
    },

    // ---------- Sidebar ----------
    renderSidebar: function () {
        const user = this.getUser();
        if (!user) return;
        const role = this.getUserRole();
        const isDark = this.getTheme() === 'dark';
        const palette = this.getPalette();

        const existingSidebar = document.querySelector('aside#sidebar, aside#mainSidebar');
        if (existingSidebar) existingSidebar.remove();
        const existingOverlay = document.getElementById('mobileOverlay');
        if (existingOverlay) existingOverlay.remove();

        const sidebarHTML = `
            <aside id="mainSidebar" class="fixed left-0 top-0 h-screen w-64 z-50 flex flex-col transition-transform duration-300 -translate-x-full lg:translate-x-0"
                   style="background:var(--bg-sidebar);border-right:1px solid var(--border-color);">
                <!-- Logo -->
                <div class="p-5 flex items-center gap-3" style="border-bottom:1px solid var(--border-color);">
                    <img src="/public/assets/logo.png" alt="TeftişPro" class="w-10 h-10 rounded-xl object-cover shadow-md" style="border:1px solid var(--border-color);">
                    <div>
                        <h1 class="font-bold text-lg tracking-tight" style="color:var(--text-primary);">TeftişPro</h1>
                        <p class="text-[10px] font-semibold tracking-widest" style="color:var(--text-muted);">DENETİM SİSTEMİ</p>
                    </div>
                </div>

                <!-- User Info -->
                <div class="px-5 py-3" style="background:var(--bg-hover);border-bottom:1px solid var(--border-color);">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full flex items-center justify-center font-bold text-xs" style="background:var(--color-accent-100);color:var(--color-accent-700);">
                            ${this.getUserInitials()}
                        </div>
                        <div class="overflow-hidden flex-1">
                            <p class="text-sm font-semibold truncate" style="color:var(--text-primary);">${this.getUserName()}</p>
                            <p class="text-xs truncate capitalize" style="color:var(--text-muted);">${this.getRoleDisplayName(role)}</p>
                        </div>
                    </div>
                </div>

                <!-- Menu -->
                <nav class="flex-1 overflow-y-auto px-3 py-4 space-y-1">
                    ${this.menuItems.map(item => {
                        if (!item.roles.includes(role)) return '';
                        return `
                            <a href="${item.path}" class="menu-link flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all group" data-path="${item.path}"
                               style="color:var(--text-secondary);"
                               onmouseover="this.style.background='var(--bg-hover)';this.style.color='var(--color-accent)'"
                               onmouseout="if(!this.classList.contains('menu-active')){this.style.background='';this.style.color='var(--text-secondary)'}">
                                <span class="material-symbols-outlined text-[22px] transition-transform group-hover:scale-110">${item.icon}</span>
                                <span class="font-medium text-[14px]">${item.title}</span>
                            </a>
                        `;
                    }).join('')}
                </nav>

                <!-- Footer -->
                <div class="px-3 py-3" style="border-top:1px solid var(--border-color);">
                    <!-- Palette & Theme Row -->
                    <div class="flex items-center justify-between px-3 py-2 mb-1">
                        <div class="flex items-center gap-2">
                            <div class="tp-palette-dot ${palette === 'emerald' ? 'active' : ''}" data-palette="emerald" style="background:#10b981;" onclick="LAYOUT.setPalette('emerald')" title="Emerald"></div>
                            <div class="tp-palette-dot ${palette === 'corporate' ? 'active' : ''}" data-palette="corporate" style="background:#d97706;" onclick="LAYOUT.setPalette('corporate')" title="Corporate"></div>
                        </div>
                        <button onclick="LAYOUT.toggleTheme()" class="p-1.5 rounded-lg transition-colors" style="color:var(--text-muted);"
                                onmouseover="this.style.background='var(--bg-hover)'" onmouseout="this.style.background=''">
                            <span class="material-symbols-outlined tp-theme-icon text-[20px]">${isDark ? 'light_mode' : 'dark_mode'}</span>
                        </button>
                    </div>
                    <button onclick="logout()" class="w-full flex items-center gap-3 px-3 py-2 rounded-xl transition-colors"
                            style="color:#ef4444;"
                            onmouseover="this.style.background='rgba(239,68,68,0.08)'"
                            onmouseout="this.style.background=''">
                        <span class="material-symbols-outlined text-[20px]">logout</span>
                        <span class="font-medium text-sm">Çıkış Yap</span>
                    </button>
                    <p class="mt-2 text-center text-[10px]" style="color:var(--text-muted);">v2.2.0 &copy; 2026</p>
                </div>
            </aside>
            <div id="mobileOverlay" class="fixed inset-0 z-40 hidden lg:hidden backdrop-blur-sm" style="background:rgba(0,0,0,0.5);" onclick="LAYOUT.toggleSidebar()"></div>
        `;

        document.body.insertAdjacentHTML('afterbegin', sidebarHTML);

        const main = document.querySelector('main');
        if (main) {
            main.classList.add('lg:ml-64', 'min-h-screen', 'transition-all', 'duration-300');
        }
    },

    // ---------- Header ----------
    renderHeader: function () {
        let pageTitle = document.title.split('-')[0].trim();
        const isDark = this.getTheme() === 'dark';

        const existingHeader = document.querySelector('header');
        if (existingHeader) existingHeader.remove();

        // Build breadcrumb
        const pageName = document.title.split('-')[0].trim();
        const breadcrumb = `<div class="tp-breadcrumb mt-0.5"><a href="/public/kontrol_paneli.html">Ana Sayfa</a><span class="separator">/</span><span>${pageName}</span></div>`;

        const headerHTML = `
            <header class="sticky top-0 z-30 lg:ml-64 transition-all duration-300 backdrop-blur-md"
                    style="background:var(--bg-header);border-bottom:1px solid var(--border-color);">
                <div class="px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between">
                    <div class="flex items-center gap-3">
                        <button onclick="LAYOUT.toggleSidebar()" class="lg:hidden p-2 rounded-lg transition-colors"
                                style="color:var(--text-secondary);"
                                onmouseover="this.style.background='var(--bg-hover)'" onmouseout="this.style.background=''">
                            <span class="material-symbols-outlined">menu</span>
                        </button>
                        <div>
                            <h2 class="text-lg font-bold" style="color:var(--text-primary);">${pageTitle}</h2>
                            ${breadcrumb}
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <button onclick="LAYOUT.toggleTheme()" class="p-2 rounded-lg transition-colors"
                                style="color:var(--text-muted);"
                                onmouseover="this.style.background='var(--bg-hover)';this.style.color='var(--text-primary)'"
                                onmouseout="this.style.background='';this.style.color='var(--text-muted)'" title="Tema Değiştir">
                            <span class="material-symbols-outlined tp-theme-icon">${isDark ? 'light_mode' : 'dark_mode'}</span>
                        </button>
                        <button class="p-2 rounded-lg transition-colors relative"
                                style="color:var(--text-muted);"
                                onmouseover="this.style.background='var(--bg-hover)';this.style.color='var(--text-primary)'"
                                onmouseout="this.style.background='';this.style.color='var(--text-muted)'">
                            <span class="material-symbols-outlined">notifications</span>
                        </button>
                        <a href="/public/profil.html" class="w-9 h-9 rounded-full flex items-center justify-center overflow-hidden transition-all text-sm font-bold"
                           style="background:var(--color-accent-100);color:var(--color-accent-700);">
                            ${this.getUserInitials()}
                        </a>
                    </div>
                </div>
            </header>
        `;

        const sidebar = document.getElementById('mainSidebar');
        if (sidebar) sidebar.insertAdjacentHTML('afterend', headerHTML);
        else document.body.insertAdjacentHTML('afterbegin', headerHTML);
    },

    highlightCurrentPage: function () {
        const path = window.location.pathname;
        document.querySelectorAll('.menu-link').forEach(link => {
            const linkPath = link.getAttribute('data-path');
            if (linkPath && path.includes(linkPath.split('/').pop())) {
                link.classList.add('menu-active');
                link.style.background = 'var(--color-accent-50)';
                link.style.color = 'var(--color-accent-700)';
                link.style.fontWeight = '600';
            }
        });
    },

    toggleSidebar: function () {
        const sidebar = document.getElementById('mainSidebar');
        const overlay = document.getElementById('mobileOverlay');
        if (!sidebar) return;
        const isHidden = sidebar.classList.contains('-translate-x-full');
        if (isHidden) {
            sidebar.classList.remove('-translate-x-full');
            sidebar.classList.add('translate-x-0');
            if (overlay) overlay.classList.remove('hidden');
        } else {
            sidebar.classList.add('-translate-x-full');
            sidebar.classList.remove('translate-x-0');
            if (overlay) overlay.classList.add('hidden');
        }
    },

    initToastContainer: function () {
        if (!document.getElementById('toastContainer')) {
            document.body.insertAdjacentHTML('beforeend', '<div id="toastContainer" class="tp-toast-container"></div>');
        }
    },

    toast: function (message, type = 'info', duration = 3000) {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        const icons = { success: 'check_circle', error: 'error', warning: 'warning', info: 'info' };
        const toast = document.createElement('div');
        toast.className = `tp-toast ${type}`;
        toast.innerHTML = `<span class="material-symbols-outlined" style="font-size:1.25rem;">${icons[type] || 'info'}</span><span>${message}</span>`;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.animation = 'toastSlideOut 0.3s ease-in forwards';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
};

// ---------- Global Functions ----------
window.logout = function () {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/public/login.html';
};

window.showToast = function (message, type, duration) {
    LAYOUT.toast(message, type, duration);
};

// ---------- Initialize ----------
document.addEventListener('DOMContentLoaded', () => {
    LAYOUT.applyTheme();
    LAYOUT.applyPalette();
    LAYOUT.applyCSSVarTailwind();
    if (!window.location.pathname.includes('login.html')) {
        LAYOUT.init();
    }
});
