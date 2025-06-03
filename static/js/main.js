// Main JavaScript functionality for MCP Server interface

// Theme management
class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'light';
        this.init();
    }
    
    init() {
        this.applyTheme();
        this.setupToggle();
    }
    
    applyTheme() {
        document.documentElement.setAttribute('data-bs-theme', this.theme);
        this.updateToggleButton();
        this.updateSyntaxHighlighting();
    }
    
    toggle() {
        this.theme = this.theme === 'light' ? 'dark' : 'light';
        localStorage.setItem('theme', this.theme);
        this.applyTheme();
    }
    
    setupToggle() {
        const toggleBtn = document.getElementById('themeToggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggle());
        }
    }
    
    updateToggleButton() {
        const toggleBtn = document.getElementById('themeToggle');
        if (toggleBtn) {
            const icon = toggleBtn.querySelector('[data-feather]');
            const text = toggleBtn.querySelector('span') || toggleBtn.childNodes[2];
            
            if (this.theme === 'dark') {
                icon.setAttribute('data-feather', 'sun');
                if (text) text.textContent = ' Light Mode';
            } else {
                icon.setAttribute('data-feather', 'moon');
                if (text) text.textContent = ' Dark Mode';
            }
            
            feather.replace();
        }
    }
    
    updateSyntaxHighlighting() {
        const lightTheme = document.querySelector('link[href*="prism.min.css"]');
        const darkTheme = document.querySelector('#prism-dark');
        
        if (lightTheme && darkTheme) {
            if (this.theme === 'dark') {
                lightTheme.disabled = true;
                darkTheme.disabled = false;
            } else {
                lightTheme.disabled = false;
                darkTheme.disabled = true;
            }
        }
    }
}

// WebSocket connection management
class WebSocketManager {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.init();
    }
    
    init() {
        if (typeof io !== 'undefined') {
            this.connect();
        }
    }
    
    connect() {
        try {
            this.socket = io();
            this.setupEventListeners();
            this.updateStatus('connected');
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.updateStatus('disconnected');
            this.scheduleReconnect();
        }
    }
    
    setupEventListeners() {
        if (!this.socket) return;
        
        this.socket.on('connect', () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            this.updateStatus('connected');
        });
        
        this.socket.on('disconnect', () => {
            console.log('WebSocket disconnected');
            this.updateStatus('disconnected');
            this.scheduleReconnect();
        });
        
        this.socket.on('mcp_activity', (data) => {
            this.handleActivityUpdate(data);
        });
        
        this.socket.on('tools_updated', (data) => {
            this.handleToolsUpdate(data);
        });
        
        this.socket.on('connect_error', (error) => {
            console.error('WebSocket connection error:', error);
            this.updateStatus('error');
            this.scheduleReconnect();
        });
    }
    
    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            setTimeout(() => {
                this.reconnectAttempts++;
                console.log(`Reconnection attempt ${this.reconnectAttempts}`);
                this.connect();
            }, this.reconnectDelay * Math.pow(2, this.reconnectAttempts));
        }
    }
    
    updateStatus(status) {
        const statusIndicator = document.getElementById('serverStatus');
        const statusText = document.getElementById('statusText');
        
        if (statusIndicator) {
            statusIndicator.className = 'status-indicator me-2';
            
            switch (status) {
                case 'connected':
                    statusIndicator.style.backgroundColor = 'hsl(var(--success))';
                    if (statusText) statusText.textContent = 'Connected';
                    break;
                case 'disconnected':
                    statusIndicator.style.backgroundColor = 'hsl(var(--warning))';
                    if (statusText) statusText.textContent = 'Disconnected';
                    break;
                case 'error':
                    statusIndicator.style.backgroundColor = 'hsl(var(--danger))';
                    if (statusText) statusText.textContent = 'Error';
                    break;
            }
        }
    }
    
    handleActivityUpdate(data) {
        // Update real-time activity indicators
        console.log('Activity update:', data);
        
        // Add activity notification
        this.showActivityNotification(data);
    }
    
    handleToolsUpdate(data) {
        console.log('Tools update:', data);
        
        // Show notification for tool changes
        if (data.action === 'added') {
            this.showNotification(`Tool "${data.tool.name}" was added`, 'success');
        }
    }
    
    showActivityNotification(data) {
        // Create a small notification for recent activity
        const notification = document.createElement('div');
        notification.className = 'activity-notification';
        notification.innerHTML = `
            <small class="text-muted">
                <i data-feather="activity" style="width: 12px; height: 12px;"></i>
                ${data.method} - ${Math.round(data.duration_ms)}ms
            </small>
        `;
        
        // Add to a notifications container if it exists
        const container = document.querySelector('.activity-notifications');
        if (container) {
            container.prepend(notification);
            
            // Remove after 5 seconds
            setTimeout(() => {
                notification.remove();
            }, 5000);
            
            // Keep only last 5 notifications
            const notifications = container.querySelectorAll('.activity-notification');
            if (notifications.length > 5) {
                notifications[notifications.length - 1].remove();
            }
        }
    }
    
    showNotification(message, type = 'info') {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        toast.style.cssText = `
            top: 80px;
            right: 20px;
            z-index: 1050;
            min-width: 300px;
        `;
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(toast);
        
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (toast.parentNode) {
                toast.remove();
            }
        }, 5000);
    }
}

// API utilities
class APIUtils {
    static async request(url, options = {}) {
        try {
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    }
    
    static async get(url) {
        return this.request(url, { method: 'GET' });
    }
    
    static async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }
    
    static async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }
    
    static async delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
}

// Form utilities
class FormUtils {
    static serializeForm(form) {
        const formData = new FormData(form);
        const data = {};
        
        for (const [key, value] of formData.entries()) {
            if (data[key]) {
                // Handle multiple values (arrays)
                if (Array.isArray(data[key])) {
                    data[key].push(value);
                } else {
                    data[key] = [data[key], value];
                }
            } else {
                data[key] = value;
            }
        }
        
        return data;
    }
    
    static validateJSON(str) {
        try {
            JSON.parse(str);
            return true;
        } catch (error) {
            return false;
        }
    }
    
    static showFieldError(field, message) {
        // Remove existing error
        const existingError = field.parentNode.querySelector('.field-error');
        if (existingError) {
            existingError.remove();
        }
        
        // Add error class
        field.classList.add('is-invalid');
        
        // Add error message
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error text-danger small mt-1';
        errorDiv.textContent = message;
        field.parentNode.appendChild(errorDiv);
    }
    
    static clearFieldErrors(form) {
        const fields = form.querySelectorAll('.is-invalid');
        const errors = form.querySelectorAll('.field-error');
        
        fields.forEach(field => field.classList.remove('is-invalid'));
        errors.forEach(error => error.remove());
    }
}

// Code highlighting utilities
class CodeHighlighter {
    static highlight(element) {
        if (typeof Prism !== 'undefined') {
            Prism.highlightElement(element);
        }
    }
    
    static highlightAll() {
        if (typeof Prism !== 'undefined') {
            Prism.highlightAll();
        }
    }
    
    static formatJSON(obj) {
        return JSON.stringify(obj, null, 2);
    }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme manager
    window.themeManager = new ThemeManager();
    
    // Initialize WebSocket manager
    window.wsManager = new WebSocketManager();
    
    // Initialize Feather icons
    if (typeof feather !== 'undefined') {
        feather.replace();
    }
    
    // Initialize code highlighting
    CodeHighlighter.highlightAll();
    
    // Add smooth scrolling to anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Add copy functionality to code blocks
    document.querySelectorAll('pre code').forEach(block => {
        const button = document.createElement('button');
        button.className = 'btn btn-sm btn-outline-secondary copy-btn';
        button.innerHTML = '<i data-feather="copy"></i>';
        button.style.cssText = `
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            opacity: 0;
            transition: opacity 0.2s;
        `;
        
        const container = block.parentNode;
        container.style.position = 'relative';
        container.appendChild(button);
        
        container.addEventListener('mouseenter', () => {
            button.style.opacity = '1';
        });
        
        container.addEventListener('mouseleave', () => {
            button.style.opacity = '0';
        });
        
        button.addEventListener('click', () => {
            navigator.clipboard.writeText(block.textContent).then(() => {
                button.innerHTML = '<i data-feather="check"></i>';
                setTimeout(() => {
                    button.innerHTML = '<i data-feather="copy"></i>';
                    feather.replace();
                }, 1000);
            });
        });
        
        feather.replace();
    });
    
    console.log('MCP Server interface initialized');
});

// Export utilities for global use
window.APIUtils = APIUtils;
window.FormUtils = FormUtils;
window.CodeHighlighter = CodeHighlighter;
