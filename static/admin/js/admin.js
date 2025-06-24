/**
 * Основной JavaScript для админ-панели RemoteMCP
 * Включает утилиты, AJAX запросы и интерактивность
 */

class AdminPanel {
    constructor() {
        this.init();
        this.initEventListeners();
        this.startTimers();
    }

    init() {
        console.log('AdminPanel инициализирована');
        
        // Инициализация компонентов
        this.initTooltips();
        this.initModals();
        this.initCharts();
        
        // Проверка соединения
        this.checkConnection();
    }

    initEventListeners() {
        // Мобильное меню
        const sidebarToggle = document.getElementById('sidebarToggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                document.querySelector('.sidebar').classList.toggle('show');
            });
        }

        // Закрытие мобильного меню при клике вне его
        document.addEventListener('click', (e) => {
            const sidebar = document.querySelector('.sidebar');
            const sidebarToggle = document.getElementById('sidebarToggle');
            
            if (sidebar && !sidebar.contains(e.target) && !sidebarToggle?.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        });

        // Форма смены пароля
        const changePasswordForm = document.getElementById('changePasswordForm');
        if (changePasswordForm) {
            changePasswordForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handlePasswordChange(e.target);
            });
        }

        // Автообновление данных
        const autoRefreshCheckbox = document.getElementById('autoRefresh');
        if (autoRefreshCheckbox) {
            autoRefreshCheckbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.startAutoRefresh();
                } else {
                    this.stopAutoRefresh();
                }
            });
        }

        // Поиск в таблицах
        const searchInputs = document.querySelectorAll('.table-search');
        searchInputs.forEach(input => {
            input.addEventListener('input', (e) => {
                this.filterTable(e.target);
            });
        });

        // Сортировка таблиц
        const sortableHeaders = document.querySelectorAll('.sortable');
        sortableHeaders.forEach(header => {
            header.addEventListener('click', (e) => {
                this.sortTable(e.target);
            });
        });
    }

    initTooltips() {
        // Инициализация Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    initModals() {
        // Инициализация модальных окон
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('hidden.bs.modal', () => {
                // Очистка форм при закрытии модального окна
                const forms = modal.querySelectorAll('form');
                forms.forEach(form => form.reset());
                
                // Удаление ошибок
                const alerts = modal.querySelectorAll('.alert');
                alerts.forEach(alert => alert.remove());
            });
        });
    }

    initCharts() {
        // Инициализация графиков Chart.js
        if (typeof Chart !== 'undefined') {
            Chart.defaults.font.family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";
            Chart.defaults.color = '#6c757d';
        }
    }

    startTimers() {
        // Обновление времени
        this.updateTime();
        setInterval(() => this.updateTime(), 1000);

        // Проверка состояния системы
        this.checkSystemStatus();
        setInterval(() => this.checkSystemStatus(), 30000); // каждые 30 секунд
    }

    updateTime() {
        const timeElement = document.getElementById('current-time');
        if (timeElement) {
            const now = new Date();
            timeElement.textContent = now.toLocaleTimeString('ru-RU');
        }
    }

    async checkConnection() {
        try {
            const response = await fetch('/admin/api/ping');
            const data = await response.json();
            
            if (data.status === 'ok') {
                this.showConnectionStatus('online');
            } else {
                this.showConnectionStatus('offline');
            }
        } catch (error) {
            this.showConnectionStatus('offline');
        }
    }

    showConnectionStatus(status) {
        const statusElement = document.getElementById('connection-status');
        if (statusElement) {
            statusElement.className = `connection-status ${status}`;
            statusElement.textContent = status === 'online' ? 'Подключено' : 'Отключено';
        }
    }

    async checkSystemStatus() {
        try {
            const response = await fetch('/admin/api/system-status');
            const data = await response.json();
            
            this.updateSystemMetrics(data);
        } catch (error) {
            console.error('Ошибка получения статуса системы:', error);
        }
    }

    updateSystemMetrics(data) {
        // Обновление метрик на главной странице
        const elements = {
            'cpu-usage': data.cpu_usage,
            'memory-usage': data.memory_usage,
            'disk-usage': data.disk_usage,
            'active-connections': data.active_connections
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
            }
        });
    }

    async handlePasswordChange(form) {
        const formData = new FormData(form);
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.textContent;
        
        // Показываем индикатор загрузки
        submitButton.disabled = true;
        submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Изменение...';
        
        try {
            const response = await fetch('/admin/change-password', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                // Закрываем модальное окно
                const modal = bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'));
                modal.hide();
                
                // Показываем уведомление
                this.showNotification('Пароль успешно изменен', 'success');
                
                // Очищаем форму
                form.reset();
            } else {
                this.showNotification(result.error, 'danger');
            }
        } catch (error) {
            this.showNotification('Ошибка изменения пароля', 'danger');
            console.error('Ошибка смены пароля:', error);
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = originalText;
        }
    }

    showNotification(message, type = 'info', duration = 5000) {
        const alertsContainer = document.getElementById('alerts-container') || document.querySelector('.container-fluid');
        
        const alertId = 'alert-' + Date.now();
        const alertHTML = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                <i class="fas fa-${this.getAlertIcon(type)} me-2"></i>${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        alertsContainer.insertAdjacentHTML('afterbegin', alertHTML);
        
        // Автоматическое удаление через duration миллисекунд
        setTimeout(() => {
            const alert = document.getElementById(alertId);
            if (alert) {
                const bootstrapAlert = new bootstrap.Alert(alert);
                bootstrapAlert.close();
            }
        }, duration);
    }

    getAlertIcon(type) {
        const icons = {
            'success': 'check-circle',
            'danger': 'exclamation-triangle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    filterTable(searchInput) {
        const table = searchInput.closest('.card').querySelector('table');
        const filter = searchInput.value.toLowerCase();
        const rows = table.querySelectorAll('tbody tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(filter) ? '' : 'none';
        });
    }

    sortTable(header) {
        const table = header.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const column = header.cellIndex;
        const isAscending = !header.classList.contains('sort-asc');
        
        // Удаляем предыдущие классы сортировки
        table.querySelectorAll('.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
        });
        
        // Добавляем текущий класс сортировки
        header.classList.add(isAscending ? 'sort-asc' : 'sort-desc');
        
        // Сортируем строки
        rows.sort((a, b) => {
            const aVal = a.cells[column].textContent.trim();
            const bVal = b.cells[column].textContent.trim();
            
            // Попытка преобразовать в число
            const aNum = parseFloat(aVal);
            const bNum = parseFloat(bVal);
            
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return isAscending ? aNum - bNum : bNum - aNum;
            }
            
            return isAscending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });
        
        // Обновляем DOM
        rows.forEach(row => tbody.appendChild(row));
    }

    startAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
        
        this.autoRefreshInterval = setInterval(() => {
            this.refreshCurrentPageData();
        }, 10000); // каждые 10 секунд
        
        console.log('Автообновление включено');
    }

    stopAutoRefresh() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
            this.autoRefreshInterval = null;
        }
        
        console.log('Автообновление отключено');
    }

    async refreshCurrentPageData() {
        const currentPath = window.location.pathname;
        
        try {
            if (currentPath === '/admin/') {
                await this.refreshDashboard();
            } else if (currentPath === '/admin/monitoring') {
                await this.refreshMonitoring();
            } else if (currentPath === '/admin/logs') {
                await this.refreshLogs();
            }
        } catch (error) {
            console.error('Ошибка автообновления:', error);
        }
    }

    async refreshDashboard() {
        const response = await fetch('/admin/api/dashboard-data');
        const data = await response.json();
        
        // Обновляем статистику
        this.updateSystemMetrics(data.stats);
        
        // Обновляем события
        this.updateRecentEvents(data.recent_events);
    }

    updateRecentEvents(events) {
        const container = document.getElementById('recent-events');
        if (container && events) {
            container.innerHTML = events.map(event => `
                <div class="event-item">
                    <span class="event-time">${event.time}</span>
                    <span class="event-message">${event.message}</span>
                </div>
            `).join('');
        }
    }

    async refreshMonitoring() {
        const response = await fetch('/admin/api/monitoring-data');
        const data = await response.json();
        
        // Обновляем графики
        this.updateCharts(data);
    }

    updateCharts(data) {
        // Обновление графиков Chart.js
        if (window.cpuChart && data.cpu_history) {
            window.cpuChart.data.datasets[0].data = data.cpu_history;
            window.cpuChart.update();
        }
        
        if (window.memoryChart && data.memory_history) {
            window.memoryChart.data.datasets[0].data = data.memory_history;
            window.memoryChart.update();
        }
    }

    async refreshLogs() {
        const response = await fetch('/admin/api/recent-logs');
        const data = await response.json();
        
        const logsContainer = document.getElementById('logs-container');
        if (logsContainer && data.logs) {
            // Добавляем только новые логи
            data.logs.forEach(log => {
                if (!document.querySelector(`[data-log-id="${log.id}"]`)) {
                    const logElement = this.createLogElement(log);
                    logsContainer.insertAdjacentElement('afterbegin', logElement);
                }
            });
        }
    }

    createLogElement(log) {
        const div = document.createElement('div');
        div.className = `log-entry ${log.level}`;
        div.setAttribute('data-log-id', log.id);
        div.innerHTML = `
            <span class="log-time">${log.timestamp}</span>
            <span class="log-level badge badge-${log.level}">${log.level.toUpperCase()}</span>
            <span class="log-message">${log.message}</span>
        `;
        return div;
    }

    // Утилитарные функции
    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        if (hours > 0) {
            return `${hours}ч ${minutes}м ${secs}с`;
        } else if (minutes > 0) {
            return `${minutes}м ${secs}с`;
        } else {
            return `${secs}с`;
        }
    }

    async exportData(dataType) {
        try {
            const response = await fetch(`/admin/api/export/${dataType}`);
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${dataType}_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            this.showNotification(`${dataType} успешно экспортированы`, 'success');
        } catch (error) {
            this.showNotification(`Ошибка экспорта ${dataType}`, 'danger');
            console.error('Ошибка экспорта:', error);
        }
    }
}

// Глобальные функции для использования в шаблонах
window.adminPanel = null;

// Инициализация при загрузке DOM
document.addEventListener('DOMContentLoaded', function() {
    window.adminPanel = new AdminPanel();
});

// Функции для работы с API
const AdminAPI = {
    async get(endpoint) {
        const response = await fetch(`/admin/api/${endpoint}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    },

    async post(endpoint, data) {
        const response = await fetch(`/admin/api/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    },

    async delete(endpoint) {
        const response = await fetch(`/admin/api/${endpoint}`, {
            method: 'DELETE'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }
};

// Экспорт для использования в модулях
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AdminPanel, AdminAPI };
}
