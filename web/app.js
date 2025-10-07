// Cloud Security Monitor Frontend Application
class SecurityMonitor {
    constructor() {
        this.apiBaseUrl = 'http://localhost:8000';
        this.currentPage = 1;
        this.pageSize = 10;
        this.currentFilters = {};
        this.isDarkMode = false;
        this.currentSort = { field: null, direction: 'asc' };
        this.allFindings = []; // Cache for client-side sorting
        
        this.initializeEventListeners();
        this.loadDashboard();
    }

    initializeEventListeners() {
        // Theme toggle
        document.getElementById('themeToggle').addEventListener('click', () => this.toggleTheme());
        
        // Scan button
        document.getElementById('scanBtn').addEventListener('click', () => this.showUploadModal());
        
        // Back to dashboard
        document.getElementById('backToDashboard').addEventListener('click', () => this.showDashboard());
        
        // View all findings
        document.getElementById('viewAllFindings').addEventListener('click', () => this.showFindings());
        
        // Apply filters
        document.getElementById('applyFilters').addEventListener('click', () => this.applyFilters());
        
        // Start scan
        document.getElementById('startScan').addEventListener('click', () => this.startScan());
        
        // Close details panel
        document.getElementById('closeDetails').addEventListener('click', () => this.closeDetailsPanel());
        document.getElementById('overlay').addEventListener('click', () => this.closeDetailsPanel());
        
        // File input change
        document.getElementById('resourceFile').addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                document.getElementById('startScan').disabled = false;
            }
        });

        // Table sorting
        document.addEventListener('click', (e) => {
            if (e.target.closest('.sortable')) {
                const th = e.target.closest('.sortable');
                const field = th.dataset.sort;
                this.sortTable(field);
            }
        });
    }

    toggleTheme() {
        this.isDarkMode = !this.isDarkMode;
        document.body.classList.toggle('dark-mode', this.isDarkMode);
        
        const themeIcon = document.querySelector('#themeToggle i');
        themeIcon.className = this.isDarkMode ? 'fas fa-sun' : 'fas fa-moon';
        
        localStorage.setItem('darkMode', this.isDarkMode);
    }

    showUploadModal() {
        const modal = new bootstrap.Modal(document.getElementById('uploadModal'));
        modal.show();
    }

    async startScan() {
        const fileInput = document.getElementById('resourceFile');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a JSON file first.');
            return;
        }

        try {
            const text = await file.text();
            const resources = JSON.parse(text);
            
            if (!Array.isArray(resources)) {
                throw new Error('JSON file must contain an array of resources.');
            }

            this.showLoading();
            
            const response = await fetch(`${this.apiBaseUrl}/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ resources })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log('Scan completed:', result);
            
            // Close modal and hide loading
            bootstrap.Modal.getInstance(document.getElementById('uploadModal')).hide();
            this.hideLoading();
            
            // Refresh dashboard
            await this.loadDashboard();
            
            // Show success message
            this.showAlert(`Scan completed successfully! Found ${result.count} security issues.`, 'success');
            
        } catch (error) {
            console.error('Error during scan:', error);
            this.hideLoading();
            this.showAlert(`Error during scan: ${error.message}`, 'danger');
        }
    }

    async loadDashboard() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/findings/summary/stats`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const stats = await response.json();
            this.updateDashboard(stats);
            
        } catch (error) {
            console.error('Error loading dashboard:', error);
            this.showAlert('Error loading dashboard data', 'warning');
        }
    }

    updateDashboard(stats) {
        // Update severity counts
        document.getElementById('criticalCount').textContent = stats.severity_breakdown.CRITICAL || 0;
        document.getElementById('highCount').textContent = stats.severity_breakdown.HIGH || 0;
        document.getElementById('mediumCount').textContent = stats.severity_breakdown.MEDIUM || 0;
        document.getElementById('lowCount').textContent = stats.severity_breakdown.LOW || 0;

        // Update resource breakdown
        const resourceBreakdown = document.getElementById('resourceBreakdown');
        resourceBreakdown.innerHTML = '';
        
        for (const [resourceType, count] of Object.entries(stats.resource_type_breakdown)) {
            const col = document.createElement('div');
            col.className = 'col-md-2 mb-2';
            col.innerHTML = `
                <div class="card text-center">
                    <div class="card-body p-2">
                        <div class="h5 mb-1">${count}</div>
                        <small class="text-muted">${resourceType.toUpperCase()}</small>
                    </div>
                </div>
            `;
            resourceBreakdown.appendChild(col);
        }

        // Add pulse animation to cards with findings
        if (stats.total_findings > 0) {
            document.querySelectorAll('.stat-card').forEach(card => {
                if (parseInt(card.querySelector('.stat-number').textContent) > 0) {
                    card.classList.add('pulse');
                }
            });
        }
    }

    async loadFindings() {
        try {
            console.log('Loading findings from:', `${this.apiBaseUrl}/findings`);
            
            // Try to load all findings for client-side sorting and filtering
            let response = await fetch(`${this.apiBaseUrl}/findings?page=1&page_size=100`);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('API Error Details:', {
                    status: response.status,
                    statusText: response.statusText,
                    errorText: errorText
                });
                throw new Error(`HTTP error! status: ${response.status} - ${errorText}`);
            }
            
            const data = await response.json();
            console.log('Findings loaded:', data);
            this.allFindings = data.findings || [];
            this.applyClientSideFilteringAndSorting();
            
        } catch (error) {
            console.error('Error loading findings:', error);
            this.showAlert(`Error loading findings: ${error.message}`, 'danger');
            
            // Show empty state
            this.updateFindingsTable({
                findings: [],
                total: 0,
                page: 1,
                page_size: 10
            });
        }
    }

    applyClientSideFilteringAndSorting() {
        let filteredFindings = [...this.allFindings];

        // Apply filters
        if (this.currentFilters.severity) {
            filteredFindings = filteredFindings.filter(f => 
                f.severity.toLowerCase() === this.currentFilters.severity.toLowerCase()
            );
        }
        if (this.currentFilters.resource_type) {
            filteredFindings = filteredFindings.filter(f => 
                f.resource.type === this.currentFilters.resource_type
            );
        }
        if (this.currentFilters.account_id) {
            filteredFindings = filteredFindings.filter(f => 
                f.resource.account_id.includes(this.currentFilters.account_id)
            );
        }

        // Apply sorting
        if (this.currentSort.field) {
            filteredFindings.sort((a, b) => {
                let aVal, bVal;
                
                switch (this.currentSort.field) {
                    case 'severity':
                        const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
                        aVal = severityOrder[a.severity] || 0;
                        bVal = severityOrder[b.severity] || 0;
                        break;
                    case 'rule_id':
                        aVal = a.rule_id;
                        bVal = b.rule_id;
                        break;
                    case 'resource_name':
                        aVal = a.resource.name;
                        bVal = b.resource.name;
                        break;
                    case 'account_id':
                        aVal = a.resource.account_id;
                        bVal = b.resource.account_id;
                        break;
                    case 'timestamp':
                        aVal = new Date(a.timestamp);
                        bVal = new Date(b.timestamp);
                        break;
                    default:
                        return 0;
                }

                if (aVal < bVal) return this.currentSort.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return this.currentSort.direction === 'asc' ? 1 : -1;
                return 0;
            });
        }

        // Apply pagination
        const totalPages = Math.ceil(filteredFindings.length / this.pageSize);
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = startIndex + this.pageSize;
        const paginatedFindings = filteredFindings.slice(startIndex, endIndex);

        // Update display
        this.updateFindingsTable({
            findings: paginatedFindings,
            total: filteredFindings.length,
            page: this.currentPage,
            page_size: this.pageSize
        });
        this.updatePagination({
            findings: paginatedFindings,
            total: filteredFindings.length,
            page: this.currentPage,
            page_size: this.pageSize
        });
    }

    sortTable(field) {
        if (this.currentSort.field === field) {
            this.currentSort.direction = this.currentSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.currentSort.field = field;
            this.currentSort.direction = 'asc';
        }

        // Update sort indicators
        document.querySelectorAll('.sortable').forEach(th => {
            th.classList.remove('sorted-asc', 'sorted-desc');
            if (th.dataset.sort === field) {
                th.classList.add(`sorted-${this.currentSort.direction}`);
            }
        });

        this.applyClientSideFilteringAndSorting();
    }

    updateFindingsTable(data) {
        const tbody = document.getElementById('findingsTableBody');
        tbody.innerHTML = '';

        if (data.findings.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted py-4">
                        <i class="fas fa-search fa-2x mb-2"></i><br>
                        No findings found
                    </td>
                </tr>
            `;
            return;
        }

        data.findings.forEach(finding => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span></td>
                <td><code>${finding.rule_id}</code></td>
                <td>
                    <strong>${finding.resource.name}</strong><br>
                    <small class="text-muted">${finding.resource.type}</small>
                </td>
                <td><code>${finding.resource.account_id}</code></td>
                <td><small>${new Date(finding.timestamp).toLocaleString()}</small></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="securityMonitor.showFindingDetails('${finding.id}')">
                        <i class="fas fa-eye"></i> View
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    updatePagination(data) {
        const pagination = document.getElementById('pagination');
        pagination.innerHTML = '';

        const totalPages = Math.ceil(data.total / this.pageSize);
        
        if (totalPages <= 1) return;

        // Previous button
        const prevLi = document.createElement('li');
        prevLi.className = `page-item ${this.currentPage === 1 ? 'disabled' : ''}`;
        prevLi.innerHTML = `<a class="page-link" href="#" onclick="securityMonitor.changePage(${this.currentPage - 1})">Previous</a>`;
        pagination.appendChild(prevLi);

        // Page numbers
        for (let i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || (i >= this.currentPage - 2 && i <= this.currentPage + 2)) {
                const li = document.createElement('li');
                li.className = `page-item ${i === this.currentPage ? 'active' : ''}`;
                li.innerHTML = `<a class="page-link" href="#" onclick="securityMonitor.changePage(${i})">${i}</a>`;
                pagination.appendChild(li);
            } else if (i === this.currentPage - 3 || i === this.currentPage + 3) {
                const li = document.createElement('li');
                li.className = 'page-item disabled';
                li.innerHTML = '<span class="page-link">...</span>';
                pagination.appendChild(li);
            }
        }

        // Next button
        const nextLi = document.createElement('li');
        nextLi.className = `page-item ${this.currentPage === totalPages ? 'disabled' : ''}`;
        nextLi.innerHTML = `<a class="page-link" href="#" onclick="securityMonitor.changePage(${this.currentPage + 1})">Next</a>`;
        pagination.appendChild(nextLi);
    }

    changePage(page) {
        this.currentPage = page;
        this.applyClientSideFilteringAndSorting();
    }

    applyFilters() {
        this.currentFilters = {
            severity: document.getElementById('severityFilter').value,
            resource_type: document.getElementById('resourceTypeFilter').value,
            account_id: document.getElementById('accountFilter').value
        };

        // Remove empty filters
        Object.keys(this.currentFilters).forEach(key => {
            if (!this.currentFilters[key]) {
                delete this.currentFilters[key];
            }
        });

        this.currentPage = 1;
        this.applyClientSideFilteringAndSorting();
    }

    async showFindingDetails(findingId) {
        try {
            const response = await fetch(`${this.apiBaseUrl}/findings/${findingId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const finding = await response.json();
            this.displayFindingDetails(finding);
            this.showDetailsPanel();
            
        } catch (error) {
            console.error('Error loading finding details:', error);
            this.showAlert('Error loading finding details', 'danger');
        }
    }

    displayFindingDetails(finding) {
        const detailsContainer = document.getElementById('findingDetails');
        detailsContainer.innerHTML = `
            <div class="mb-4">
                <div class="d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">${finding.rule_id}</h5>
                    <span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
                </div>
            </div>
            
            <div class="mb-4">
                <h6><i class="fas fa-server me-2"></i>Resource Information</h6>
                <div class="card">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Name:</strong> ${finding.resource.name}</p>
                                <p><strong>Type:</strong> <span class="badge bg-secondary">${finding.resource.type}</span></p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Account ID:</strong> <code>${finding.resource.account_id}</code></p>
                                <p><strong>Detected:</strong> ${new Date(finding.timestamp).toLocaleString()}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="mb-4">
                <h6><i class="fas fa-search me-2"></i>Evidence</h6>
                <div class="card">
                    <div class="card-body">
                        <div class="evidence-code">
                            <pre class="mb-0"><code>${JSON.stringify(finding.evidence, null, 2)}</code></pre>
                        </div>
                    </div>
                </div>
            </div>

            <div class="mb-4">
                <h6><i class="fas fa-robot me-2"></i>AI Explanation</h6>
                <div class="card">
                    <div class="card-body">
                        <p class="mb-0">${finding.ai_explanation}</p>
                    </div>
                </div>
            </div>

            <div class="mb-4">
                <h6><i class="fas fa-tools me-2"></i>Remediation Steps</h6>
                <div class="card">
                    <div class="card-body">
                        ${finding.ai_remediation.map((step, index) => `
                            <div class="remediation-step">
                                <div class="d-flex align-items-start">
                                    <span class="badge bg-primary me-3">${index + 1}</span>
                                    <span>${step}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    showDetailsPanel() {
        document.getElementById('overlay').classList.add('show');
        document.getElementById('detailsPanel').classList.add('show');
    }

    closeDetailsPanel() {
        document.getElementById('overlay').classList.remove('show');
        document.getElementById('detailsPanel').classList.remove('show');
    }

    showDashboard() {
        document.getElementById('dashboard').style.display = 'block';
        document.getElementById('findings').style.display = 'none';
        this.loadDashboard();
    }

    showFindings() {
        document.getElementById('dashboard').style.display = 'none';
        document.getElementById('findings').style.display = 'block';
        this.loadFindings();
    }

    showLoading() {
        document.getElementById('loadingOverlay').classList.add('show');
    }

    hideLoading() {
        document.getElementById('loadingOverlay').classList.remove('show');
    }

    showAlert(message, type) {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 1060; min-width: 300px;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(alertDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    }

    // Initialize dark mode from localStorage
    initTheme() {
        const savedTheme = localStorage.getItem('darkMode');
        if (savedTheme === 'true') {
            this.toggleTheme();
        }
    }
}

// Initialize the application
const securityMonitor = new SecurityMonitor();
securityMonitor.initTheme();

// Add click handlers for findings table rows
document.addEventListener('click', (e) => {
    if (e.target.closest('.findings-table tbody tr')) {
        const row = e.target.closest('tr');
        const viewBtn = row.querySelector('button[onclick*="showFindingDetails"]');
        if (viewBtn) {
            viewBtn.click();
        }
    }
});

// Add keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        securityMonitor.closeDetailsPanel();
    }
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        securityMonitor.showUploadModal();
    }
});
