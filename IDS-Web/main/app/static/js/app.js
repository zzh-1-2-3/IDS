// 全局变量
let currentToken = localStorage.getItem('token');
let currentUser = localStorage.getItem('username');
let trafficTrendChart = null;
let protocolChart = null;
let srcIpChart = null;
let dstIpChart = null;
let dstPortChart = null;
let threatLevelChart = null;
let attackTypeChart = null;

// 翻页相关变量
let trafficCurrentPage = 1;
let trafficTotalPages = 1;
let maliciousCurrentPage = 1;
let maliciousTotalPages = 1;

// API基础URL
const API_BASE = '/api';

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    if (currentToken) {
        showMainPage();
        initDashboard();
    } else {
        showLoginPage();
    }
    
    // 绑定登录表单
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // 绑定导航
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const page = this.dataset.page;
            showPage(page);
        });
    });
    
    // 绑定退出
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // 绑定表单提交
    // 已经在 resetAdaptiveForm 和其他地方通过 onsubmit 绑定，不需要重复绑定
    // document.getElementById('adaptive-strategy-form').addEventListener('submit', handleAddAdaptiveStrategy);
    // document.getElementById('custom-strategy-form').addEventListener('submit', handleAddCustomStrategy);
    document.getElementById('train-form').addEventListener('submit', handleTrainModel);
    document.getElementById('import-training-data-form').addEventListener('submit', handleImportTrainingData);
});

// 页面切换
function showLoginPage() {
    document.getElementById('login-page').classList.remove('hidden');
    document.getElementById('main-page').classList.add('hidden');
}

function showMainPage() {
    document.getElementById('login-page').classList.add('hidden');
    document.getElementById('main-page').classList.remove('hidden');
    document.getElementById('current-user').textContent = currentUser || 'admin';
}

function showPage(page) {
    // 隐藏所有页面
    document.querySelectorAll('.content-page').forEach(p => p.classList.add('hidden'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    // 显示目标页面
    document.getElementById(page + '-page').classList.remove('hidden');
    document.querySelector(`.nav-item[data-page="${page}"]`).classList.add('active');
    
    // 初始化页面数据
    if (page === 'dashboard') {
        loadDashboardData();
    } else if (page === 'traffic') {
        initTrafficPage();
    } else if (page === 'detection') {
        initDetectionPage();
    } else if (page === 'strategy') {
        initStrategyPage();
    } else if (page === 'model') {
        initModelPage();
    }
}

// 登录处理
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentToken = data.access_token;
            currentUser = data.user.username;
            localStorage.setItem('token', currentToken);
            localStorage.setItem('username', currentUser);
            showMainPage();
            initDashboard();
        } else {
            alert('登录失败: ' + (data.detail || '用户名或密码错误'));
        }
    } catch (error) {
        alert('登录失败: ' + error.message);
    }
}

// 退出处理
function handleLogout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    currentToken = null;
    currentUser = null;
    showLoginPage();
}

// API请求封装
async function apiRequest(url, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (currentToken) {
        headers['Authorization'] = `Bearer ${currentToken}`;
    }
    
    // 确保body被正确处理
    const fetchOptions = {
        ...options,
        headers
    };
    
    // 只有当body不是FormData时才序列化为JSON
    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
        fetchOptions.body = JSON.stringify(options.body);
    }
    
    // 如果body是FormData，删除Content-Type头，让浏览器自动设置
    if (options.body instanceof FormData) {
        delete fetchOptions.headers['Content-Type'];
    }
    
    const response = await fetch(`${API_BASE}${url}`, fetchOptions);
    
    if (!response.ok) {
        if (response.status === 401) {
            handleLogout();
            throw new Error('认证已过期，请重新登录');
        }
        throw new Error('请求失败: ' + response.statusText);
    }
    
    return response.json();
}

// ==================== 仪表盘 ====================
function initDashboard() {
    loadDashboardData();
    // 每30秒刷新一次
    setInterval(loadDashboardData, 30000);
}

async function loadDashboardData() {
    try {
        // 加载统计数据
        const stats = await apiRequest('/dashboard/stats');
        document.getElementById('stat-total').textContent = stats.total_traffic;
        document.getElementById('stat-abnormal').textContent = stats.abnormal_traffic;
        document.getElementById('stat-threat').textContent = stats.threat_detections;
        document.getElementById('stat-strategy').textContent = stats.response_strategies;
        document.getElementById('stat-total-new').textContent = stats.total_traffic_new;
        document.getElementById('stat-abnormal-new').textContent = stats.abnormal_traffic_new;
        document.getElementById('stat-threat-new').textContent = stats.threat_detections_new;
        document.getElementById('stat-strategy-new').textContent = stats.response_strategies_new;
        
        // 加载流量趋势
        const trend = await apiRequest('/dashboard/traffic-trend');
        renderTrafficTrendChart(trend);
        
        // 加载最近检测
        const recent = await apiRequest('/dashboard/recent-detections');
        renderRecentDetections(recent);
    } catch (error) {
        console.error('加载仪表盘数据失败:', error);
    }
}

function renderTrafficTrendChart(data) {
    const ctx = document.getElementById('traffic-trend-chart').getContext('2d');
    
    if (trafficTrendChart) {
        trafficTrendChart.destroy();
    }
    
    trafficTrendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(d => d.time_label),
            datasets: [
                {
                    label: '正常流量',
                    data: data.map(d => d.normal_count),
                    borderColor: '#52c41a',
                    backgroundColor: 'rgba(82, 196, 26, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3
                },
                {
                    label: '异常流量',
                    data: data.map(d => d.abnormal_count),
                    borderColor: '#f5222d',
                    backgroundColor: 'rgba(245, 34, 45, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: '数据包数量'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '时间'
                    }
                }
            }
        }
    });
}

function renderRecentDetections(detections) {
    const tbody = document.getElementById('recent-detections-body');
    tbody.innerHTML = '';
    
    detections.forEach(d => {
        const row = document.createElement('tr');
        const statusClass = d.status === 'normal' ? 'normal' : 'abnormal';
        row.innerHTML = `
            <td>${d.timestamp}</td>
            <td>${d.src_ip}</td>
            <td>${d.src_port}</td>
            <td>${d.dst_ip}</td>
            <td>${d.dst_port}</td>
            <td>${d.protocol}</td>
            <td>${d.packet_size}</td>
            <td><span class="status-badge ${statusClass}">${d.status === 'normal' ? '正常' : '异常'}</span></td>
        `;
        tbody.appendChild(row);
    });
}

// ==================== 网络流量 ====================
async function initTrafficPage() {
    // 加载网卡列表
    try {
        const interfaces = await apiRequest('/traffic/interfaces');
        const select = document.getElementById('network-interface');
        select.innerHTML = '';
        interfaces.interfaces.forEach(iface => {
            const option = document.createElement('option');
            option.value = iface.name;
            option.textContent = iface.display;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('加载网卡失败:', error);
    }
    
    // 检查捕获状态
    await checkCaptureStatus();
    
    // 确保停止按钮可用
    ensureStopButton();
    
    // 加载流量列表
    loadTrafficList();
    
    // 加载图表
    loadTrafficCharts();
    
    // 每5秒检查一次捕获状态
    setInterval(checkCaptureStatus, 5000);
}

async function checkCaptureStatus() {
    try {
        const status = await apiRequest('/traffic/realtime-status');
        if (status.is_capturing) {
            document.getElementById('start-capture-btn').classList.add('hidden');
            document.getElementById('stop-capture-btn').classList.remove('hidden');
        } else {
            document.getElementById('start-capture-btn').classList.remove('hidden');
            // 始终显示停止捕获按钮
            document.getElementById('stop-capture-btn').classList.remove('hidden');
        }
    } catch (error) {
        console.error('检查捕获状态失败:', error);
        // 出错时也显示停止捕获按钮
        document.getElementById('stop-capture-btn').classList.remove('hidden');
    }
}

async function loadTrafficList(page = 1) {
    try {
        const limit = 10; // 每页显示10条记录
        const skip = (page - 1) * limit;
        const response = await apiRequest(`/traffic/list?skip=${skip}&limit=${limit}`);
        const traffic = response.items;
        const total = response.total;
        
        // 计算总页数
        trafficTotalPages = Math.ceil(total / limit);
        
        renderTrafficTable(traffic);
        updateTrafficPagination(page, trafficTotalPages);
    } catch (error) {
        console.error('加载流量列表失败:', error);
    }
}

function renderTrafficTable(traffic) {
    const tbody = document.getElementById('traffic-table-body');
    tbody.innerHTML = '';
    
    // 安全检查：确保traffic是数组
    if (!traffic || !Array.isArray(traffic)) {
        console.error('renderTrafficTable: traffic不是数组', traffic);
        tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;">暂无数据</td></tr>';
        return;
    }
    
    if (traffic.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;">暂无数据</td></tr>';
        return;
    }
    
    traffic.forEach(t => {
        const row = document.createElement('tr');
        const statusClass = t.status === 'normal' ? 'normal' : 'abnormal';
        row.innerHTML = `
            <td>${new Date(t.timestamp).toLocaleString()}</td>
            <td>${t.src_ip}</td>
            <td>${t.src_port}</td>
            <td>${t.dst_ip}</td>
            <td>${t.dst_port}</td>
            <td>${t.protocol}</td>
            <td>${t.packet_size}</td>
            <td>${t.attack_type || '-'}</td>
            <td>${t.confidence ? (t.confidence * 100).toFixed(2) + '%' : '-'}</td>
            <td><span class="status-badge ${statusClass}">${t.status === 'normal' ? '正常' : '异常'}</span></td>
        `;
        tbody.appendChild(row);
    });
}

async function loadTrafficCharts() {
    try {
        const protocolData = await apiRequest('/traffic/protocol-distribution');
        renderProtocolChart(protocolData.distribution);
        
        const srcIpData = await apiRequest('/traffic/src-ip-distribution');
        renderSrcIpChart(srcIpData.distribution);
        
        const dstIpData = await apiRequest('/traffic/dst-ip-distribution');
        renderDstIpChart(dstIpData.distribution);
        
        const dstPortData = await apiRequest('/traffic/dst-port-distribution');
        renderDstPortChart(dstPortData.distribution);
    } catch (error) {
        console.error('加载图表失败:', error);
    }
}

function renderProtocolChart(data) {
    const ctx = document.getElementById('protocol-chart').getContext('2d');
    
    if (protocolChart) {
        protocolChart.destroy();
    }
    
    protocolChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.protocol),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: ['#667eea', '#764ba2', '#f093fb', '#f5576c']
            }]
        },
        options: {
            responsive: true
        }
    });
}

function renderSrcIpChart(data) {
    const ctx = document.getElementById('src-ip-chart').getContext('2d');
    
    if (srcIpChart) {
        srcIpChart.destroy();
    }
    
    srcIpChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.src_ip),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: ['#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2', '#eb2f96', '#f5222d', '#fa8c16', '#1890ff', '#52c41a']
            }]
        },
        options: {
            responsive: true
        }
    });
}

function renderDstIpChart(data) {
    const ctx = document.getElementById('dst-ip-chart').getContext('2d');
    
    if (dstIpChart) {
        dstIpChart.destroy();
    }
    
    dstIpChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.dst_ip),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: ['#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2', '#eb2f96', '#f5222d', '#fa8c16', '#1890ff', '#52c41a']
            }]
        },
        options: {
            responsive: true
        }
    });
}

function renderDstPortChart(data) {
    const ctx = document.getElementById('dst-port-chart').getContext('2d');
    
    if (dstPortChart) {
        dstPortChart.destroy();
    }
    
    dstPortChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.dst_port),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: ['#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2', '#eb2f96', '#f5222d', '#fa8c16', '#1890ff', '#52c41a']
            }]
        },
        options: {
            responsive: true
        }
    });
}

async function uploadPcap() {
    const fileInput = document.getElementById('pcap-file');
    if (!fileInput.files.length) {
        alert('请选择PCAP文件');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    try {
        const response = await fetch(`${API_BASE}/traffic/upload-pcap`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });
        
        const data = await response.json();
        alert(data.message);
        
        if (data.success) {
            loadTrafficList();
        }
    } catch (error) {
        alert('上传失败: ' + error.message);
    }
}

async function startRealtimeCapture() {
    const interfaces = Array.from(document.getElementById('network-interface').selectedOptions).map(o => o.value);
    const interval = document.getElementById('update-interval').value;
    
    if (interfaces.length === 0) {
        alert('请选择网卡');
        return;
    }
    
    try {
        const result = await apiRequest('/traffic/start-realtime', {
            method: 'POST',
            body: JSON.stringify({ interfaces, update_interval: parseInt(interval) })
        });
        
        if (result.success) {
            document.getElementById('start-capture-btn').classList.add('hidden');
            document.getElementById('stop-capture-btn').classList.remove('hidden');
            alert('实时捕获已启动');
        }
    } catch (error) {
        alert('启动失败: ' + error.message);
    }
}

// 确保停止捕获按钮始终可用
function ensureStopButton() {
    // 检查是否正在捕获
    checkCaptureStatus();
    
    // 确保停止按钮存在且可点击
    const stopBtn = document.getElementById('stop-capture-btn');
    if (stopBtn) {
        stopBtn.classList.remove('hidden');
    }
}

async function stopRealtimeCapture() {
    try {
        const result = await apiRequest('/traffic/stop-realtime', { method: 'POST' });
        
        document.getElementById('start-capture-btn').classList.remove('hidden');
        // 不要隐藏停止捕获按钮
        // document.getElementById('stop-capture-btn').classList.add('hidden');
        alert(result.message);
        loadTrafficList();
    } catch (error) {
        alert('停止失败: ' + error.message);
    }
}

async function filterTraffic() {
    // 获取筛选条件
    const srcIp = document.getElementById('filter-src-ip').value.trim();
    const srcPort = document.getElementById('filter-src-port').value.trim();
    const dstIp = document.getElementById('filter-dst-ip').value.trim();
    const dstPort = document.getElementById('filter-dst-port').value.trim();
    const protocol = document.getElementById('filter-protocol').value;
    const attackType = document.getElementById('filter-attack-type').value;
    const status = document.getElementById('filter-status').value;
    
    // 构建查询参数
    const params = new URLSearchParams();
    params.append('limit', '50');
    params.append('_t', Date.now()); // 添加时间戳避免缓存
    if (srcIp) params.append('src_ip', srcIp);
    if (srcPort) params.append('src_port', srcPort);
    if (dstIp) params.append('dst_ip', dstIp);
    if (dstPort) params.append('dst_port', dstPort);
    if (protocol) params.append('protocol', protocol);
    if (attackType) params.append('attack_type', attackType);
    if (status) params.append('status', status);
    
    try {
        const response = await apiRequest(`/traffic/list?${params.toString()}`);
        console.log('筛选API响应:', response);
        
        if (!response || !response.items) {
            console.error('API响应格式错误:', response);
            alert('筛选失败: 服务器返回数据格式错误');
            return;
        }
        
        const traffic = response.items;
        renderTrafficTable(traffic);
    } catch (error) {
        console.error('筛选流量失败:', error);
        alert('筛选失败: ' + error.message);
    }
}

async function clearAllTraffic() {
    if (!confirm('确定要清空所有流量数据吗？此操作不可恢复！')) return;
    
    try {
        const result = await apiRequest('/traffic/clear', { method: 'POST' });
        if (result.success) {
            alert('流量数据已清空');
            loadTrafficList();
        } else {
            alert('清空失败: ' + result.message);
        }
    } catch (error) {
        console.error('清空流量失败:', error);
        alert('清空失败: ' + error.message);
    }
}

// ==================== 检测结果 ====================
async function initDetectionPage() {
    loadDetectionStats();
    loadDetectionCharts();
    loadMaliciousList();
}

async function loadDetectionStats() {
    try {
        const stats = await apiRequest('/detection/stats');
        document.getElementById('detect-total').textContent = stats.total_flows;
        document.getElementById('detect-high').textContent = stats.high_risk;
        document.getElementById('detect-medium').textContent = stats.medium_risk;
        document.getElementById('detect-low').textContent = stats.low_risk;
        document.getElementById('detect-total-new').textContent = stats.total_flows;
        document.getElementById('detect-high-new').textContent = stats.high_risk_new;
        document.getElementById('detect-medium-new').textContent = stats.medium_risk_new;
        document.getElementById('detect-low-new').textContent = stats.low_risk_new;
    } catch (error) {
        console.error('加载统计失败:', error);
    }
}

async function loadDetectionCharts() {
    try {
        const threatData = await apiRequest('/detection/threat-distribution');
        renderThreatLevelChart(threatData.distribution);
        
        const attackData = await apiRequest('/detection/attack-type-distribution');
        renderAttackTypeChart(attackData.distribution);
    } catch (error) {
        console.error('加载图表失败:', error);
    }
}

function renderThreatLevelChart(data) {
    const ctx = document.getElementById('threat-level-chart').getContext('2d');
    
    if (threatLevelChart) {
        threatLevelChart.destroy();
    }
    
    threatLevelChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['高危', '中危', '低危', '无危害'],
            datasets: [{
                data: [data.high, data.medium, data.low, data.none],
                backgroundColor: ['#f5222d', '#faad14', '#52c41a', '#1890ff']
            }]
        },
        options: {
            responsive: true
        }
    });
}

function renderAttackTypeChart(data) {
    const ctx = document.getElementById('attack-type-chart').getContext('2d');
    
    if (attackTypeChart) {
        attackTypeChart.destroy();
    }
    
    attackTypeChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: data.map(d => d.attack_type),
            datasets: [{
                data: data.map(d => d.count),
                backgroundColor: ['#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2', '#eb2f96', '#f5222d']
            }]
        },
        options: {
            responsive: true
        }
    });
}

async function loadMaliciousList(page = 1) {
    try {
        const limit = 10; // 每页显示10条记录
        const skip = (page - 1) * limit;
        const includeWhitelist = document.getElementById('include-whitelist')?.checked || false;
        const response = await apiRequest(`/detection/malicious-list?skip=${skip}&limit=${limit}&include_whitelist=${includeWhitelist}`);
        const list = response.items;
        const total = response.total;
        
        // 计算总页数
        maliciousTotalPages = Math.ceil(total / limit);
        
        renderMaliciousTable(list);
        updateMaliciousPagination(page, maliciousTotalPages);
    } catch (error) {
        console.error('加载恶意流量失败:', error);
    }
}

function renderMaliciousTable(list) {
    const tbody = document.getElementById('malicious-table-body');
    tbody.innerHTML = '';
    
    // 创建一个Map来存储相同流量的响应策略
    // 以 "src_ip:dst_ip:attack_type" 为key
    const flowStrategyMap = new Map();
    
    // 第一遍遍历：收集所有已执行的响应策略
    list.forEach(item => {
        const flowKey = `${item.src_ip}:${item.dst_ip}:${item.attack_type}`;
        if (item.response_strategy && item.response_strategy !== '未配置' && item.response_strategy !== '') {
            flowStrategyMap.set(flowKey, item.response_strategy);
        }
    });
    
    // 第二遍遍历：渲染表格，相同流量显示已执行的响应策略
    list.forEach(item => {
        const row = document.createElement('tr');
        const threatClass = item.threat_level;
        const threatText = item.threat_level === 'none' ? '无危害' : 
                          item.threat_level === 'low' ? '低危' : 
                          item.threat_level === 'medium' ? '中危' : '高危';
        
        // 检查是否有相同流量的响应策略
        const flowKey = `${item.src_ip}:${item.dst_ip}:${item.attack_type}`;
        const strategy = flowStrategyMap.get(flowKey) || item.response_strategy || '未配置';
        
        row.innerHTML = `
            <td>${new Date(item.timestamp).toLocaleString()}</td>
            <td>${item.src_ip}</td>
            <td>${item.dst_ip}</td>
            <td>${item.attack_type || 'Unknown'}</td>
            <td>${(item.confidence * 100).toFixed(2)}%</td>
            <td><span class="status-badge ${threatClass}">${threatText}</span></td>
            <td>${strategy}</td>
            <td>
                <button class="action-btn view" onclick="viewDetectionDetail(${item.id})">查看</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function viewDetectionDetail(id) {
    try {
        const detail = await apiRequest(`/detection/detail/${id}`);
        const content = document.getElementById('detection-detail-content');
        content.innerHTML = `
            <p><strong>时间:</strong> ${new Date(detail.timestamp).toLocaleString()}</p>
            <p><strong>源IP:</strong> ${detail.src_ip}:${detail.src_port}</p>
            <p><strong>目的IP:</strong> ${detail.dst_ip}:${detail.dst_port}</p>
            <p><strong>协议:</strong> ${detail.protocol}</p>
            <p><strong>攻击类型:</strong> ${detail.attack_type}</p>
            <p><strong>置信度:</strong> ${(detail.confidence * 100).toFixed(2)}%</p>
            <p><strong>威胁等级:</strong> ${detail.threat_level_chinese || detail.threat_level}</p>
            <p><strong>威胁分数:</strong> ${detail.threat_score ? detail.threat_score.toFixed(4) : '-'}</p>
            <p><strong>权值计算:</strong> ${detail.weight_calculation}</p>
            <p><strong>响应策略:</strong> ${detail.response_strategy || '无'}</p>
        `;
        showModal('detection-detail-modal');
    } catch (error) {
        alert('加载详情失败: ' + error.message);
    }
}



async function clearMaliciousTraffic() {
    if (!confirm('确定要清空所有检测结果吗？此操作不可恢复。')) return;
    
    try {
        const result = await apiRequest('/detection/clear-all', { method: 'DELETE' });
        alert(result.message);
        loadMaliciousList();
        loadDetectionStats();
        loadDetectionCharts();
    } catch (error) {
        alert('清空失败: ' + error.message);
    }
}

// ==================== 响应策略 ====================
async function initStrategyPage() {
    // 加载系统类型
    try {
        const osInfo = await apiRequest('/strategy/os-type');
        document.getElementById('os-type').textContent = osInfo.os_type === 'windows' ? 'Windows' : 'Linux';
    } catch (error) {
        console.error('加载系统信息失败:', error);
    }
    
    loadAdaptiveStrategies();
    loadCustomStrategies();
    loadExecutedStrategies();
}

async function loadAdaptiveStrategies() {
    try {
        const strategies = await apiRequest('/strategy/adaptive/list');
        renderAdaptiveStrategies(strategies);
    } catch (error) {
        console.error('加载自适应策略失败:', error);
    }
}

function renderAdaptiveStrategies(strategies) {
    const tbody = document.getElementById('adaptive-strategy-body');
    tbody.innerHTML = '';
    
    strategies.forEach(s => {
        const row = document.createElement('tr');
        const config = s.action === 'block' ? `封禁${s.block_duration || '永久'}` : 
                      s.action === 'throttle' ? `限流${s.packet_limit}包/秒` : '仅告警';
        const statusClass = s.is_active ? 'normal' : 'abnormal';
        const statusText = s.is_active ? '已启用' : '已禁用';
        const threatText = s.threat_level === 'none' ? '无危害' : 
                          s.threat_level === 'low' ? '低危' : 
                          s.threat_level === 'medium' ? '中危' : '高危';
        row.innerHTML = `
            <td>${s.name}</td>
            <td><span class="status-badge ${s.threat_level}">${threatText}</span></td>
            <td>${s.attack_type}</td>
            <td>${s.action === 'block' ? '封禁' : s.action === 'throttle' ? '限流' : '仅告警'}</td>
            <td>${config}</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>
                <button class="action-btn ${s.is_active ? 'cancel' : 'execute'}" onclick="toggleAdaptiveStrategy(${s.id})">${s.is_active ? '禁用' : '启用'}</button>
                <button class="action-btn edit" onclick="editAdaptiveStrategy(${s.id})">编辑</button>
                <button class="action-btn delete" onclick="deleteAdaptiveStrategy(${s.id})">删除</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function loadCustomStrategies() {
    try {
        const strategies = await apiRequest('/strategy/custom/list');
        renderCustomStrategies(strategies);
    } catch (error) {
        console.error('加载自定义策略失败:', error);
    }
}

function renderCustomStrategies(strategies) {
    const tbody = document.getElementById('custom-strategy-body');
    tbody.innerHTML = '';
    
    strategies.forEach(s => {
        const row = document.createElement('tr');
        const statusText = s.is_active ? '已执行' : s.is_executed ? '已取消' : '未执行';
        row.innerHTML = `
            <td>${s.name}</td>
            <td>${s.strategy_type === 'whitelist' ? '白名单' : s.strategy_type === 'block' ? '封禁' : '限流'}</td>
            <td>${s.direction || '-'}</td>
            <td>${s.ip_range || '-'}</td>
            <td>${s.port_range || '-'}</td>
            <td>${statusText}</td>
            <td>
                ${!s.is_active ? `<button class="action-btn execute" onclick="executeStrategy(${s.id})">执行</button>` : ''}
                ${s.is_active ? `<button class="action-btn cancel" onclick="cancelStrategy(${s.id})">取消</button>` : ''}
                <button class="action-btn delete" onclick="deleteStrategy(${s.id})">删除</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function loadExecutedStrategies() {
    try {
        const strategies = await apiRequest('/strategy/executed/list');
        renderExecutedStrategies(strategies);
    } catch (error) {
        console.error('加载执行策略失败:', error);
    }
}

function renderExecutedStrategies(strategies) {
    const tbody = document.getElementById('executed-strategy-body');
    tbody.innerHTML = '';
    
    strategies.forEach(s => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date(s.timestamp).toLocaleString()}</td>
            <td>${s.annotation}</td>
            <td>${s.target_ip}</td>
            <td>${s.action === 'block' ? '封禁' : s.action === 'throttle' ? '限流' : '告警'}</td>
            <td>
                <button class="action-btn cancel" onclick="cancelExecutedStrategy(${s.id})">取消</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function showAddAdaptiveModal() {
    resetAdaptiveForm();
    toggleAdaptiveOptions();
    showModal('adaptive-strategy-modal');
}

function showAddCustomModal() {
    showModal('custom-strategy-modal');
}

function toggleAdaptiveOptions() {
    const action = document.getElementById('adaptive-action').value;
    const blockGroup = document.getElementById('block-duration-group');
    const throttleGroup = document.getElementById('throttle-limit-group');
    if (blockGroup) blockGroup.style.display = action === 'block' ? 'block' : 'none';
    if (throttleGroup) throttleGroup.style.display = action === 'throttle' ? 'block' : 'none';
}

function toggleCustomOptions() {
    const type = document.getElementById('custom-type').value;
    document.getElementById('custom-direction-group').style.display = type === 'whitelist' ? 'none' : 'block';
    document.getElementById('custom-port-group').style.display = type === 'whitelist' ? 'none' : 'block';
    document.getElementById('custom-throttle-group').style.display = type === 'throttle' ? 'block' : 'none';
}

async function handleAddAdaptiveStrategy(e) {
    e.preventDefault();
    
    const action = document.getElementById('adaptive-action').value;
    const blockDurationElem = document.getElementById('adaptive-block-duration');
    const packetLimitElem = document.getElementById('adaptive-packet-limit');
    
    const data = {
        name: document.getElementById('adaptive-name').value,
        threat_level: document.getElementById('adaptive-threat-level').value,
        attack_type: document.getElementById('adaptive-attack-type').value,
        action: action,
        block_duration: action === 'block' && blockDurationElem ? blockDurationElem.value : null,
        packet_limit: action === 'throttle' && packetLimitElem ? parseInt(packetLimitElem.value) || null : null
    };
    
    try {
        await apiRequest('/strategy/adaptive/create', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        closeModal();
        loadAdaptiveStrategies();
        alert('策略创建成功');
    } catch (error) {
        alert('创建失败: ' + error.message);
    }
}

async function handleAddCustomStrategy(e) {
    e.preventDefault();
    
    const data = {
        name: document.getElementById('custom-name').value,
        strategy_type: document.getElementById('custom-type').value,
        direction: document.getElementById('custom-direction').value,
        ip_range: document.getElementById('custom-ip-range').value,
        port_range: document.getElementById('custom-port-range').value,
        packet_limit: parseInt(document.getElementById('custom-packet-limit').value) || null
    };
    
    try {
        await apiRequest('/strategy/custom/create', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        closeModal();
        loadCustomStrategies();
        alert('策略创建成功');
    } catch (error) {
        alert('创建失败: ' + error.message);
    }
}

async function executeStrategy(id) {
    try {
        await apiRequest(`/strategy/custom/execute/${id}`, { method: 'POST' });
        loadCustomStrategies();
        alert('策略执行成功');
    } catch (error) {
        alert('执行失败: ' + error.message);
    }
}

async function cancelStrategy(id) {
    try {
        await apiRequest(`/strategy/custom/cancel/${id}`, { method: 'POST' });
        loadCustomStrategies();
        alert('策略已取消');
    } catch (error) {
        alert('取消失败: ' + error.message);
    }
}

async function deleteStrategy(id) {
    if (!confirm('确定删除此策略?')) return;
    
    try {
        await apiRequest(`/strategy/custom/delete/${id}`, { method: 'DELETE' });
        loadCustomStrategies();
        alert('策略已删除');
    } catch (error) {
        alert('删除失败: ' + error.message);
    }
}

async function deleteAdaptiveStrategy(id) {
    if (!confirm('确定删除此策略?')) return;

    try {
        await apiRequest(`/strategy/adaptive/delete/${id}`, { method: 'DELETE' });
        loadAdaptiveStrategies();
        alert('策略已删除');
    } catch (error) {
        alert('删除失败: ' + error.message);
    }
}

async function toggleAdaptiveStrategy(id) {
    try {
        const result = await apiRequest(`/strategy/adaptive/toggle/${id}`, { method: 'POST' });
        if (result.success) {
            loadAdaptiveStrategies();
            alert(result.message);
        } else {
            alert('操作失败: ' + result.message);
        }
    } catch (error) {
        alert('操作失败: ' + error.message);
    }
}

// 当前编辑的策略ID
let currentEditingAdaptiveId = null;

async function editAdaptiveStrategy(id) {
    try {
        // 获取策略详情
        const strategy = await apiRequest(`/strategy/adaptive/${id}`);
        if (!strategy || strategy.success === false) {
            alert('获取策略信息失败');
            return;
        }
        
        // 保存当前编辑的ID
        currentEditingAdaptiveId = id;
        
        // 填充表单
        document.getElementById('adaptive-name').value = strategy.name;
        document.getElementById('adaptive-threat-level').value = strategy.threat_level;
        document.getElementById('adaptive-attack-type').value = strategy.attack_type;
        document.getElementById('adaptive-action').value = strategy.action;
        
        // 根据动作类型显示/隐藏相关字段
        toggleAdaptiveOptions();
        
        // 填充配置字段
        if (strategy.action === 'block') {
            const blockDuration = document.getElementById('adaptive-block-duration');
            if (blockDuration) blockDuration.value = strategy.block_duration || '1h';
        } else if (strategy.action === 'throttle') {
            const packetLimit = document.getElementById('adaptive-packet-limit');
            if (packetLimit) packetLimit.value = strategy.packet_limit || 100;
        }
        
        // 修改表单提交处理
        const form = document.getElementById('adaptive-strategy-form');
        form.onsubmit = handleUpdateAdaptiveStrategy;
        
        // 修改标题和按钮文本
        const titleElem = document.querySelector('#adaptive-strategy-modal h3');
        if (titleElem) titleElem.textContent = '编辑自适应策略';
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.textContent = '保存修改';
        
        // 显示模态框
        showModal('adaptive-strategy-modal');
    } catch (error) {
        console.error('加载策略信息失败:', error);
        alert('加载策略信息失败: ' + error.message);
    }
}

async function handleUpdateAdaptiveStrategy(e) {
    e.preventDefault();
    
    if (!currentEditingAdaptiveId) {
        alert('未找到要更新的策略');
        return;
    }
    
    const action = document.getElementById('adaptive-action').value;
    const blockDurationElem = document.getElementById('adaptive-block-duration');
    const packetLimitElem = document.getElementById('adaptive-packet-limit');
    
    const data = {
        name: document.getElementById('adaptive-name').value,
        threat_level: document.getElementById('adaptive-threat-level').value,
        attack_type: document.getElementById('adaptive-attack-type').value,
        action: action,
        block_duration: action === 'block' && blockDurationElem ? blockDurationElem.value : null,
        packet_limit: action === 'throttle' && packetLimitElem ? parseInt(packetLimitElem.value) : null
    };
    
    try {
        await apiRequest(`/strategy/adaptive/update/${currentEditingAdaptiveId}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
        
        // 重置表单
        resetAdaptiveForm();
        
        closeModal();
        loadAdaptiveStrategies();
        alert('策略更新成功');
    } catch (error) {
        alert('更新失败: ' + error.message);
    }
}

function resetAdaptiveForm() {
    const form = document.getElementById('adaptive-strategy-form');
    form.reset();
    form.onsubmit = handleAddAdaptiveStrategy;
    currentEditingAdaptiveId = null;
    
    // 恢复标题和按钮
    const titleElem = document.querySelector('#adaptive-strategy-modal h3');
    if (titleElem) titleElem.textContent = '新增自适应策略';
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.textContent = '保存';
    
    // 隐藏配置字段
    const blockGroup = document.getElementById('block-duration-group');
    const throttleGroup = document.getElementById('throttle-limit-group');
    if (blockGroup) blockGroup.style.display = 'none';
    if (throttleGroup) throttleGroup.style.display = 'none';
}

async function cancelExecutedStrategy(id) {
    try {
        await apiRequest(`/strategy/executed/cancel/${id}`, { method: 'POST' });
        loadExecutedStrategies();
        alert('策略已取消');
    } catch (error) {
        alert('取消失败: ' + error.message);
    }
}

// ==================== 模型管理 ====================
async function initModelPage() {
    loadModelList();
    loadTrainingHistory();
}

async function loadModelList() {
    try {
        const data = await apiRequest('/model/list');
        renderModelTable(data.configs);
        
        // 显示当前激活模型
        const activeModel = data.configs.find(m => m.is_active);
        const infoDiv = document.getElementById('active-model-info');
        if (activeModel) {
            infoDiv.innerHTML = `
                <p><strong>模型名称:</strong> ${activeModel.name}</p>
                <p><strong>类型:</strong> ${activeModel.model_type.toUpperCase()}</p>
                <p><strong>数据集:</strong> ${activeModel.dataset_type}</p>
                <p><strong>准确率:</strong> ${activeModel.accuracy ? (activeModel.accuracy * 100).toFixed(2) + '%' : '未评估'}</p>
            `;
        } else {
            infoDiv.innerHTML = '<p>未选择模型</p>';
        }
    } catch (error) {
        console.error('加载模型列表失败:', error);
    }
}

function renderModelTable(models) {
    const tbody = document.getElementById('model-table-body');
    tbody.innerHTML = '';
    
    models.forEach(m => {
        const row = document.createElement('tr');
        // 对于二分类模型（binary 或 CNN_2），使用专用的评估字段
        const isBinary = m.model_type === 'binary' || m.model_type === 'CNN_2';
        const accuracy = isBinary ? m.binary_accuracy : m.accuracy;
        const precision = isBinary ? m.binary_precision : m.precision_score;
        const recall = isBinary ? m.binary_recall : m.recall_score;
        const f1 = isBinary ? m.binary_f1 : m.f1_score;
        
        row.innerHTML = `
            <td>${m.name}</td>
            <td>${formatModelType(m.model_type)}</td>
            <td>${m.dataset_type}</td>
            <td>${accuracy ? (accuracy * 100).toFixed(2) + '%' : '-'}</td>
            <td>${precision ? (precision * 100).toFixed(2) + '%' : '-'}</td>
            <td>${recall ? (recall * 100).toFixed(2) + '%' : '-'}</td>
            <td>${f1 ? (f1 * 100).toFixed(2) + '%' : '-'}</td>
            <td>${m.is_active ? '<span class="status-badge normal">使用中</span>' : '<span class="status-badge abnormal">未使用</span>'}</td>
            <td>
                ${!m.is_active ? `<button class="action-btn execute" onclick="setActiveModel(${m.id})">使用</button>` : ''}
                <button class="action-btn view" onclick="evaluateModel(${m.id})">评估</button>
                ${!m.is_active ? `<button class="action-btn delete" onclick="deleteModel(${m.id})">删除</button>` : ''}
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function loadTrainingHistory() {
    try {
        const history = await apiRequest('/model/training-history');
        renderTrainingHistory(history);
    } catch (error) {
        console.error('加载训练历史失败:', error);
    }
}

function renderTrainingHistory(history) {
    const tbody = document.getElementById('training-history-body');
    tbody.innerHTML = '';
    
    history.forEach(h => {
        const row = document.createElement('tr');
        const statusText = h.status === 'running' ? '训练中' : h.status === 'completed' ? '已完成' : '失败';
        const statusClass = h.status === 'running' ? 'medium' : h.status === 'completed' ? 'normal' : 'abnormal';
        row.innerHTML = `
            <td>${h.model_name}</td>
            <td>${formatModelType(h.model_type)}</td>
            <td>${h.dataset_type}</td>
            <td>${h.batch_size}</td>
            <td>${h.epochs}</td>
            <td>${h.learning_rate}</td>
            <td>${h.progress}%</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function showTrainModal() {
    showModal('train-modal');
}

function showImportTrainingDataModal() {
    showModal('import-training-data-modal');
}

async function handleImportTrainingData(e) {
    e.preventDefault();
    
    // 使用e.target获取表单元素
    const form = e.target;
    const fileInput = form.querySelector('#pcap-file');
    const label = form.querySelector('#pcap-label').value;
    
    console.log('form:', form);
    console.log('fileInput:', fileInput);
    console.log('fileInput.files:', fileInput.files);
    console.log('fileInput.files.length:', fileInput.files.length);
    
    if (!fileInput.files || fileInput.files.length === 0) {
        alert('请选择PCAP文件');
        return;
    }
    
    console.log('Selected file:', fileInput.files[0]);
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('label', label);
    
    try {
        const result = await apiRequest('/model/upload-pcap-for-training', {
            method: 'POST',
            body: formData
        });
        
        if (result.success) {
            alert('导入成功: ' + result.message);
            closeModal();
        } else {
            alert('导入失败: ' + result.message);
        }
    } catch (error) {
        alert('导入失败: ' + error.message);
        console.error('Error:', error);
    }
}

async function handleTrainModel(e) {
    e.preventDefault();
    
    const data = {
        model_type: document.getElementById('train-model-type').value,
        dataset_type: document.getElementById('train-dataset-type').value,
        batch_size: parseInt(document.getElementById('train-batch-size').value),
        epochs: parseInt(document.getElementById('train-epochs').value),
        learning_rate: parseFloat(document.getElementById('train-lr').value),
        hidden_dim: parseInt(document.getElementById('train-hidden-dim').value),
        num_layers: parseInt(document.getElementById('train-num-layers').value),
        use_cuda: document.getElementById('train-use-cuda').checked
    };
    
    try {
        await apiRequest('/model/train', {
            method: 'POST',
            body: JSON.stringify(data)
        });
        closeModal();
        loadTrainingHistory();
        alert('训练任务已启动');
    } catch (error) {
        alert('启动失败: ' + error.message);
    }
}

async function uploadModel() {
    const fileInput = document.getElementById('model-file');
    if (!fileInput.files.length) return;
    
    const name = prompt('请输入模型名称:');
    if (!name) return;
    
    const modelType = prompt('请输入模型类型 (cnn):', 'cnn');
    const datasetType = prompt('请输入数据集类型 (cicids2017):', 'cicids2017');
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('name', name);
    formData.append('model_type', modelType);
    formData.append('dataset_type', datasetType);
    
    try {
        const response = await fetch(`${API_BASE}/model/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });
        
        const data = await response.json();
        if (data.success) {
            loadModelList();
            alert('模型导入成功');
        } else {
            alert('导入失败: ' + data.message);
        }
    } catch (error) {
        alert('导入失败: ' + error.message);
    }
}

async function setActiveModel(id) {
    try {
        await apiRequest(`/model/set-active/${id}`, { method: 'POST' });
        loadModelList();
        alert('模型已激活');
    } catch (error) {
        alert('激活失败: ' + error.message);
    }
}

async function deleteModel(id) {
    if (!confirm('确定要删除这个模型吗？此操作不可恢复。')) {
        return;
    }
    
    try {
        const response = await apiRequest(`/model/delete/${id}`, { method: 'DELETE' });
        if (response.success) {
            loadModelList();
            alert('模型删除成功');
        } else {
            alert('删除失败: ' + response.message);
        }
    } catch (error) {
        alert('删除失败: ' + error.message);
    }
}

// 全局变量存储当前评估结果
let currentEvalResult = null;
let currentModelType = null;

async function evaluateModel(id) {
    try {
        // 首先尝试获取缓存的评估结果
        const cachedResult = await apiRequest(`/model/evaluate/${id}`, { method: 'GET' });
        
        if (cachedResult.success && !cachedResult.need_eval) {
            // 使用缓存结果
            currentEvalResult = cachedResult;
            currentModelType = cachedResult.model_type;
            showEvaluationResult(cachedResult);
            return;
        }
        
        // 没有缓存，进行新的评估
        alert('开始评估模型，请稍候...');
        const result = await apiRequest(`/model/evaluate/${id}`, { method: 'POST' });
        
        if (result.error) {
            alert('评估失败: ' + result.error);
        } else {
            currentEvalResult = result;
            currentModelType = result.model_type;
            showEvaluationResult(result);
            loadModelList();
        }
    } catch (error) {
        alert('评估失败: ' + error.message);
    }
}

// 显示评估结果
function showEvaluationResult(result) {
    const modelType = result.model_type;
    
    if (modelType === 'two_stage') {
        // 两阶段模型：显示切换按钮和两个结果
        showTwoStageEvaluationResult(result);
    } else if (modelType === 'binary') {
        // 二分类模型
        showBinaryEvaluationResult(result);
    } else {
        // 七分类模型（cnn）
        showMultiClassEvaluationResult(result);
    }
}

// 显示二分类评估结果
function showBinaryEvaluationResult(result) {
    let reportHtml = `
        <div style="text-align: left; max-height: 60vh; overflow-y: auto;">
            <h3>二分类模型评估结果</h3>
            <p style="color: #666; font-size: 12px; margin-bottom: 15px;">
                评估时间: ${result.last_eval_time ? new Date(result.last_eval_time).toLocaleString() : '刚刚'}
                ${result.from_cache ? ' (缓存结果)' : ''}
            </p>
            <table style="width: 100%; margin: 10px 0; border-collapse: collapse;">
                <tr style="background: #f0f0f0;">
                    <th style="padding: 8px; border: 1px solid #ddd;">指标</th>
                    <th style="padding: 8px; border: 1px solid #ddd;">数值</th>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">准确率 (Accuracy)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.accuracy * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">精确率 (Precision)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.precision * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">召回率 (Recall)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.recall * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">F1分数 (F1-score)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.f1_score * 100).toFixed(2)}%</td>
                </tr>
            </table>
            
            <h4>各类别详细指标</h4>
            <table style="width: 100%; margin: 10px 0; border-collapse: collapse; font-size: 12px;">
                <tr style="background: #f0f0f0;">
                    <th style="padding: 6px; border: 1px solid #ddd;">类别</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">精确率</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">召回率</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">F1分数</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">支持数</th>
                </tr>
    `;
    
    // 添加各类别指标
    if (result.classification_report) {
        const labels = ['正常(BENIGN)', '异常(Attack)'];
        labels.forEach(label => {
            if (result.classification_report[label]) {
                const r = result.classification_report[label];
                reportHtml += `
                    <tr>
                        <td style="padding: 6px; border: 1px solid #ddd;">${label}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.precision * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.recall * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r['f1-score'] * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${r.support}</td>
                    </tr>
                `;
            }
        });
    }
    
    reportHtml += `</table>`;
    
    // 添加图表按钮
    let chartButtons = '';
    if (result.confusion_matrix_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.confusion_matrix_image}', '混淆矩阵')" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">混淆矩阵</button>`;
    }
    if (result.roc_curve_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.roc_curve_image}', 'ROC曲线')" style="padding: 10px 20px; background: #764ba2; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">ROC曲线</button>`;
    }
    if (result.pr_curve_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.pr_curve_image}', 'PR曲线')" style="padding: 10px 20px; background: #f093fb; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">PR曲线</button>`;
    }
    if (result.train_loss_history && result.train_loss_history.length > 0) {
        chartButtons += `<button class="btn btn-primary" onclick="showTrainingCurves(${JSON.stringify(result).replace(/"/g, '&quot;')})" style="padding: 10px 20px; background: #4facfe; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">训练曲线</button>`;
    }
    
    if (chartButtons) {
        reportHtml += `
            <div style="margin-top: 20px; text-align: center;">
                ${chartButtons}
            </div>
        `;
    }
    
    reportHtml += `</div>`;
    
    showEvaluationResultModal(reportHtml);
}

// 显示七分类评估结果
function showMultiClassEvaluationResult(result) {
    let reportHtml = `
        <div style="text-align: left; max-height: 60vh; overflow-y: auto;">
            <h3>七分类模型评估结果</h3>
            <p style="color: #666; font-size: 12px; margin-bottom: 15px;">
                评估时间: ${result.last_eval_time ? new Date(result.last_eval_time).toLocaleString() : '刚刚'}
                ${result.from_cache ? ' (缓存结果)' : ''}
            </p>
            <table style="width: 100%; margin: 10px 0; border-collapse: collapse;">
                <tr style="background: #f0f0f0;">
                    <th style="padding: 8px; border: 1px solid #ddd;">指标</th>
                    <th style="padding: 8px; border: 1px solid #ddd;">数值</th>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">准确率 (Accuracy)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.accuracy * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">精确率 (Precision)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.precision * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">召回率 (Recall)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.recall * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">F1分数 (F1-score)</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">${(result.f1_score * 100).toFixed(2)}%</td>
                </tr>
            </table>
            
            <h4>各类别详细指标</h4>
            <table style="width: 100%; margin: 10px 0; border-collapse: collapse; font-size: 12px;">
                <tr style="background: #f0f0f0;">
                    <th style="padding: 6px; border: 1px solid #ddd;">类别</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">精确率</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">召回率</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">F1分数</th>
                    <th style="padding: 6px; border: 1px solid #ddd;">支持数</th>
                </tr>
    `;
    
    // 添加各类别指标
    if (result.classification_report) {
        const labels = ['BENIGN', 'Bot', 'BruteForce', 'DoS', 'Infiltration', 'PortScan', 'WebAttack'];
        labels.forEach(label => {
            if (result.classification_report[label]) {
                const r = result.classification_report[label];
                reportHtml += `
                    <tr>
                        <td style="padding: 6px; border: 1px solid #ddd;">${label}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.precision * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.recall * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r['f1-score'] * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${r.support}</td>
                    </tr>
                `;
            }
        });
    }
    
    reportHtml += `</table>`;
    
    // 添加图表按钮
    let chartButtons = '';
    if (result.confusion_matrix_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.confusion_matrix_image}', '混淆矩阵')" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">混淆矩阵</button>`;
    }
    if (result.roc_curve_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.roc_curve_image}', 'ROC曲线')" style="padding: 10px 20px; background: #764ba2; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">ROC曲线</button>`;
    }
    if (result.pr_curve_image) {
        chartButtons += `<button class="btn btn-primary" onclick="showImageModal('${result.pr_curve_image}', 'PR曲线')" style="padding: 10px 20px; background: #f093fb; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">PR曲线</button>`;
    }
    if (result.train_loss_history && result.train_loss_history.length > 0) {
        chartButtons += `<button class="btn btn-primary" onclick="showTrainingCurves(${JSON.stringify(result).replace(/"/g, '&quot;')})" style="padding: 10px 20px; background: #4facfe; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">训练曲线</button>`;
    }
    
    if (chartButtons) {
        reportHtml += `
            <div style="margin-top: 20px; text-align: center;">
                ${chartButtons}
            </div>
        `;
    }
    
    reportHtml += `</div>`;
    
    showEvaluationResultModal(reportHtml);
}

// 显示两阶段模型评估结果（带切换功能）
function showTwoStageEvaluationResult(result) {
    const binaryResults = result.binary_results;
    const attackResults = result.attack_results;
    
    let reportHtml = `
        <div style="text-align: left; max-height: 60vh; overflow-y: auto;">
            <h3>两阶段模型评估结果</h3>
            <p style="color: #666; font-size: 12px; margin-bottom: 15px;">
                评估时间: ${result.last_eval_time ? new Date(result.last_eval_time).toLocaleString() : '刚刚'}
                ${result.from_cache ? ' (缓存结果)' : ''}
            </p>
            
            <!-- 切换按钮 -->
            <div style="margin-bottom: 20px; text-align: center;">
                <button id="btn-binary-stage" onclick="switchStage('binary')" 
                    style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 4px 0 0 4px; cursor: pointer;">
                    第一阶段：二分类
                </button>
                <button id="btn-attack-stage" onclick="switchStage('attack')" 
                    style="padding: 10px 20px; background: #e0e0e0; color: #333; border: none; border-radius: 0 4px 4px 0; cursor: pointer;">
                    第二阶段：六分类
                </button>
            </div>
            
            <!-- 二分类结果 -->
            <div id="binary-stage-result">
                <h4>第一阶段：二分类（正常 vs 异常）</h4>
                <table style="width: 100%; margin: 10px 0; border-collapse: collapse;">
                    <tr style="background: #f0f0f0;">
                        <th style="padding: 8px; border: 1px solid #ddd;">指标</th>
                        <th style="padding: 8px; border: 1px solid #ddd;">数值</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">准确率 (Accuracy)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(binaryResults.accuracy * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">精确率 (Precision)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(binaryResults.precision * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">召回率 (Recall)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(binaryResults.recall * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">F1分数 (F1-score)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(binaryResults.f1_score * 100).toFixed(2)}%</td>
                    </tr>
                </table>
                
                <h5>各类别详细指标</h5>
                <table style="width: 100%; margin: 10px 0; border-collapse: collapse; font-size: 12px;">
                    <tr style="background: #f0f0f0;">
                        <th style="padding: 6px; border: 1px solid #ddd;">类别</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">精确率</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">召回率</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">F1分数</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">支持数</th>
                    </tr>
    `;
    
    if (binaryResults.classification_report) {
        const binaryLabels = ['正常(BENIGN)', '异常(Attack)'];
        binaryLabels.forEach(label => {
            if (binaryResults.classification_report[label]) {
                const r = binaryResults.classification_report[label];
                reportHtml += `
                    <tr>
                        <td style="padding: 6px; border: 1px solid #ddd;">${label}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.precision * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.recall * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r['f1-score'] * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${r.support}</td>
                    </tr>
                `;
            }
        });
    }
    
    reportHtml += `
                </table>
                ${binaryResults.confusion_matrix_image ? `
                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn btn-primary" onclick="showImageModal('${binaryResults.confusion_matrix_image}', '二分类混淆矩阵')" 
                        style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        混淆矩阵
                    </button>
                    ${binaryResults.roc_curve_image ? `
                    <button class="btn btn-primary" onclick="showImageModal('${binaryResults.roc_curve_image}', '二分类ROC曲线')" 
                        style="padding: 8px 16px; background: #764ba2; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        ROC曲线
                    </button>
                    ` : ''}
                    ${binaryResults.pr_curve_image ? `
                    <button class="btn btn-primary" onclick="showImageModal('${binaryResults.pr_curve_image}', '二分类PR曲线')" 
                        style="padding: 8px 16px; background: #f093fb; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        PR曲线
                    </button>
                    ` : ''}
                    ${result.binary_train_loss_history && result.binary_train_loss_history.length > 0 ? `
                    <button class="btn btn-primary" onclick="showTrainingCurves(${JSON.stringify({...result, train_loss_history: result.binary_train_loss_history, val_loss_history: result.binary_val_loss_history, train_acc_history: result.binary_train_acc_history, val_acc_history: result.binary_val_acc_history}).replace(/"/g, '&quot;')})" 
                        style="padding: 8px 16px; background: #4facfe; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        训练曲线
                    </button>
                    ` : ''}
                </div>
                ` : ''}
            </div>
            
            <!-- 六分类结果 -->
            <div id="attack-stage-result" style="display: none;">
                <h4>第二阶段：六分类（攻击类型识别）</h4>
                <table style="width: 100%; margin: 10px 0; border-collapse: collapse;">
                    <tr style="background: #f0f0f0;">
                        <th style="padding: 8px; border: 1px solid #ddd;">指标</th>
                        <th style="padding: 8px; border: 1px solid #ddd;">数值</th>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">准确率 (Accuracy)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(attackResults.accuracy * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">精确率 (Precision)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(attackResults.precision * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">召回率 (Recall)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(attackResults.recall * 100).toFixed(2)}%</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px; border: 1px solid #ddd;">F1分数 (F1-score)</td>
                        <td style="padding: 8px; border: 1px solid #ddd;">${(attackResults.f1_score * 100).toFixed(2)}%</td>
                    </tr>
                </table>
                
                <h5>各类别详细指标</h5>
                <table style="width: 100%; margin: 10px 0; border-collapse: collapse; font-size: 12px;">
                    <tr style="background: #f0f0f0;">
                        <th style="padding: 6px; border: 1px solid #ddd;">类别</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">精确率</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">召回率</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">F1分数</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">支持数</th>
                    </tr>
    `;
    
    if (attackResults.classification_report) {
        const attackLabels = ['Bot', 'BruteForce', 'DoS', 'Infiltration', 'PortScan', 'WebAttack'];
        attackLabels.forEach(label => {
            if (attackResults.classification_report[label]) {
                const r = attackResults.classification_report[label];
                reportHtml += `
                    <tr>
                        <td style="padding: 6px; border: 1px solid #ddd;">${label}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.precision * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r.recall * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${(r['f1-score'] * 100).toFixed(2)}%</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${r.support}</td>
                    </tr>
                `;
            }
        });
    }
    
    reportHtml += `
                </table>
                ${attackResults.confusion_matrix_image ? `
                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn btn-primary" onclick="showImageModal('${attackResults.confusion_matrix_image}', '六分类混淆矩阵')" 
                        style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        混淆矩阵
                    </button>
                    ${attackResults.roc_curve_image ? `
                    <button class="btn btn-primary" onclick="showImageModal('${attackResults.roc_curve_image}', '六分类ROC曲线')" 
                        style="padding: 8px 16px; background: #764ba2; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        ROC曲线
                    </button>
                    ` : ''}
                    ${attackResults.pr_curve_image ? `
                    <button class="btn btn-primary" onclick="showImageModal('${attackResults.pr_curve_image}', '六分类PR曲线')" 
                        style="padding: 8px 16px; background: #f093fb; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        PR曲线
                    </button>
                    ` : ''}
                    ${result.attack_train_loss_history && result.attack_train_loss_history.length > 0 ? `
                    <button class="btn btn-primary" onclick="showTrainingCurves(${JSON.stringify({...result, train_loss_history: result.attack_train_loss_history, val_loss_history: result.attack_val_loss_history, train_acc_history: result.attack_train_acc_history, val_acc_history: result.attack_val_acc_history}).replace(/"/g, '&quot;')})" 
                        style="padding: 8px 16px; background: #4facfe; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 5px;">
                        训练曲线
                    </button>
                    ` : ''}
                </div>
                ` : ''}
            </div>
        </div>
    `;
    
    showEvaluationResultModal(reportHtml);
}

// 显示训练曲线
function showTrainingCurves(result) {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        z-index: 3000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.8);
        display: flex;
        justify-content: center;
        align-items: center;
        overflow: auto;
    `;
    
    // 准备训练数据
    const trainLoss = result.train_loss_history || [];
    const valLoss = result.val_loss_history || [];
    const trainAcc = result.train_acc_history || [];
    const valAcc = result.val_acc_history || [];
    
    // 生成图表数据URL
    const lossChartUrl = generateChartUrl(trainLoss, valLoss, '损失', '训练损失', '验证损失');
    const accChartUrl = generateChartUrl(trainAcc, valAcc, '准确率', '训练准确率', '验证准确率');
    
    modal.innerHTML = `
        <div style="position: relative; max-width: 95%; max-height: 95%; padding: 20px; background: white; border-radius: 8px; overflow: auto;">
            <span onclick="this.parentElement.parentElement.remove()" style="
                position: absolute;
                top: 10px;
                right: 15px;
                color: #333;
                font-size: 30px;
                cursor: pointer;
            ">&times;</span>
            <h3 style="text-align: center; margin-bottom: 20px;">训练曲线</h3>
            <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 20px;">
                <div style="text-align: center;">
                    <h4>损失曲线</h4>
                    <img src="${lossChartUrl}" style="max-width: 500px; max-height: 350px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);" />
                </div>
                <div style="text-align: center;">
                    <h4>准确率曲线</h4>
                    <img src="${accChartUrl}" style="max-width: 500px; max-height: 350px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);" />
                </div>
            </div>
        </div>
    `;
    
    modal.onclick = function(e) {
        if (e.target === modal) {
            modal.remove();
        }
    };
    
    document.body.appendChild(modal);
}

// 生成图表URL（使用QuickChart.io）
function generateChartUrl(trainData, valData, title, trainLabel, valLabel) {
    const labels = trainData.map((_, i) => i + 1);
    
    const config = {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: trainLabel,
                    data: trainData,
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                },
                {
                    label: valLabel,
                    data: valData,
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: title
                }
            },
            scales: {
                y: {
                    beginAtZero: false
                }
            }
        }
    };
    
    return `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(config))}&w=500&h=350`;
}

// 切换两阶段模型的显示阶段
function switchStage(stage) {
    const binaryDiv = document.getElementById('binary-stage-result');
    const attackDiv = document.getElementById('attack-stage-result');
    const binaryBtn = document.getElementById('btn-binary-stage');
    const attackBtn = document.getElementById('btn-attack-stage');
    
    if (stage === 'binary') {
        binaryDiv.style.display = 'block';
        attackDiv.style.display = 'none';
        binaryBtn.style.background = '#667eea';
        binaryBtn.style.color = 'white';
        attackBtn.style.background = '#e0e0e0';
        attackBtn.style.color = '#333';
    } else {
        binaryDiv.style.display = 'none';
        attackDiv.style.display = 'block';
        binaryBtn.style.background = '#e0e0e0';
        binaryBtn.style.color = '#333';
        attackBtn.style.background = '#667eea';
        attackBtn.style.color = 'white';
    }
}

// 显示评估结果弹窗
function showEvaluationResultModal(content) {
    // 创建或获取弹窗元素
    let modal = document.getElementById('evaluation-result-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'evaluation-result-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 800px; width: 90%;">
                <span class="close-btn" onclick="closeEvaluationModal()">&times;</span>
                <div id="evaluation-result-content"></div>
            </div>
        `;
        document.body.appendChild(modal);
        
        // 添加样式
        const style = document.createElement('style');
        style.textContent = `
            #evaluation-result-modal {
                display: none;
                position: fixed;
                z-index: 2000;
                left: 0;
                top: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0,0,0,0.5);
            }
            #evaluation-result-modal.active {
                display: flex;
                justify-content: center;
                align-items: center;
            }
            #evaluation-result-modal .modal-content {
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                position: relative;
            }
        `;
        document.head.appendChild(style);
    }
    
    document.getElementById('evaluation-result-content').innerHTML = content;
    modal.classList.add('active');
}

// 关闭评估结果弹窗
function closeEvaluationModal() {
    const modal = document.getElementById('evaluation-result-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

// 网络流量翻页功能
async function changeTrafficPage(page) {
    if (page < 1 || page > trafficTotalPages) return;
    trafficCurrentPage = page;
    loadTrafficList(page);
}

function updateTrafficPagination(currentPage, totalPages) {
    trafficTotalPages = totalPages;
    document.getElementById('traffic-page-info').textContent = `第 ${currentPage} 页，共 ${totalPages} 页`;
}

// 威胁流量翻页功能
async function changeMaliciousPage(page) {
    if (page < 1 || page > maliciousTotalPages) return;
    maliciousCurrentPage = page;
    loadMaliciousList(page);
}

function updateMaliciousPagination(currentPage, totalPages) {
    maliciousTotalPages = totalPages;
    document.getElementById('malicious-page-info').textContent = `第 ${currentPage} 页，共 ${totalPages} 页`;
}

// 加载恶意流量（用于白名单选项变化时）
async function loadMaliciousTraffic() {
    loadMaliciousList(1);
}

// 格式化模型类型显示
function formatModelType(modelType) {
    const typeMap = {
        'cnn': 'CNN_7',
        'CNN_7': 'CNN_7',
        'binary': 'CNN_2',
        'CNN_2': 'CNN_2',
        'two_stage': 'CNN_2+6'
    };
    return typeMap[modelType] || modelType.toUpperCase();
}

// 显示白名单模态框
function showWhitelistModal() {
    showModal('whitelist-modal');
    loadWhitelistIPs();
}

// 加载白名单IP列表
async function loadWhitelistIPs() {
    try {
        const whitelist = await apiRequest('/strategy/whitelist');
        const listElement = document.getElementById('whitelist-ip-list');
        listElement.innerHTML = '';
        
        whitelist.ips.forEach(ip => {
            const li = document.createElement('li');
            li.style.cssText = `
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 10px 15px;
                border-bottom: 1px solid #eee;
                font-size: 14px;
            `;
            li.innerHTML = `
                <span>${ip}</span>
                <button class="btn-small" onclick="removeWhitelistIP('${ip}')" style="
                    padding: 4px 12px;
                    background: #f44336;
                    color: white;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                    font-size: 12px;
                ">删除</button>
            `;
            listElement.appendChild(li);
        });
    } catch (error) {
        console.error('加载白名单失败:', error);
    }
}

// 添加白名单IP
async function addWhitelistIP() {
    const ip = document.getElementById('whitelist-ip').value.trim();
    if (!ip) {
        alert('请输入IP地址');
        return;
    }
    
    try {
        await apiRequest('/strategy/whitelist/add', {
            method: 'POST',
            body: { ip: ip }
        });
        document.getElementById('whitelist-ip').value = '';
        loadWhitelistIPs();
    } catch (error) {
        alert('添加失败: ' + error.message);
    }
}

// 删除白名单IP
async function removeWhitelistIP(ip) {
    try {
        await apiRequest('/strategy/whitelist/remove', {
            method: 'POST',
            body: { ip: ip }
        });
        loadWhitelistIPs();
    } catch (error) {
        alert('删除失败: ' + error.message);
    }
}

// 检查IP是否在白名单中
async function isIPInWhitelist(ip) {
    try {
        const whitelist = await apiRequest('/strategy/whitelist');
        return whitelist.ips.includes(ip);
    } catch (error) {
        console.error('检查白名单失败:', error);
        return false;
    }
}

// 显示混淆矩阵图片
function showConfusionMatrix(imagePath) {
    showImageModal(imagePath, '混淆矩阵');
}

function showImageModal(imagePath, title = '图片预览') {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        z-index: 3000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0,0,0,0.8);
        display: flex;
        justify-content: center;
        align-items: center;
    `;
    
    modal.innerHTML = `
        <div style="position: relative; max-width: 90%; max-height: 90%;">
            <span onclick="this.parentElement.parentElement.remove()" style="
                position: absolute;
                top: -40px;
                right: 0;
                color: white;
                font-size: 30px;
                cursor: pointer;
            ">&times;</span>
            <h3 style="color: white; text-align: center; margin-bottom: 10px;">${title}</h3>
            <img src="${imagePath}" style="max-width: 100%; max-height: 80vh; border-radius: 8px;" />
        </div>
    `;
    
    modal.onclick = function(e) {
        if (e.target === modal) {
            modal.remove();
        }
    };
    
    document.body.appendChild(modal);
}

// ==================== 模态框 ====================
function showModal(modalId) {
    document.getElementById('modal-overlay').classList.remove('hidden');
    document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    document.getElementById(modalId).classList.remove('hidden');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.add('hidden');
    document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    
    // 如果正在编辑自适应策略，重置表单
    if (currentEditingAdaptiveId !== null) {
        resetAdaptiveForm();
    }
}

// 点击遮罩关闭模态框
document.getElementById('modal-overlay').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});

// 初始化清空历史按钮
document.addEventListener('DOMContentLoaded', function() {
    const clearBtn = document.getElementById('clear-history-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async function() {
            if (confirm('确定要清空所有训练历史吗？此操作不可恢复。')) {
                try {
                    const response = await fetch('/api/model/training-history', {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        }
                    });
                    
                    const result = await response.json();
                    if (result.success) {
                        alert('训练历史已清空');
                        loadTrainingHistory();
                    } else {
                        alert('清空失败: ' + result.message);
                    }
                } catch (error) {
                    console.error('清空训练历史失败:', error);
                    alert('清空训练历史失败');
                }
            }
        });
    }
});
