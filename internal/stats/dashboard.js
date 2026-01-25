// Dashboard SSE Logic
(function () {
    const evtSource = new EventSource("/events");

    evtSource.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);

            // System Stats
            updateText('agent-uptime', data.agent.uptime);
            updateText('cpu-cores', data.cpu.cores);

            // Memory
            updateText('mem-used', (data.memory.allocated / 1048576.0).toFixed(1));
            updateText('mem-total', (data.memory.total / 1048576.0).toFixed(1));

            // WireGuard
            updateText('wg-peers', data.wireguard.peers);
            const wgStatusEl = document.getElementById('wg-status');
            if (wgStatusEl) {
                wgStatusEl.innerHTML = data.wireguard.connected ?
                    '<span class="badge badge-success">Encrypted</span>' :
                    '<span class="badge badge-warning">Inactive</span>';
            }

            // WireGuard Neighbors
            const wgPeersItems = document.getElementById('wg-peers-items');
            if (wgPeersItems && data.wireguard.peers_list) {
                if (data.wireguard.peers_list.length > 0) {
                    wgPeersItems.innerHTML = data.wireguard.peers_list.map(peer => `
                        <div class="nearby-item" style="flex-direction: column; align-items: flex-start; gap: 4px;">
                            <div style="display: flex; width: 100%; justify-content: space-between; align-items: center;">
                                <span class="nearby-ssid" style="font-weight: 600;">${peer.ip}</span>
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    ${peer.latency_ms ? `<span style="font-size: 10px; color: var(--text-secondary);">${peer.latency_ms}ms</span>` : ''}
                                    <span class="badge badge-success" style="font-size: 9px; padding: 2px 6px;">Active</span>
                                </div>
                            </div>
                            <div style="font-size: 10px; color: var(--text-secondary); display: flex; gap: 8px;">
                                <span>${peer.hostname || 'unknown'}</span>
                                <span style="opacity: 0.5;">|</span>
                                <span>${peer.os || 'unknown'}</span>
                            </div>
                        </div>
                    `).join('');
                } else {
                    wgPeersItems.innerHTML = '<div style="font-size: 11px; color: var(--text-secondary); text-align: center; padding: 8px;">No neighbors detected</div>';
                }
            }

            // WiFi Rendering
            const wifiContainer = document.getElementById('wifi-container');
            if (wifiContainer && data.wifi && data.wifi.interfaces) {
                wifiContainer.innerHTML = data.wifi.interfaces.map(iface => renderWiFiCard(iface)).join('');
            }

            // Network Interfaces
            const netContainer = document.getElementById('interfaces-list');
            if (netContainer && data.network && data.network.interfaces) {
                netContainer.innerHTML = data.network.interfaces.map(iface => renderNetRow(iface)).join('');
            }

            // Footer
            updateText('footer-timestamp', new Date(data.timestamp).toLocaleString());

        } catch (e) {
            console.error("Dashboard update error:", e);
        }
    };

    function updateText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    function renderWiFiCard(iface) {
        const status = iface.connected ? '<span class="badge badge-success">Online</span>' : '<span class="badge badge-warning">Offline</span>';
        let stats = '';
        if (iface.connected) {
            stats = `
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-label">Signal Strength</div>
                        <div class="stat-value">${iface.signal}<span class="stat-unit">dBm</span></div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-label">Bitrate</div>
                        <div class="stat-value">${iface.bitrate}<span class="stat-unit">Mbps</span></div>
                    </div>
                </div>
                <div style="margin-top: 16px; font-size: 11px; color: var(--text-secondary); background: var(--accent-bg); padding: 8px; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                        <span>SSID: <strong style="color: var(--text-color);">${iface.ssid}</strong></span>
                        <span>Channel: <strong>${iface.channel}</strong></span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Mode: <strong>${iface.phy_mode}</strong></span>
                        <span>MAC: <strong>${iface.mac}</strong></span>
                    </div>
                </div>`;
        } else {
            stats = `<div style="text-align: center; padding: 20px; color: var(--text-secondary); font-size: 14px;">Offline</div>`;
        }

        const nearby = iface.nearby ? `
            <div class="nearby-list">
                <div class="nearby-title">Nearby Access Points</div>
                <div style="max-height: 200px; overflow-y: auto;">
                    ${iface.nearby.map(n => `
                        <div class="nearby-item">
                            <span class="nearby-ssid">${n.ssid}</span>
                            <span class="badge ${n.signal >= -70 ? 'badge-success' : 'badge-warning'}" style="font-size: 9px; padding: 2px 6px;">${n.signal} dBm</span>
                        </div>
                    `).join('')}
                </div>
            </div>` : '';

        return `
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
                    </div>
                    <div class="card-title">WiFi: ${iface.name}</div>
                    <div style="margin-left: auto;">${status}</div>
                </div>
                ${stats}
                ${nearby}
            </div>`;
    }

    function renderNetRow(iface) {
        const ips = iface.ips ? iface.ips.map(ip => `<div style="font-family: monospace; font-size: 11px;">${ip}</div>`).join('') : '';
        const state = iface.up ? '<div class="status-dot"></div>' : '<span style="color: var(--text-secondary);">Offline</span>';
        return `
            <tr>
                <td><strong>${iface.name}</strong></td>
                <td>${ips}</td>
                <td>${(iface.rx_bytes / 1048576.0).toFixed(1)} MB</td>
                <td>${(iface.tx_bytes / 1048576.0).toFixed(1)} MB</td>
                <td>${state}</td>
            </tr>`;
    }
})();
