// --- State Management ---
const db = {
  logs: [],          // Stores all ingested ECS log objects
  filteredLogs: [],  // Filtered view based on KQL
  alerts: [],        // Triggered security alerts
  failedCounts: {},  // Failed logins tracked by IP (for alerts)
  timelineData: []   // [{ time: Date, success: count, failure: count }]
};

// Global config strings (embedded for instant display in Code Repository tab)
let configs = {
  'docker-compose': '',
  'logstash-conf': '',
  'dashboard-ndjson': '',
  'watcher-json': '',
  'detection-report': ''
};

// Attack sources (coordinates on SVG map)
const GEOMAP_COORDINATES = {
  'kali_attacker': { x: 550, y: 110, name: 'Kali Attacker (Russia)' },
  'beijing_node': { x: 730, y: 160, name: 'Hacker Group (China)' },
  'brazil_node': { x: 300, y: 380, name: 'Botnet Node (Brazil)' },
  'germany_node': { x: 480, y: 120, name: 'Normal User (Frankfurt)' },
  'us_east': { x: 200, y: 180, name: 'Target Server (US East)' }
};

// Initialize application
window.addEventListener('DOMContentLoaded', () => {
  initTimelineChart();
  initMapPins();
  loadConfigContent();
  loadDetectionReportDoc();
  
  // Start background noise (normal traffic) every few seconds to look active
  setInterval(injectBackgroundTraffic, 6000);
});

// --- Tab Switching ---
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
  
  // Set active tab button
  const clickedBtn = Array.from(document.querySelectorAll('.tab-btn'))
    .find(btn => btn.getAttribute('onclick').includes(tabId));
  if (clickedBtn) clickedBtn.classList.add('active');
  
  // Show active container
  const targetContent = document.getElementById(`tab-${tabId}`);
  if (targetContent) targetContent.classList.add('active');
  
  // Redraw canvas if dashboard tab opened (needs dimensions)
  if (tabId === 'dashboard') {
    setTimeout(renderTimelineChart, 50);
  }
}

// --- Dynamic Canvas Timeline Chart ---
let chartCanvas, chartCtx;
const timelineMaxPoints = 20;

function initTimelineChart() {
  chartCanvas = document.getElementById('timeSeriesChart');
  chartCtx = chartCanvas.getContext('2d');
  
  // Initialize mock historical timeline data
  const now = new Date();
  for (let i = timelineMaxPoints; i > 0; i--) {
    db.timelineData.push({
      time: new Date(now.getTime() - i * 10000),
      success: Math.floor(Math.random() * 8) + 5,
      failure: Math.floor(Math.random() * 2)
    });
  }
  
  // Setup resizing
  window.addEventListener('resize', () => {
    if (document.getElementById('tab-dashboard').classList.contains('active')) {
      renderTimelineChart();
    }
  });
  
  renderTimelineChart();
}

function renderTimelineChart() {
  if (!chartCanvas) return;
  
  // Adjust canvas resolution dynamically
  const rect = chartCanvas.parentElement.getBoundingClientRect();
  chartCanvas.width = rect.width;
  chartCanvas.height = rect.height;
  
  const width = chartCanvas.width;
  const height = chartCanvas.height;
  const padding = { top: 20, right: 20, bottom: 30, left: 40 };
  
  chartCtx.clearRect(0, 0, width, height);
  
  // Draw Background Grid
  chartCtx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
  chartCtx.lineWidth = 1;
  const gridCount = 5;
  for (let i = 0; i <= gridCount; i++) {
    const y = padding.top + (height - padding.top - padding.bottom) * (i / gridCount);
    chartCtx.beginPath();
    chartCtx.moveTo(padding.left, y);
    chartCtx.lineTo(width - padding.right, y);
    chartCtx.stroke();
    
    // Draw Y-axis labels
    chartCtx.fillStyle = '#64748b';
    chartCtx.font = '9px JetBrains Mono';
    const val = Math.round(25 * (gridCount - i) / gridCount);
    chartCtx.fillText(val, 10, y + 3);
  }
  
  // Prepare data points coordinates
  const data = db.timelineData;
  const graphWidth = width - padding.left - padding.right;
  const graphHeight = height - padding.top - padding.bottom;
  const maxVal = 25; // fixed scale max
  
  const getX = (index) => padding.left + (index / (data.length - 1)) * graphWidth;
  const getY = (val) => padding.top + graphHeight - (Math.min(val, maxVal) / maxVal) * graphHeight;
  
  // Draw Success Line
  drawTimelineTrend(data.map(d => d.success), '#4ade80', 'rgba(74, 222, 128, 0.1)', getX, getY);
  
  // Draw Failure Line
  drawTimelineTrend(data.map(d => d.failure), '#ef4444', 'rgba(239, 68, 68, 0.15)', getX, getY);
  
  // Draw Legend
  chartCtx.font = '10px Outfit';
  chartCtx.fillStyle = '#4ade80';
  chartCtx.fillRect(width - 150, 10, 10, 6);
  chartCtx.fillText('Success Logins', width - 135, 16);
  
  chartCtx.fillStyle = '#ef4444';
  chartCtx.fillRect(width - 70, 10, 10, 6);
  chartCtx.fillText('Failed Logins', width - 55, 16);
}

function drawTimelineTrend(points, strokeColor, fillColor, getX, getY) {
  if (points.length === 0) return;
  
  // Draw Line
  chartCtx.beginPath();
  chartCtx.moveTo(getX(0), getY(points[0]));
  for (let i = 1; i < points.length; i++) {
    chartCtx.lineTo(getX(i), getY(points[i]));
  }
  chartCtx.strokeStyle = strokeColor;
  chartCtx.lineWidth = 2.5;
  chartCtx.shadowColor = strokeColor;
  chartCtx.shadowBlur = 6;
  chartCtx.stroke();
  chartCtx.shadowBlur = 0; // reset
  
  // Draw Fill Area
  chartCtx.lineTo(getX(points.length - 1), getY(0));
  chartCtx.lineTo(getX(0), getY(0));
  chartCtx.closePath();
  chartCtx.fillStyle = fillColor;
  chartCtx.fill();
}

function pushTimelineLog(successCount, failCount) {
  db.timelineData.shift();
  db.timelineData.push({
    time: new Date(),
    success: successCount,
    failure: failCount
  });
  renderTimelineChart();
}


// --- SVG Map Attacks ---
function initMapPins() {
  const pinsGroup = document.getElementById('map-pins-group');
  if (!pinsGroup) return;
  
  // Draw nodes on world map
  for (const [key, val] of Object.entries(GEOMAP_COORDINATES)) {
    const isTarget = key === 'us_east';
    
    // Create group
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'map-pin');
    
    // Create circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', val.x);
    circle.setAttribute('cy', val.y);
    circle.setAttribute('r', isTarget ? '7' : '4.5');
    circle.setAttribute('fill', isTarget ? '#00f2fe' : '#ef4444');
    if (isTarget) {
      circle.setAttribute('stroke', '#0c0e14');
      circle.setAttribute('stroke-width', '1.5');
    }
    
    // Add title element
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = val.name;
    g.appendChild(title);
    g.appendChild(circle);
    
    pinsGroup.appendChild(g);
  }
}

function drawAttackVectorOnMap(sourceKey, isNormal = false) {
  const attacksGroup = document.getElementById('map-attacks-group');
  if (!attacksGroup) return;
  
  const source = GEOMAP_COORDINATES[sourceKey];
  const target = GEOMAP_COORDINATES['us_east'];
  if (!source) return;
  
  // Calculate a curved path (quadratic Bezier curve)
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const cx = source.x + dx / 2 - dy * 0.15; // bend factor
  const cy = source.y + dy / 2 + dx * 0.15;
  
  const pathD = `M ${source.x} ${source.y} Q ${cx} ${cy} ${target.x} ${target.y}`;
  const pathId = `path-${Math.random().toString(36).substr(2, 9)}`;
  
  // Create path element
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('id', pathId);
  path.setAttribute('d', pathD);
  path.setAttribute('class', isNormal ? 'normal-line' : 'attack-line');
  attacksGroup.appendChild(path);
  
  // Create pulsing dot that moves along the line
  const pulse = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  pulse.setAttribute('r', isNormal ? '3.5' : '5');
  pulse.setAttribute('class', isNormal ? 'normal-pulse' : 'attack-pulse');
  
  // Add animation element to follow the path
  const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
  anim.setAttribute('dur', isNormal ? '2.5s' : '1.2s');
  anim.setAttribute('repeatCount', '1');
  anim.setAttribute('rotate', 'auto');
  
  const mpath = document.createElementNS('http://www.w3.org/2000/svg', 'mpath');
  mpath.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`);
  
  anim.appendChild(mpath);
  pulse.appendChild(anim);
  attacksGroup.appendChild(pulse);
  
  // Cleanup after animation completes
  setTimeout(() => {
    path.remove();
    pulse.remove();
  }, 3000);
}


// --- Log Ingestion & Grok Parsing (Logstash Simulation) ---
function ingestRawLog(rawLine, agentType, filePath) {
  // 1. Add to raw log terminal
  const rawTerm = document.getElementById('raw-log-terminal');
  if (rawTerm) {
    const lineEl = document.createElement('div');
    lineEl.className = 'terminal-line';
    
    // Add custom coloring based on log severity hints
    if (rawLine.includes('Failed') || rawLine.includes('NOT in sudoers') || rawLine.includes('mimikatz')) {
      lineEl.classList.add('log-entry-fail');
    } else if (rawLine.includes('Accepted') || rawLine.includes('session opened')) {
      lineEl.classList.add('log-entry-success');
    } else if (rawLine.includes('nmap') || rawLine.includes('exfiltration')) {
      lineEl.classList.add('log-entry-warn');
    }
    
    lineEl.textContent = `[${new Date().toISOString()}] [${agentType.toUpperCase()}] ${rawLine}`;
    rawTerm.appendChild(lineEl);
    
    // Cap terminal output and scroll
    if (rawTerm.children.length > 80) rawTerm.removeChild(rawTerm.firstChild);
    rawTerm.scrollTop = rawTerm.scrollHeight;
  }
  
  // 2. Simulate Logstash filter processing
  const ecsObj = parseLogstashFilters(rawLine, agentType, filePath);
  db.logs.push(ecsObj);
  
  // 3. Add to ECS JSON terminal
  const ecsTerm = document.getElementById('ecs-json-terminal');
  if (ecsTerm) {
    const jsonEl = document.createElement('pre');
    jsonEl.className = 'terminal-line';
    if (ecsObj.event.severity >= 4) jsonEl.classList.add('log-entry-fail');
    else if (ecsObj.event.severity >= 3) jsonEl.classList.add('log-entry-warn');
    else if (ecsObj.event.outcome === 'success') jsonEl.classList.add('log-entry-success');
    
    jsonEl.textContent = JSON.stringify(ecsObj, null, 2);
    ecsTerm.appendChild(jsonEl);
    
    if (ecsTerm.children.length > 50) ecsTerm.removeChild(ecsTerm.firstChild);
    ecsTerm.scrollTop = ecsTerm.scrollHeight;
  }
  
  // 4. Update core database analysis state
  processSecurityAlertRules(ecsObj);
  updateDashboardMetrics();
}

function parseLogstashFilters(rawLine, agentType, filePath) {
  const now = new Date();
  
  // Default ECS base
  const ecs = {
    "@timestamp": now.toISOString(),
    "agent": {
      "type": agentType,
      "version": "8.12.0"
    },
    "log": {
      "file": { "path": filePath }
    },
    "event": {
      "category": "authentication",
      "action": "unknown",
      "outcome": "unknown",
      "severity": 1
    },
    "source": { "ip": "127.0.0.1" },
    "user": { "name": "unknown" },
    "message": rawLine
  };

  // Mock Grok Parsing logic matching logstash.conf
  if (agentType === 'filebeat') {
    // Linux auth parser
    if (rawLine.includes('Failed password for invalid user')) {
      const match = rawLine.match(/Failed password for invalid user (\S+) from (\S+) port (\d+)/);
      if (match) {
        ecs.user.name = match[1];
        ecs.source.ip = match[2];
        ecs.source.port = parseInt(match[3]);
        ecs.event.action = "ssh_login";
        ecs.event.outcome = "failure";
        ecs.event.severity = 3;
      }
    } else if (rawLine.includes('Failed password for')) {
      const match = rawLine.match(/Failed password for (\S+) from (\S+) port (\d+)/);
      if (match) {
        ecs.user.name = match[1];
        ecs.source.ip = match[2];
        ecs.source.port = parseInt(match[3]);
        ecs.event.action = "ssh_login";
        ecs.event.outcome = "failure";
        ecs.event.severity = 3;
      }
    } else if (rawLine.includes('Accepted password for')) {
      const match = rawLine.match(/Accepted password for (\S+) from (\S+) port (\d+)/);
      if (match) {
        ecs.user.name = match[1];
        ecs.source.ip = match[2];
        ecs.source.port = parseInt(match[3]);
        ecs.event.action = "ssh_login";
        ecs.event.outcome = "success";
        ecs.event.severity = 1;
      }
    } else if (rawLine.includes('NOT in sudoers')) {
      const match = rawLine.match(/(\S+) : user NOT in sudoers ; TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)/);
      if (match) {
        ecs.user.name = match[1];
        ecs.user.target_user = match[4];
        ecs.process = {
          tty: match[2],
          working_directory: match[3],
          command_line: match[5]
        };
        ecs.event.category = "iam";
        ecs.event.action = "privilege_escalation";
        ecs.event.outcome = "failure";
        ecs.event.severity = 4;
      }
    } else if (rawLine.includes('nmap')) {
      ecs.event.category = "network";
      ecs.event.action = "network_flow";
      ecs.event.outcome = "failure";
      ecs.event.severity = 2;
      ecs.source.ip = rawLine.match(/from (\S+)/)?.[1] || "192.168.1.50";
    }
  } else if (agentType === 'winlogbeat') {
    // Windows events parsing
    if (rawLine.includes('EventID 4625')) {
      const match = rawLine.match(/User: (\S+), SourceIP: (\S+)/);
      ecs.user.name = match ? match[1] : "Administrator";
      ecs.source.ip = match ? match[2] : "192.168.1.99";
      ecs.event.action = "win_login";
      ecs.event.outcome = "failure";
      ecs.event.code = 4625;
      ecs.event.severity = 3;
    } else if (rawLine.includes('EventID 4624')) {
      const match = rawLine.match(/User: (\S+), SourceIP: (\S+)/);
      ecs.user.name = match ? match[1] : "Administrator";
      ecs.source.ip = match ? match[2] : "192.168.1.99";
      ecs.event.action = "win_login";
      ecs.event.outcome = "success";
      ecs.event.code = 4624;
      ecs.event.severity = 1;
    } else if (rawLine.includes('EventID 4688')) {
      ecs.event.category = "process";
      ecs.event.action = "process_creation";
      ecs.event.code = 4688;
      
      const cmdMatch = rawLine.match(/Command: (.+)/);
      ecs.process = {
        command_line: cmdMatch ? cmdMatch[1] : "cmd.exe",
        name: cmdMatch ? cmdMatch[1].split(' ')[0] : "cmd.exe"
      };
      
      if (rawLine.includes('mimikatz')) {
        ecs.event.action = "credential_dumping";
        ecs.event.severity = 5; // Critical
      }
    }
  } else if (agentType === 'network_log') {
    ecs.event.category = "network";
    ecs.event.action = "data_transfer";
    
    if (rawLine.includes('exfiltration')) {
      ecs.event.severity = 4;
      ecs.event.outcome = "failure";
      ecs.source.ip = "192.168.1.15";
      ecs.network = { bytes_written: 5583457280 }; // ~5.2 GB
    }
  }

  // Inject GeoIP coordinates matching public IPs
  if (ecs.source.ip && isPublicIp(ecs.source.ip)) {
    let geo = { country_name: "Unknown", location: { lat: 0, lon: 0 } };
    if (ecs.source.ip.startsWith('93.')) {
      geo = { country_name: "Russia", location: { lat: 55.75, lon: 37.61 } };
    } else if (ecs.source.ip.startsWith('222.')) {
      geo = { country_name: "China", location: { lat: 39.9, lon: 116.4 } };
    } else if (ecs.source.ip.startsWith('177.')) {
      geo = { country_name: "Brazil", location: { lat: -23.55, lon: -46.63 } };
    } else if (ecs.source.ip.startsWith('80.')) {
      geo = { country_name: "Germany", location: { lat: 50.11, lon: 8.68 } };
    }
    ecs.source.geo = geo;
  }

  return ecs;
}

function isPublicIp(ip) {
  return !(ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('172.16.'));
}


// --- Attack Simulation Triggers ---
const attacks = {
  ssh_brute_force: {
    name: "SSH Brute Force",
    agent: "filebeat",
    logPath: "/var/log/auth.log",
    sourceIp: "93.184.216.34", // Russian mock IP
    sourceGeoKey: "kali_attacker",
    targetUser: "admin",
    steps: 12,
    generateLog: (step, user, ip) => {
      if (step < 11) {
        return `Failed password for invalid user ${user} from ${ip} port ${45000 + step * 25} ssh2`;
      } else {
        // Last step successful to show threat escalation
        return `Accepted password for ${user} from ${ip} port ${45000 + step * 25} ssh2`;
      }
    }
  },
  rdp_brute_force: {
    name: "RDP Brute Force",
    agent: "winlogbeat",
    logPath: "Security",
    sourceIp: "177.34.12.87", // Brazil mock IP
    sourceGeoKey: "brazil_node",
    targetUser: "Administrator",
    steps: 8,
    generateLog: (step, user, ip) => {
      return `EventID 4625 - Failed Logon. Account: ${user}, SourceIP: ${ip}, Port: 3389`;
    }
  },
  sudo_misuse: {
    name: "Sudo Privilege Abuse",
    agent: "filebeat",
    logPath: "/var/log/auth.log",
    sourceIp: "192.168.1.120", // local kali
    sourceGeoKey: null,
    targetUser: "kali",
    steps: 2,
    generateLog: (step, user, ip) => {
      return `${user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`;
    }
  },
  port_scan: {
    name: "Nmap Port Scan",
    agent: "filebeat",
    logPath: "/var/log/syslog",
    sourceIp: "222.12.89.43", // China mock IP
    sourceGeoKey: "beijing_node",
    targetUser: "root",
    steps: 15,
    generateLog: (step, user, ip) => {
      return `Connection rejected from ${ip} to target port ${22 + step * 51} - nmap probe`;
    }
  },
  mimikatz: {
    name: "Credential Dumping",
    agent: "winlogbeat",
    logPath: "Security",
    sourceIp: "192.168.1.99",
    sourceGeoKey: null,
    targetUser: "LocalSystem",
    steps: 1,
    generateLog: (step, user, ip) => {
      return `EventID 4688 - Process Created. User: ${user}, Command: C:\\Windows\\Temp\\mimikatz.exe sekurlsa::logonpasswords exit`;
    }
  },
  data_exfil: {
    name: "Data Exfiltration",
    agent: "network_log",
    logPath: "firewall.log",
    sourceIp: "192.168.1.15",
    sourceGeoKey: "brazil_node", // Exfiltrate to Botnet
    targetUser: "db_service",
    steps: 1,
    generateLog: (step, user, ip) => {
      return `Security Firewall: anomalous outbound data exfiltration of 5583457280 bytes to IP 177.34.12.87`;
    }
  }
};

let activeSimulations = 0;

function triggerSimulation(attackType) {
  if (attackType === 'normal_traffic') {
    injectNormalLogs(3);
    showPopupAlert("Traffic Injection", "Injected normal background operations logs.", "success-severity");
    return;
  }

  const attack = attacks[attackType];
  if (!attack) return;

  // Signal UI active flow
  activeSimulations++;
  triggerArchVisualFlow(attack.agent, attack.sourceIp ? 'alert' : 'normal');

  // Trigger map vector if external IP exists
  if (attack.sourceGeoKey) {
    drawAttackVectorOnMap(attack.sourceGeoKey);
  }

  showPopupAlert("Attack Initiated", `Threat Simulation Started: ${attack.name}`, "crit-severity");

  // Step-by-step log output simulation
  let currentStep = 0;
  const interval = setInterval(() => {
    const logStr = attack.generateLog(currentStep, attack.targetUser, attack.sourceIp);
    ingestRawLog(logStr, attack.agent, attack.logPath);
    
    // Redraw map vector at intervals for brute force visual effect
    if (attack.sourceGeoKey && currentStep % 4 === 0 && currentStep > 0) {
      drawAttackVectorOnMap(attack.sourceGeoKey);
    }
    
    currentStep++;
    if (currentStep >= attack.steps) {
      clearInterval(interval);
      activeSimulations--;
      if (activeSimulations === 0) {
        resetArchVisualFlow();
      }
    }
  }, 400);
}

function injectBackgroundTraffic() {
  if (activeSimulations > 0) return; // Prioritize showing attacks
  injectNormalLogs(1);
}

function injectNormalLogs(count) {
  const users = ['john', 'sarah', 'alice', 'bob', 'system_service'];
  const ips = ['192.168.1.100', '192.168.1.102', '80.45.67.12']; // last one is Germany
  
  for (let i = 0; i < count; i++) {
    const user = users[Math.floor(Math.random() * users.length)];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    
    // Choose Windows or Linux randomly
    if (Math.random() > 0.5) {
      // Windows normal logon (4624)
      const line = `EventID 4624 - Successful Logon. User: ${user}, SourceIP: ${ip}`;
      ingestRawLog(line, "winlogbeat", "Security");
    } else {
      // Linux normal session
      const line = `Accepted password for ${user} from ${ip} port ${51000 + Math.floor(Math.random() * 200)} ssh2`;
      ingestRawLog(line, "filebeat", "/var/log/auth.log");
      
      // Draw map vector for Germany IP
      if (ip.startsWith('80.')) {
        drawAttackVectorOnMap('germany_node', true);
      }
    }
  }
}


// --- Alert Rules Processor (Elastic Watcher Simulation) ---
function processSecurityAlertRules(log) {
  const now = new Date();
  
  // Alert Rule 1: Failed login threshold watcher (>5 failures from same IP within short time)
  if (log.event.action && log.event.action.includes('login') && log.event.outcome === 'failure') {
    const ip = log.source.ip;
    if (!db.failedCounts[ip]) db.failedCounts[ip] = [];
    
    // Keep failure log times
    db.failedCounts[ip].push(now);
    
    // Filter failures in the last 1 minute
    db.failedCounts[ip] = db.failedCounts[ip].filter(t => (now - t) < 60000);
    
    if (db.failedCounts[ip].length >= 5) {
      // Check if alert already raised for this IP recently to avoid spam
      const recentAlert = db.alerts.find(a => a.source_ip === ip && (now - new Date(a.timestamp)) < 15000);
      if (!recentAlert) {
        triggerSecurityAlert({
          name: "Brute Force Attack Detected",
          desc: `Watcher triggered: ${db.failedCounts[ip].length} failed authentication attempts detected from IP ${ip} in under 1 minute.`,
          source_ip: ip,
          target_user: log.user.name,
          severity: 4 // High
        });
        
        // Reset counter after alert to require another 5 failures
        db.failedCounts[ip] = [];
      }
    }
  }
  
  // Alert Rule 2: Privilege Escalation Sudo Misuse (Immediate trigger)
  if (log.event.action === 'privilege_escalation' && log.event.outcome === 'failure') {
    triggerSecurityAlert({
      name: "Sudo Privilege Escalation Failure",
      desc: `Alert: User '${log.user.name}' tried to execute command '${log.process.command_line}' as target user '${log.user.target_user}', but is NOT in sudoers.`,
      source_ip: log.source.ip,
      target_user: log.user.name,
      severity: 4 // High
    });
  }

  // Alert Rule 3: Credential Dumping Mimikatz (Immediate trigger)
  if (log.event.action === 'credential_dumping') {
    triggerSecurityAlert({
      name: "Mimikatz Credential Dumping Attempt",
      desc: `Critical Alert: Process execution of Mimikatz credentials harvester detected. Command Line: "${log.process.command_line}"`,
      source_ip: log.source.ip,
      target_user: log.user.name,
      severity: 5 // Critical
    });
  }

  // Alert Rule 4: Data Exfiltration (Immediate trigger)
  if (log.event.category === 'network' && log.event.severity === 4) {
    triggerSecurityAlert({
      name: "Critical Data Exfiltration Detected",
      desc: `Alert: Major outbound data leakage flow detected. IP "${log.source.ip}" transmitted 5.2 GB of data to external IP.`,
      source_ip: log.source.ip,
      target_user: log.user.name,
      severity: 5 // Critical
    });
  }
}

function triggerSecurityAlert(alert) {
  alert.id = `alert-${Math.random().toString(36).substr(2, 9)}`;
  alert.timestamp = new Date().toISOString();
  
  db.alerts.unshift(alert); // Add to beginning of array
  
  // Render alert card in UI feed
  const feed = document.getElementById('security-alerts-feed');
  if (feed) {
    // Remove "no alerts" message
    const noAlertsMsg = feed.querySelector('.no-alerts-msg');
    if (noAlertsMsg) noAlertsMsg.remove();
    
    const isCrit = alert.severity === 5;
    const card = document.createElement('div');
    card.className = `alert-item-card ${isCrit ? 'crit-severity' : ''}`;
    
    card.innerHTML = `
      <div class="alert-icon">${isCrit ? '💀' : '🚨'}</div>
      <div class="alert-info-body">
        <div class="alert-title-row">
          <span class="alert-name-txt text-${isCrit ? 'purple' : 'red'}">${alert.name.toUpperCase()}</span>
          <span class="alert-time-txt">${alert.timestamp.split('T')[1].substr(0, 8)}</span>
        </div>
        <p class="alert-desc-txt">${alert.desc}</p>
        <div class="alert-meta-details">
          <span>Source: <code>${alert.source_ip}</code></span>
          <span>Account: <code>${alert.target_user}</code></span>
          <span>Severity: <code class="text-${isCrit ? 'purple' : 'orange'}">${isCrit ? 'CRITICAL' : 'HIGH'}</code></span>
        </div>
      </div>
    `;
    
    feed.insertBefore(card, feed.firstChild);
    
    // Limit UI alerts listed
    if (feed.children.length > 20) feed.removeChild(feed.lastChild);
  }
  
  // Update header and dashboard
  showPopupAlert(alert.name, alert.desc, alert.severity === 5 ? "crit-severity" : "alert-severity");
  
  // Alert visual effect on System Status
  const statusEl = document.getElementById('system-status');
  if (statusEl) {
    statusEl.textContent = alert.severity === 5 ? "BREACH DETECTED" : "WARNING";
    statusEl.className = "stat-value text-red";
  }
}

function clearSecurityAlerts() {
  db.alerts = [];
  const feed = document.getElementById('security-alerts-feed');
  if (feed) {
    feed.innerHTML = `
      <div class="no-alerts-msg">
        <span class="shield-icon">🛡️</span>
        <p>NO ACTIVE ALERTS. MONITORED SYSTEMS REPORT SECURE ENVIRONMENT.</p>
      </div>
    `;
  }
  
  const statusEl = document.getElementById('system-status');
  if (statusEl) {
    statusEl.textContent = "SECURE";
    statusEl.className = "stat-value text-green";
  }
  
  updateDashboardMetrics();
}

function showPopupAlert(title, message, severityClass) {
  const container = document.getElementById('alert-banner-wrapper');
  if (!container) return;
  
  const banner = document.createElement('div');
  banner.className = `alert-banner ${severityClass}`;
  
  let icon = '🔔';
  if (severityClass === 'crit-severity') icon = '💀';
  else if (severityClass === 'success-severity') icon = '✓';
  else if (severityClass === 'alert-severity') icon = '🚨';
  
  banner.innerHTML = `
    <div class="alert-banner-icon">${icon}</div>
    <div class="alert-banner-content">
      <div class="alert-banner-title">${title}</div>
      <div class="alert-banner-desc">${message}</div>
    </div>
  `;
  
  container.appendChild(banner);
  
  // Auto remove popup banner
  setTimeout(() => {
    banner.style.animation = "slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) reverse";
    setTimeout(() => banner.remove(), 300);
  }, 4000);
}


// --- Dashboard Metrics & Tables Rendering ---
function updateDashboardMetrics() {
  const logsToProcess = db.filteredLogs.length > 0 || document.getElementById('kql-search-input').value.trim() !== '' 
    ? db.filteredLogs 
    : db.logs;
    
  // 1. Core counters
  const totalLogs = logsToProcess.length;
  const failedLogins = logsToProcess.filter(l => l.event.action && l.event.action.includes('login') && l.event.outcome === 'failure').length;
  const successLogins = logsToProcess.filter(l => l.event.action && l.event.action.includes('login') && l.event.outcome === 'success').length;
  const sudoViolations = logsToProcess.filter(l => l.event.action === 'privilege_escalation').length;
  const activeAlertsCount = db.alerts.length;
  
  // 2. Write counters to DOM
  document.getElementById('metric-total-logs').textContent = totalLogs.toLocaleString();
  document.getElementById('metric-failed-logins').textContent = failedLogins.toLocaleString();
  document.getElementById('metric-sudo-violations').textContent = sudoViolations.toLocaleString();
  document.getElementById('metric-alerts-triggered').textContent = activeAlertsCount.toLocaleString();
  document.getElementById('hud-alerts-count').textContent = activeAlertsCount;
  
  // Update failure rate sub-label
  const totalAttempts = failedLogins + successLogins;
  const failureRate = totalAttempts > 0 ? Math.round((failedLogins / totalAttempts) * 100) : 0;
  document.getElementById('metric-failed-sub').textContent = `${failureRate}% failure rate`;
  
  // Dynamic alerts metrics highlight class
  const alertCard = document.getElementById('alert-card');
  if (alertCard) {
    if (activeAlertsCount > 0) alertCard.classList.add('alert-active');
    else alertCard.classList.remove('alert-active');
  }

  // Update Ingestion Rate text
  const rateEl = document.getElementById('ingest-rate');
  if (rateEl) {
    const rate = activeSimulations > 0 ? (2.5 + Math.random() * 2).toFixed(1) : (0.2 + Math.random() * 0.3).toFixed(1);
    rateEl.textContent = `${rate} EPS`;
  }

  // 3. Render Targeted Users Table
  renderTargetedUsersTable(logsToProcess);
  
  // 4. Render Critical Events Table
  renderCriticalEventsTable(logsToProcess);
  
  // 5. Update timeline data trend counts
  if (activeSimulations > 0 || Math.random() > 0.7) {
    pushTimelineLog(successLogins + 5, failedLogins + (activeSimulations > 0 ? 3 : 0));
  }
}

function renderTargetedUsersTable(logs) {
  const tbody = document.getElementById('table-targeted-users');
  if (!tbody) return;
  
  // Calculate failed/success logons per user
  const userStats = {};
  logs.forEach(log => {
    if (log.event.action && log.event.action.includes('login') && log.user.name !== 'unknown') {
      const name = log.user.name;
      if (!userStats[name]) userStats[name] = { failed: 0, success: 0 };
      if (log.event.outcome === 'failure') userStats[name].failed++;
      else if (log.event.outcome === 'success') userStats[name].success++;
    }
  });
  
  // Convert to array and sort by failed count
  const sorted = Object.entries(userStats)
    .map(([user, stat]) => ({ user, ...stat }))
    .sort((a, b) => b.failed - a.failed)
    .slice(0, 5); // top 5
    
  if (sorted.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No login data processed yet.</td></tr>`;
    return;
  }
  
  tbody.innerHTML = sorted.map(row => {
    let risk = "LOW";
    let riskClass = "risk-low";
    if (row.failed > 20) { risk = "CRITICAL"; riskClass = "risk-crit"; }
    else if (row.failed > 5) { risk = "HIGH"; riskClass = "risk-high"; }
    else if (row.failed > 1) { risk = "MEDIUM"; riskClass = "risk-med"; }
    
    return `
      <tr>
        <td><code>${row.user}</code></td>
        <td class="text-red">${row.failed}</td>
        <td class="text-green">${row.success}</td>
        <td class="${riskClass}">${risk}</td>
      </tr>
    `;
  }).join('');
}

function renderCriticalEventsTable(logs) {
  const tbody = document.getElementById('table-critical-events');
  if (!tbody) return;
  
  // Filter for severity >= 4 (High/Critical events)
  const critEvents = logs.filter(l => l.event.severity >= 4)
    .slice(-5) // last 5
    .reverse(); // newest first
    
  if (critEvents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No escalation events detected.</td></tr>`;
    return;
  }
  
  tbody.innerHTML = critEvents.map(log => {
    const isCrit = log.event.severity === 5;
    const time = log['@timestamp'].split('T')[1].substr(0, 8);
    const host = log.agent.type === 'winlogbeat' ? 'Windows-AD' : 'Linux-Gateway';
    const cmd = log.process ? log.process.command_line : log.message;
    
    return `
      <tr>
        <td class="text-muted font-mono" style="font-size:0.75rem;">${time}</td>
        <td>${host}</td>
        <td><code>${log.user.name}</code></td>
        <td><code class="text-secondary">${cmd.substring(0, 45)}${cmd.length > 45 ? '...' : ''}</code></td>
        <td><span class="agent-badge ${isCrit ? 'btn-critical' : 'btn-danger'}" style="padding:1px 6px; font-size:0.6rem;">${isCrit ? 'CRITICAL' : 'HIGH'}</span></td>
      </tr>
    `;
  }).join('');
}

function resetSimulatorData() {
  db.logs = [];
  db.filteredLogs = [];
  db.alerts = [];
  db.failedCounts = {};
  
  // Reset terminals
  document.getElementById('raw-log-terminal').innerHTML = `<div class="terminal-line text-muted">// Logs cleared. Ready.</div>`;
  document.getElementById('ecs-json-terminal').innerHTML = `<div class="terminal-line text-muted">// Logs cleared. Ready.</div>`;
  
  // Mute alerts feed
  clearSecurityAlerts();
  
  // Clear map vectors
  const attacksGroup = document.getElementById('map-attacks-group');
  if (attacksGroup) attacksGroup.innerHTML = '';
  
  // Reset metrics
  updateDashboardMetrics();
  
  showPopupAlert("System Reset", "All log indices, metrics, and alert tables have been cleared.", "success-severity");
}


// --- KQL Search Sandbox Execution ---
function executeKQLSearch() {
  const input = document.getElementById('kql-search-input').value.trim();
  if (input === '') {
    clearKQLSearch();
    return;
  }
  
  try {
    // Basic KQL Interpreter supporting simple AND combinations
    // Format supported: field: value AND field2: value2
    // Also supports inequalities for numbers: event.severity >= 4
    const terms = input.split(/\s+AND\s+/i);
    const filters = [];
    
    terms.forEach(term => {
      // Check for operators: >=, <=, >, <, :
      let op = ':';
      let key, val;
      
      if (term.includes('>=')) {
        op = '>=';
        [key, val] = term.split('>=');
      } else if (term.includes('<=')) {
        op = '<=';
        [key, val] = term.split('<=');
      } else if (term.includes('>')) {
        op = '>';
        [key, val] = term.split('>');
      } else if (term.includes('<')) {
        op = '<';
        [key, val] = term.split('<');
      } else if (term.includes(':')) {
        [key, val] = term.split(':');
      } else {
        throw new Error(`Unsupported operator in term: "${term}"`);
      }
      
      key = key.trim();
      val = val.trim().replace(/^["']|["']$/g, ''); // strip quotes
      
      filters.push({ key, op, val });
    });
    
    // Filter database
    db.filteredLogs = db.logs.filter(log => {
      return filters.every(f => {
        const actualVal = getObjectValue(log, f.key);
        if (actualVal === undefined) return false;
        
        const expected = f.val;
        if (f.op === ':') {
          // Case insensitive string compare or exact match
          return String(actualVal).toLowerCase() === String(expected).toLowerCase();
        } else {
          // Numeric compares
          const actNum = Number(actualVal);
          const expNum = Number(expected);
          if (isNaN(actNum) || isNaN(expNum)) return false;
          if (f.op === '>=') return actNum >= expNum;
          if (f.op === '<=') return actNum <= expNum;
          if (f.op === '>') return actNum > expNum;
          if (f.op === '<') return actNum < expNum;
        }
        return false;
      });
    });
    
    // Render feedback in HUD
    showPopupAlert("KQL Filter Applied", `Found ${db.filteredLogs.length} matching events in ES index.`, "success-severity");
    
    // Update metric cards and tables with filtered subset
    updateDashboardMetrics();
    
    // Redraw map with only filtered geo pins if filters filter logs
    redrawFilteredMapPins();
    
  } catch (err) {
    showPopupAlert("KQL Error", `Invalid syntax: ${err.message}`, "crit-severity");
    console.error(err);
  }
}

function clearKQLSearch() {
  document.getElementById('kql-search-input').value = '';
  db.filteredLogs = [];
  
  // Re-render full stats
  updateDashboardMetrics();
  
  // Redraw full pins
  const pinsGroup = document.getElementById('map-pins-group');
  if (pinsGroup) {
    pinsGroup.innerHTML = '';
    initMapPins();
  }
  
  showPopupAlert("Filters Cleared", "Displaying full indices logs feed.", "success-severity");
}

function getObjectValue(obj, path) {
  return path.split('.').reduce((acc, part) => acc && acc[part], obj);
}

function redrawFilteredMapPins() {
  const pinsGroup = document.getElementById('map-pins-group');
  if (!pinsGroup) return;
  pinsGroup.innerHTML = ''; // clear
  
  // Redraw target node
  const target = GEOMAP_COORDINATES['us_east'];
  const targetGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  targetGroup.setAttribute('class', 'map-pin');
  const targetCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  targetCircle.setAttribute('cx', target.x);
  targetCircle.setAttribute('cy', target.y);
  targetCircle.setAttribute('r', '7');
  targetCircle.setAttribute('fill', '#00f2fe');
  targetCircle.setAttribute('stroke', '#0c0e14');
  targetCircle.setAttribute('stroke-width', '1.5');
  targetGroup.appendChild(targetCircle);
  pinsGroup.appendChild(targetGroup);
  
  // Find which attacker nodes match the filtered logs IPs
  const matchedIps = [...new Set(db.filteredLogs.map(l => l.source.ip))];
  
  matchedIps.forEach(ip => {
    // Find matching coordinate key
    let coordKey = null;
    if (ip.startsWith('93.')) coordKey = 'kali_attacker';
    else if (ip.startsWith('222.')) coordKey = 'beijing_node';
    else if (ip.startsWith('177.')) coordKey = 'brazil_node';
    else if (ip.startsWith('80.')) coordKey = 'germany_node';
    
    if (coordKey) {
      const val = GEOMAP_COORDINATES[coordKey];
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'map-pin');
      
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', val.x);
      circle.setAttribute('cy', val.y);
      circle.setAttribute('r', '5');
      circle.setAttribute('fill', coordKey === 'germany_node' ? '#4ade80' : '#ef4444');
      
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = val.name;
      
      g.appendChild(title);
      g.appendChild(circle);
      pinsGroup.appendChild(g);
    }
  });
}


// --- Architecture Network Flow Visual Animations ---
function triggerArchVisualFlow(agentType, severityClass) {
  // Highlight Shippers node
  const agentsNode = document.getElementById('node-agents');
  if (agentsNode) {
    agentsNode.className = `arch-node ${severityClass === 'alert' ? 'active-pulse-node' : 'active-pulse-node-normal'}`;
  }
  
  // Animate flow line 1
  const connectors = document.querySelectorAll('.arch-connector');
  if (connectors.length > 0) {
    connectors[0].className = `arch-connector ${severityClass === 'alert' ? 'active-flow-alert' : ''}`;
  }
  
  // Sequential network path timing animations
  setTimeout(() => {
    const logstashNode = document.getElementById('node-logstash');
    if (logstashNode) logstashNode.className = `arch-node ${severityClass === 'alert' ? 'active-pulse-node' : 'active-pulse-node-normal'}`;
    if (connectors.length > 1) connectors[1].className = `arch-connector ${severityClass === 'alert' ? 'active-flow-alert' : ''}`;
  }, 300);

  setTimeout(() => {
    const esNode = document.getElementById('node-elasticsearch');
    if (esNode) esNode.className = `arch-node ${severityClass === 'alert' ? 'active-pulse-node' : 'active-pulse-node-normal'}`;
    if (connectors.length > 2) connectors[2].className = `arch-connector ${severityClass === 'alert' ? 'active-flow-alert' : ''}`;
  }, 600);

  setTimeout(() => {
    const kibanaNode = document.getElementById('node-kibana');
    if (kibanaNode) kibanaNode.className = `arch-node ${severityClass === 'alert' ? 'active-pulse-node' : 'active-pulse-node-normal'}`;
  }, 900);
}

function resetArchVisualFlow() {
  document.querySelectorAll('.arch-node').forEach(node => {
    node.className = 'arch-node';
  });
  document.querySelectorAll('.arch-connector').forEach(c => {
    c.className = 'arch-connector';
  });
}


// --- Bind Configurations Explorer Codes ---
function showRepoCode(fileKey) {
  document.querySelectorAll('.repo-file-item').forEach(item => item.classList.remove('active'));
  
  // Set active sidebar item
  const clickedItem = Array.from(document.querySelectorAll('.repo-file-item'))
    .find(item => item.getAttribute('onclick').includes(fileKey));
  if (clickedItem) clickedItem.classList.add('active');
  
  // Update header and code area
  const titleMap = {
    'docker-compose': 'docker-compose.yml',
    'logstash-conf': 'logstash/pipeline/logstash.conf',
    'dashboard-ndjson': 'kibana/dashboard.ndjson',
    'watcher-json': 'alerts/watcher-brute-force.json'
  };
  
  document.getElementById('repo-file-title').textContent = titleMap[fileKey];
  document.getElementById('repo-code-content').textContent = configs[fileKey] || "File content is not loaded yet.";
}

function copyRepoCode() {
  const code = document.getElementById('repo-code-content').textContent;
  navigator.clipboard.writeText(code).then(() => {
    showPopupAlert("Code Copied", "File content has been copied to your clipboard.", "success-severity");
  }).catch(err => {
    showPopupAlert("Copy Failed", "Failed to write clipboard.", "crit-severity");
    console.error(err);
  });
}

// Load physical file contents to variables for UI viewer rendering
function loadConfigContent() {
  // We fetch them locally from the file system. In client side, we can also embed fallback templates if server fetch fails.
  const filesToFetch = [
    { key: 'docker-compose', url: '/docker-compose.yml' },
    { key: 'logstash-conf', url: '/logstash/pipeline/logstash.conf' },
    { key: 'dashboard-ndjson', url: '/kibana/dashboard.ndjson' },
    { key: 'watcher-json', url: '/alerts/watcher-brute-force.json' }
  ];
  
  filesToFetch.forEach(f => {
    fetch(f.url)
      .then(res => {
        if (!res.ok) throw new Error("File not found");
        return res.text();
      })
      .then(text => {
        configs[f.key] = text;
        // If it's docker-compose, display it first
        if (f.key === 'docker-compose') {
          showRepoCode('docker-compose');
        }
      })
      .catch(err => {
        console.warn(`Could not fetch ${f.url} dynamically. Using local fallback templates.`, err);
        loadLocalFallbacks();
      });
  });
}

function loadLocalFallbacks() {
  // If fetching fails, we provide fallback codes so the UI repo remains functional.
  configs['docker-compose'] = `version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=siem-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - ELASTIC_PASSWORD=changeme
    ports:
      - "9200:9200"
  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    volumes:
      - ./logstash/pipeline/logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - "5044:5044"
  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    ports:
      - "5601:5601"`;
      
  configs['logstash-conf'] = `input { beats { port => 5044 } }
filter {
  grok { match => { "message" => "Failed password for %{USER:user.name} from %{IP:source.ip}" } }
  geoip { source => "source.ip" }
}
output { elasticsearch { hosts => ["http://elasticsearch:9200"] } }`;

  configs['dashboard-ndjson'] = `{"type":"index-pattern","id":"siem-logs-pattern","attributes":{"title":"siem-logs-*"}}
{"type":"visualization","id":"siem-geomap","attributes":{"title":"SIEM: Geo Map"}}`;

  configs['watcher-json'] = `{"trigger":{"schedule":{"interval":"1m"}},"input":{"search":{...}}}`;
  
  showRepoCode('docker-compose');
}

function loadDetectionReportDoc() {
  fetch('/docs/detection_report.md')
    .then(res => {
      if (!res.ok) throw new Error("Report not found");
      return res.text();
    })
    .then(text => {
      // Basic markdown to html compiler
      document.getElementById('detection-report-markdown-content').innerHTML = parseMarkdown(text);
    })
    .catch(err => {
      console.warn("Could not fetch detection report from server.", err);
    });
}

// Simple regex-based Markdown to HTML parser
function parseMarkdown(md) {
  let html = md;
  
  // Headers
  html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');
  html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  
  // Horizontal Rules
  html = html.replace(/^---$/gim, '<hr>');
  
  // Lists
  html = html.replace(/^\* (.*$)/gim, '<ul><li>$1</li></ul>');
  html = html.replace(/<\/ul>\s*<ul>/g, ''); // consolidate bullets
  
  // Code Blocks
  html = html.replace(/```kql([\s\S]*?)```/gim, '<pre><code>$1</code></pre>');
  html = html.replace(/```([\s\S]*?)```/gim, '<pre><code>$1</code></pre>');
  
  // Inline Code
  html = html.replace(/`([^`]+)`/gim, '<code>$1</code>');
  
  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/gim, '<a href="$2" target="_blank">$1</a>');
  
  // Bold
  html = html.replace(/\*\*([^*]+)\*\*/gim, '<strong>$1</strong>');
  
  // Linebreaks / Paragraphs
  // Very basic: split double lines into paragraphs
  const paragraphs = html.split(/\n\s*\n/);
  html = paragraphs.map(p => {
    if (p.trim().startsWith('<h') || p.trim().startsWith('<pre') || p.trim().startsWith('<hr') || p.trim().startsWith('<ul')) {
      return p;
    }
    return `<p>${p.replace(/\n/g, '<br>')}</p>`;
  }).join('\n');
  
  return html;
}
