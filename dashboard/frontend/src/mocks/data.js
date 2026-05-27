export const ANALYSTS = [
  { id: 'analyst01', name: 'Morgan Lee',    role: 'senior_analyst', status: 'online',  avatar: 'ML' },
  { id: 'analyst02', name: 'Jordan Kim',    role: 'analyst',        status: 'online',  avatar: 'JK' },
  { id: 'analyst03', name: 'Sam Rivera',    role: 'analyst',        status: 'away',    avatar: 'SR' },
  { id: 'analyst04', name: 'Casey Patel',   role: 'analyst',        status: 'offline', avatar: 'CP' },
  { id: 'analyst05', name: 'Alex Chen',     role: 'senior_analyst', status: 'online',  avatar: 'AC' },
]

export const ALERTS = [
  {
    alert_id: 'a1b2c3d4-0001',
    classification: 'SQL Injection Attempt',
    priority: 'critical',
    approval_status: 'plans_generated',
    src_ip: '203.0.113.42',
    dst_ip: '10.0.1.15',
    dst_port: 5432,
    anomaly_score: 0.967,
    created_at: new Date(Date.now() - 4 * 60 * 1000).toISOString(),
    assigned_to: 'analyst01',
    cve_matches: [
      { cve_id: 'CVE-2023-34362', cvss_score: 9.8, exploit_available: true },
      { cve_id: 'CVE-2021-44228', cvss_score: 10.0, exploit_available: true },
    ],
    affected_assets: [
      { ip: '10.0.1.15', hostname: 'db-prod-01', criticality_tier: 1, zone: 'data' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0002',
    classification: 'Lateral Movement Detected',
    priority: 'high',
    approval_status: 'triaged',
    src_ip: '10.0.2.88',
    dst_ip: '10.0.1.20',
    dst_port: 445,
    anomaly_score: 0.812,
    created_at: new Date(Date.now() - 22 * 60 * 1000).toISOString(),
    assigned_to: 'analyst02',
    cve_matches: [
      { cve_id: 'CVE-2017-0144', cvss_score: 8.1, exploit_available: true },
    ],
    affected_assets: [
      { ip: '10.0.1.20', hostname: 'app-server-03', criticality_tier: 2, zone: 'app' },
      { ip: '10.0.2.88', hostname: 'workstation-12', criticality_tier: 3, zone: 'user' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0003',
    classification: 'Brute Force SSH Login',
    priority: 'medium',
    approval_status: 'approved',
    src_ip: '198.51.100.77',
    dst_ip: '10.0.0.5',
    dst_port: 22,
    anomaly_score: 0.654,
    created_at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    assigned_to: 'analyst03',
    cve_matches: [],
    affected_assets: [
      { ip: '10.0.0.5', hostname: 'bastion-01', criticality_tier: 1, zone: 'dmz' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0004',
    classification: 'Data Exfiltration Suspected',
    priority: 'high',
    approval_status: 'executed',
    src_ip: '10.0.1.44',
    dst_ip: '185.220.101.5',
    dst_port: 443,
    anomaly_score: 0.891,
    created_at: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
    assigned_to: 'analyst05',
    cve_matches: [],
    affected_assets: [
      { ip: '10.0.1.44', hostname: 'app-server-07', criticality_tier: 2, zone: 'app' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0005',
    classification: 'Port Scan',
    priority: 'low',
    approval_status: 'closed',
    src_ip: '192.0.2.10',
    dst_ip: '10.0.0.0/24',
    dst_port: 0,
    anomaly_score: 0.321,
    created_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    assigned_to: null,
    cve_matches: [],
    affected_assets: [],
  },
  {
    alert_id: 'a1b2c3d4-0006',
    classification: 'Ransomware C2 Beacon',
    priority: 'critical',
    approval_status: 'received',
    src_ip: '10.0.3.55',
    dst_ip: '91.193.18.22',
    dst_port: 8443,
    anomaly_score: 0.993,
    created_at: new Date(Date.now() - 90 * 1000).toISOString(),
    assigned_to: null,
    cve_matches: [
      { cve_id: 'CVE-2024-3400', cvss_score: 10.0, exploit_available: true },
    ],
    affected_assets: [
      { ip: '10.0.3.55', hostname: 'finance-ws-03', criticality_tier: 2, zone: 'finance' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0007',
    classification: 'Log4Shell Exploit Attempt',
    priority: 'critical',
    approval_status: 'plans_generated',
    src_ip: '45.33.32.156',
    dst_ip: '10.0.1.88',
    dst_port: 8080,
    anomaly_score: 0.981,
    created_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    assigned_to: 'analyst01',
    cve_matches: [
      { cve_id: 'CVE-2021-44228', cvss_score: 10.0, exploit_available: true },
      { cve_id: 'CVE-2022-22965', cvss_score: 9.8, exploit_available: true },
    ],
    affected_assets: [
      { ip: '10.0.1.88', hostname: 'api-gateway-01', criticality_tier: 1, zone: 'dmz' },
      { ip: '10.0.1.89', hostname: 'api-gateway-02', criticality_tier: 1, zone: 'dmz' },
    ],
  },
  {
    alert_id: 'a1b2c3d4-0008',
    classification: 'Privilege Escalation',
    priority: 'high',
    approval_status: 'rejected',
    src_ip: '10.0.2.31',
    dst_ip: '10.0.1.10',
    dst_port: 3389,
    anomaly_score: 0.743,
    created_at: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
    assigned_to: 'analyst02',
    cve_matches: [],
    affected_assets: [
      { ip: '10.0.1.10', hostname: 'dc-prod-01', criticality_tier: 1, zone: 'core' },
    ],
  },
]

export const PLANS = {
  'a1b2c3d4-0001': {
    plans: [
      {
        plan_id: 'plan-001',
        automation_tier: 'semi-automated',
        risk_level: 'high',
        confidence: 0.89,
        rationale: 'SQL injection from external IP targeting production database. Recommend immediate firewall block and credential rotation.',
        actions: [
          { action_type: 'firewall_block', target: '203.0.113.42', parameters: { direction: 'inbound' }, rationale: 'Block attacker IP at perimeter' },
          { action_type: 'credential_rotate', target: 'db-prod-01', parameters: { service: 'postgres' }, rationale: 'Rotate DB credentials as precaution' },
        ],
      },
      {
        plan_id: 'plan-002',
        automation_tier: 'manual',
        risk_level: 'medium',
        confidence: 0.72,
        rationale: 'Conservative approach: monitor and alert without active blocking until further investigation.',
        actions: [
          { action_type: 'alert_analyst', target: 'soc-team', parameters: {}, rationale: 'Escalate to senior analyst for review' },
          { action_type: 'capture_traffic', target: '203.0.113.42', parameters: { duration: 300 }, rationale: 'Capture traffic for forensic analysis' },
        ],
      },
    ],
  },
  'a1b2c3d4-0002': {
    plans: [
      {
        plan_id: 'plan-003',
        automation_tier: 'automated',
        risk_level: 'critical',
        confidence: 0.94,
        rationale: 'Lateral movement via SMB exploit detected. Isolate affected host immediately to prevent further spread.',
        actions: [
          { action_type: 'isolate_host', target: 'workstation-12', parameters: {}, rationale: 'Prevent further lateral spread' },
          { action_type: 'firewall_block', target: '10.0.2.88', parameters: { direction: 'both' }, rationale: 'Block compromised host at network level' },
        ],
      },
      {
        plan_id: 'plan-004',
        automation_tier: 'semi-automated',
        risk_level: 'high',
        confidence: 0.81,
        rationale: 'Patch the vulnerable SMBv1 service and run a full credential audit on affected systems.',
        actions: [
          { action_type: 'patch_apply', target: 'workstation-12', parameters: { patch: 'MS17-010' }, rationale: 'Remediate EternalBlue vulnerability' },
          { action_type: 'credential_rotate', target: 'app-server-03', parameters: {}, rationale: 'Rotate credentials on potentially compromised server' },
        ],
      },
    ],
  },
  'a1b2c3d4-0003': {
    plans: [
      {
        plan_id: 'plan-005',
        automation_tier: 'automated',
        risk_level: 'medium',
        confidence: 0.87,
        rationale: 'Brute force detected on bastion host. Block source IP and enforce MFA immediately.',
        actions: [
          { action_type: 'firewall_block', target: '198.51.100.77', parameters: { direction: 'inbound', ttl: 86400 }, rationale: 'Block attacking IP for 24 hours' },
          { action_type: 'alert_analyst', target: 'soc-team', parameters: { severity: 'medium' }, rationale: 'Notify team of brute force activity' },
        ],
      },
    ],
  },
  'a1b2c3d4-0007': {
    plans: [
      {
        plan_id: 'plan-006',
        automation_tier: 'semi-automated',
        risk_level: 'critical',
        confidence: 0.96,
        rationale: 'Active Log4Shell exploitation detected against API gateway. Immediate patching and WAF rule deployment required.',
        actions: [
          { action_type: 'firewall_block', target: '45.33.32.156', parameters: { direction: 'inbound' }, rationale: 'Block known exploit source' },
          { action_type: 'patch_apply', target: 'api-gateway-01', parameters: { package: 'log4j', version: '2.17.1' }, rationale: 'Patch Log4j to safe version' },
          { action_type: 'patch_apply', target: 'api-gateway-02', parameters: { package: 'log4j', version: '2.17.1' }, rationale: 'Patch Log4j to safe version' },
        ],
      },
      {
        plan_id: 'plan-007',
        automation_tier: 'manual',
        risk_level: 'high',
        confidence: 0.78,
        rationale: 'Isolate gateways and perform full forensic analysis before bringing back online.',
        actions: [
          { action_type: 'isolate_host', target: 'api-gateway-01', parameters: {}, rationale: 'Prevent potential RCE payload execution from spreading' },
          { action_type: 'capture_traffic', target: '45.33.32.156', parameters: { duration: 600 }, rationale: 'Capture full exploit traffic for forensics' },
        ],
      },
    ],
  },
  'a1b2c3d4-0008': {
    plans: [
      {
        plan_id: 'plan-008',
        automation_tier: 'manual',
        risk_level: 'high',
        confidence: 0.75,
        rationale: 'Privilege escalation on domain controller. Reset credentials and audit access logs.',
        actions: [
          { action_type: 'credential_rotate', target: 'dc-prod-01', parameters: { scope: 'admin' }, rationale: 'Reset all admin credentials on DC' },
          { action_type: 'alert_analyst', target: 'soc-lead', parameters: { priority: 'high' }, rationale: 'Escalate to SOC lead for manual review' },
        ],
      },
    ],
  },
}

export const TRACES = {
  'a1b2c3d4-0001': [
    { event_id: 'ev-001', agent_name: 'orchestrator', action: 'alert_received', rationale: 'New critical alert ingested from SIEM', confidence: null, duration_ms: 12, timestamp: new Date(Date.now() - 3.9 * 60 * 1000).toISOString() },
    { event_id: 'ev-002', agent_name: 'cve_lookup', action: 'cve_search', rationale: 'Searching CVE database for SQL injection signatures matching dst port 5432', confidence: 0.95, duration_ms: 340, timestamp: new Date(Date.now() - 3.7 * 60 * 1000).toISOString() },
    { event_id: 'ev-003', agent_name: 'asset_discovery', action: 'asset_resolve', rationale: 'Resolved 10.0.1.15 to db-prod-01 (Tier 1, data zone)', confidence: 0.88, duration_ms: 210, timestamp: new Date(Date.now() - 3.5 * 60 * 1000).toISOString() },
    { event_id: 'ev-004', agent_name: 'planning', action: 'plan_generation', rationale: 'Generating 2 remediation plans based on CVE context and asset criticality', confidence: 0.89, duration_ms: 1240, timestamp: new Date(Date.now() - 3.2 * 60 * 1000).toISOString() },
    { event_id: 'ev-005', agent_name: 'orchestrator', action: 'awaiting_approval', rationale: 'Plans generated and surfaced for analyst review', confidence: null, duration_ms: 5, timestamp: new Date(Date.now() - 2.9 * 60 * 1000).toISOString() },
  ],
  'a1b2c3d4-0002': [
    { event_id: 'ev-010', agent_name: 'orchestrator', action: 'alert_received', rationale: 'Lateral movement alert ingested — SMB traffic between internal hosts', confidence: null, duration_ms: 9, timestamp: new Date(Date.now() - 21 * 60 * 1000).toISOString() },
    { event_id: 'ev-011', agent_name: 'cve_lookup', action: 'cve_search', rationale: 'CVE-2017-0144 (EternalBlue) matched for SMB port 445', confidence: 0.97, duration_ms: 290, timestamp: new Date(Date.now() - 20.5 * 60 * 1000).toISOString() },
    { event_id: 'ev-012', agent_name: 'asset_discovery', action: 'asset_resolve', rationale: 'Resolved both src and dst IPs — workstation-12 and app-server-03', confidence: 0.91, duration_ms: 185, timestamp: new Date(Date.now() - 20 * 60 * 1000).toISOString() },
    { event_id: 'ev-013', agent_name: 'planning', action: 'plan_generation', rationale: 'High-confidence exploit match — generating isolation and patch plans', confidence: 0.94, duration_ms: 980, timestamp: new Date(Date.now() - 19.5 * 60 * 1000).toISOString() },
    { event_id: 'ev-014', agent_name: 'orchestrator', action: 'triaged', rationale: 'Alert triaged — elevated to analyst queue for plan approval', confidence: null, duration_ms: 6, timestamp: new Date(Date.now() - 19 * 60 * 1000).toISOString() },
  ],
  'a1b2c3d4-0007': [
    { event_id: 'ev-020', agent_name: 'orchestrator', action: 'alert_received', rationale: 'Critical alert: JNDI lookup string detected in HTTP request headers', confidence: null, duration_ms: 8, timestamp: new Date(Date.now() - 14.5 * 60 * 1000).toISOString() },
    { event_id: 'ev-021', agent_name: 'cve_lookup', action: 'cve_search', rationale: 'Pattern matched CVE-2021-44228 and CVE-2022-22965 with high confidence', confidence: 0.98, duration_ms: 410, timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString() },
    { event_id: 'ev-022', agent_name: 'asset_discovery', action: 'asset_resolve', rationale: 'Two Tier-1 API gateways identified as targets', confidence: 0.93, duration_ms: 230, timestamp: new Date(Date.now() - 13.5 * 60 * 1000).toISOString() },
    { event_id: 'ev-023', agent_name: 'planning', action: 'plan_generation', rationale: 'Generating patch + isolate plans given critical asset exposure', confidence: 0.96, duration_ms: 1560, timestamp: new Date(Date.now() - 13 * 60 * 1000).toISOString() },
    { event_id: 'ev-024', agent_name: 'executor', action: 'awaiting_approval', rationale: 'Destructive actions flagged — human approval required before execution', confidence: null, duration_ms: 4, timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString() },
  ],
  'a1b2c3d4-0003': [
    { event_id: 'ev-030', agent_name: 'orchestrator', action: 'alert_received', rationale: 'Brute force SSH alert from external IP', confidence: null, duration_ms: 11, timestamp: new Date(Date.now() - 1.9 * 60 * 60 * 1000).toISOString() },
    { event_id: 'ev-031', agent_name: 'cve_lookup', action: 'cve_search', rationale: 'No matching CVEs — generic brute force pattern', confidence: 0.60, duration_ms: 200, timestamp: new Date(Date.now() - 1.85 * 60 * 60 * 1000).toISOString() },
    { event_id: 'ev-032', agent_name: 'asset_discovery', action: 'asset_resolve', rationale: 'Resolved 10.0.0.5 to bastion-01 — Tier 1 DMZ host', confidence: 0.99, duration_ms: 95, timestamp: new Date(Date.now() - 1.8 * 60 * 60 * 1000).toISOString() },
    { event_id: 'ev-033', agent_name: 'planning', action: 'plan_generation', rationale: 'Automated IP block recommended given repeated attempts', confidence: 0.87, duration_ms: 620, timestamp: new Date(Date.now() - 1.75 * 60 * 60 * 1000).toISOString() },
    { event_id: 'ev-034', agent_name: 'executor', action: 'plan_approved', rationale: 'Plan approved by analyst — executing firewall block', confidence: null, duration_ms: 3, timestamp: new Date(Date.now() - 1.5 * 60 * 60 * 1000).toISOString() },
    { event_id: 'ev-035', agent_name: 'executor', action: 'firewall_block_applied', rationale: 'Firewall rule applied — 198.51.100.77 blocked for 24h', confidence: 0.99, duration_ms: 380, timestamp: new Date(Date.now() - 1.4 * 60 * 60 * 1000).toISOString() },
  ],
}

export const CVES = [
  { cve_id: 'CVE-2023-34362', cvss_v3_score: 9.8, severity: 'CRITICAL', affected_product: 'MOVEit Transfer', attack_vector: 'NETWORK', exploit_available: true, description: 'SQL injection vulnerability in MOVEit Transfer web application allowing unauthenticated attackers to gain access to the database.' },
  { cve_id: 'CVE-2021-44228', cvss_v3_score: 10.0, severity: 'CRITICAL', affected_product: 'Apache Log4j', attack_vector: 'NETWORK', exploit_available: true, description: 'Remote code execution vulnerability in Apache Log4j2 JNDI features. Allows an attacker who can control log messages to execute arbitrary code.' },
  { cve_id: 'CVE-2017-0144', cvss_v3_score: 8.1, severity: 'HIGH', affected_product: 'Microsoft SMBv1', attack_vector: 'NETWORK', exploit_available: true, description: 'The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets — exploited by EternalBlue/WannaCry.' },
  { cve_id: 'CVE-2022-22965', cvss_v3_score: 9.8, severity: 'CRITICAL', affected_product: 'Spring Framework', attack_vector: 'NETWORK', exploit_available: true, description: 'Spring4Shell: RCE vulnerability in Spring MVC running on JDK 9+ via data binding.' },
  { cve_id: 'CVE-2023-44487', cvss_v3_score: 7.5, severity: 'HIGH', affected_product: 'HTTP/2 Servers', attack_vector: 'NETWORK', exploit_available: false, description: 'HTTP/2 Rapid Reset Attack allowing denial-of-service via stream cancellation.' },
  { cve_id: 'CVE-2024-3400', cvss_v3_score: 10.0, severity: 'CRITICAL', affected_product: 'Palo Alto PAN-OS', attack_vector: 'NETWORK', exploit_available: true, description: 'OS command injection vulnerability in GlobalProtect feature of PAN-OS allowing unauthenticated RCE.' },
  { cve_id: 'CVE-2024-21762', cvss_v3_score: 9.6, severity: 'CRITICAL', affected_product: 'Fortinet FortiOS', attack_vector: 'NETWORK', exploit_available: true, description: 'Out-of-bounds write vulnerability in FortiOS allowing unauthenticated remote code execution via specially crafted HTTP requests.' },
  { cve_id: 'CVE-2023-20198', cvss_v3_score: 10.0, severity: 'CRITICAL', affected_product: 'Cisco IOS XE', attack_vector: 'NETWORK', exploit_available: true, description: 'Privilege escalation vulnerability in Cisco IOS XE web UI allowing unauthenticated attacker to create admin-level accounts.' },
  { cve_id: 'CVE-2022-1388', cvss_v3_score: 9.8, severity: 'CRITICAL', affected_product: 'F5 BIG-IP', attack_vector: 'NETWORK', exploit_available: true, description: 'Authentication bypass vulnerability in F5 BIG-IP iControl REST API allowing unauthenticated command execution.' },
  { cve_id: 'CVE-2023-27997', cvss_v3_score: 9.8, severity: 'CRITICAL', affected_product: 'Fortinet FortiGate', attack_vector: 'NETWORK', exploit_available: true, description: 'Heap-based buffer overflow in FortiOS SSL-VPN allowing remote unauthenticated attacker to execute arbitrary code.' },
  { cve_id: 'CVE-2024-1709', cvss_v3_score: 10.0, severity: 'CRITICAL', affected_product: 'ConnectWise ScreenConnect', attack_vector: 'NETWORK', exploit_available: true, description: 'Authentication bypass vulnerability allowing unauthenticated access to the setup wizard and creation of admin accounts.' },
  { cve_id: 'CVE-2023-46604', cvss_v3_score: 9.8, severity: 'CRITICAL', affected_product: 'Apache ActiveMQ', attack_vector: 'NETWORK', exploit_available: true, description: 'Remote code execution vulnerability in Apache ActiveMQ allowing attackers to execute shell commands via the OpenWire protocol.' },
]

export const ASSETS = [
  { id: 'asset-01', hostname: 'db-prod-01', ip_address: '10.0.1.15', zone_name: 'data', os: 'Ubuntu 22.04', asset_type: 'database', criticality_tier: 1 },
  { id: 'asset-02', hostname: 'app-server-03', ip_address: '10.0.1.20', zone_name: 'app', os: 'RHEL 9', asset_type: 'application', criticality_tier: 2 },
  { id: 'asset-03', hostname: 'bastion-01', ip_address: '10.0.0.5', zone_name: 'dmz', os: 'Ubuntu 22.04', asset_type: 'bastion', criticality_tier: 1 },
  { id: 'asset-04', hostname: 'workstation-12', ip_address: '10.0.2.88', zone_name: 'user', os: 'Windows 11', asset_type: 'workstation', criticality_tier: 3 },
  { id: 'asset-05', hostname: 'api-gateway-01', ip_address: '10.0.0.10', zone_name: 'dmz', os: 'Ubuntu 22.04', asset_type: 'gateway', criticality_tier: 1 },
  { id: 'asset-06', hostname: 'api-gateway-02', ip_address: '10.0.1.89', zone_name: 'dmz', os: 'Ubuntu 22.04', asset_type: 'gateway', criticality_tier: 1 },
  { id: 'asset-07', hostname: 'dc-prod-01', ip_address: '10.0.1.10', zone_name: 'core', os: 'Windows Server 2022', asset_type: 'domain_controller', criticality_tier: 1 },
  { id: 'asset-08', hostname: 'app-server-07', ip_address: '10.0.1.44', zone_name: 'app', os: 'Ubuntu 20.04', asset_type: 'application', criticality_tier: 2 },
  { id: 'asset-09', hostname: 'finance-ws-03', ip_address: '10.0.3.55', zone_name: 'finance', os: 'Windows 11', asset_type: 'workstation', criticality_tier: 2 },
  { id: 'asset-10', hostname: 'db-replica-01', ip_address: '10.0.1.16', zone_name: 'data', os: 'Ubuntu 22.04', asset_type: 'database', criticality_tier: 1 },
  { id: 'asset-11', hostname: 'monitoring-01', ip_address: '10.0.0.20', zone_name: 'ops', os: 'Ubuntu 22.04', asset_type: 'monitoring', criticality_tier: 2 },
  { id: 'asset-12', hostname: 'vpn-gateway-01', ip_address: '10.0.0.3', zone_name: 'dmz', os: 'Palo Alto PAN-OS', asset_type: 'firewall', criticality_tier: 1 },
]
