**# ðŸ›¡ï¸ AttackGuard v2 â€” SIEM & SOAR Automation Framework**



**\*\*AttackGuard v2\*\*** is a cybersecurity monitoring, detection, threat-intelligence, AI-assisted triage, and automated response framework designed for authorized security labs and controlled environments.



It combines endpoint telemetry, security event detection, incident correlation, MITRE ATT&CK mapping, threat intelligence, AI-assisted analysis, Telegram alerting, and automated firewall containment into a multi-node security monitoring architecture.



\> **\*\*Creator / Owner:\*\*** Shreyash Vidhate Â 

\> **\*\*Project:\*\*** AttackGuard v2 Â 

\> **\*\*Domain:\*\*** Cybersecurity / SIEM / SOAR / VAPT / Security Automation



**---**



**## âš ï¸ Disclaimer**



AttackGuard v2 is intended **\*\*strictly for authorized security testing, cybersecurity education, research, and controlled laboratory environments\*\***.



Do not deploy or use this project to monitor, scan, attack, block, access, or interfere with systems, networks, accounts, or devices without explicit authorization from the owner.



The creator is not responsible for misuse, unauthorized access, damage, disruption, data loss, or any illegal activity performed using this project.



**### Recommended environment**



Use AttackGuard v2 in:



\- Your own systems

\- Authorized penetration-testing environments

\- VMware/VirtualBox laboratories

\- Cybersecurity training labs

\- CTF environments where permitted

\- Systems for which you have explicit authorization



**---**



**# ðŸš€ Project Overview**



AttackGuard v2 follows a multi-node security monitoring architecture.



\`\`\`text

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â Attacker Kali Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â Nmap / SSH / Testing Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚ Authorized Testing

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â–¼

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Target Kali Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â agent.py Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Network Detection Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ SSH Monitoring Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Sudo Monitoring Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Kernel Monitoring Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Firewall Response Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚ Authenticated

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚ Telemetry

Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â–¼

Â  Â  Â  Â  Â  Â  Â  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Windows SIEM Server Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â run.py Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Flask API Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ SQLite Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Incident Correlation Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ MITRE ATT&CK Mapping Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Threat Intelligence Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ AI Threat Triage Â  Â  Â  Â  Â  Â  Â  Â  â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Telegram Alerts Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â”‚ â€¢ Web Dashboard Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

\`\`\`



**---**



**# âœ¨ Key Features**



**## ðŸ” Detection**



AttackGuard can monitor and detect security activity including:



\- TCP SYN scanning

\- UDP scanning

\- SSH brute-force activity

\- SSH authentication events

\- Sudo privilege activity

\- Kernel/network security events

\- Firewall containment events



**---**



**## ðŸ§  Incident Correlation**



AttackGuard correlates related security events into incidents instead of treating every event as an isolated alert.



Incident information can include:



\- Source IP

\- Target asset

\- Event count

\- First seen

\- Last seen

\- Severity

\- Attack chain

\- MITRE ATT&CK techniques

\- AI analysis

\- Threat-intelligence information

\- Incident status



**---**



**## ðŸ›¡ï¸ Automated SOAR Containment**



When configured detection conditions are triggered, AttackGuard can automatically perform firewall containment.



Example response:



\`\`\`text

Detection

Â  Â  â†“

Event Classification

Â  Â  â†“

Incident Correlation

Â  Â  â†“

Critical Severity

Â  Â  â†“

Automated Containment

Â  Â  â†“

Firewall IP Blocking

Â  Â  â†“

Telemetry Sent to SIEM

\`\`\`



The endpoint firewall can insert a blocking rule for the detected source IP.



**---**



**## ðŸ¤– AI-Assisted Threat Triage**



AttackGuard supports AI-assisted incident analysis through the Google Gemini API.



AI enrichment can help provide contextual analysis of incoming security incidents.



\> Users must provide their own Gemini API credentials.



No API key is included in this repository.



**---**



**## ðŸŒ Threat Intelligence**



AttackGuard includes a threat-intelligence module for enriching security events with external intelligence where configured.



Relevant information can be incorporated into incident analysis and investigation workflows.



**---**



**## ðŸ“± Telegram Critical Alerts**



AttackGuard can send Telegram notifications for critical security incidents.



Configuration requires:



\`\`\`text

TELEGRAM\_BOT\_TOKEN

TELEGRAM\_CHAT\_ID

\`\`\`



Users must create and configure their own Telegram bot.



No Telegram credentials are included in this repository.



**---**



**# ðŸ—ï¸ Architecture**



AttackGuard v2 consists of three logical components.



**## 1. Windows SIEM Command Center**



The Windows machine acts as the central monitoring server.



Responsibilities:



\- Flask API

\- Telemetry ingestion

\- SQLite persistence

\- Incident correlation

\- AI analysis

\- Threat intelligence

\- Alert routing

\- Dashboard

\- Incident investigation

\- CSV export



Main entry point:



\`\`\`text

run.py

\`\`\`



**---**



**## 2. Target Kali Linux Endpoint**



The Target Kali system runs the AttackGuard endpoint agent.



Main entry point:



\`\`\`text

agent.py

\`\`\`



The agent monitors security-relevant system activity and sends authenticated telemetry to the Windows SIEM server.



The agent can perform:



\- Network scan detection

\- UDP scan detection

\- SSH brute-force detection

\- SSH authentication monitoring

\- Sudo monitoring

\- Kernel event monitoring

\- Automated firewall containment

\- SIEM telemetry transmission



The agent requires root privileges for the relevant monitoring and firewall operations.



**---**



**## 3. Attacker Kali Linux**



A separate Kali Linux machine can be used as an authorized testing node.



It can generate controlled activity such as:



\`\`\`text

Nmap scans

SSH authentication attempts

UDP scanning

\`\`\`



The activity is detected by the Target Kali agent and forwarded to the SIEM.



**---**



**# ðŸ“ Project Structure**



\`\`\`text

Attackguard-v2/

â”‚

â”œâ”€â”€ .gitignore

â”œâ”€â”€ agent.py

â”œâ”€â”€ config.py

â”œâ”€â”€ README.md

â”œâ”€â”€ requirements.txt

â”œâ”€â”€ run.py

â”‚

â”œâ”€â”€ core/

â”‚ Â  â”œâ”€â”€ database.py

â”‚ Â  â”œâ”€â”€ ingestion.py

â”‚ Â  â””â”€â”€ \_\_init\_\_.py

â”‚

â”œâ”€â”€ modules/

â”‚ Â  â”œâ”€â”€ ai\_analyst.py

â”‚ Â  â”œâ”€â”€ alert\_router.py

â”‚ Â  â”œâ”€â”€ threat\_intel.py

â”‚ Â  â””â”€â”€ \_\_init\_\_.py

â”‚

â””â”€â”€ templates/

Â  Â  â”œâ”€â”€ dashboard.html

Â  Â  â”œâ”€â”€ dashboard1 - Copy.html

Â  Â  â”œâ”€â”€ dashboard2.html

Â  Â  â””â”€â”€ dashboard3.html

\`\`\`



**### Important files**



\| File | Purpose |

\|---|---|

\| \`run.py\` | Starts the Windows SIEM server |

\| \`agent.py\` | Endpoint monitoring and response agent |

\| \`config.py\` | Environment-based configuration |

\| \`core/database.py\` | Database and incident management |

\| \`core/ingestion.py\` | Telemetry ingestion and processing |

\| \`modules/ai\_analyst.py\` | AI-assisted security analysis |

\| \`modules/alert\_router.py\` | Alert routing and notifications |

\| \`modules/threat\_intel.py\` | Threat intelligence enrichment |

\| \`templates/dashboard.html\` | SIEM web dashboard |

\| \`requirements.txt\` | Python dependencies |



**---**



**# ðŸ’» Requirements**



**## Windows SIEM**



Recommended:



\- Windows 10/11

\- Python 3.11+

\- Git

\- Network connectivity to the Target Kali machine

\- Google Gemini API key (optional)

\- Telegram Bot credentials (optional)



**---**



**## Kali Linux Agent**



Recommended:



\- Kali Linux

\- Python 3

\- Root/sudo privileges

\- Git

\- Network connectivity to the Windows SIEM server



**---**



**# ðŸ“¥ Installation**



AttackGuard v2 uses **\*\*one GitHub repository\*\***.



The repository can be cloned separately on the Windows SIEM machine and Kali endpoint.



**---**



**# ðŸªŸ Setup 1 â€” Windows SIEM Server**



**## Step 1 â€” Clone the repository**



Open PowerShell:



\`\`\`powershell

git clone https\://github.com/shreyash-vidhate/AttackGuard-v2.git

cd AttackGuard-v2

\`\`\`



Replace:



\`\`\`text

shreyash-vidhate

\`\`\`



with the GitHub account that hosts the repository.



**---**



**## Step 2 â€” Create a virtual environment**



\`\`\`powershell

python -m venv .venv

\`\`\`



Activate it:



\`\`\`powershell

.\\.venv\Scripts\Activate.ps1

\`\`\`



If PowerShell blocks activation, you can alternatively run Python directly from the virtual environment.



**---**



**## Step 3 â€” Install dependencies**



\`\`\`powershell

pip install -r requirements.txt

\`\`\`



**---**



**# ðŸ” Windows Configuration**



AttackGuard uses environment variables instead of storing API keys directly in source code.



Configure the following variables according to the features you want to use.



**### Required SIEM authentication**



\`\`\`powershell

$env:ATTACKGUARD\_TOKEN="YOUR\_OWN\_ATTACKGUARD\_TOKEN"

\`\`\`



**### Gemini AI**



\`\`\`powershell

$env:GEMINI\_API\_KEY="YOUR\_OWN\_GEMINI\_API\_KEY"

\`\`\`



**### Telegram**



\`\`\`powershell

$env:TELEGRAM\_BOT\_TOKEN="YOUR\_OWN\_TELEGRAM\_BOT\_TOKEN"

$env:TELEGRAM\_CHAT\_ID="YOUR\_OWN\_TELEGRAM\_CHAT\_ID"

\`\`\`



**### Optional server configuration**



\`\`\`powershell

$env:ATTACKGUARD\_HOST="0.0.0.0"

$env:ATTACKGUARD\_PORT="5000"

$env:ATTACKGUARD\_DEBUG="false"

\`\`\`



\> **\*\*Never commit real API keys, bot tokens, chat IDs, passwords, or authentication tokens to GitHub.\*\***



**---**



**# â–¶ï¸ Start the Windows SIEM**



From the project directory:



\`\`\`powershell

python run.py

\`\`\`



The Flask server listens on the configured port.



Default:



\`\`\`text

http\://0.0.0.0:5000

\`\`\`



For a browser on the Windows machine, use:



\`\`\`text

http\://127.0.0.1:5000

\`\`\`



For another authorized machine on the same lab network, use:



\`\`\`text

http\://\<WINDOWS-SIEM-IP>:5000

\`\`\`



**---**



**# ðŸ‰ Setup 2 â€” Kali Linux Agent**



The Kali endpoint uses the **\*\*same GitHub repository\*\***.



Open a terminal on the Target Kali machine:



\`\`\`bash

git clone https\://github.com/shreyash-vidhate/AttackGuard-v2.git

cd AttackGuard-v2

\`\`\`



**---**



**## Install Python dependencies**



\`\`\`bash

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt

\`\`\`



If your environment requires system-level packages, install them according to your Kali configuration.



**---**



**# ðŸ” Configure the Kali Agent**



The agent uses environment variables for the SIEM destination and authentication token.



Set the Windows SIEM address:



\`\`\`bash

export ATTACKGUARD\_SIEM\_URL="http\://\<WINDOWS-SIEM-IP>:5000/ingest"

\`\`\`



Set the same authentication token configured on the SIEM:



\`\`\`bash

export ATTACKGUARD\_TOKEN="YOUR\_OWN\_ATTACKGUARD\_TOKEN"

\`\`\`



Verify:



\`\`\`bash

echo $ATTACKGUARD\_SIEM\_URL

echo $ATTACKGUARD\_TOKEN

\`\`\`



Do not publish the token.



**---**



**# â–¶ï¸ Start the Kali Agent**



The agent performs monitoring and firewall-related operations that require elevated privileges.



Run:



\`\`\`bash

sudo -E python3 agent.py

\`\`\`



Using \`-E\` allows the configured environment variables to be preserved when running through \`sudo\`.



**---**



**# ðŸ”— Connecting the Two Nodes**



The Windows SIEM and Target Kali must be able to communicate over the lab network.



Example topology:



\`\`\`text

Windows SIEM

Â  Â  Â â”‚

Â  Â  Â â”‚ TCP/5000

Â  Â  Â â”‚

Â  Â  Â â–¼

Target Kali

Â  Â  Â â–²

Â  Â  Â â”‚

Â  Â  Â â”‚ Authorized testing traffic

Â  Â  Â â”‚

Attacker Kali

\`\`\`



Use your own private lab IP addresses.



Do **\*\*not\*\*** copy private lab addresses from screenshots or examples into your production configuration.



**---**



**# ðŸ–¥ï¸ VMware Lab Setup**



AttackGuard can be demonstrated using a VMware-based laboratory.



Recommended logical setup:



\`\`\`text

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

â”‚ Â  Â Windows Host Â  Â  Â â”‚

â”‚ Â  Â  Â  Â  Â  Â  Â  Â  Â  Â  Â â”‚

â”‚ Â AttackGuard SIEM Â  Â â”‚

â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Â  Â  Â  Â  Â  Â â”‚

Â  Â  Â  Virtual Network

Â  Â  Â  Â  Â  Â â”‚

Â  Â  â”Œâ”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”

Â  Â  â”‚ Â  Â  Â  Â  Â  Â  Â â”‚

Â  Â  â–¼ Â  Â  Â  Â  Â  Â  Â â–¼

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â” Â  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

â”‚ Attackerâ”‚ Â  â”‚ Target Kali â”‚

â”‚ Â Kali Â  â”‚ Â  â”‚ Â  Â  Â  Â  Â  Â  â”‚

â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ Â  â”‚ agent.py Â  Â â”‚

Â  Â  Â  Â  Â  Â  Â  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

\`\`\`



The exact IP addresses depend on the user's VMware network configuration.



Recommended network isolation:



\- Host-only network for isolated demonstrations

\- NAT where Internet access is required

\- Avoid exposing the SIEM or test endpoint directly to the public Internet



**---**



**# ðŸ§ª Authorized Testing Workflow**



Once the Windows SIEM and Target Kali agent are running:



\`\`\`text

1\. Start Windows SIEM

Â  Â  Â  Â  â†“

2\. Start Target Kali agent

Â  Â  Â  Â  â†“

3\. Verify telemetry connectivity

Â  Â  Â  Â  â†“

4\. Generate authorized test activity

Â  Â  Â  Â  â†“

5\. Agent detects activity

Â  Â  Â  Â  â†“

6\. Telemetry is authenticated

Â  Â  Â  Â  â†“

7\. SIEM ingests event

Â  Â  Â  Â  â†“

8\. Incident is classified

Â  Â  Â  Â  â†“

9\. Events are correlated

Â  Â  Â  Â  â†“

10\. Threat intelligence enrichment

Â  Â  Â  Â  â†“

11\. AI analysis

Â  Â  Â  Â  â†“

12\. Critical alert / containment

Â  Â  Â  Â  â†“

13\. Dashboard investigation

\`\`\`



**---**



**# ðŸ”Ž Example Detection Scenarios**



**## TCP SYN Scan**



An authorized Nmap SYN scan can be used in the lab to generate network reconnaissance activity.



Example:



\`\`\`bash

sudo nmap -sS \<TARGET-IP>

\`\`\`



The Target Kali agent can detect the resulting network activity and send telemetry to the SIEM.



**---**



**## UDP Scan**



Example controlled test:



\`\`\`bash

sudo nmap -sU \<TARGET-IP>

\`\`\`



The agent can identify repeated UDP scan activity and forward the detection.



**---**



**## SSH Brute-Force Simulation**



Only perform this against a system you own or are explicitly authorized to test.



A controlled series of SSH authentication failures can be used to validate the SSH detection logic.



**---**



**# ðŸ›¡ï¸ Automated Containment**



When configured detection conditions trigger automated response, AttackGuard can perform firewall containment on the monitored endpoint.



Conceptually:



\`\`\`text

Suspicious Source

Â  Â  Â  Â â†“

Detection

Â  Â  Â  Â â†“

Classification

Â  Â  Â  Â â†“

CRITICAL Incident

Â  Â  Â  Â â†“

SOAR Response

Â  Â  Â  Â â†“

Firewall Block

Â  Â  Â  Â â†“

Telemetry

Â  Â  Â  Â â†“

SIEM Dashboard

\`\`\`



This demonstrates the integration of:



\`\`\`text

Detection + Correlation + Response + Investigation

\`\`\`



**---**



**# ðŸ§  MITRE ATT&CK Mapping**



AttackGuard associates detected activity with relevant MITRE ATT&CK techniques where supported by the event classification logic.



Examples include:



\`\`\`text

T1046

Network Service Scanning



T1110.001

Password Guessing



T1078

Valid Accounts



T1548.003

Sudo and Sudo Caching

\`\`\`



The exact technique associated with an incident depends on the event classification and observed activity.



**---**



**# ðŸ“Š SIEM Dashboard**



The dashboard provides visibility into security telemetry and incidents.



Typical investigation information includes:



\- Event counts

\- Incident counts

\- Severity

\- Source IP

\- Target asset

\- Attack chain

\- MITRE ATT&CK techniques

\- Incident status

\- Threat intelligence

\- AI analysis

\- Forensic information

\- CSV export



**---**



**# ðŸ“¸ Proof of Work**



The following screenshots demonstrate AttackGuard v2 operating in an **authorized laboratory environment**. The screenshots have been sanitized to remove private lab identifiers and credentials.



**## SIEM Dashboard & Incident Correlation**



![AttackGuard SIEM Dashboard](screenshots/01-siem-dashboard-incident.png)



The dashboard demonstrates security telemetry, severity analytics, incident correlation, attack-chain visualization, MITRE ATT&CK mapping, threat-intelligence enrichment, and AI-assisted threat triage.



**## Detection & Automated SOAR Containment**



![AttackGuard Detection and SOAR Containment](screenshots/02-detection-soar-containment.png)



This demonstrates endpoint network-scan detection, automated firewall containment, and successful authenticated telemetry delivery to the SIEM.



**## Critical Telegram Alert**



![AttackGuard Telegram Critical Alert](screenshots/03-telegram-critical-alert.png)



This demonstrates critical incident notification through the configured Telegram alerting workflow.



> **Security note:** Never publish API keys, authentication tokens, Telegram bot tokens, passwords, private keys, or other sensitive credentials in screenshots or repository files.



**---**



**# ðŸ“± Telegram Alerting**



For configured Telegram integration, critical incidents can generate notifications.



Required:



\`\`\`text

TELEGRAM\_BOT\_TOKEN

TELEGRAM\_CHAT\_ID

\`\`\`



Create and configure your own Telegram bot.



Never publish:



\- Bot token

\- Chat ID if considered sensitive in your environment

\- API credentials

\- Screenshots containing credentials



**---**



**# ðŸ¤– Gemini AI Configuration**



AI-assisted analysis requires a Google Gemini API key.



Configure:



\`\`\`powershell

$env:GEMINI\_API\_KEY="YOUR\_OWN\_GEMINI\_API\_KEY"

\`\`\`



The project does not provide API credentials.



Users are responsible for:



\- Creating their own API account

\- Obtaining their own API key

\- Following the provider's terms

\- Managing API usage and limits

\- Keeping credentials private



**---**



**# ðŸ”‘ Security Configuration**



AttackGuard uses environment variables for sensitive configuration.



Do not hard-code:



\`\`\`text

API keys

Authentication tokens

Telegram bot tokens

Passwords

Private credentials

\`\`\`



Before publishing:



\`\`\`text

âœ” Remove databases

âœ” Remove logs

âœ” Remove credentials

âœ” Remove .env files

âœ” Remove virtual environments

âœ” Remove \_\_pycache\_\_

âœ” Review Git history

âœ” Review screenshots

\`\`\`



**---**



**# ðŸš« What Should Never Be Committed**



Never commit files containing:



\`\`\`text

.env

.env.\*

\*.db

\*.sqlite

\*.log

API keys

Bot tokens

Passwords

Private SSH keys

Private certificates

Personal credentials

\`\`\`



The included \`.gitignore\` is configured to exclude common local secrets, databases, logs, virtual environments, and development artifacts.



**---**



**# ðŸ§¹ Public Repository Hygiene**



Before pushing AttackGuard v2 to GitHub, verify:



\`\`\`powershell

git status

\`\`\`



Review every file shown by Git.



Then check:



\`\`\`powershell

git diff

\`\`\`



Make sure no credentials or private lab information are present.



If credentials were previously exposed anywhere, rotate them before public release.



**---**



**# ðŸ“¦ GitHub Repository Setup**



Initialize the repository:



\`\`\`bash

git init

\`\`\`



Add the files:



\`\`\`bash

git add .

\`\`\`



Review what will be committed:



\`\`\`bash

git status

\`\`\`



Create the first commit:



\`\`\`bash

git commit -m "Initial AttackGuard v2 release"

\`\`\`



Connect your GitHub repository:



\`\`\`bash

git remote add origin https\://github.com/shreyash-vidhate/AttackGuard-v2.git

\`\`\`



Push:



\`\`\`bash

git branch -M main

git push -u origin main

\`\`\`



**---**



**# ðŸ”„ Using the Repository on Multiple Machines**



The same repository is intentionally used for both components.



**### Windows SIEM**



\`\`\`bash

git clone https\://github.com/shreyash-vidhate/AttackGuard-v2.git

\`\`\`



Run:



\`\`\`text

run.py

\`\`\`



**### Kali Agent**



\`\`\`bash

git clone https\://github.com/shreyash-vidhate/AttackGuard-v2.git

\`\`\`



Run:



\`\`\`text

agent.py

\`\`\`



The difference is the **\*\*role of the machine\*\***, not a different repository.



**---**



**# ðŸ§© Technology Stack**



AttackGuard v2 uses:



\- Python

\- Flask

\- SQLite

\- Linux/Kali

\- Windows

\- iptables

\- Google Gemini API

\- Telegram Bot API

\- VMware

\- MITRE ATT&CK concepts

\- Security telemetry

\- Threat intelligence

\- Automated response



**---**



**# ðŸŽ¯ Security Engineering Concepts Demonstrated**



This project demonstrates practical concepts across:



**### Blue Team**



\- Security monitoring

\- Event detection

\- Incident correlation

\- Threat intelligence

\- Alerting

\- Incident investigation

\- Automated response



**### Red Team / VAPT Lab**



\- Network reconnaissance

\- Port scanning

\- SSH authentication testing

\- Controlled attack simulation



**### Security Engineering**



\- Endpoint telemetry

\- Authenticated API communication

\- SQLite persistence

\- Incident lifecycle

\- MITRE ATT&CK mapping

\- SOAR containment

\- AI-assisted triage



**---**






**# âš ï¸ Production Security Notice**



AttackGuard v2 is primarily a security research, education, and controlled laboratory project.



Before considering production deployment, additional hardening should be performed, including where appropriate:



\- HTTPS/TLS

\- Strong authentication

\- Secure secret management

\- API rate limiting

\- Network segmentation

\- Access control

\- Centralized secure logging

\- Database hardening

\- Input validation

\- Secure deployment configuration

\- Monitoring of the SIEM itself



Do not expose the development Flask server directly to the public Internet.



**---**



**# ðŸ¤ Contributions**



Contributions, improvements, bug reports, detection ideas, and security engineering suggestions are welcome.



When contributing:



1\. Do not submit credentials.

2\. Do not submit private logs.

3\. Do not submit private IP information unnecessarily.

4\. Do not submit database files.

5\. Test changes in an authorized environment.

6\. Clearly document security-impacting changes.



**---**



**# ðŸ‘¨â€ðŸ’» Creator**



**## Shreyash Vidhate**



**\*\*Creator / Owner â€” AttackGuard v2\*\***



Cybersecurity | VAPT | SIEM | SOAR | Security Automation



This project was developed as a practical cybersecurity engineering and security operations laboratory project.



**---**



**# ðŸ“œ License**



Choose and add an appropriate open-source license before publishing the repository.



For example:



\`\`\`text

MIT License

\`\`\`



If an MIT License is selected, include the complete \`LICENSE\` file in the repository.



**---**



**# â­ Project Goals**



AttackGuard v2 is designed to demonstrate how multiple security capabilities can be combined into a single security monitoring workflow:



\`\`\`text

Endpoint Monitoring

Â  Â  Â  Â  +

Detection Engineering

Â  Â  Â  Â  +

Incident Correlation

Â  Â  Â  Â  +

Threat Intelligence

Â  Â  Â  Â  +

MITRE ATT&CK

Â  Â  Â  Â  +

AI-Assisted Triage

Â  Â  Â  Â  +

Alerting

Â  Â  Â  Â  +

Automated Containment

Â  Â  Â  Â  =

AttackGuard v2

\`\`\`



**---**



**## âš ï¸ Final Reminder**



**\*\*Use AttackGuard v2 only on systems and networks you own or have explicit authorization to test.\*\***



Security testing should always be performed within the scope of the applicable authorization and rules of engagement.



**\*\*Created by Shreyash Vidhate\*\***
