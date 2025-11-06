# SOC Detection Lab – Purple Team Simulation

**Auteur :** Fatima Zahra EL MOUCHARDAL  
**Contact :** elmouchardalfatimazahraa@gmail.com

---

## Table of Contents

1. [Description](#description)  
2. [Objectifs](#objectifs)  
3. [Architecture du laboratoire](#architecture-du-laboratoire)  
4. [Contenu du dépôt](#contenu-du-dépôt)  
5. [Prérequis](#prérequis)  
6. [Topologie & IPs d'exemple](#topologie--ips-dexemple)  
7. [VMs : ressources & configuration recommandée](#vms--ressources--configuration-recommandée)  
8. [Configuration pfSense & Suricata (détaillée)](#configuration-pfsense--suricata-détaillée)  
9. [Caldera (Kali) : installation et utilisation](#caldera-kali--installation-et-utilisation)  
10. [VM Windows (victime) : scripts et déploiement](#vm-windows-victime--scripts-et-déploiement)  
11. [Wazuh Manager & ELK : points clés](#wazuh-manager--elk--points-clés)  
12. [Exécution : déroulé recommandé (checklist)](#exécution--déroulé-recommandé-checklist)  
13. [Validation / preuves de détection](#validation--preuves-de-détection)  
14. [Reports & exemples (template)](#reports--exemples-template)  
15. [Améliorations possibles](#améliorations-possibles)  
16. [Sécurité, éthique & snapshots](#sécurité-éthique--snapshots)  
17. [Annexes : commandes utiles & références rapides](#annexes--commandes-utiles--références-rapides)

---

## Description

Ce laboratoire simule des attaques MITRE ATT&CK avec **Caldera** (Kali), collecte la télémétrie Windows via **Sysmon**, détecte / corrèle via **Wazuh** et visualise les résultats dans **Kibana/ELK**. pfSense + Suricata fournissent la visibilité réseau.  
L’objectif : démontrer la chaîne complète **Simulation → Visibilité → Détection → Analyse → Rapport**.

---

## Objectifs

- Déployer un lab Purple Team complet et reproductible.  
- Exécuter des TTPs (ex. Discovery) via Caldera/Sandcat.  
- Capturer logs Windows (Sysmon) et logs réseau (Suricata).  
- Détecter via Wazuh / rules & dashboards (Kibana).  
- Produire un rapport d’investigation orienté MITRE ATT&CK.

---

## Architecture du laboratoire

KALI (Caldera, File Server) ---> pfSense (LAN) ---> Windows Victime (Sandcat, Sysmon, Wazuh Agent)
|
+--> Wazuh Manager (ELK / Kibana)
|
+--> (optionnel) Collector / Filebeat pour Suricata

## Contenu du dépôt

/ (root)
├── README.md
├── LICENSE
├── powershell-scripts/
│ ├── deploy-sandcat.ps1
│ ├── install-sysmon.ps1
│ ├── install-wazuh-agent.ps1
│ └── run_all_lab_setup.ps1
├── configs/
│ └── sysmonconfig-export.xml (optionnel: SwiftOnSecurity)
├── reports/
│ └── incident-report-discovery.md
└── screenshots/
├── caldera-login.png
├── caldera-agent.png
├── caldera-adversary.png
├── operation-graph.png
├── sysmon-installed.png
└── kibana-mitre.png


---

## Prérequis

- Hôte capable de faire tourner plusieurs VMs (16–32 GB RAM recommandé).  
- Virtualisation : VirtualBox / VMware / Proxmox.  
- Images/VMs : Kali Linux (Caldera), Windows 10, pfSense, Wazuh Manager (ELK).  
- Accès administrateur sur la VM Windows victime.  
- Réseau isolé (internal network / host-only) pour le lab.

---

## Topologie & IPs d'exemple

- **pfSense (LAN)** : `192.168.100.1/24`  
- **Kali (Caldera)** : `192.168.100.96`  
- **Wazuh Manager / ELK** : `192.168.100.50`  
- **Windows Victime** : `192.168.100.120`

Assure-toi que les IPs sont statiques ou configurées en DHCP static mapping.

---

## VMs : ressources & configuration recommandée

### pfSense
- CPU : 1–2 vCPU  
- RAM : 1–2 GB  
- Disk : 8–16 GB  
- Interfaces : WAN (NAT/Bridge) + LAN (Host-only/Internal)

### Kali (Attacker / Caldera)
- CPU : 2 vCPU  
- RAM : 4–6 GB  
- Disk : 40 GB  
- Installer Python3, pip, virtualenv, Caldera

### Wazuh Manager + ELK (SIEM)
- CPU : 4 vCPU (min)  
- RAM : 8–12 GB (Elasticsearch gourmand)  
- Disk : 60–100 GB (SSD recommandé)

### Windows 10 (Victime)
- CPU : 2 vCPU  
- RAM : 4 GB  
- Disk : 40 GB  
- Activer PowerShell en admin, Sysmon, Wazuh Agent

---

## Configuration pfSense & Suricata (détaillée)

### 1) Accès GUI
- Accéder à `http://<pfSense-LAN-IP>` (ex : `http://192.168.100.1`) depuis une machine du LAN.

### 2) AssignInterfaces / IPs via console
- Dans console pfSense, option `2` → Set interface(s) IP address. Exemple pour LAN :
  - Interface: `em1`  
  - IPv4: `192.168.100.1/24`  
  - DHCP : disable (si IP statique)

### 3) Installer Suricata
- GUI → `System > Package Manager > Available Packages` → Rechercher `suricata` → Install.

### 4) Configurer Suricata sur LAN
- `Services > Suricata > Interfaces` → Edit `LAN` (em1) :
  - Enable : checked
  - Operation mode : `alert` (pour commencer)
  - Rules selection : activer catégories pertinentes (ET PRO, DNS, SMB, HTTP)
  - JSON / EVE output : activer **EVE JSON** et définir un chemin (ex : `/var/log/suricata/eve.json`) si disponible
  - Save & Apply

### 5) Forward logs vers Wazuh
- Option A — **Remote Syslog** :
  - GUI → `System > Advanced > Logging` (ou `Status > System Logs > Settings`)  
  - Remote syslog server : `192.168.100.50` (Wazuh) ; port `514` UDP/TCP
- Option B — **Collector** :
  - Installer Filebeat sur une VM collector qui lit `eve.json` puis envoie vers Wazuh/ELK via Filebeat module Suricata.

### 6) Firewall rules
- `Firewall > Rules > LAN` :
  - Allow Kali → Windows (TCP 8888)  
  - Allow Windows → Wazuh agent/manager (ports agent-auth, syslog, etc.)
- `NAT` : vérifier si Internet access via WAN est nécessaire.

---

## Caldera (Kali) : installation et utilisation

### Installer Caldera (si non installé)
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/mitre/caldera.git ~/caldera
cd ~/caldera
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# initial setup selon doc Caldera
python server.py --insecure 
```  
### Lancer & utiliser UI

Lancer : `python server.py --insecure`
Accéder UI : `http://<kali-ip>:8888`
Créer adversary : `Adversaries → new profile` (ex: `win-discovery-minimal`)
Déployer agent Sandcat : `Agents → Deploy → choisir platform Windows → copier script / télécharger binaire`

## VM Windows (victime) : scripts et déploiement
### Scripts fournis (dans `powershell-scripts/`)

`deploy-sandcat.ps1` — télécharge et lance l'agent Sandcat depuis Caldera.
`install-sysmon.ps1` — télécharge Sysmon, applique une config (SwiftOnSecurity) et installe.
`install-wazuh-agent.ps1` — installe l'agent Wazuh Windows et tente l’enregistrement auprès du manager.
`run_all_lab_setup.ps1` — script maître qui exécute les étapes ci-dessus dans l’ordre.
Important : exécuter PowerShell en mode Administrateur. Adapter les variables `$CalderaServer` et `$WazuhManagerIP` dans les scripts avant exécution.

### Exemple d’exécution (PowerShell admin)

```bash
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\deploy-sandcat.ps1 -CalderaServer "http://192.168.100.96:8888" -OutPath "C:\Users\Public\sandcat.exe"
.\install-sysmon.ps1
.\install-wazuh-agent.ps1 -WazuhManagerIP "192.168.100.50"
```

### Vérifications post-install

Sysmon : Event Viewer → `Applications and Services Logs → Microsoft → Windows → Sysmon/Operational`.
Wazuh Agent : vérifier sur Wazuh Manager la présence de l’agent (nom/ID).
Sandcat : vérifier processus (`tasklist` / `Get-Process`) et agent visible dans Caldera.

## Wazuh Manager & ELK : points clés
### Installation (lab)

- Option simple : docker-compose Wazuh all-in-one (doc officielle).
- Ou VM Ubuntu Server + installation native (Wazuh Manager, Elasticsearch, Kibana).

### Vérifier :

- Elasticsearch reachable (9200)
- Kibana reachable (5601)
- Wazuh Manager écoute agents (ports 1514/1515 selon config)

### Mapping & dashboards

- Index pattern : `wazuh-*`
- Importer dashboards MITRE / Wazuh si disponible.
- Vérifier règles déclenchées via l’interface Wazuh / Kibana (filtrer `agent.name`).

## Exécution : déroulé recommandé (checklist)

1- Vérifier connectivité réseau entre VMs (ping).

2- Démarrer pfSense (interfaces & Suricata configurés).

3- Démarrer Wazuh Manager (ELK).

4- Démarrer Kali → Lancer Caldera (`python server.py --insecure`).

5- Sur Windows (PowerShell admin) : lancer scripts (`deploy-sandcat`, `install-sysmon`, `install-wazuh-agent`).

6- Dans Caldera : vérifier agent `alive` / `trusted` / `elevated`.

7- Créer Operation → choisir `win-discovery-minimal` → Start.

8- Sur Wazuh / Kibana : filtrer `agent.name:"fati"` / `rule.mitre.id` pour voir alertes.

9- Capturer preuves (screenshots, export Kibana, export logs).

## Validation / preuves de détection

- Caldera : Operations → statut `success` / `failed` / `collect` pour chaque ability.
- Windows / Sysmon : événements `Process Create`, `Network Connect`, `Logon` dans Sysmon/Operational.
- Wazuh / Kibana : hits (ex : plusieurs centaines), mapping MITRE ATT&CK visible, règles déclenchées (`rule.mitre.id` exemples : T1057, T1082…).
- Suricata : événements réseau (HTTP, SMB, DNS) si EVE/forward configuré.
