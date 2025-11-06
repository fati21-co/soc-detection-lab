# Rapport d'incident – Simulation Discovery (MITRE ATT&CK)

**Titre :** Simulation d'activités Discovery sur machine Windows via Caldera  
**Date d’exécution :** YYYY-MM-DD  
**Environnement :** SOC Detection Lab – Purple Team  
**Rédigé par :** Fatima Zahra EL MOUCHARDAL

---

## 1. Contexte & Objectif

Une opération de Purple Team a été menée afin d’évaluer la capacité du SOC à détecter des actions de reconnaissance exécutées sur un poste Windows compromis.

L’attaquant simulé (Caldera / Sandcat) a exécuté plusieurs techniques de découverte système et processus.  
L’objectif du rapport est de :

- lister les actions exécutées ;
- valider la détection par Sysmon + Wazuh ;
- vérifier le mapping MITRE ATT&CK ;
- identifier les améliorations possibles.

---

## 2. Infrastructure concernée

| Composant | Rôle | IP |
|-----------|------|----|
| Kali Linux (Caldera) | Attacker / C2 | 192.168.100.96 |
| Windows 10 | Victime / Agent Sandcat | 192.168.100.120 |
| Wazuh Manager + ELK | SIEM / Dashboards | 192.168.100.50 |
| pfSense + Suricata | Pare-feu & IDS réseau | 192.168.100.1 |

---

## 3. Techniques MITRE simulées

| Technique | ID | Description |
|-----------|----|-------------|
| System Information Discovery | T1082 | Récupération infos système, OS, hostname, etc. |
| Process Discovery | T1057 | Récupération liste des processus actifs |

L’adversaire utilisé dans Caldera : **win-discovery-minimal**

---

## 4. Chronologie de l’exercice

| Heure | Action |
|-------|--------|
| 10:03 | Exécution du script `deploy-sandcat.ps1` sur Windows (PowerShell admin) |
| 10:04 | L’agent apparaît dans Caldera (`alive`, elevated) |
| 10:06 | Démarrage de l’opération `win-discovery-minimal` |
| 10:06–10:07 | Exécution des TTP Discovery |
| 10:07+ | Sysmon journalise les événements → Wazuh détecte → Kibana affiche les alertes |

---

## 5. Détection & preuves

### ✅ Sysmon
Les événements suivants ont été observés :

- `Event ID 1` — Process Create (powershell.exe, sandcat.exe)
- `Event ID 3` — Network Connection (communication agent ↔ C2)
- `Event ID 7` — Image loaded (.dll)
- `Event ID 11` — File Create (binaire Sandcat)

Configuration utilisée : **sysmonconfig-export.xml** (base SwiftOnSecurity)

---

### ✅ Wazuh & MITRE ATT&CK
Les alertes suivantes ont été générées :

| Timestamp | Agent | MITRE ID | Description |
|-----------|-------|----------|-------------|
| 2025-08-08 22:57:21 | fati | **T1078** | Windows Logon Success |
| 2025-08-08 22:51:45 | fati | **T1082** | System Information Discovery |
| 2025-08-08 22:51:43 | fati | **T1057** | Process Discovery |

Total des événements corrélés : ~300–400 selon filtres Kibana.

Dashboard : `MITRE ATT&CK – Wazuh`  
Filtre : `agent.name:"fati"`

---

### ✅ Kibana – Analyse visuelle

- Histogramme des événements sur la timeline
- Liste des règles déclenchées
- Mapping tactile MITRE
- Agent, processus, et description des alertes

*Voir screenshots dans le dossier `/screenshots/`.*

---

## 6. Résultats

| Élément validé | Status |
|----------------|--------|
| Agent Sandcat fonctionnel | ✅ |
| Exécution des TTP Discovery | ✅ |
| Logs Windows collectés via Sysmon | ✅ |
| Envoi logs → Wazuh Manager | ✅ |
| Détection & mapping MITRE dans Kibana | ✅ |

L’ensemble de la chaîne **attaque → collecte → corrélation → visibilité** est opérationnelle.

---

## 7. Points d’amélioration

| Amélioration | Pourquoi ? |
|--------------|------------|
| Activer Script Block Logging PowerShell | Détection plus fine des commandes offensives |
| Ajouter règles Suricata ciblées Sandcat | Visibilité réseau supplémentaire |
| Parse eve.json via Filebeat → ELK | Corrélation réseau + endpoint |
| Ajouter TTP supplémentaires (Credential Access, Lateral Movement, Exfiltration) | Étendre la couverture MITRE |
| Playbooks SOC (réponse automatisée) | Industrialisation de la détection |

---

## 8. Conclusion

Le SOC a été capable de détecter avec succès les activités Discovery exécutées via l’agent Sandcat sur la machine Windows.  
Les alertes ont été correctement corrélées et présentées dans Kibana, avec mapping MITRE ATT&CK.  
Le pipeline de collecte fonctionne et peut servir de base pour des campagnes Red Team plus complexes.

✅ Objectif atteint.  
🔧 Prochaines étapes : durcissement, enrichissement des règles, automatisation.

---

## 9. Annexes

- `deploy-sandcat.ps1`  
- `install-sysmon.ps1`  
- `install-wazuh-agent.ps1`  
- `sysmonconfig-export.xml`  
- Screenshots : `operation-graph.png`, `kibana-mitre.png`, `sysmon-installed.png`
