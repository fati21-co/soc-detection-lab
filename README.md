# soc-detection-lab
Simulation d’attaques MITRE Caldera et détection via Wazuh, Suricata, Sysmon et Kibana dans un laboratoire SOC.

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

