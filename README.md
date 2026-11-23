# Auditeur de Résilience HTTP/2 & Crash de Noyau Linux - TAVARDT France

> Audit de Résilience contre NoisyTCP, Rapid Reset (CVE-2023-44487) et Durcissement de Serveurs Web

[![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Active-brightgreen)](https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: CIS Linux](https://img.shields.io/badge/Security-CIS%20Linux%20%7C%20RFC%209113-red.svg)](https://www.cisecurity.org/)

## Vue d'Ensemble de l'Architecture et Résilience HTTP/2 & Noyau Linux

La stabilité et la résilience opérationnelle des infrastructures web d'entreprise reposent sur l'ajustement rigoureux de la pile TCP du noyau Linux et des moteurs de multiplexage HTTP/2.

Deux vecteurs majeurs menacent les architectures non sécurisées:
1. **Vulnérabilité NoisyTCP du Noyau Linux:** Des séquences TCP anormales provoquent une allocation incontrôlée de mémoire dans les files du noyau, entraînant le crash de Nginx, Apache et SSH sans authentification préalable.
2. **Abus Rapid Reset en HTTP/2 (CVE-2023-44487):** Des rafales massives de requêtes immédiatement annulées par des trames `RST_STREAM` saturent les descripteurs de fichiers et les processus serveur.

Ce dépôt met à disposition un outil interactif dans le navigateur et un utilitaire CLI en Python (bibliothèque standard) pour auditer les paramètres de noyau et les serveurs distants.

## Application Web Interactive

Accédez à l'outil en ligne et auditez votre infrastructure en temps réel:

* [https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/](https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/)

L'application évalue 5 étapes de sécurité, calcule un score de résilience (0 à 100), identifie les failles et fournit des modèles de durcissement prêts pour la production.

## Utilisation du Scanner CLI (Python)

Le dépôt inclut le script autonome `http2_kernel_dos_checker.py`, conçu avec la bibliothèque standard Python:

```bash
# Auditer les parametres locaux du noyau Linux contre NoisyTCP
python3 http2_kernel_dos_checker.py --kernel

# Auditer un serveur distant (negociation ALPN h2, TLS et en-tetes)
python3 http2_kernel_dos_checker.py --host votre-serveur.fr --port 443

# Executer l'audit en format JSON pour pipeline CI/CD
python3 http2_kernel_dos_checker.py --host votre-serveur.fr --json
```

## Contrôles Architecturaux et Mitigations Défensives

* **Noyau Linux (/etc/sysctl.conf):** Paramétrage de `net.ipv4.tcp_syncookies = 1`, désactivation de `net.ipv4.tcp_timestamps = 0` pour contrer NoisyTCP, calibration des tampons (`tcp_rmem`, `tcp_wmem`) et `somaxconn = 4096`.
* **Nginx (nginx.conf):** Masquage de signatures (`server_tokens off`), limitation des flux simultanés (`http2_max_concurrent_streams 100`) et zones de débit (`limit_req_zone`) contre les attaques `RST_STREAM`.
* **Apache HTTP Server (httpd.conf):** Suppression des bannières (`ServerTokens Prod`, `ServerSignature Off`), encadrement du multiplexage via `mod_http2` (`H2MaxSessionStreams 100`) et délais stricts avec `mod_reqtimeout`.
* **Protection Périmétrique:** Terminaison TLS managée sur Cloudflare WAF et masquage total de l'IP d'origine.

## Portails Officiels

* **Portail Corporatif TAVARDT France:** [https://ag.tavardt.com/fr/](https://ag.tavardt.com/fr/)
* **Services de Cybersécurité:** [https://ag.tavardt.com/fr/cybersecurite/](https://ag.tavardt.com/fr/cybersecurite/)
* **Hub d'Outils Sécurité:** [https://tools.tavardt.com/fr/](https://tools.tavardt.com/fr/)
* **Organisation GitHub:** [https://github.com/TAVARDT-France](https://github.com/TAVARDT-France)

## Licence

Distribué sous licence MIT. Consultez le fichier `LICENSE` pour plus d'informations.
