# Hub de Durcissement et Résilience DoS HTTP/2 et Noyau Linux

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)

**Hub d'Architecture Défensive et d'Atténuation contre le DoS HTTP/2 (Rapid Reset CVE-2023-44487) et Noyau Linux**

Développé et maintenu par la division d'ingénierie de sécurité et d'infrastructuré de **TAVARDT**.

***

## Démonstration en Ligne & Hub d'Architecture Défensive

Vous pouvez consulter les spécifications techniques, les diagnostics architecturaux et les blueprints de durcissement directement dans votre navigateur :

* **[Application Web Officielle sur GitHub Pages](https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/)**
* **Centre d'Outils TAVARDT**

> [!NOTE]
> **Périmètre d'Exécution Technique :** Ce hub web fournit des spécifications d'architecture défensive et des blueprints de configuration. L'inspection active de l'etat du noyau Linux et les audits de la pile réseau requièrent des privilèges système (root) et doivent etre exécutés directement sur l'hote via l'utilitaire CLI officiel (`http2_kernel_dos_checker.py`). Les pages web exécutées dans le bac a sable d'un navigateur ne peuvent auditer les paramètres internes du noyau.

***

## Blueprints Techniques de Durcissement

1. **sysctl-hardening.conf :** Paramètres optimisés dans `/proc/sys/net/ipv4` atténuant les inondations SYN, les attaques de timestamp NoisyTCP et l'épuisement des sockets orphelins.
2. **nginx-http2-hardened.conf :** Configuration de proxy inverse NGINX durcie imposant des quotas stricts de flux simultanes (`http2_max_concurrent_streams 64`) et une limitation rigoureuse des trames RST_STREAM.
3. **nftables-dos-protection.conf :** Règles de filtrage de paquets de Couche 4 rejetant les salves anormales TCP SYN et RST avant l'allocation des sockets dans le noyau.
4. **docker-compose-hardened.yml :** Architecture de conteneurs isolés appliquant des limites strictes de ressources (mémoire, processeur, ulimits) aux proxies web de bordure.
5. **http2_kernel_dos_checker.py :** Utilitaire CLI local déterministe exécuté avec des privilèges système sur le serveur pour auditer directement les paramètres `/proc/sys` et valider la conformité RFC.

***

## Utilisation de l'Outil CLI Déterministe

Pour exécutér l'inspection déterministe directement sur le serveur hote Linux :

```bash
# 1. Télécharger le script d'audit depuis le dépôt officiel
curl -sO https://raw.githubusercontent.com/TAVARDT-France/http2-kernel-dos-resilience-checker-fr/main/http2_kernel_dos_checker.py

# 2. Inspecter les paramètres locaux du noyau Linux
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Exporter les resultats au format JSON structuré
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

***

## Liens Utiles

* **Portail Entreprise:** https://ag.tavardt.com/fr/
* **Suite de Diagnostic:** https://tools.tavardt.com/fr/
* **Contact Technique:** https://ag.tavardt.com/fr/contact/

***

© 2026 TAVARDT. Tous droits réservés.
