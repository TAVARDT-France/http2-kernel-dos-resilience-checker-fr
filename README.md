# HTTP/2 & Linux Kernel DoS Resilience Checker

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![RFC 7540](https://img.shields.io/badge/RFC-7540-blue.svg)](https://datatracker.ietf.org/doc/html/rfc7540)
[![RFC 9113](https://img.shields.io/badge/RFC-9113-blue.svg)](https://datatracker.ietf.org/doc/html/rfc9113)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditeur de sécurité automatisé pour les paramètres réseau du noyau Linux, la négociation du protocole HTTP/2 (ALPN) et la résilience contre les attaques par déni de service, développé par **TAVARDT**, en conformité rigoureuse avec les recommandations de l'ANSSI, la directive NIS2 et les normes RFC 9113.

Les services web contemporains sont confrontés à des menaces constantes de déni de service ciblant les protocoles de bas niveau, notamment NoisyTCP et HTTP/2 Rapid Reset. Sans un calibrage rigoureux des sockets système et une validation systématique des protocoles, les serveurs d'origine subissent une saturation rapide de leurs files d'attente sous l'effet de flux malveillants asymétriques.

***

## Fonctionnalités Clés et Architecture Défensive

* **Audit Déterministe des Paramètres du Noyau Linux**: Analyse les configurations sous `/proc/sys/net/` afin de renforcer le système face aux attaques NoisyTCP, aux inondations SYN et à la saturation des connexions.
* **Vérification Distante du Protocole HTTP/2**: Contrôle la négociation ALPN via TLS sur les connexions réseau pour valider la prise en charge exclusive du multiplexage `h2`.
* **Détection de la Fuite d'Informations Techniques**: Identifie l'exposition non sécurisée de bannières logicielles au sein des en-têtes `Server` et `X-Powered-By`.
* **Zéro Dépendance Logicielle Externe**: Conçu exclusivement à l'aide de la bibliothèque standard Python (`socket`, `ssl`, `json`, `os`, `sys`), garantissant une exécution instantanée sans modules tiers.
* **Automatisation pour Intégration Continue (CI/CD)**: Produit des rapports structurés en JSON via l'option `-json` pour un contrôle continu de conformité dans les flux de déploiement.

***

## Vecteurs de Risque et Impact Opérationnel

Exploiter des serveurs avec les configurations réseau Linux par défaut fragilise considérablement l'infrastructure face aux agressions volumétriques. L'outil analyse quatre vecteurs critiques :

* **Attaque NoisyTCP et Altération des Séquences**: Exploitation des horodatages TCP pour forcer un réordonnancement artificiel des paquets et saturer le processeur réseau.
* **Inondation SYN et Épuisement des Sockets**: Saturation des files d'attente de connexions provoquée par l'absence de cookies SYN et des limites de backlog trop réduites.
* **Dégradation Protocolaire et Échec ALPN**: Impossibilité de négocier `h2`, contraignant la connexion à basculer vers des flux HTTP/1.1 moins performants.
* **Reconnaissance et Empreinte par Bannières**: Divulgation publique des versions de serveur dans les en-têtes, simplifiant les attaques ciblées vers des failles connues.

***

## Installation et Utilisation CLI

Exécutez des audits locaux sur le noyau Linux ou des vérifications protocolaires distantes via des commandes Python standard :

```bash
# Cloner le dépôt officiel
git clone https://github.com/TAVARDT-France/http2-kernel-dos-resilience-checker-fr.git

# Accéder au répertoire du projet
cd http2-kernel-dos-resilience-checker-fr

# Auditer les paramètres réseau locaux du noyau Linux
python http2_kernel_dos_checker.py -kernel

# Auditer un point de terminaison distant pour HTTP/2 et les bannières
python http2_kernel_dos_checker.py -host example.com -port 443

# Exporter un rapport JSON pour les chaînes CI/CD
python http2_kernel_dos_checker.py -host example.com -json
```

***

## Foire Aux Questions Techniques

### En quoi l'ajustement des paramètres sysctl du noyau Linux neutralise-t-il les attaques NoisyTCP ?

La désactivation des horodatages TCP empêche la prédiction des numéros de séquence et le réordonnancement artificiel de paquets qui saturent les files d'attente réseau. L'activation conjointe des cookies SYN et l'accroissement des limites de backlog protègent efficacement l'infrastructure lors d'inondations massives de requêtes.

### Pourquoi la validation de la négociation ALPN est-elle déterminante pour la sécurité HTTP/2 ?

Le mécanisme ALPN garantit que le client et le serveur établissent un multiplexage binaire sécurisé sur TLS sans rétrograder vers des flux non chiffrés. Confirmer la sélection du protocole h2 valide l'application immédiate des mécanismes modernes de régulation de débit et de gestion des flux dès l'établissement de la connexion.

### Pourquoi la divulgation des en-têtes Server et X-Powered-By augmente-t-elle le risque de déni de service ?

Révéler les versions exactes des serveurs web permet à des acteurs hostiles d'exploiter des vulnérabilités spécifiques de traitement mémoire propres à cette version. Supprimer ces en-têtes d'information prive les outils automatisés d'exploration des données requises pour concevoir des attaques ciblées.

### Quelle distinction opérationnelle existe-t-il entre l'audit local du noyau et l'évaluation distante ?

L'audit local inspecte les paramètres sysctl directement au sein du système de fichiers proc afin d'évaluer la posture défensive du système hôte. L'évaluation distante contrôle pour sa part la négociation TLS, la compatibilité ALPN et la présence de bannières à travers le réseau sans exiger d'accès privilégié.

### L'auditeur de résilience peut-il s'intégrer dans les chaînes d'intégration continue CI/CD ?

L'outil en ligne de commande génère une sortie structurée via l'option -json, facilitant la lecture automatique des scores de conformité par les plateformes d'automatisation. Les équipes d'ingénierie peuvent exploiter ce rapport pour suspendre le déploiement de serveurs dont les réglages ne satisfont pas aux exigences de durcissement.

***

## Liens Utiles

* **Portail Institutionnel:** https://ag.tavardt.com/fr/
* **Suite de Diagnostic:** https://tools.tavardt.com/fr/
* **Contact Technique:** https://ag.tavardt.com/fr/contact/

***

### Licence
Distribué sous la Licence MIT. Consultez [LICENSE](LICENSE) pour obtenir tous les détails.

***

© 2026 TAVARDT. Tous droits réservés.
