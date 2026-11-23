# Hub de Durcissement et Resilience DoS HTTP/2 et Noyau Linux

Specification technique d'entreprise en ingenierie defensive et blueprints d'infrastructure pour attenuer les vecteurs de saturation HTTP/2 Rapid Reset (CVE-2023-44487) et NoisyTCP, durcissement du noyau Linux (sysctl) et verification CLI deterministe locale.

## Perimetre Technique du Depot

Ce depot fournit des modeles de durcissement testes en production et un outillage CLI deterministe :

1. **sysctl-hardening.conf :** Parametres optimises dans `/proc/sys/net/ipv4` attenuant les inondations SYN, les attaques de timestamp NoisyTCP et l'epuisement des sockets orphelins.
2. **nginx-http2-hardened.conf :** Configuration de proxy inverse NGINX durcie imposant des quotas stricts de flux simultanes (`http2_max_concurrent_streams 64`) et une limitation rigoureuse des trames RST_STREAM.
3. **nftables-dos-protection.conf :** Regles de filtrage de paquets de Couche 4 rejetant les salves anormales TCP SYN et RST avant l'allocation des sockets dans le noyau.
4. **docker-compose-hardened.yml :** Architecture de conteneurs isoles appliquant des limites strictes de ressources (memoire, processeur, ulimits) aux proxies web de bordure.
5. **http2_kernel_dos_checker.py :** Utilitaire CLI local deterministe execute avec des privileges systeme sur le serveur pour auditer directement les parametres `/proc/sys` et valider la conformite RFC.

> [!NOTE]
> L'inspection active de l'etat du noyau Linux et des parametres reseau requiert des privileges systeme et doit etre executee directement sur le serveur hote via l'outil CLI Python. Les pages web executees dans le bac a sable d'un navigateur ne peuvent auditer les parametres du noyau hote.

## Utilisation de l'Outil CLI

Executez le script d'audit deterministe directement sur le serveur hote :

```bash
# 1. Telecharger le script d'audit
curl -sO https://raw.githubusercontent.com/TAVARDT-France/http2-kernel-dos-resilience-checker-fr/main/http2_kernel_dos_checker.py

# 2. Inspecter les parametres locaux du noyau Linux
sudo python3 http2_kernel_dos_checker.py -kernel

# 3. Exporter les resultats au format JSON
sudo python3 http2_kernel_dos_checker.py -kernel -json
```

## Gouvernance et Souverainete

* **Organisation :** TAVARDT-France
* **Juridiction :** France
* **Conformite aux Normes :** RFC 7540, RFC 9113, CVE-2023-44487, Architecture Zero Trust

Developpe par la Division Cybersecurite & Ingenierie d'Infrastructure de **TAVARDT France**. Tous droits reserves.
