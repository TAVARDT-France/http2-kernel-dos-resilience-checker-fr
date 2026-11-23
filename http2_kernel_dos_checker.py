#!/usr/bin/env python3
"""
TAVARDT HTTP/2 & Linux Kernel DoS Resilience Checker
Auditeur de Résilience contre NoisyTCP, Rapid Reset et Crash de Serveurs Web
TAVARDT France
"""

import sys
import os
import json
import socket
import ssl
import argparse
from typing import Dict, Any, List

VERSION = "1.0.0"

RECOMMENDED_SYSCTL = {
    "net.ipv4.tcp_syncookies": {"expected": "1", "weight": 20, "desc": "Protection contre SYN Flood et saturation des connexions"},
    "net.ipv4.tcp_timestamps": {"expected": "0", "weight": 20, "desc": "Atténuation de l'empoisonnement et réordonnancement NoisyTCP"},
    "net.ipv4.tcp_sack": {"expected": "1", "weight": 15, "desc": "Accusé de réception sélectif TCP (SACK)"},
    "net.ipv4.tcp_fin_timeout": {"expected": "15", "weight": 15, "desc": "Libération rapide des sockets en état FIN-WAIT"},
    "net.ipv4.tcp_max_syn_backlog": {"expected": "8192", "weight": 15, "desc": "File d'attente étendue pour requêtes de handshake en attente"},
    "net.core.somaxconn": {"expected": "4096", "weight": 15, "desc": "Limite de backlog des connexions sockets du système"}
}

def audit_local_kernel() -> Dict[str, Any]:
    """Audite les paramètres réseau du noyau Linux local contre la vulnérabilité NoisyTCP."""
    results = {
        "platform": sys.platform,
        "is_linux": sys.platform.startswith("linux"),
        "checks": [],
        "score": 100,
        "critical_alerts": []
    }

    if not results["is_linux"]:
        results["warning"] = "Audit du noyau applicable nativement sur les hôtes Linux. Sur les autres systèmes d'exploitation, utilisez l'audit distant via le réseau."
        return results

    total_weight = sum(v["weight"] for v in RECOMMENDED_SYSCTL.values())
    accumulated_score = 0

    for param, meta in RECOMMENDED_SYSCTL.items():
        proc_path = os.path.join("/proc/sys", param.replace(".", "/"))
        current_val = None
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "r", encoding="utf-8") as f:
                    current_val = f.read().strip()
            except Exception:
                pass

        conforming = (current_val == meta["expected"])
        if conforming:
            accumulated_score += meta["weight"]
        else:
            results["critical_alerts"].append({
                "param": param,
                "current": current_val or "non_configure",
                "recommended": meta["expected"],
                "desc": meta["desc"]
            })

        results["checks"].append({
            "param": param,
            "current": current_val or "indisponible",
            "recommended": meta["expected"],
            "status": "CONFORME" if conforming else "VULNÉRABLE",
            "desc": meta["desc"]
        })

    results["score"] = round((accumulated_score / total_weight) * 100)
    return results

def audit_remote_host(host: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    """Audite un endpoint distant en évaluant la négociation HTTP/2, TLS et la fuite de version."""
    report = {
        "target": f"{host}:{port}",
        "http2_supported": False,
        "tls_version": None,
        "alpn_negotiated": None,
        "server_banner": None,
        "banner_leaked": False,
        "score": 100,
        "findings": []
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                report["tls_version"] = ssock.version()
                alpn = ssock.selected_alpn_protocol()
                report["alpn_negotiated"] = alpn
                report["http2_supported"] = (alpn == "h2")
    except Exception as e:
        report["connection_error"] = str(e)
        report["score"] = 30
        report["findings"].append(f"Échec de connexion TLS avec {host}:{port}: {e}")
        return report

    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: TAVARDT-Security-Auditor/1.0\r\nConnection: close\r\n\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.sendall(req.encode())
                raw_resp = ssock.recv(4096).decode("utf-8", errors="ignore")
                for line in raw_resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        report["server_banner"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
                    if line.lower().startswith("x-powered-by:"):
                        report["x_powered_by"] = line.split(":", 1)[1].strip()
                        report["banner_leaked"] = True
    except Exception:
        pass

    deductions = 0
    if not report["http2_supported"]:
        deductions += 40
        report["findings"].append("ALPN h2 non négocié : serveur sans multiplexage moderne ou avec h2c en texte clair.")
    if report["banner_leaked"]:
        deductions += 30
        report["findings"].append(f"Fuite active de version logicielle dans la bannière : '{report.get('server_banner')}'")

    report["score"] = max(10, 100 - deductions)
    return report

def main():
    parser = argparse.ArgumentParser(
        description="TAVARDT France Auditeur de Résilience HTTP/2 & NoisyTCP Linux Kernel"
    )
    parser.add_argument("--host", help="Hôte distant pour audit de négociation HTTP/2 et bannières", default=None)
    parser.add_argument("--port", help="Port distant (par défaut : 443)", type=int, default=443)
    parser.add_argument("--kernel", action="store_true", help="Exécuter l'audit local des paramètres réseau Linux")
    parser.add_argument("--json", action="store_true", help="Afficher les résultats exclusivement au format JSON")

    args = parser.parse_args()

    results = {
        "version": VERSION,
        "auditor": "TAVARDT France",
        "documentation": "https://ag.tavardt.com/fr/cybersecurite/",
        "web_tool": "https://tavardt-france.github.io/http2-kernel-dos-resilience-checker-fr/"
    }

    if args.kernel or (not args.host and not args.kernel):
        results["kernel_audit"] = audit_local_kernel()

    if args.host:
        results["remote_audit"] = audit_remote_host(args.host, args.port)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    print("================================================================================")
    print("      TAVARDT FRANCE : AUDITEUR DE RÉSILIENCE HTTP/2 ET CRASH DU NOYAU LINUX           ")
    print("================================================================================")
    print(f"Version: {VERSION} | Juridiction: France | Portail: https://ag.tavardt.com/fr/cybersecurite/")
    print("--------------------------------------------------------------------------------\n")

    if "kernel_audit" in results:
        ka = results["kernel_audit"]
        print(f"[*] AUDIT DU NOYAU LINUX (Atténuation NoisyTCP) | Score: {ka['score']}/100")
        if not ka["is_linux"]:
            print(f"    [AVERTISSEMENT] {ka.get('warning')}")
        else:
            for c in ka["checks"]:
                tag = "[OK]        " if c["status"] == "CONFORME" else "[VULNÉRABLE]"
                print(f"    {tag} {c['param']}: actuel={c['current']} | recommandé={c['recommended']}")
        print()

    if "remote_audit" in results:
        ra = results["remote_audit"]
        print(f"[*] AUDIT DISTANT DE PROTOCOLE: {ra['target']} | Score: {ra['score']}/100")
        print(f"    HTTP/2 Supporté (ALPN): 'OUI' if ra['http2_supported'] else 'NON'")
        print(f"    Version TLS: {ra['tls_version'] or 'Inconnue'}")
        print(f"    Bannière Serveur Exposée: 'OUI (' + str(ra['server_banner']) + ')' if ra['banner_leaked'] else 'NON (Protégé)'")
        if ra["findings"]:
            print("    Alertes de Risque Identifiées :")
            for f in ra["findings"]:
                print(f"      * {f}")
        print()

    print("Pour support technique et durcissement périmétrique :")
    print(f"TAVARDT France: https://ag.tavardt.com/fr/cybersecurite/")

if __name__ == "__main__":
    main()
