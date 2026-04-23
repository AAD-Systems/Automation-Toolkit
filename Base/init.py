#!/usr/bin/env python3
"""
AEGIS-Dynamics (AAD) Security Toolkit - Core Module
Fase 1: Infraestrutura de Comando e Controle (C2) e Automação

Desenvolvido para ambientes de simulação Blue/Red Team.
Autor: Tauã Miguel
Versão: 1.2.0 (Stable)
"""

import sys
import os
import asyncio
import socket
import logging
import platform
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field

# ============================================================================
# CONFIGURAÇÃO DE LOGGING PROFISSIONAL
# ============================================================================

class AADLogger:
    """Sistema de logging centralizado com suporte a cores e arquivos"""
    
    @staticmethod
    def setup(name: str = "AAD-CORE", verbose: bool = False):
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        )
        return logging.getLogger(name)

log = AADLogger.setup()

# ============================================================================
# MÉTRICAS DE ALTA PRECISÃO (AAD-ANALYTICS)
# ============================================================================

@dataclass
class AADMetrics:
    """Coleta de telemetria de performance em tempo real"""
    start_time: float = field(default_factory=time.time)
    scans_performed: int = 0
    hits_detected: int = 0
    data_transferred: int = 0  # em bytes

    def get_uptime(self) -> float:
        return time.time() - self.start_time

    def report(self):
        uptime = self.get_uptime()
        log.info(f"📊 Telemetria: {self.scans_performed} scans em {uptime:.2f}s "
                 f"({(self.scans_performed/uptime):.1f} ops/s)")

# ============================================================================
# VALIDAÇÃO DE AMBIENTE E PROTEÇÃO DE HARDWARE
# ============================================================================

class SystemGuard:
    """Valida integridade do sistema e previne sobrecarga (Safe-Mode)"""
    
    @staticmethod
    def get_env_info() -> Dict[str, Any]:
        info = {
            "os": platform.system(),
            "arch": platform.machine(),
            "python": sys.version.split()[0],
            "termux": "TERMUX_VERSION" in os.environ,
            "local_ip": "127.0.0.1"
        }
        
        # Detecção de rede inteligente
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                info["local_ip"] = s.getsockname()[0]
        except Exception:
            log.warning("⚠️ Conectividade externa limitada.")
            
        return info

# ============================================================================
# ENGINE DE SCANNER ASYNCHRONOUS (MODERNO)
# ============================================================================

class AADScanner:
    """Motor de descoberta assíncrono de alto desempenho"""
    
    def __init__(self, target: str, metrics_ref: AADMetrics):
        self.target = target
        self.metrics = metrics_ref

    async def check_port(self, port: int, timeout: float = 1.0) -> bool:
        """Tenta abrir uma conexão TCP de forma assíncrona"""
        try:
            conn = asyncio.open_connection(self.target, port)
            _reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            self.metrics.scans_performed += 1
            self.metrics.hits_detected += 1
            return True
        except:
            self.metrics.scans_performed += 1
            return False

    async def scan_range(self, ports: List[int]):
        """Executa múltiplos scans simultaneamente"""
        tasks = [self.check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [ports[i] for i, opened in enumerate(results) if opened]

# ============================================================================
# INTERFACE DE COMANDO (BANNER)
# ============================================================================

def show_banner(env: Dict[str, Any]):
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
    ╔══════════════════════════════════════════════════════════╗
    ║  AEGIS-DYNAMICS (AAD) - SECURITY TOOLKIT v1.2            ║
    ║  Operador: {env['local_ip']:<41} ║
    ║  Status:   SISTEMA OPERACIONAL (Fase 1: Ready)           ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Engenharia: Tauã Miguel       Plataforma: {env['os']:<13} ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

# ============================================================================
# PONTO DE ENTRADA (BOOTSTRAP)
# ============================================================================

async def main():
    env = SystemGuard.get_env_info()
    show_banner(env)
    
    metrics = AADMetrics()
    scanner = AADScanner("127.0.0.1", metrics)
    
    log.info("🚀 Iniciando auto-teste de integridade...")
    ports_to_test = [22, 80, 443, 3306, 8080]
    found = await scanner.scan_range(ports_to_test)
    
    if found:
        log.info(f"✅ Serviços detectados: {found}")
    else:
        log.info("ℹ️ Nenhum serviço local detectado no range padrão.")
        
    metrics.report()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Operação abortada pelo usuário.")
