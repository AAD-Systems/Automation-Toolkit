#!/usr/bin/env python3
"""
Python Security Toolkit - Base Module
Fase 1: Fundamentos Sólidos

Este módulo fornece as ferramentas fundamentais para automação de segurança:
- Scanner TCP simples e multi-thread
- Sistema de logging profissional
- Utilitários para parsing, validação e exportação

Auto-melhoramento:
- Detecção automática de dependências
- Validação de ambiente
- Métricas de performance
- Sistema de plugins para extensão futura
"""

__version__ = "1.0.0"
__author__ = "Security Labor Team"
__license__ = "MIT"
__status__ = "Production/Stable"

import sys
import os
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# ============================================================================
# AUTO-DETECÇÃO E VALIDAÇÃO DE AMBIENTE
# ============================================================================

class EnvironmentValidator:
    """Valida e otimiza o ambiente de execução"""
    
    @staticmethod
    def check_python_version() -> bool:
        """Verifica versão mínima do Python"""
        if sys.version_info < (3, 8):
            print(f"⚠️  Python 3.8+ é recomendado. Versão atual: {sys.version}")
            return False
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        return True
    
    @staticmethod
    def check_platform() -> str:
        """Identifica plataforma para otimizações"""
        import platform
        system = platform.system().lower()
        print(f"✅ Plataforma: {system.capitalize()}")
        return system
    
    @staticmethod
    def check_dependencies() -> Dict[str, bool]:
        """Verifica dependências opcionais"""
        deps = {
            'scapy': False,
            'colorama': False,
            'tqdm': False
        }
        
        # Verifica Scapy (para futuras features)
        try:
            import scapy
            deps['scapy'] = True
            print("✅ Scapy disponível (para packet crafting)")
        except ImportError:
            print("ℹ️  Scapy não instalado (opcional para packet crafting)")
        
        # Verifica Colorama (fallback para cores)
        try:
            import colorama
            deps['colorama'] = True
        except ImportError:
            pass
        
        # Verifica tqdm (barra de progresso)
        try:
            import tqdm
            deps['tqdm'] = True
        except ImportError:
            pass
        
        return deps
    
    @staticmethod
    def validate_network() -> Dict[str, Any]:
        """Valida configuração de rede"""
        import socket
        
        network_info = {
            'hostname': socket.gethostname(),
            'ip_local': None,
            'conectividade': False
        }
        
        try:
            # Obtém IP local
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            network_info['ip_local'] = s.getsockname()[0]
            s.close()
            network_info['conectividade'] = True
        except Exception:
            network_info['ip_local'] = '127.0.0.1'
        
        return network_info


# ============================================================================
# SISTEMA DE MÉTRICAS E PERFORMANCE
# ============================================================================

class PerformanceMetrics:
    """Coleta e exibe métricas de performance"""
    
    def __init__(self):
        self.metrics = {
            'scans': [],
            'total_scans': 0,
            'total_ports_scanned': 0,
            'total_open_ports': 0,
            'avg_time_per_port': 0.0,
            'fastest_scan': float('inf'),
            'slowest_scan': 0.0
        }
    
    def record_scan(self, ports: int, open_ports: int, duration: float):
        """Registra métricas de um scan"""
        self.metrics['scans'].append({
            'ports': ports,
            'open_ports': open_ports,
            'duration': duration,
            'ports_per_second': ports / duration if duration > 0 else 0
        })
        
        self.metrics['total_scans'] += 1
        self.metrics['total_ports_scanned'] += ports
        self.metrics['total_open_ports'] += open_ports
        self.metrics['avg_time_per_port'] = (
            self.metrics['total_ports_scanned'] / 
            sum(s['duration'] for s in self.metrics['scans'])
        ) if self.metrics['scans'] else 0
        
        if duration < self.metrics['fastest_scan']:
            self.metrics['fastest_scan'] = duration
        if duration > self.metrics['slowest_scan']:
            self.metrics['slowest_scan'] = duration
    
    def get_summary(self) -> Dict[str, Any]:
        """Retorna resumo das métricas"""
        if not self.metrics['scans']:
            return {'status': 'no_data'}
        
        return {
            'total_scans': self.metrics['total_scans'],
            'total_ports_scanned': self.metrics['total_ports_scanned'],
            'total_open_ports': self.metrics['total_open_ports'],
            'avg_ports_per_second': f"{self.metrics['avg_time_per_port']:.2f}",
            'fastest_scan': f"{self.metrics['fastest_scan']:.2f}s",
            'slowest_scan': f"{self.metrics['slowest_scan']:.2f}s"
        }
    
    def display(self):
        """Exibe métricas formatadas"""
        summary = self.get_summary()
        if summary.get('status') == 'no_data':
            print("📊 Nenhum scan realizado ainda")
            return
        
        print("\n" + "="*50)
        print("📊 MÉTRICAS DE PERFORMANCE")
        print("="*50)
        print(f"Total de scans: {summary['total_scans']}")
        print(f"Portas escaneadas: {summary['total_ports_scanned']}")
        print(f"Portas abertas: {summary['total_open_ports']}")
        print(f"Média portas/segundo: {summary['avg_ports_per_second']}")
        print(f"Scan mais rápido: {summary['fastest_scan']}")
        print(f"Scan mais lento: {summary['slowest_scan']}")
        print("="*50)


# ============================================================================
# SISTEMA DE PLUGINS (PARA EXTENSÃO FUTURA)
# ============================================================================

class PluginManager:
    """Gerencia plugins e extensões do toolkit"""
    
    def __init__(self):
        self.plugins = {}
        self.plugin_path = Path(__file__).parent / "plugins"
        self.plugin_path.mkdir(exist_ok=True)
    
    def register_plugin(self, name: str, plugin_class):
        """Registra um novo plugin"""
        self.plugins[name] = plugin_class
        print(f"🔌 Plugin registrado: {name}")
    
    def load_plugins(self):
        """Carrega plugins do diretório plugins/"""
        if not self.plugin_path.exists():
            return
        
        import importlib.util
        for plugin_file in self.plugin_path.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                if hasattr(module, 'register'):
                    module.register(self)
                    print(f"✅ Plugin carregado: {plugin_file.stem}")
            except Exception as e:
                print(f"⚠️  Erro ao carregar plugin {plugin_file.stem}: {e}")
    
    def get_plugin(self, name: str):
        """Retorna um plugin pelo nome"""
        return self.plugins.get(name)


# ============================================================================
# EXPORTAÇÃO DE MÓDULOS (VERSÃO OTIMIZADA)
# ============================================================================

# Inicializa sistema de métricas global
metrics = PerformanceMetrics()

# Valida ambiente na importação
_validator = EnvironmentValidator()
_validator.check_python_version()
_platform = _validator.check_platform()
_deps = _validator.check_dependencies()
_network = _validator.validate_network()

# Exporta classes e funções principais
from .logger import setup_logger, tool_logger, Colors
from .utils import (
    validate_ip, validate_port, parse_ip_range, parse_ports,
    save_json, load_json, save_csv, sanitize_filename
)
from .tcp_scanner_simple import TCPScanner
from .multi_thread_scanner import MultiThreadScanner

# Define __all__ para controle de exportação
__all__ = [
    # Versão
    '__version__', '__author__', '__license__',
    
    # Logger
    'setup_logger', 'tool_logger', 'Colors',
    
    # Utils
    'validate_ip', 'validate_port', 'parse_ip_range', 'parse_ports',
    'save_json', 'load_json', 'save_csv', 'sanitize_filename',
    
    # Scanners
    'TCPScanner', 'MultiThreadScanner',
    
    # Métricas e gestão
    'metrics', 'PerformanceMetrics', 'PluginManager', 'EnvironmentValidator'
]

# Mensagem de boas-vindas (opcional, desativar em produção)
if os.environ.get('TOOLKIT_VERBOSE'):
    print(f"""
╔══════════════════════════════════════════════════════════╗
║  🐍 Python Security Toolkit v{__version__}                    ║
║  📦 Base Module - Fase 1: Fundamentos Sólidos            ║
║  👤 Author: {__author__}                                ║
║  📜 License: {__license__}                                      ║
╠══════════════════════════════════════════════════════════╣
║  ✅ Ambiente validado                                    ║
║  💻 Plataforma: {_platform.capitalize():<36}║
║  🌐 IP Local: {_network['ip_local']:<40}║
║  🔌 Plugins carregados: {len(PluginManager().plugins)}                                   ║
╚══════════════════════════════════════════════════════════╝
    """)

# ============================================================================
# AUTO-TESTE (executa quando o módulo é executado diretamente)
# ============================================================================

if __name__ == '__main__':
    print("\n🔧 Executando auto-teste do módulo base...\n")
    
    # Teste 1: Logger
    print("1️⃣  Testando logger...")
    from .logger import setup_logger
    test_logger = setup_logger('test', verbose=True)
    test_logger.info("Logger funcionando!")
    
    # Teste 2: Utils
    print("\n2️⃣  Testando utils...")
    from .utils import parse_ports, validate_ip
    ports = parse_ports("22,80,443")
    print(f"   Portas parseadas: {ports}")
    print(f"   IP válido (192.168.1.1): {validate_ip('192.168.1.1')}")
    
    # Teste 3: Métricas
    print("\n3️⃣  Testando métricas...")
    metrics.record_scan(1000, 5, 2.5)
    metrics.display()
    
    # Teste 4: Plugin manager
    print("\n4️⃣  Testando plugin manager...")
    pm = PluginManager()
    pm.load_plugins()
    
    print("\n✅ Todos os testes concluídos!")
    print("\n📖 Para usar o toolkit:")
    print("   from base import TCPScanner, MultiThreadScanner")
    print("   scanner = TCPScanner('192.168.1.1')")
    print("   scanner.scan_ports([80, 443, 8080])")
