#!/usr/bin/env python3
"""
Scanner TCP simples - Teste de conectividade de portas
"""

import socket
import sys
import argparse
from typing import List, Tuple
import time

# Importa módulos locais
from logger import setup_logger
from utils import validate_ip, validate_port, save_json, save_csv

class TCPScanner:
    """Scanner TCP simples"""
    
    def __init__(self, target: str, timeout: float = 1.0, verbose: bool = False):
        """
        Inicializa scanner
        
        Args:
            target: IP ou hostname alvo
            timeout: Timeout em segundos
            verbose: Modo detalhado
        """
        self.target = target
        self.timeout = timeout
        self.logger = setup_logger(f'scanner_{target}', verbose=verbose)
        self.open_ports = []
        
    def scan_port(self, port: int) -> bool:
        """
        Escaneia uma única porta
        
        Returns:
            True se porta aberta, False caso contrário
        """
        try:
            # Cria socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Tenta conectar
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                self.logger.debug(f"Porta {port} ABERTA")
                return True
            else:
                self.logger.debug(f"Porta {port} FECHADA")
                return False
                
        except socket.gaierror:
            self.logger.error(f"Host {self.target} não encontrado")
            sys.exit(1)
        except socket.error as e:
            self.logger.error(f"Erro na porta {port}: {e}")
            return False
    
    def scan_ports(self, ports: List[int]) -> List[int]:
        """
        Escaneia lista de portas
        
        Args:
            ports: Lista de portas para escanear
            
        Returns:
            Lista de portas abertas
        """
        self.logger.info(f"Iniciando scan em {self.target}")
        self.logger.info(f"Escaneando {len(ports)} portas...")
        
        open_ports = []
        start_time = time.time()
        
        for i, port in enumerate(ports):
            if self.scan_port(port):
                open_ports.append(port)
            
            # Progresso a cada 10 portas
            if (i + 1) % 10 == 0:
                self.logger.debug(f"Progresso: {i+1}/{len(ports)} portas")
        
        elapsed = time.time() - start_time
        self.logger.info(f"Scan concluído em {elapsed:.2f}s")
        self.logger.info(f"Portas abertas encontradas: {len(open_ports)}")
        
        return open_ports
    
    def get_service_name(self, port: int) -> str:
        """Tenta identificar serviço pela porta"""
        common_ports = {
            20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            111: 'RPC', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return common_ports.get(port, 'Unknown')
    
    def generate_report(self, open_ports: List[int], output_file: str = None):
        """Gera relatório do scan"""
        if not open_ports:
            self.logger.warning("Nenhuma porta aberta encontrada")
            return
        
        report = []
        for port in open_ports:
            report.append({
                'port': port,
                'service': self.get_service_name(port),
                'status': 'open'
            })
        
        # Exibe no console
        print("\n" + "="*60)
        print(f"RELATÓRIO DE SCAN - {self.target}")
        print("="*60)
        print(f"{'PORTA':<10} {'SERVIÇO':<15} {'STATUS':<10}")
        print("-"*60)
        for r in report:
            print(f"{r['port']:<10} {r['service']:<15} {r['status']:<10}")
        print("="*60)
        
        # Salva em arquivo se especificado
        if output_file:
            if output_file.endswith('.json'):
                save_json(report, output_file)
            elif output_file.endswith('.csv'):
                save_csv(report, output_file)
            self.logger.info(f"Relatório salvo em: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Scanner TCP Simples',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s 192.168.1.1 -p 80,443,8080
  %(prog)s 192.168.1.1 -p 1-100 -t 0.5 -v
  %(prog)s google.com -p 80,443 -o resultado.json
        """
    )
    
    parser.add_argument('target', help='IP ou hostname alvo')
    parser.add_argument('-p', '--ports', default='1-1024',
                       help='Portas para scan (ex: 80,443 ou 1-1000)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Timeout em segundos (default: 1.0)')
    parser.add_argument('-o', '--output', help='Arquivo de saída (.json ou .csv)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Modo verbose')
    
    args = parser.parse_args()
    
    # Valida IP/hostname
    if not validate_ip(args.target):
        try:
            # Tenta resolver hostname
            socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"Erro: Host {args.target} inválido")
            sys.exit(1)
    
    # Parse das portas
    try:
        from utils import parse_ports
        ports = parse_ports(args.ports)
        if not ports:
            print("Erro: Nenhuma porta válida especificada")
            sys.exit(1)
    except Exception as e:
        print(f"Erro ao parsear portas: {e}")
        sys.exit(1)
    
    # Executa scan
    scanner = TCPScanner(args.target, args.timeout, args.verbose)
    open_ports = scanner.scan_ports(ports)
    scanner.generate_report(open_ports, args.output)

if __name__ == '__main__':
    main()
