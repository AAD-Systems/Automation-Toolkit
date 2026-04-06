#!/usr/bin/env python3
"""
Scanner TCP Multi-threaded - Alta performance com threads
"""

import socket
import threading
import queue
import time
import sys
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from logger import setup_logger
from utils import validate_ip, parse_ports, save_json, save_csv

class MultiThreadScanner:
    """Scanner TCP com suporte a múltiplas threads"""
    
    def __init__(self, target: str, timeout: float = 1.0, 
                 max_threads: int = 100, verbose: bool = False):
        """
        Inicializa scanner multi-thread
        
        Args:
            target: IP ou hostname alvo
            timeout: Timeout em segundos
            max_threads: Número máximo de threads simultâneas
            verbose: Modo detalhado
        """
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.logger = setup_logger(f'multiscan_{target}', verbose=verbose)
        self.open_ports = []
        self.lock = threading.Lock()
        
    def scan_port(self, port: int) -> Dict:
        """
        Escaneia uma porta (thread-safe)
        
        Returns:
            Dicionário com resultado do scan
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((self.target, port))
            elapsed = time.time() - start_time
            
            sock.close()
            
            if result == 0:
                self.logger.debug(f"[+] Porta {port} ABERTA ({elapsed:.3f}s)")
                return {
                    'port': port,
                    'status': 'open',
                    'response_time': elapsed
                }
            else:
                return {
                    'port': port,
                    'status': 'closed',
                    'response_time': elapsed
                }
                
        except Exception as e:
            self.logger.error(f"Erro na porta {port}: {e}")
            return {
                'port': port,
                'status': 'error',
                'error': str(e)
            }
    
    def scan_ports_parallel(self, ports: List[int]) -> List[int]:
        """
        Escaneia portas usando ThreadPoolExecutor
        
        Args:
            ports: Lista de portas para escanear
            
        Returns:
            Lista de portas abertas
        """
        self.logger.info(f"Iniciando scan paralelo em {self.target}")
        self.logger.info(f"Portas: {len(ports)} | Threads: {self.max_threads}")
        
        open_ports = []
        start_time = time.time()
        
        # Usa ThreadPoolExecutor para gerenciar threads
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submete todas as tarefas
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in ports
            }
            
            # Processa resultados conforme completam
            completed = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        open_ports.append(port)
                        self.logger.info(f"Porta {port} aberta!")
                    
                    completed += 1
                    if completed % 100 == 0:
                        self.logger.debug(f"Progresso: {completed}/{len(ports)} portas")
                        
                except Exception as e:
                    self.logger.error(f"Erro ao processar porta {port}: {e}")
        
        elapsed = time.time() - start_time
        self.logger.info(f"Scan concluído em {elapsed:.2f}s")
        self.logger.info(f"Portas abertas: {len(open_ports)}")
        
        return open_ports
    
    def scan_with_queue(self, ports: List[int]) -> List[int]:
        """
        Alternativa: Scanner usando fila (Queue) para controle fino
        Útil para cenários com rate limiting
        """
        port_queue = queue.Queue()
        open_ports = []
        
        # Adiciona portas à fila
        for port in ports:
            port_queue.put(port)
        
        def worker():
            """Função worker para threads"""
            while True:
                try:
                    port = port_queue.get_nowait()
                except queue.Empty:
                    break
                
                result = self.scan_port(port)
                if result['status'] == 'open':
                    with self.lock:
                        open_ports.append(port)
                        self.logger.info(f"Porta {port} aberta!")
                
                port_queue.task_done()
        
        # Cria e inicia threads
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Aguarda conclusão
        port_queue.join()
        for t in threads:
            t.join()
        
        return open_ports
    
    def generate_detailed_report(self, open_ports: List[int], output_file: str = None):
        """Gera relatório detalhado do scan"""
        from utils import save_json
        
        report = {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_open_ports': len(open_ports),
            'open_ports': [],
            'scan_config': {
                'timeout': self.timeout,
                'max_threads': self.max_threads
            }
        }
        
        # Tenta identificar serviços
        for port in open_ports:
            report['open_ports'].append({
                'port': port,
                'service': self._get_service_banner(port)
            })
        
        # Exibe resumo
        print("\n" + "="*70)
        print(f"RELATÓRIO DETALHADO - {self.target}")
        print("="*70)
        print(f"Data: {report['scan_date']}")
        print(f"Total de portas abertas: {len(open_ports)}")
        print("-"*70)
        print(f"{'PORTA':<10} {'SERVIÇO':<20}")
        print("-"*70)
        for p in report['open_ports']:
            print(f"{p['port']:<10} {p['service']:<20}")
        print("="*70)
        
        if output_file:
            save_json(report, output_file)
            self.logger.info(f"Relatório salvo em: {output_file}")
    
    def _get_service_banner(self, port: int) -> str:
        """Tenta obter banner do serviço (básico)"""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
            27017: 'MongoDB', 6379: 'Redis'
        }
        return common_services.get(port, 'Unknown')
    
    def scan_and_save(self, ports: List[int], output_file: str = None):
        """Método principal para executar scan e salvar resultados"""
        open_ports = self.scan_ports_parallel(ports)
        self.generate_detailed_report(open_ports, output_file)
        return open_ports

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scanner TCP Multi-threaded de Alta Performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s 192.168.1.1 -p 1-1000 -t 0.5 -T 200
  %(prog)s 192.168.1.1 -p 80,443,8080,3306 -T 50 -v
  %(prog)s target.com -p 1-65535 -o scan_results.json -v
        """
    )
    
    parser.add_argument('target', help='IP ou hostname alvo')
    parser.add_argument('-p', '--ports', default='1-1024',
                       help='Portas para scan (ex: 80,443 ou 1-1000)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0,
                       help='Timeout em segundos (default: 1.0)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Número de threads (default: 100)')
    parser.add_argument('-o', '--output', help='Arquivo de saída (.json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Modo verbose')
    
    args = parser.parse_args()
    
    # Valida target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Erro: Host {args.target} inválido")
        sys.exit(1)
    
    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print("Erro: Nenhuma porta válida especificada")
        sys.exit(1)
    
    # Executa scan
    scanner = MultiThreadScanner(
        target=args.target,
        timeout=args.timeout,
        max_threads=args.threads,
        verbose=args.verbose
    )
    
    scanner.scan_and_save(ports, args.output)

if __name__ == '__main__':
    main()
