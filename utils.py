#!/usr/bin/env python3
"""
Utilitários comuns para ferramentas de segurança
"""

import json
import csv
import ipaddress
from typing import List, Dict, Any, Union
from pathlib import Path
import re

def validate_ip(ip: str) -> bool:
    """Valida se string é um IP válido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """Valida se porta está no range válido (1-65535)"""
    return 1 <= port <= 65535

def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse de ranges de IP
    Exemplos:
        - "192.168.1.1" -> IP único
        - "192.168.1.1-10" -> Range de IPs
        - "192.168.1.0/24" -> CIDR
    """
    ips = []
    
    # Verifica se é CIDR
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        except ValueError:
            pass
    
    # Verifica se é range com hífen
    elif '-' in ip_range:
        try:
            base = ip_range.split('-')[0]
            start = int(ip_range.split('-')[0].split('.')[-1])
            end = int(ip_range.split('-')[1])
            
            prefix = '.'.join(base.split('.')[:-1])
            for i in range(start, end + 1):
                ips.append(f"{prefix}.{i}")
        except (ValueError, IndexError):
            pass
    
    # IP único
    else:
        if validate_ip(ip_range):
            ips.append(ip_range)
    
    return ips

def parse_ports(port_str: str) -> List[int]:
    """
    Parse de portas
    Exemplos:
        - "80" -> [80]
        - "80,443,8080" -> [80, 443, 8080]
        - "1-100" -> [1,2,3,...,100]
    """
    ports = []
    
    if '-' in port_str:
        try:
            start, end = map(int, port_str.split('-'))
            ports = list(range(start, min(end + 1, 65536)))
        except ValueError:
            pass
    elif ',' in port_str:
        try:
            ports = [int(p.strip()) for p in port_str.split(',')]
        except ValueError:
            pass
    else:
        try:
            ports = [int(port_str)]
        except ValueError:
            pass
    
    # Filtra portas válidas
    return [p for p in ports if validate_port(p)]

def save_json(data: Any, filename: str) -> bool:
    """Salva dados em formato JSON"""
    try:
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erro ao salvar JSON: {e}")
        return False

def load_json(filename: str) -> Any:
    """Carrega dados de arquivo JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Erro ao carregar JSON: {e}")
        return None

def save_csv(data: List[Dict], filename: str) -> bool:
    """Salva dados em formato CSV"""
    if not data:
        return False
    
    try:
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return True
    except Exception as e:
        print(f"Erro ao salvar CSV: {e}")
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitiza nome de arquivo removendo caracteres inválidos"""
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    return filename[:255]  # Limita tamanho

if __name__ == '__main__':
    # Testes
    print("=== Teste Utils ===")
    print(f"parse_ip_range('192.168.1.1-5'): {parse_ip_range('192.168.1.1-5')}")
    print(f"parse_ports('22,80,443'): {parse_ports('22,80,443')}")
    print(f"parse_ports('1-100'): {parse_ports('1-100')}")
