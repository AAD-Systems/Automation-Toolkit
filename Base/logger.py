#!/usr/bin/env python3
"""
Advanced Security Logging Module
Projetado para resiliência, rotação de arquivos e integridade forense.
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# 

class LogColors:
    """Suporte a cores ANSI com detecção de compatibilidade básica."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'

    @staticmethod
    def supports_color() -> bool:
        """Verifica se o terminal suporta cores (evita caracteres estranhos em logs puros)."""
        return sys.stdout.isatty() and os.environ.get('TERM') != 'dumb'

class SecurityFormatter(logging.Formatter):
    """Formatter com metadados detalhados para análise forense."""
    
    COLORS = {
        'DEBUG': LogColors.GRAY,
        'INFO': LogColors.GREEN,
        'WARNING': LogColors.YELLOW,
        'ERROR': LogColors.RED,
        'CRITICAL': LogColors.BOLD + LogColors.RED,
    }

    def format(self, record):
        # Adiciona o nome do processo/thread para logs concorrentes
        record.process_info = f"{record.processName}:{record.threadName}"
        log_message = super().format(record)
        
        if LogColors.supports_color():
            color = self.COLORS.get(record.levelname, LogColors.RESET)
            return f"{color}{log_message}{LogColors.RESET}"
        return log_message

def setup_logger(
    name: str, 
    log_file: Optional[str] = None, 
    verbose: bool = False,
    max_size_mb: int = 10,
    backup_count: int = 5
) -> logging.Logger:
    """
    Configura logger de alta disponibilidade.
    
    Args:
        max_size_mb: Tamanho máximo por arquivo para evitar DoS de disco.
        backup_count: Quantidade de arquivos históricos para manter.
    """
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(logging.DEBUG) # Base sempre debug, handlers filtram

    # Formato Forense: Data | Nível | Processo | Mensagem
    format_str = '%(asctime)s | %(levelname)-8s | [%(process_info)s] | %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # 1. Console Handler (Foco em legibilidade)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(SecurityFormatter(format_str, date_format))
    logger.addHandler(console_handler)

    # 2. File Handler (Foco em integridade e persistência)
    if log_file:
        try:
            log_path = Path(log_file).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # ROTAÇÃO: Evita estouro de disco e facilita análise de logs antigos
            file_handler = RotatingFileHandler(
                log_path, 
                maxBytes=max_size_mb * 1024 * 1024, 
                backupCount=backup_count, 
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG) # Arquivo sempre grava tudo
            file_handler.setFormatter(logging.Formatter(format_str, date_format))
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Falha Crítica ao configurar arquivo de log: {e}")

    return logger

# Singleton para a ferramenta
log = setup_logger('security_core', 'logs/security_audit.log', verbose=True)

if __name__ == '__main__':
    log.info("Iniciando auditoria de sistema...")
    log.debug("Checando dependências ocultas...")
    log.warning("Tentativa de acesso não autorizada detectada (Simulação)")
    log.error("Falha ao resolver host remoto.")
    
