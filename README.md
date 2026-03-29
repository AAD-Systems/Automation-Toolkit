# 🐍 Python Security Toolkit

Um toolkit modular para automatização de tarefas de segurança, reconhecimento e exploração de redes.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Pages](https://img.shields.io/badge/GitHub-Pages-green.svg)](https://security-labor.github.io/Automation-Toolkit/)
![Educational Purpose Only](https://img.shields.io/badge/purpose-educational-brightgreen)
![Not For Production](https://img.shields.io/badge/production-unsafe-red)


## 📋 Índice

- [Sobre o Projeto](#sobre-o-projeto)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Ferramentas](#ferramentas)
  - [Scanner TCP Simples](#scanner-tcp-simples)
  - [Scanner Multi-thread](#scanner-multi-thread)
- [Roadmap](#roadmap)
- [Contribuição](#contribuição)
- [Licença](#licença)
- [Aviso Legal](#aviso-legal)

## 🎯 Sobre o Projeto

Este projeto é um laboratório educacional para desenvolvimento de ferramentas de segurança em Python. Cada ferramenta é construída com foco em:

- Código limpo e modular
- Logging profissional
- Tratamento robusto de erros
- Performance otimizada
- Documentação completa

**🌐 Landing Page Oficial:** [https://security-labor.github.io/Automation-Toolkit/](https://security-labor.github.io/Automation-Toolkit/)

## 📁 Estrutura do Projeto

```

automation-toolkit/
├── base/                          # Módulos fundamentais
│   ├── init.py
│   ├── tcp_scanner_simple.py      # Scanner TCP básico
│   ├── multi_thread_scanner.py    # Scanner com threads
│   ├── logger.py                  # Sistema de logging
│   ├── utils.py                   # Utilitários comuns
│   └── requirements.txt           # Dependências
├── recon/                         # Ferramentas de recon (em desenvolvimento)
├── exploits/                      # Módulos de exploração (em desenvolvimento)
├── network/                       # Ferramentas de rede (em desenvolvimento)
├── logs/                          # Diretório para arquivos de log
├── outputs/                       # Resultados de scans
└── README.md

```

## 🔧 Pré-requisitos

- Python 3.8 ou superior
- Pip (gerenciador de pacotes Python)
- Acesso root (para algumas funcionalidades de rede)

## 📦 Instalação

```bash
# Clone o repositório
git clone https://github.com/Security-Labor/Automation-Toolkit.git
cd Automation-Toolkit

# Instale as dependências
pip install -r base/requirements.txt

# Dê permissão de execução (opcional)
chmod +x base/*.py
```

🛠️ Ferramentas

Scanner TCP Simples

Scanner básico para identificação de portas abertas.

```bash
# Escaneia portas específicas
python base/tcp_scanner_simple.py 192.168.1.1 -p 80,443,8080

# Escaneia range de portas
python base/tcp_scanner_simple.py 192.168.1.1 -p 1-1000 -t 0.5 -v

# Salva resultado em JSON
python base/tcp_scanner_simple.py google.com -p 80,443 -o resultados.json
```

Parâmetros:

Parâmetro Descrição Default
```target IP ou hostname alvo Obrigatório
-p, --ports Portas para escanear (ex: 80,443 ou 1-1000) 1-1024
-t, --timeout Timeout em segundos 1.0
-o, --output Arquivo de saída (.json ou .csv) None
-v, --verbose Modo detalhado False
```
Scanner Multi-thread

Scanner de alta performance com suporte a múltiplas threads.

```bash
# Scan rápido com 200 threads
python base/multi_thread_scanner.py 192.168.1.1 -p 1-1000 -T 200 -v

# Scan completo com salvamento
python base/multi_thread_scanner.py target.com -p 1-65535 -o full_scan.json -T 500

# Scan com timeout reduzido
python base/multi_thread_scanner.py 10.0.0.1 -p 1-10000 -t 0.3 -T 300
```

Parâmetros:

Parâmetro Descrição Default
target IP ou hostname alvo Obrigatório
```bash
-p, --ports Portas para escanear 1-1024
-t, --timeout Timeout em segundos 1.0
-T, --threads Número de threads 100
-o, --output Arquivo de saída (.json) None
-v, --verbose Modo detalhado False
```
Utilitários

Teste os módulos utilitários:

```bash
# Testa sistema de logging
python base/logger.py

# Testa funções utilitárias
python base/utils.py
```

📊 Exemplos de Saída

Console (JSON formatado)

```json
{
  "target": "192.168.1.1",
  "scan_date": "2026-03-28 14:30:22",
  "total_open_ports": 5,
  "open_ports": [
    {"port": 22, "service": "SSH"},
    {"port": 80, "service": "HTTP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 3306, "service": "MySQL"},
    {"port": 8080, "service": "HTTP-Alt"}
  ]
}
```

Console (formatado)

```
============================================================
RELATÓRIO DE SCAN - 192.168.1.1
============================================================
PORTA      SERVIÇO          STATUS    
------------------------------------------------------------
22         SSH              open      
80         HTTP             open      
443        HTTPS            open      
3306       MySQL            open      
8080       HTTP-Alt         open      
============================================================
```

🗺️ Roadmap

Fase 1: Fundamentos ✅ (40h)

· Sockets e networking básico
· Scanner TCP simples
· Scanner multi-thread
· Sistema de logging
· Utilitários de parsing

Fase 2: Reconhecimento (40h)

· DNS enumeration
· Subdomain discovery
· Web crawling
· Service fingerprinting
· Banner grabbing

Fase 3: Exploits (60h)

· Buffer overflow exploits
· SQL injection automation
· Command injection
· Custom exploit development

Fase 4: Ferramentas de Rede (60h)

· Packet crafting (Scapy)
· ARP spoofing
· Network sniffing
· MITM framework

🤝 **Contribuição**

Contribuições são bem-vindas! Siga os passos:

1. Fork o projeto
2. Crie sua branch (git checkout -b feature/AmazingFeature)
3. Commit suas mudanças (git commit -m 'Add some AmazingFeature')
4. Push para a branch (git push origin feature/AmazingFeature)
5. Abra um Pull Request

**Padrões de código:**

· Use type hints
· Documente funções com docstrings
· Siga PEP 8
· Inclua exemplos de uso

📝 **Licença**

Distribuído sob a licença Apache 2.0. Veja LICENSE para mais informações.

⚠️ **Aviso Legal**

Este projeto é apenas para fins educacionais!

**O uso destas ferramentas para atividades maliciosas é estritamente proibido. Você é responsável por cumprir todas as leis aplicáveis e obter autorização apropriada antes de realizar qualquer teste de segurança.**

· ✅ Use apenas em sistemas que você possui autorização para testar
· ✅ Respeite leis locais e internacionais
· ✅ Pratique em ambientes controlados (VMs, CTF, labs)
· ❌ **Não utilize para ataques não autorizados**

📚 Referências

· Python Socket Programming
· OWASP Testing Guide
· Nmap Network Scanning

📞 **Contato**

URSA UNIVERSITY - @ursa_university - suporteursauniversity.tech@gmail.com

🔗 **Links:**

· GitHub: https://github.com/Security-Labor/Automation-Toolkit
· Landing Page: https://security-labor.github.io/Automation-Toolkit/

---

⭐️ **Dê uma estrela se este projeto foi útil!**

```├── exploits/                      # Módulos de exploração (em desenvolvimento)
├── network/                       # Ferramentas de rede (em desenvolvimento)
├── logs/                          # Diretório para arquivos de log
├── outputs/                       # Resultados de scans
└── README.md

```
