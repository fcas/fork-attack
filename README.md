# Fork-Attack: Análise de Vulnerabilidades em Bibliotecas de ML

![alt text](resources/logo.jpeg)

**Ferramenta para detecção de falhas de segurança em bibliotecas de aprendizado de máquina (ML)**

## 📌 Visão Geral
Este projeto visa **identificar e analisar vulnerabilidades** em bibliotecas populares de *Machine Learning* (ML), fornecendo:
- Um **conjunto de dados** de vulnerabilidades e falhas e suas correlações.
- **Scripts automatizados** para verificação de dependências inseguras.
- **Relatórios de segurança** baseados em CWE e CVEs.

O objetivo é **ajudar pesquisadores e desenvolvedores** a avaliar riscos em seus projetos e contribuir para um ecossistema de ML mais seguro.

---  
## 🔧 Funcionalidades
✔ **Análise estática de código** (SAST) para detectar vulnerabilidades e falhas comuns, usando Dependabot e CodeQL.  
✔ **Verificação de dependências** desatualizadas ou com falhas conhecidas (CVE e CWE).  
✔ **Geração de relatórios** em CSV. 

---  
## 🚀 Como Usar

### Pré-requisitos
- Python 3.9+
- `pip` (gerenciador de pacotes)

### Instalação
```bash
git clone https://github.com/<>/fork-attack.git
cd fork-attack
poetry install
poetry run python fork_attack/scan.py

# HELP
poetry run python fork_attack/scan.py --help