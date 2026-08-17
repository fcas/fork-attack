import typer
from estige import main as estige_run
from reachability import fetch_and_save_findings, fetch_and_save_sast_findings
from analysis import main as analysis_run
from scrap import main as scrap_run
from time_machine import main as time_machine_run


def main():
    # Estige é o rio da invulnerabilidade na mitologia Grega. Este scrip varre
    # os repositórios listados no arquivo settings.py para verificar se de
    # fato estão invulneráveis, para isso, todos os repos são bifurcados
    # e parametrizados para executar análise estática usando CodeQL e Dependabot.
    # O resultado da análise estática é armazenado no diretório /data.
    estige_run()
    # Semgrep Supply Chain roda por fora do GitHub Actions (API própria da
    # Semgrep), então precisa ser buscado explicitamente aqui -- analysis.py/
    # scrap.py/time_machine.py só devem processar depois que as três fontes
    # (Dependabot, CodeQL, Semgrep) já estiverem coletadas para a mesma data.
    fetch_and_save_findings()
    # Semgrep Code's SAST findings are used only for the hard-coded-secrets
    # use case (Section "Semgrep SAST Findings"), same rationale as above:
    # fetched here via Semgrep's own API, not GitHub Actions.
    fetch_and_save_sast_findings()
    # Os arquivos brutos do /data são sumarizados por severidade, gerando as
    # listas de CWE/CVE (code_analysis_cwe_*.csv, dependabot_cve_*.csv) que
    # o scrap.py precisa como entrada -- por isso corre antes dele.
    analysis_run()
    # A partir dessas listas, os relacionamentos internos dos CWEs (hierarquia
    # ChildOf/ParentOf/etc.) são obtidos raspando cwe.mitre.org.
    scrap_run()
    # Por último, o time_machine.py faz uma análise retroativa para mapear
    # os resultados das análises com as bibliotecas e repositórios parametrizados.
    time_machine_run()


if __name__ == "__main__":
    typer.run(main)
