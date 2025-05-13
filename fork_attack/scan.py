import typer
from scrap import main as scrap_run
from estige import main as estige_run
from analysis import main as analysis_run
from time_machine import main as time_machine_run


def main():
    # Estige é o rio da invulnerabilidade na mitologia Grega. Este scrip varre
    # os repositórios listados no arquivo settings.py para verificar se de
    # fato estão invulneráveis, para isso, todos os repos são bifurcados
    # e parametrizados para executar análise estática usando CodeQL e Dependabot.
    # O resultado da análise estática é armazenado no diretório /data.
    estige_run()
    # Após a parametrização, os arquivos do /data são usados para extrair
    # as informações do CWE. Os relacionamentos internos dos CWEs são obtidos
    # conforme os CVEs e CWEs identificados pelo estige.py
    scrap_run()
    # Após a extração de CWEs e CVEs as informações são sumarizadas.
    analysis_run()
    # Por último, o time_machine.py faz uma análise retroativa para mapear
    # os resultados das análises com as bibliotecas e repositórios parametrizados.
    time_machine_run()


if __name__ == "__main__":
    typer.run(main)
