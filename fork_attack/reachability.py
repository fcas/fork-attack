import os
import requests
import json
import logging
import time
from datetime import date

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def fetch_and_save_findings(output_file=None):
    # Persisted under today's date, the raw extraction date, following the same
    # convention as the per-repo Dependabot/CodeQL dumps in data/<date>/.
    if output_file is None:
        output_file = f"data/{date.today()}/semgrep_findings.json"

    base_url = f"https://semgrep.dev/api/v1/deployments/{os.environ['SEMGREP_DEPLOYMENT_SLUG']}/findings"

    # SEMGREP_APP_TOKEN is the same token the semgrep.yml workflow's `semgrep
    # ci` step uses; SEMGREP_TOKEN is an alternate name this script also
    # accepts so a shell that already exports one doesn't need the other too.
    token = os.getenv("SEMGREP_TOKEN") or os.getenv("SEMGREP_APP_TOKEN")

    if not token:
        logger.error("Nenhuma das variáveis de ambiente SEMGREP_TOKEN/SEMGREP_APP_TOKEN está definida.")
        return

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Configuração Inicial (Offset Strategy)
    params = {
        "issue_type": "sca",
        "page": 0,        # Página inicial
        "page_size": 100  # Itens por página
    }

    all_findings = []

    logger.info("Iniciando a extração dos findings do Semgrep...")
    logger.info(f"Configuração: page_size={params['page_size']}")

    try:
        while True:
            current_page = params['page']

            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()

            current_findings = data.get('findings', [])
            count = len(current_findings)

            # Lógica de Parada (Offset):
            # Se a lista vier vazia, significa que acabaram as páginas.
            if count == 0:
                logger.info(f"Página {current_page} retornou 0 itens. Paginação finalizada.")
                break

            # Acumula os resultados
            all_findings.extend(current_findings)
            logger.info(f"Página {current_page} processada. {count} itens recebidos. Total acumulado: {len(all_findings)}")

            # Incrementa para a próxima página
            params['page'] += 1

            # Opcional: Pausa para evitar rate limit
            time.sleep(0.2)

        logger.info(f"Escrevendo {len(all_findings)} findings no arquivo '{output_file}'...")

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, ensure_ascii=False, indent=4)

        logger.info(f"Arquivo '{output_file}' salvo com sucesso.")

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao acessar a API: {e}")
        if e.response is not None:
            logger.error(f"Detalhes da resposta: {e.response.text}")
    except Exception as e:
        logger.error(f"Ocorreu um erro inesperado: {e}")

def fetch_and_save_sast_findings(output_file=None):
    """Same pagination/auth as fetch_and_save_findings, but issue_type=sast:
    Semgrep Code's SAST findings, used in this study only for the hard-coded
    credentials use case (Section "Semgrep SAST Findings")."""
    if output_file is None:
        output_file = f"data/{date.today()}/semgrep_sast_findings.json"

    base_url = f"https://semgrep.dev/api/v1/deployments/{os.environ['SEMGREP_DEPLOYMENT_SLUG']}/findings"

    token = os.getenv("SEMGREP_TOKEN") or os.getenv("SEMGREP_APP_TOKEN")

    if not token:
        logger.error("Nenhuma das variáveis de ambiente SEMGREP_TOKEN/SEMGREP_APP_TOKEN está definida.")
        return

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    params = {
        "issue_type": "sast",
        "page": 0,
        "page_size": 100
    }

    all_findings = []

    logger.info("Iniciando a extração dos findings SAST do Semgrep...")

    try:
        while True:
            current_page = params['page']

            response = requests.get(base_url, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()

            current_findings = data.get('findings', [])
            count = len(current_findings)

            if count == 0:
                logger.info(f"Página {current_page} retornou 0 itens. Paginação finalizada.")
                break

            all_findings.extend(current_findings)
            logger.info(f"Página {current_page} processada. {count} itens recebidos. Total acumulado: {len(all_findings)}")

            params['page'] += 1
            time.sleep(0.2)

        logger.info(f"Escrevendo {len(all_findings)} findings SAST no arquivo '{output_file}'...")

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, ensure_ascii=False, indent=4)

        logger.info(f"Arquivo '{output_file}' salvo com sucesso.")

    except requests.exceptions.HTTPError as e:
        logger.error(f"Erro HTTP ao acessar a API: {e}")
        if e.response is not None:
            logger.error(f"Detalhes da resposta: {e.response.text}")
    except Exception as e:
        logger.error(f"Ocorreu um erro inesperado: {e}")


if __name__ == "__main__":
    fetch_and_save_findings()
    fetch_and_save_sast_findings()