import os
import logging
from pathlib import Path
from core.collector import iniciar_monitoramento_zeek
from core.processor import ProcessadorLogsSeguranca
from core.analyzer import AnalisadorSeguranca
from core.storage import GerenciadorArmazenamento
from core.alerts import BatchAlertManager
from utils.importa_zeek_logs import importar_log_zeek
from core.storage import GerenciadorArmazenamento
import glob
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_RULES_PATH = os.path.join(BASE_DIR, "config", "alert_rules.yml")


def main():
    INTERFACE_REDE = os.getenv("INTERFACE_REDE", "enp0s3")
    DIRETORIO_LOGS = os.getenv("DIRETORIO_LOGS", "./zeek_logs")
    DB_LOCAL = "/home/davi-monken/Documentos/SO/output.db"

    # Garante que o diretório de logs existe
    Path(DIRETORIO_LOGS).mkdir(parents=True, exist_ok=True)

    # Importa todos os logs do Zeek para o banco antes de processar

    armazenamento = GerenciadorArmazenamento(f"sqlite:///{DB_LOCAL}")
    arquivos_logs = glob.glob(os.path.join(DIRETORIO_LOGS, "*.log"))
    for arquivo in arquivos_logs:
        importar_log_zeek(arquivo, armazenamento)
        print('oi')

    try:
        # 1. Iniciar Zeek
        iniciar_monitoramento_zeek(INTERFACE_REDE, DIRETORIO_LOGS)

        # 2. Processar
        processador = ProcessadorLogsSeguranca(DB_LOCAL, use_pyzeek=False)
        conexoes = processador.carregar_logs('conn')
        if conexoes is None or conexoes.empty:
            logger.error("Nenhum dado de conexão encontrado na tabela 'conn'.")
            return
        # Padroniza nomes das colunas para o formato esperado pelo analisador
        conexoes = conexoes.rename(columns={
            'id_orig_h': 'id.orig_h',
            'id_resp_h': 'id.resp_h',
            'id_orig_p': 'id.orig_p',
            'id_resp_p': 'id.resp_p'
        })

        # Converte colunas de tempo para float
        for col in ['ts', 'duration']:
            if col in conexoes.columns:
                conexoes[col] = pd.to_numeric(conexoes[col], errors='coerce')

        if 'ts' in conexoes.columns:
            conexoes['ts'] = pd.to_datetime(conexoes['ts'], unit='s', errors='coerce')

        # logger.info(f"Colunas disponíveis em 'conn': {list(conexoes.columns)}")  # Removido para não exibir prints

        # 3. Analisar
        analisador = AnalisadorSeguranca()
        anomalias = analisador.detectar_anomalias(conexoes)
        varreduras = analisador.detectar_varredura_portas(conexoes)

        # 4. Alertas
        alert_manager = BatchAlertManager(DB_LOCAL, config_path=ALERT_RULES_PATH)
        alert_manager.run_detections()

        # 5. Armazenar (sempre no banco local)
        armazenamento = GerenciadorArmazenamento(f"sqlite:///{DB_LOCAL}")
        if conexoes is not None and not conexoes.empty:
            armazenamento.salvar_logs_processados(conexoes, 'conexoes_network')
        if anomalias is not None and not anomalias.empty:
            armazenamento.salvar_alertas(anomalias)
        if varreduras is not None and not varreduras.empty:
            armazenamento.salvar_alertas(varreduras)

        logger.info("Sistema de auditoria de segurança executado com sucesso!")
    except Exception as e:
        logger.error(f"Erro na execução do sistema: {e}")

if __name__ == "__main__":
    main()
