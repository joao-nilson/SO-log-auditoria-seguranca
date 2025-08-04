import os
import logging
from core.collector import iniciar_monitoramento_zeek
from core.processor import ProcessadorLogsSeguranca
from core.analyzer import AnalisadorSeguranca
from core.storage import GerenciadorArmazenamento
from core.alerts import BatchAlertManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    INTERFACE_REDE = os.getenv("INTERFACE_REDE", "eth0")
    DIRETORIO_LOGS = os.getenv("DIRETORIO_LOGS", "./logs")
    DB_LOCAL = f"{DIRETORIO_LOGS}/zeek.sqlite"
    DB_CENTRAL = os.getenv("DB_CENTRAL", "sqlite:///auditoria_local.db")  # pode ser PostgreSQL via URL

    # 1. Iniciar Zeek
    iniciar_monitoramento_zeek(INTERFACE_REDE, DIRETORIO_LOGS)

    # 2. Processar
    processador = ProcessadorLogsSeguranca(DB_LOCAL, use_pyzeek=False)
    conexoes = processador.carregar_logs('conn')
    
    # 3. Analisar
    analisador = AnalisadorSeguranca()
    anomalias = analisador.detectar_anomalias(conexoes)
    varreduras = analisador.detectar_varredura_portas(conexoes)

    # 4. Alertas
    alert_manager = BatchAlertManager(DB_LOCAL)
    # Ex: alimentar o alert_manager com regras e executar detecções
    alert_manager.run_detections()

    # 5. Armazenar
    armazenamento = GerenciadorArmazenamento(DB_CENTRAL)
    if conexoes is not None:
        armazenamento.salvar_logs_processados(conexoes, 'conexoes_network')
    if not anomalias.empty:
        armazenamento.salvar_alertas(anomalias)
    if not varreduras.empty:
        armazenamento.salvar_alertas(varreduras)

    logger.info("Sistema de auditoria de segurança executado com sucesso!")

if __name__ == "__main__":
    main()
