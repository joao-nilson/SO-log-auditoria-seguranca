import os
import logging
from pathlib import Path
import pandas as pd
from core.collector import iniciar_monitoramento_zeek
from core.processor import ProcessadorLogsSeguranca
from core.analyzer import AnalisadorSeguranca
from core.storage import GerenciadorArmazenamento
from core.alerts import BatchAlertManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = Path(__file__).parent.absolute()
CONFIG = {
    'logs_dir': BASE_DIR / "zeek_logs",
    'db_path': BASE_DIR / "zeek_data" / "output.db",
    'alert_rules': BASE_DIR / "config" / "alert_rules.yml",
    'interface': os.getenv("INTERFACE_REDE", "wlp3s0")
}

def _load_sample_data():
    """Generate sample connection data for testing"""
    from datetime import datetime
    return pd.DataFrame({
        'ts': [datetime.now().timestamp()],
        'uid': ['C123'],
        'id.orig_h': ['192.168.1.1'],
        'id.resp_h': ['8.8.8.8'],
        'id.orig_p': [54321],
        'id.resp_p': [53],
        'proto': ['udp'],
        'duration': [0.1]
    })

def main():
    # Ensure directories exist
    CONFIG['logs_dir'].mkdir(parents=True, exist_ok=True)
    CONFIG['db_path'].parent.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Start Zeek monitoring - CORRECTED CALL
        logger.info(f"Starting Zeek on interface {CONFIG['interface']}")
        iniciar_monitoramento_zeek(
            CONFIG['interface'],  # interface_rede parameter (positional)
            str(CONFIG['logs_dir'])  # diretorio_saida parameter (positional)
        )

        # 2. Initialize processor
        #logger.info(f"Initializing processor with database: {CONFIG['db_path']}")
        processor = ProcessadorLogsSeguranca(
        caminho_db=str(CONFIG['db_path']),
        use_pyzeek=False
    )

        # 3. Load connection logs
        conexoes = processor.carregar_logs('conn')

        conexoes = processor.carregar_logs('conn')
    
        if conexoes is None:  # Explicit None check
            logger.warning("Received None from carregar_logs(), creating empty DataFrame")
            conexoes = pd.DataFrame()  # Create empty DataFrame as fallback
        elif not isinstance(conexoes, pd.DataFrame):  # Type safety check
            logger.warning(f"Unexpected type {type(conexoes)}, converting to DataFrame")
            conexoes = pd.DataFrame(conexoes) if conexoes else pd.DataFrame()


        if conexoes.empty:
            logger.warning("No connection data found. Using sample data...")
            conexoes = _load_sample_data()
            # Save sample data to database
            # Save sample data if processor has the method
            if hasattr(processor, '_save_dataframe'):
                processor._save_dataframe(conexoes, 'conn')
            else:
                logger.warning("Processor lacks _save_dataframe method, sample data not saved")

        # Standardize column names
        conexoes = conexoes.rename(columns={
            'id_orig_h': 'id.orig_h',
            'id_resp_h': 'id.resp_h',
            'id_orig_p': 'id.orig_p',
            'id_resp_p': 'id.resp_p'
        })

        # Convert timestamp columns
        if 'ts' in conexoes.columns:
            conexoes['ts'] = pd.to_datetime(conexoes['ts'], unit='s', errors='coerce')

        # 4. Analyze
        analisador = AnalisadorSeguranca()
        anomalias = analisador.detectar_anomalias(conexoes)
        varreduras = analisador.detectar_varredura_portas(conexoes)

        # 5. Alerts
        alert_manager = BatchAlertManager(
    str(CONFIG['db_path']),  # First argument
    config_path=str(CONFIG['alert_rules'])  # Second argument with correct key name
)

        # 6. Storage
        armazenamento = GerenciadorArmazenamento(f"sqlite:///{CONFIG['db_path']}")
        armazenamento.salvar_logs_processados(conexoes, 'conexoes_network')
        if not anomalias.empty:
            armazenamento.salvar_alertas(anomalias)
        if not varreduras.empty:
            armazenamento.salvar_alertas(varreduras)

        logger.info("Security audit system executed successfully!")

    except Exception as e:
        logger.error(f"System execution error: {e}", exc_info=True)

if __name__ == "__main__":
    main()