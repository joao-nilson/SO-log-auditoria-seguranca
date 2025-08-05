import os
import logging
from pathlib import Path
from core.collector import iniciar_monitoramento_zeek
from core.processor import ProcessadorLogsSeguranca
from core.analyzer import AnalisadorSeguranca
from core.storage import GerenciadorArmazenamento
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test():
    # Configuration - using absolute paths
    BASE_DIR = Path(__file__).parent.absolute()
    
    # Define all paths
    CONFIG = {
        'DIRETORIO_LOGS': BASE_DIR / "zeek_logs",
        'DB_LOCAL': BASE_DIR / "zeek_data" / "output.db",
        'ALERT_RULES': BASE_DIR / "config" / "alert_rules.yml",
        'INTERFACE_REDE': os.getenv("INTERFACE_REDE", "wlp3s0")
    }

    # Ensure directories exist
    CONFIG['DIRETORIO_LOGS'].mkdir(parents=True, exist_ok=True)
    CONFIG['DB_LOCAL'].parent.mkdir(parents=True, exist_ok=True)

    try:
        # 1. Start Zeek monitoring
        logger.info(f"Starting Zeek on interface {CONFIG['INTERFACE_REDE']}")
        iniciar_monitoramento_zeek(
            CONFIG['INTERFACE_REDE'],
            str(CONFIG['DIRETORIO_LOGS'])
        )

        # 2. Initialize processor with automatic DB creation
        logger.info(f"Using database at: {CONFIG['DB_LOCAL']}")
        processor = ProcessadorLogsSeguranca(str(CONFIG['DB_LOCAL']))
        
        # 3. Load connection logs
        conexoes = processor.carregar_logs('conn')
        if conexoes.empty:
            logger.warning("No connection data found. Using sample data...")
            conexoes = pd.DataFrame({
                'ts': [pd.Timestamp.now().timestamp()],
                'id.orig_h': ['192.168.1.1'],
                'id.resp_h': ['8.8.8.8'],
                'proto': ['tcp'],
                'duration': [0.5]
            })

        # 4. Analysis
        analyzer = AnalisadorSeguranca()
        anomalias = analyzer.detectar_anomalias(conexoes)
        
        # 5. Storage
        storage = GerenciadorArmazenamento(f"sqlite:///{CONFIG['DB_LOCAL']}")
        storage.salvar_logs_processados(conexoes, 'conexoes_network')
        
        logger.info("Analysis completed successfully!")

    except Exception as e:
        logger.error(f"System error: {str(e)}", exc_info=True)
        raise

if __name__ == "__test__":
    test()