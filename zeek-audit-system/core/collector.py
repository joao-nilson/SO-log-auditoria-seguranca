import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
if not logger.hasHandlers():
    logger.addHandler(handler)

def iniciar_monitoramento_zeek(interface_rede: str, diretorio_saida: str):
    """
    Inicia o monitoramento de rede com Zeek e valida se o processo levantou.
    """
    Path(diretorio_saida).mkdir(parents=True, exist_ok=True)
    # Ajuste o comando conforme seu ambiente/plugin
    comando = [
        "zeek", "-i", interface_rede, "-C", "-b"
        # Adicione flags/plugins para SQLite se necessário
    ]
    try:
        proc = subprocess.Popen(comando, cwd=diretorio_saida, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Monitoramento Zeek iniciado na interface {interface_rede} (PID {proc.pid})")
        return proc
    except Exception as e:
        logger.error(f"Erro ao iniciar Zeek: {e}")
        raise
