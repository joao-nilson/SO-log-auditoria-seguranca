import subprocess
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
"""logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
if not logger.hasHandlers():
    logger.addHandler(handler)"""

def iniciar_monitoramento_zeek(interface_rede: str, diretorio_saida: str) -> Optional[int]:
    """
    Inicia o monitoramento de rede com Zeek e valida se o processo levantou.
    """
    try:
        comando = [
            "zeek",
            "-i", interface_rede,
            "-C",
            "-b",
            "-s", f"{diretorio_saida}/zeek.sqlite"
        ]
        processo = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Zeek iniciado na interface {interface_rede} (PID {processo.pid})")
        return processo.pid
    except Exception as e:
        logger.error(f"Falha ao iniciar Zeek: {e}")
        return None

    """Path(diretorio_saida).mkdir(parents=True, exist_ok=True)
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
        raise"""
