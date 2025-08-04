import pandas as pd
import sqlite3
from datetime import datetime
from typing import Optional, Dict

class ProcessadorLogsSeguranca:
    def __init__(self, caminho_db, use_pyzeek=False):
        self.caminho_db = caminho_db
        self.use_pyzeek = use_pyzeek
        self.tipos_logs = self._detectar_tipos_logs()

    def _detectar_tipos_logs(self):
        try:
            conn = sqlite3.connect(self.caminho_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tipos = [tipo[0] for tipo in cursor.fetchall()]
            conn.close()
            return tipos
        except Exception as e:
            print(f"[Processor] Erro ao detectar tipos de logs: {e}")
            return []

    def carregar_logs(self, tipo_log: str, filtros: Optional[Dict] = None):
        if self.use_pyzeek:
            return self._carregar_com_pyzeek(tipo_log, filtros)
        else:
            return self._carregar_com_sqlite(tipo_log, filtros)

    def _carregar_com_sqlite(self, tipo_log, filtros):
        if tipo_log not in self.tipos_logs:
            print(f"[Processor] Tipo de log {tipo_log} não encontrado no DB ({self.tipos_logs})")
            return pd.DataFrame()
        try:
            conn = sqlite3.connect(self.caminho_db)
            query = f"SELECT * FROM {tipo_log}"
            params = []
            if filtros:
                conds = []
                for campo, valor in filtros.items():
                    if isinstance(valor, (list, tuple)):
                        placeholders = ",".join("?" for _ in valor)
                        conds.append(f"{campo} IN ({placeholders})")
                        params.extend(valor)
                    else:
                        conds.append(f"{campo} = ?")
                        params.append(valor)
                query += " WHERE " + " AND ".join(conds)
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            # conversão simples de timestamps
            for col in df.columns:
                if col.startswith("ts") and pd.api.types.is_numeric_dtype(df[col]):
                    df[col] = pd.to_datetime(df[col], unit="s", errors="coerce")
            return df
        except Exception as e:
            print(f"[Processor] Erro ao carregar logs SQLite: {e}")
            return pd.DataFrame()
