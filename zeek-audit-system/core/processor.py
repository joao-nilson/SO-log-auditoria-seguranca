import pandas as pd
from utils import time_utils, log_formatter
import sqlite3
import pandas as pd
from datetime import datetime
#nao usando pyzeek
"""class ProcessadorLogsSeguranca:
    def __init__(self, caminho_db):
        self.caminho_db = caminho_db
        self.tipos_logs = self._detectar_tipos_logs()
        
    def _detectar_tipos_logs(self):
        """Detecta automaticamente os tipos de logs disponíveis"""
        try:
            conn = sqlite3.connect(self.caminho_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tipos = [tipo[0] for tipo in cursor.fetchall()]
            conn.close()
            return tipos
        except Exception as e:
            print(f"Erro ao detectar tipos de logs: {e}")
            return []
    
    def carregar_logs(self, tipo_log, filtros=None):
        """
        Carrega logs com possibilidade de filtros avançados
        :param tipo_log: Tipo de log (conn, http, dns, etc.)
        :param filtros: Dicionário com filtros {campo: valor}
        """
        if tipo_log not in self.tipos_logs:
            raise ValueError(f"Tipo de log {tipo_log} não encontrado")
            
        try:
            conn = sqlite3.connect(self.caminho_db)
            query = f"SELECT * FROM {tipo_log}"
            
            # Aplicar filtros se existirem
            if filtros:
                conditions = []
                for campo, valor in filtros.items():
                    if isinstance(valor, (list, tuple)):
                        conditions.append(f"{campo} IN ({','.join(['?']*len(valor))})")
                    else:
                        conditions.append(f"{campo} = ?")
                query += " WHERE " + " AND ".join(conditions)
                
                valores = []
                for valor in filtros.values():
                    if isinstance(valor, (list, tuple)):
                        valores.extend(valor)
                    else:
                        valores.append(valor)
                
                df = pd.read_sql_query(query, conn, params=valores)
            else:
                df = pd.read_sql_query(query, conn)
                
            conn.close()
            
            # Converter timestamps
            colunas_tempo = [col for col in df.columns if col.startswith('ts')]
            for col in colunas_tempo:
                if pd.api.types.is_numeric_dtype(df[col]):
                    df[col] = pd.to_datetime(df[col], unit='s')
            
            return df
        
        except Exception as e:
            print(f"Erro ao carregar logs: {e}")
            return None
"""
#usando pyzeek
class ProcessadorLogsSeguranca:
    def __init__(self, caminho_db, use_pyzeek=False):
        self.caminho_db = caminho_db
        self.use_pyzeek = use_pyzeek
        self.tipos_logs = self._detectar_tipos_logs()
        
    def carregar_logs(self, tipo_log, filtros=None):
        if self.use_pyzeek:
            return self._carregar_com_pyzeek(tipo_log, filtros)
        else:
            return self._carregar_com_sqlite(tipo_log, filtros)
    
    def _carregar_com_pyzeek(self, tipo_log, filtros):
        from pyzeek import LogReader
        import pandas as pd
        
        logs = []
        log_file = f"{self.caminho_db}/{tipo_log}.log"
        
        try:
            for entry in LogReader(log_file):
                if self._aplicar_filtros(entry, filtros):
                    logs.append(entry)
            return pd.DataFrame(logs)
        except Exception as e:
            print(f"Erro ao ler logs com PyZeek: {e}")
            return None
    
    def _aplicar_filtros(self, entry, filtros):
        if not filtros:
            return True
            
        for campo, valor in filtros.items():
            if campo not in entry:
                return False
            if isinstance(valor, (list, tuple)):
                if entry[campo] not in valor:
                    return False
            elif entry[campo] != valor:
                return False
        return True