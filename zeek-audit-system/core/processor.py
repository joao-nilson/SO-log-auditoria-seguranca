import pandas as pd
import sqlite3
from datetime import datetime
from typing import Optional, Dict, Optional, Union
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ProcessadorLogsSeguranca:
    def __init__(self, caminho_db: str, use_pyzeek: bool =False):
        self.caminho_db = str(Path(caminho_db).absolute())
        self.use_pyzeek = use_pyzeek
        self._initialize_database()
        self.tipos_logs = self._detectar_tipos_logs()

    def _initialize_database(self):
        """Ensure database exists with proper schema"""
        db_path = Path(self.caminho_db)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Essential Zeek tables schema
        schemas = {
            'conn': """
                CREATE TABLE IF NOT EXISTS conn (
                    ts REAL, uid TEXT, 
                    id_orig_h TEXT, id_resp_h TEXT,
                    id_orig_p INTEGER, id_resp_p INTEGER,
                    proto TEXT, duration REAL
                )
            """,
            'http': """
                CREATE TABLE IF NOT EXISTS http (
                    ts REAL, uid TEXT,
                    id_orig_h TEXT, id_resp_h TEXT,
                    method TEXT, host TEXT, uri TEXT
                )
            """
        }

        conn = sqlite3.connect(self.caminho_db)
        try:
            for table, schema in schemas.items():
                conn.execute(schema)
            conn.commit()
        finally:
            conn.close()

    def _verify_db_path(self, path):
        """Ensure database exists or create empty one"""
        path = Path(path).absolute()
        
        if not path.exists():
            logger.warning(f"Database not found at {path}, creating empty database")
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conn (
                    ts REAL, uid TEXT, 
                    'id.orig_h' TEXT, 'id.resp_h' TEXT,
                    'id.orig_p' INTEGER, 'id.resp_p' INTEGER,
                    proto TEXT, duration REAL
                )
            """)
            conn.commit()
            conn.close()
            
        return str(path)

    def _detectar_tipos_logs(self):
        try:
            if not Path(self.caminho_db).exists():
                raise FileNotFoundError(f"Database file not found: {self.caminho_db}")

            conn = sqlite3.connect(self.caminho_db)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tipos = [tipo[0] for tipo in cursor.fetchall()]
            conn.close()

            if not tipos:
                logger.warning(f"Database exists but contains no tables: {self.caminho_db}")

            return tipos

        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return []


            """
        except Exception as e:
            print(f"[Processor] Erro ao detectar tipos de logs: {e}")
            return []"""

    def carregar_logs(self, tipo_log: str, filtros: Optional[Dict] = None)-> pd.DataFrame:
        try:
            if tipo_log not in self.tipos_logs:
                logger.warning(f"Table {tipo_log} not found")
                return pd.DataFrame()  # Return empty instead of None

            # Your existing query logic...
            conn = sqlite3.connect(self.caminho_db)
            df = pd.read_sql_query(f"SELECT * FROM {tipo_log}", conn)
            conn.close()
            
            return df if not df.empty else pd.DataFrame()  # Ensure not None
    
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return pd.DataFrame()  # Fallback to empty DataFrame

    def _save_dataframe(self, df: pd.DataFrame, table_name: str) -> bool:
        """
        Save a DataFrame to the database
        
        Args:
            df: DataFrame to save
            table_name: Target table name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if df.empty:
                logger.warning(f"Not saving empty DataFrame to {table_name}")
                return False
                
            conn = sqlite3.connect(self.caminho_db)
            df.to_sql(
                name=table_name,
                con=conn,
                if_exists='append',  # Append to existing data
                index=False
            )
            conn.close()
            logger.info(f"Saved {len(df)} records to {table_name}")
            return True
        except Exception as e:
            logger.error(f"Error saving to {table_name}: {e}")
            return False

    def _initialize_table(self, table_name: str, sample_df: pd.DataFrame):
        """Create a new table based on DataFrame structure"""
        conn = sqlite3.connect(self.caminho_db)
        
        # Generate CREATE TABLE statement
        col_defs = []
        for col, dtype in sample_df.dtypes.items():
            sql_type = {
                'object': 'TEXT',
                'int64': 'INTEGER',
                'float64': 'REAL',
                'datetime64[ns]': 'REAL'
            }.get(str(dtype), 'TEXT')
            col_defs.append(f"'{col}' {sql_type}")
        
        create_sql = f"CREATE TABLE {table_name} ({', '.join(col_defs)})"
        conn.execute(create_sql)
        conn.commit()
        conn.close()
        
        # Refresh known tables
        self.tipos_logs = self._detectar_tipos_logs()
        
    def load_logs(self, log_type: str, time_range: Optional[tuple] = None) -> pd.DataFrame:
        """
        Load logs from database
        
        Args:
            log_type: Type of log to load (conn, http, dns, etc.)
            time_range: Optional tuple of (start_time, end_time) as datetime objects
            
        Returns:
            DataFrame containing log entries
        """
        if log_type not in self.log_types:
            logger.error(f"Log type {log_type} not found in database")
            return pd.DataFrame()
            
        try:
            query = f"SELECT * FROM {log_type}"
            params = []
            
            if time_range:
                start_dt, end_dt = time_range
                query += " WHERE ts BETWEEN ? AND ?"
                params.extend([start_dt.timestamp(), end_dt.timestamp()])
                
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query(query, conn, params=params if params else None)
            conn.close()
            
            # Convert timestamp columns
            ts_cols = [col for col in df.columns if col.startswith('ts')]
            for col in ts_cols:
                if pd.api.types.is_numeric_dtype(df[col]):
                    df[col] = pd.to_datetime(df[col], unit='s')
                    
            return df
            
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return pd.DataFrame()
    
    def get_connection_stats(self) -> Dict[str, Union[int, float]]:
        """
        Get basic connection statistics
        
        Returns:
            Dictionary of connection statistics
        """
        stats = {}
        try:
            if 'conn' not in self.log_types:
                return stats
                
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get total connections
            cursor.execute("SELECT COUNT(*) FROM conn")
            stats['total_connections'] = cursor.fetchone()[0]
            
            # Get unique IPs
            cursor.execute("SELECT COUNT(DISTINCT `id.orig_h`) FROM conn")
            stats['unique_source_ips'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT `id.resp_h`) FROM conn")
            stats['unique_dest_ips'] = cursor.fetchone()[0]
            
            conn.close()
            return stats
            
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}

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
