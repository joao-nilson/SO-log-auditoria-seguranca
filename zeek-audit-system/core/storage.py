from sqlalchemy import create_engine
from datetime import datetime

class GerenciadorArmazenamento:
    def __init__(self, conexao_db):
        self.engine = create_engine(conexao_db)

    def salvar_logs_processados(self, df, tabela, if_exists='append', save_csv=True):
        if df is None or df.empty:
            print("Nenhum dado para salvar.")
            return
        try:
            df.to_sql(tabela, self.engine, if_exists=if_exists, index=False)
            print(f"Dados salvos com sucesso na tabela {tabela}")
            if save_csv:
                df.to_csv(f"{tabela}.csv", index=False)
                print(f"Dados também salvos em {tabela}.csv")
        except Exception as e:
            print(f"Erro ao salvar dados: {e}")

    def salvar_alertas(self, df_alertas):
        if df_alertas is None or df_alertas.empty:
            print("Nenhum alerta para salvar.")
            return
        df_alertas = df_alertas.copy()
        df_alertas['data_deteccao'] = datetime.now()
        self.salvar_logs_processados(df_alertas, 'alertas_seguranca')
