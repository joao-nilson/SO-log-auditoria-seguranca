from sqlalchemy import create_engine

class GerenciadorArmazenamento:
    def __init__(self, conexao_db):
        """
        :param conexao_db: String de conexão (ex: 'postgresql://user:pass@localhost/db')
        """
        self.engine = create_engine(conexao_db)
        
    def salvar_logs_processados(self, df, tabela, if_exists='append'):
        """
        Salva logs processados em banco de dados central
        :param df: DataFrame com logs
        :param tabela: Nome da tabela de destino
        :param if_exists: Comportamento se tabela existir ('fail', 'replace', 'append')
        """
        try:
            df.to_sql(tabela, self.engine, if_exists=if_exists, index=False)
            print(f"Dados salvos com sucesso na tabela {tabela}")
        except Exception as e:
            print(f"Erro ao salvar dados: {e}")
    
    def salvar_alertas(self, df_alertas):
        """Salva alertas de segurança em tabela dedicada"""
        if not df_alertas.empty:
            df_alertas['data_deteccao'] = datetime.now()
            self.salvar_logs_processados(df_alertas, 'alertas_seguranca')