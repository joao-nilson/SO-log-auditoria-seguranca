import matplotlib.pyplot as plt
import seaborn as sns

class GeradorRelatorios:
    @staticmethod
    def gerar_relatorio_conexoes(df_conexoes):
        """Gera visualizações para análise de conexões"""
        plt.figure(figsize=(15, 10))
        
        # Gráfico 1: Top IPs de origem
        plt.subplot(2, 2, 1)
        top_ips = df_conexoes['id.orig_h'].value_counts().head(10)
        sns.barplot(x=top_ips.values, y=top_ips.index)
        plt.title('Top 10 IPs de Origem')
        plt.xlabel('Número de Conexões')
        
        # Gráfico 2: Distribuição de portas
        plt.subplot(2, 2, 2)
        top_portas = df_conexoes['id.resp_p'].value_counts().head(10)
        sns.barplot(x=top_portas.values, y=top_portas.index.astype(str))
        plt.title('Top 10 Portas de Destino')
        plt.xlabel('Número de Conexões')
        
        # Gráfico 3: Conexões ao longo do tempo
        if 'ts' in df_conexoes.columns:
            plt.subplot(2, 1, 2)
            df_conexoes['hora'] = df_conexoes['ts'].dt.floor('H')
            conexoes_por_hora = df_conexoes.groupby('hora').size()
            conexoes_por_hora.plot()
            plt.title('Conexões por Hora')
            plt.ylabel('Número de Conexões')
            plt.xlabel('Hora')
        
        plt.tight_layout()
        plt.savefig('relatorio_conexoes.png')
        plt.close()