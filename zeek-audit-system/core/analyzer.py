from config import alert_rules

class AnalisadorSeguranca:
    @staticmethod
    def detectar_anomalias(df_conexoes):
        """
        Detecta conexões anômalas com base em limiares estatísticos
        :return: DataFrame com conexões anômalas
        """
        anomalias = []
        
        # 1. Conexões com alta frequência
        freq_ips = df_conexoes['id.orig_h'].value_counts()
        ips_suspeitos = freq_ips[freq_ips > freq_ips.quantile(0.99)].index
        anomalias.extend(ips_suspeitos.tolist())
        
        # 2. Portas incomuns
        portas_comuns = [80, 443, 22, 53]
        conexoes_portas_estranhas = df_conexoes[~df_conexoes['id.resp_p'].isin(portas_comuns)]
        if not conexoes_portas_estranhas.empty:
            anomalias.extend(conexoes_portas_estranhas.to_dict('records'))
        
        # 3. Durações anormais
        if 'duration' in df_conexoes.columns:
            q1 = df_conexoes['duration'].quantile(0.25)
            q3 = df_conexoes['duration'].quantile(0.75)
            iqr = q3 - q1
            limite = q3 + 3*iqr
            duracoes_anormais = df_conexoes[df_conexoes['duration'] > limite]
            if not duracoes_anormais.empty:
                anomalias.extend(duracoes_anormais.to_dict('records'))
        
        return pd.DataFrame(anomalias)
    
    @staticmethod
    def detectar_varredura_portas(df_conexoes):
        """
        Detecta possíveis varreduras de portas
        :return: DataFrame com IPs suspeitos
        """
        # Agrupar por IP origem e contar portas únicas acessadas
        varreduras = df_conexoes.groupby('id.orig_h')['id.resp_p'].nunique().reset_index()
        varreduras.columns = ['ip_origem', 'portas_unicas']
        
        # Considerar suspeito quem acessou mais de 10 portas diferentes
        suspeitos = varreduras[varreduras['portas_unicas'] > 10]
        return suspeitos