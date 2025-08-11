import pandas as pd

class AnalisadorSeguranca:
    @staticmethod
    def detectar_anomalias(df_conexoes: pd.DataFrame) -> pd.DataFrame:
        alertas = []

        if df_conexoes is None or df_conexoes.empty:
            return pd.DataFrame()

        # 1. Alta frequência
        freq_ips = df_conexoes['id_orig_h'].value_counts()
        limiar = freq_ips.quantile(0.9)
        ips_suspeitos = freq_ips[freq_ips > limiar].index.tolist()
        for ip in ips_suspeitos:
            alertas.append({
                "tipo": "alta_frequencia",
                "id_orig_h": ip,
                "descricao": f"IP com frequência alta: {ip}"
            })

        # 2. Portas incomuns
        portas_comuns = [80, 443, 22, 53]
        if 'id_resp_p' in df_conexoes.columns:
            estranhas = df_conexoes[~df_conexoes['id_resp_p'].isin(portas_comuns)]
            for _, row in estranhas.iterrows():
                alertas.append({
                    "tipo": "porta_incomum",
                    "id_orig_h": row.get('id_orig_h'),
                    "id_resp_p": row.get('id_resp_p'),
                    "descricao": f"Conexão para porta incomum: {row.get('id_resp_p')}"
                })

        # 3. Durações anormais
        if 'duration' in df_conexoes.columns:
            q1 = df_conexoes['duration'].quantile(0.25)
            q3 = df_conexoes['duration'].quantile(0.75)
            iqr = q3 - q1
            limite = q3 + 2 * iqr
            anormais = df_conexoes[df_conexoes['duration'] > limite]
            for _, row in anormais.iterrows():
                alertas.append({
                    "tipo": "duracao_anormal",
                    "id_orig_h": row.get('id_orig_h'),
                    "duration": row.get('duration'),
                    "descricao": f"Duração anormal: {row.get('duration'):.2f}s"
                })

        # 4. Quantidade de pacotes anormal
        if 'resp_pkts' in df_conexoes.columns:
            df_conexoes['resp_pkts'] = pd.to_numeric(df_conexoes['resp_pkts'], errors='coerce')
            q1 = df_conexoes['resp_pkts'].quantile(0.25)
            q3 = df_conexoes['resp_pkts'].quantile(0.75)
            iqr = q3 - q1
            limite = q3 + 2 * iqr
            anormais = df_conexoes[df_conexoes['resp_pkts'] > limite]
            for _, row in anormais.iterrows():
                alertas.append({
                    "tipo": "resp_pkts_anormal",
                    "id_orig_h": row.get('id_orig_h'),
                    "resp_pkts": row.get('resp_pkts'),
                    "descricao": f"Quantidade de pacotes anormal: {row.get('resp_pkts')}"
                })

        return pd.DataFrame(alertas)

    @staticmethod
    def detectar_varredura_portas(df_conexoes: pd.DataFrame) -> pd.DataFrame:
        if df_conexoes is None or df_conexoes.empty:
            return pd.DataFrame()
        varreduras = df_conexoes.groupby('id_orig_h')['id_resp_p'].nunique().reset_index()
        varreduras.columns = ['ip_origem', 'portas_unicas']
        suspeitos = varreduras[varreduras['portas_unicas'] > 10].copy()
        suspeitos['tipo'] = 'varredura_portas'
        return suspeitos
