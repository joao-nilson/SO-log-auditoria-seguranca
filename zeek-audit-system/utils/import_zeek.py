import pandas as pd
import sqlite3
import glob
import os

def importar_zeek_conn_logs_para_db(pasta_logs, caminho_db, tabela='conn'):
    arquivos = glob.glob(os.path.join(pasta_logs, 'conn.*.log'))
    if not arquivos:
        print("Nenhum arquivo conn.*.log encontrado.")
        return

    # Lê todos os arquivos e concatena em um único DataFrame
    dfs = []
    for arquivo in arquivos:
        # Zeek logs geralmente são TSV (tab-separated)
        df = pd.read_csv(arquivo, sep='\t', comment='#', low_memory=False)
        dfs.append(df)
    df_total = pd.concat(dfs, ignore_index=True)

    # Salva no banco
    conn = sqlite3.connect(caminho_db)
    df_total.to_sql(tabela, conn, if_exists='replace', index=False)
    conn.close()
    print(f"{len(df_total)} linhas importadas para a tabela {tabela}.")