import os
import pandas as pd
from core.storage import GerenciadorArmazenamento

# Caminhos
DIRETORIO_LOGS = os.getenv("DIRETORIO_LOGS", "zeek_logs")
DB_LOCAL = os.getenv("DB_LOCAL", "/home/davi-monken/Documentos/SO/output.db")

# Função para importar um arquivo de log Zeek
def importar_log_zeek(caminho_arquivo, armazenamento):
    with open(caminho_arquivo, 'r', encoding='utf-8') as f:
        linhas = f.readlines()
    # Encontrar linha de campos
    idx_fields = None
    for i, linha in enumerate(linhas):
        if linha.startswith('#fields'):
            idx_fields = i
            break
    if idx_fields is None:
        print(f"Arquivo {caminho_arquivo} sem linha #fields. Pulando...")
        return
    campos = linhas[idx_fields].strip().split('\t')[1:]
    # Dados começam após a linha #types
    idx_types = idx_fields + 1
    while idx_types < len(linhas) and not linhas[idx_types].startswith('#types'):
        idx_types += 1
    dados = []
    for linha in linhas[idx_types+1:]:
        if linha.startswith('#') or not linha.strip():
            continue
        dados.append(linha.strip().split('\t'))
    if not dados:
        print(f"Nenhum dado encontrado em {caminho_arquivo}")
        return
    df = pd.DataFrame(dados, columns=campos)
    # Nome da tabela pelo #path ou pelo nome do arquivo
    nome_tabela = None
    for l in linhas:
        if l.startswith('#path'):
            nome_tabela = l.strip().split('\t')[1]
            break
    if not nome_tabela:
        nome_tabela = os.path.basename(caminho_arquivo).split('.')[0]
    armazenamento.salvar_logs_processados(df, nome_tabela)
    print(f"Importado {caminho_arquivo} para tabela {nome_tabela}")

if __name__ == "__main__":
    armazenamento = GerenciadorArmazenamento(f"sqlite:///{DB_LOCAL}")
    arquivos = [os.path.join(DIRETORIO_LOGS, f) for f in os.listdir(DIRETORIO_LOGS) if f.endswith('.log')]
    for arquivo in arquivos:
        importar_log_zeek(arquivo, armazenamento)