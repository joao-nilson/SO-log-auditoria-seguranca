import sqlite3

# Caminho para o seu arquivo
caminho_db = "/home/davi-monken/Documentos/SO/output.db"

# Conectar ao banco
conn = sqlite3.connect(caminho_db)

# Criar cursor
cursor = conn.cursor()

# Listar todas as tabelas do banco
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tabelas = cursor.fetchall()
print("Tabelas disponíveis:", tabelas)

# Fechar conexão
conn.close()
