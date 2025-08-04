import subprocess
from config import settings

#class ZeekCollector:
#    def start_zeek(self):
#        """Start Zeek monitoring on configured interface"""
#        cmd = f"zeek -i {settings.zeek.interface} -C -b -s {settings.zeek.log_dir}/zeek.sqlite"
#        subprocess.Popen(cmd.split())
    
#    def check_zeek_running(self):
#        """Verify Zeek is running"""
        # Implementation here
def iniciar_monitoramento_zeek(interface_rede, diretorio_saida):
    """
    Inicia o monitoramento de rede com Zeek
    :param interface_rede: Interface de rede a ser monitorada (ex: eth0)
    :param diretorio_saida: Diretório onde os logs serão armazenados
    """
    comando = f"zeek -i {interface_rede} -C -b -s {diretorio_saida}/zeek.sqlite"
    try:
        subprocess.Popen(comando.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Monitoramento Zeek iniciado na interface {interface_rede}")
    except Exception as e:
        print(f"Erro ao iniciar Zeek: {e}")