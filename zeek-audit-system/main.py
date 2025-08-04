from core.collector import ZeekCollector
from monitoring.realtime import RealTimeMonitor
from core.processor import LogProcessor
from core.analyzer import SecurityAnalyzer

#def main():
    # Initialize components
#    collector = ZeekCollector()
#    processor = LogProcessor()
#    analyzer = SecurityAnalyzer()
    
    # Start real-time monitoring
#    rt_monitor = RealTimeMonitor()
#    rt_monitor.start()
    
    # Batch processing loop
#    while True:
#        logs = processor.load_logs('conn')
#        results = analyzer.detect_anomalies(logs)
        # Generate reports and handle alerts

def main():
    # Configurações
    INTERFACE_REDE = 'eth0'
    DIRETORIO_LOGS = '/caminho/para/logs'
    DB_CENTRAL = 'postgresql://user:password@localhost/auditoria_seguranca' #trocar isso para armazenar localmente
    
    # 1. Iniciar captura de logs (Zeek)
    iniciar_monitoramento_zeek(INTERFACE_REDE, DIRETORIO_LOGS)
    
    # 2. Processar logs
    processador = ProcessadorLogsSeguranca(f"{DIRETORIO_LOGS}/zeek.sqlite")
    conexoes = processador.carregar_logs('conn')
    
    # 3. Analisar segurança
    analisador = AnalisadorSeguranca()
    anomalias = analisador.detectar_anomalias(conexoes)
    varreduras = analisador.detectar_varredura_portas(conexoes)
    
    # 4. Armazenar resultados
    armazenamento = GerenciadorArmazenamento(DB_CENTRAL) #todo: guardar logs localmente
    armazenamento.salvar_logs_processados(conexoes, 'conexoes_network')
    armazenamento.salvar_alertas(anomalias)
    armazenamento.salvar_alertas(varreduras)
    
    # 5. Gerar relatórios
    GeradorRelatorios.gerar_relatorio_conexoes(conexoes)
    
    print("Sistema de auditoria de segurança executado com sucesso!")


if __name__ == "__main__":
    main()