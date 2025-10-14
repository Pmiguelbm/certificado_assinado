import logging
import os
from datetime import datetime

class Logger:
    def __init__(self, nome_log=None):
        """
        Inicializa o logger com um nome específico ou padrão.
        
        Args:
            nome_log: Nome do arquivo de log. Se None, usa o formato 'icp_brasil_YYYY-MM-DD.log'
        """
        # Cria diretório de logs se não existir
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        # Define nome do arquivo de log
        if nome_log is None:
            data_atual = datetime.now().strftime('%Y-%m-%d')
            nome_log = f'icp_brasil_{data_atual}.log'
        
        self.log_path = os.path.join('logs', nome_log)
        
        # Configura o logger
        self.logger = logging.getLogger('icp_brasil')
        self.logger.setLevel(logging.INFO)
        
        # Evita duplicação de handlers
        if not self.logger.handlers:
            # Handler para arquivo
            file_handler = logging.FileHandler(self.log_path)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
            
            # Handler para console
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter('%(levelname)s - %(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
    
    def info(self, mensagem):
        """Registra uma mensagem informativa"""
        self.logger.info(mensagem)
    
    def warning(self, mensagem):
        """Registra um aviso"""
        self.logger.warning(mensagem)
    
    def error(self, mensagem):
        """Registra um erro"""
        self.logger.error(mensagem)
    
    def success(self, mensagem):
        """Registra uma operação bem-sucedida"""
        self.logger.info(f"SUCESSO - {mensagem}")
    
    def failure(self, mensagem):
        """Registra uma falha"""
        self.logger.error(f"FALHA - {mensagem}")
    
    def security_event(self, mensagem, tipo="INFO"):
        """Registra um evento de segurança"""
        self.logger.info(f"SEGURANÇA [{tipo}] - {mensagem}")
    
    def certificate_operation(self, operacao, entidade, resultado):
        """Registra uma operação relacionada a certificados"""
        status = "SUCESSO" if resultado else "FALHA"
        self.logger.info(f"CERTIFICADO [{status}] - {operacao} para {entidade}")
    
    def signature_operation(self, operacao, arquivo, resultado):
        """Registra uma operação relacionada a assinaturas"""
        status = "SUCESSO" if resultado else "FALHA"
        self.logger.info(f"ASSINATURA [{status}] - {operacao} para {arquivo}")
    
    def verification_operation(self, arquivo, certificado, resultado, mensagem=None):
        """Registra uma operação de verificação"""
        status = "VÁLIDO" if resultado else "INVÁLIDO"
        log_msg = f"VERIFICAÇÃO [{status}] - Arquivo: {arquivo}, Certificado: {certificado}"
        if mensagem:
            log_msg += f" - {mensagem}"
        self.logger.info(log_msg)
    
    def gerar_relatorio(self):
        """
        Gera um relatório baseado nos logs atuais
        
        Returns:
            str: Conteúdo do relatório
        """
        try:
            with open(self.log_path, 'r') as f:
                linhas = f.readlines()
            
            # Cabeçalho do relatório
            relatorio = ["# Relatório de Operações ICP-Brasil", 
                         f"Data de geração: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"]
            
            # Seções do relatório
            secoes = {
                "CERTIFICADO": [],
                "ASSINATURA": [],
                "VERIFICAÇÃO": [],
                "SEGURANÇA": [],
                "ERRO": []
            }
            
            # Classifica as entradas de log
            for linha in linhas:
                for secao in secoes.keys():
                    if secao in linha:
                        secoes[secao].append(linha)
                        break
            
            # Adiciona seções ao relatório
            for secao, entradas in secoes.items():
                if entradas:
                    relatorio.append(f"## Operações de {secao}")
                    for entrada in entradas:
                        # Formata a entrada para o relatório
                        partes = entrada.split(' - ', 1)
                        if len(partes) > 1:
                            relatorio.append(f"- {partes[1].strip()}")
                    relatorio.append("")  # Linha em branco
            
            # Resumo
            relatorio.append("## Resumo")
            relatorio.append(f"- Total de operações de certificado: {len(secoes['CERTIFICADO'])}")
            relatorio.append(f"- Total de operações de assinatura: {len(secoes['ASSINATURA'])}")
            relatorio.append(f"- Total de verificações: {len(secoes['VERIFICAÇÃO'])}")
            relatorio.append(f"- Eventos de segurança: {len(secoes['SEGURANÇA'])}")
            relatorio.append(f"- Erros registrados: {len(secoes['ERRO'])}")
            
            return "\n".join(relatorio)
        except Exception as e:
            return f"Erro ao gerar relatório: {str(e)}"