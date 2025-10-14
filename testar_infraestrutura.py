#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
from logger import Logger

# Inicializa o logger
logger = Logger()

def criar_diretorio_logs():
    """Cria o diretório de logs se não existir"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
        print("Diretório de logs criado.")

def criar_documento_teste(nome_arquivo, conteudo):
    """Cria um documento de teste para assinatura"""
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        f.write(conteudo)
    logger.info(f"Documento de teste criado: {nome_arquivo}")
    print(f"Documento de teste criado: {nome_arquivo}")

def executar_comando(comando):
    """Executa um comando e retorna o código de saída e a saída"""
    processo = subprocess.run(comando, shell=True, capture_output=True, text=True)
    return processo.returncode, processo.stdout, processo.stderr

def testar_certificados_validos():
    """Testa a assinatura e verificação com certificados válidos"""
    print("\n=== TESTE COM CERTIFICADOS VÁLIDOS ===")
    logger.info("Iniciando teste com certificados válidos")
    
    # Cria documento de teste
    criar_documento_teste("documento_valido.txt", "Este é um documento de teste para a infraestrutura ICP-Brasil simulada.")
    
    # Assina o documento com o certificado de João
    print("\n1. Assinando documento com certificado válido (João)...")
    # Usando o formato correto para passar a senha como argumento
    cmd_assinar = "python assinar_documento.py documento_valido.txt pki\\usuarios\\joao\\joao.key documento_valido.txt.assinatura \"senha123\""
    codigo, stdout, stderr = executar_comando(cmd_assinar)
    
    if codigo == 0:
        logger.success("Assinatura com certificado válido realizada com sucesso")
        print("✅ Assinatura realizada com sucesso")
    else:
        logger.error(f"Falha na assinatura: {stderr}")
        print(f"❌ Falha na assinatura: {stderr}")
        return False
    
    # Verifica a assinatura
    print("\n2. Verificando assinatura com cadeia de certificação válida...")
    cmd_verificar = "python verificar_assinatura.py documento_valido.txt documento_valido.txt.assinatura pki\\usuarios\\joao\\joao.crt pki\\ca-intermediaria\\certs\\ca-intermediaria.crt pki\\raiz-ca\\certs\\raiz-ca.crt"
    codigo, stdout, stderr = executar_comando(cmd_verificar)
    
    if codigo == 0:
        logger.success("Verificação com certificado válido realizada com sucesso")
        print("✅ Verificação realizada com sucesso")
        print(stdout)
        return True
    else:
        logger.error(f"Falha na verificação: {stderr}")
        print(f"❌ Falha na verificação: {stderr}")
        return False

def testar_certificados_invalidos():
    """Testa a assinatura e verificação com certificados inválidos (atacante)"""
    print("\n=== TESTE COM CERTIFICADOS INVÁLIDOS ===")
    logger.info("Iniciando teste com certificados inválidos (atacante)")
    
    # Cria documento do atacante
    criar_documento_teste("documento_atacante.txt", "Este é um documento malicioso criado pelo atacante.")
    
    # Assina o documento com o certificado do atacante
    print("\n1. Assinando documento com certificado do atacante...")
    cmd_assinar = "python assinar_documento.py documento_atacante.txt pki\\usuarios\\atacante\\atacante.key documento_atacante.txt.assinatura"
    codigo, stdout, stderr = executar_comando(cmd_assinar)
    
    if codigo == 0:
        logger.info("Assinatura com certificado do atacante realizada")
        print("✓ Assinatura com certificado do atacante realizada")
    else:
        logger.error(f"Falha na assinatura do atacante: {stderr}")
        print(f"❌ Falha na assinatura do atacante: {stderr}")
        return False
    
    # Tenta verificar a assinatura com a cadeia falsa
    print("\n2. Tentando verificar assinatura com cadeia falsa...")
    cmd_verificar = "python verificar_assinatura.py documento_atacante.txt documento_atacante.txt.assinatura pki\\usuarios\\atacante\\atacante.crt pki\\usuarios\\atacante\\fake-ca.crt pki\\raiz-ca\\certs\\raiz-ca.crt"
    codigo, stdout, stderr = executar_comando(cmd_verificar)
    
    if codigo != 0:
        logger.security_event("Verificação com cadeia falsa rejeitada corretamente", "SUCESSO")
        print("✅ Verificação com cadeia falsa rejeitada corretamente")
        print(stdout)
    else:
        logger.security_event("Verificação com cadeia falsa foi aceita incorretamente", "FALHA")
        print("❌ FALHA DE SEGURANÇA: Verificação com cadeia falsa foi aceita")
        return False
    
    # Tenta verificar a assinatura do atacante com a cadeia válida
    print("\n3. Tentando verificar assinatura do atacante com cadeia válida...")
    cmd_verificar = "python verificar_assinatura.py documento_atacante.txt documento_atacante.txt.assinatura pki\\usuarios\\atacante\\atacante.crt pki\\ca-intermediaria\\certs\\ca-intermediaria.crt pki\\raiz-ca\\certs\\raiz-ca.crt"
    codigo, stdout, stderr = executar_comando(cmd_verificar)
    
    if codigo != 0:
        logger.security_event("Verificação de certificado não pertencente à cadeia rejeitada corretamente", "SUCESSO")
        print("✅ Verificação de certificado não pertencente à cadeia rejeitada corretamente")
        print(stdout)
        return True
    else:
        logger.security_event("Verificação de certificado não pertencente à cadeia foi aceita incorretamente", "FALHA")
        print("❌ FALHA DE SEGURANÇA: Verificação de certificado não pertencente à cadeia foi aceita")
        return False

def gerar_relatorio():
    """Gera um relatório baseado nos logs"""
    print("\n=== GERANDO RELATÓRIO ===")
    relatorio = logger.gerar_relatorio()
    
    # Salva o relatório em um arquivo
    relatorio_path = os.path.join('logs', 'relatorio_testes.md')
    with open(relatorio_path, 'w', encoding='utf-8') as f:
        f.write(relatorio)
    
    print(f"Relatório gerado: {relatorio_path}")
    return relatorio_path

def main():
    """Função principal para testar a infraestrutura ICP-Brasil"""
    print("=== INICIANDO TESTES DA INFRAESTRUTURA ICP-BRASIL ===")
    
    # Cria diretório de logs
    criar_diretorio_logs()
    
    # Testa certificados válidos
    sucesso_validos = testar_certificados_validos()
    
    # Testa certificados inválidos
    sucesso_invalidos = testar_certificados_invalidos()
    
    # Gera relatório
    print("\n=== GERANDO RELATÓRIO ===")
    relatorio = logger.gerar_relatorio()
    print(f"Relatório gerado: {relatorio}")
    
    # Resultado final
    print("\n=== RESULTADO FINAL ===")
    if sucesso_validos and sucesso_invalidos:
        print("✅ TODOS OS TESTES PASSARAM")
    else:
        print("❌ ALGUNS TESTES FALHARAM")
        print("❌ Verifique o relatório para mais detalhes")
    
    print(f"\nRelatório completo disponível em: {relatorio}")

if __name__ == "__main__":
    main()