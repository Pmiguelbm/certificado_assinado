#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from logger import Logger

# Inicializa o logger
logger = Logger()

def calcular_hash(caminho_arquivo):
    """Calcula o hash SHA-256 de um arquivo."""
    sha256 = hashlib.sha256()
    
    with open(caminho_arquivo, 'rb') as arquivo:
        # Lê o arquivo em blocos para não sobrecarregar a memória
        for bloco in iter(lambda: arquivo.read(4096), b''):
            sha256.update(bloco)
    
    return sha256.digest()

def carregar_chave_privada(caminho_chave, senha=None):
    """Carrega uma chave privada de um arquivo."""
    with open(caminho_chave, "rb") as key_file:
        key_data = key_file.read()
        
    if senha:
        return serialization.load_pem_private_key(
            key_data,
            password=senha.encode(),
            backend=default_backend()
        )
    else:
        return serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )

def assinar_documento(caminho_documento, caminho_chave_privada, caminho_assinatura, senha=None):
    """
    Assina um documento usando uma chave privada RSA.
    
    Args:
        caminho_documento: Caminho para o documento a ser assinado
        caminho_chave_privada: Caminho para a chave privada RSA
        caminho_assinatura: Caminho onde a assinatura será salva
        senha: Senha da chave privada (opcional)
    """
    try:
        # Calcula o hash do documento
        hash_documento = calcular_hash(caminho_documento)
        print(f"Hash SHA-256 do documento: {hash_documento.hex()}")
        logger.info(f"Calculado hash SHA-256 do documento: {os.path.basename(caminho_documento)}")
        
        # Carrega a chave privada
        chave_privada = carregar_chave_privada(caminho_chave_privada, senha)
        logger.info(f"Chave privada carregada: {os.path.basename(caminho_chave_privada)}")
        
        # Assina o hash do documento
        assinatura = chave_privada.sign(
            hash_documento,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Salva a assinatura em um arquivo
        with open(caminho_assinatura, 'wb') as arquivo_assinatura:
            arquivo_assinatura.write(assinatura)
        
        print(f"Documento assinado com sucesso. Assinatura salva em: {caminho_assinatura}")
        logger.signature_operation("Assinatura", os.path.basename(caminho_documento), True)
        return True
    except Exception as e:
        print(f"Erro ao assinar o documento: {str(e)}")
        logger.signature_operation("Assinatura", os.path.basename(caminho_documento), False)
        logger.error(f"Erro na assinatura: {str(e)}")
        return False

def main():
    """Função principal."""
    if len(sys.argv) < 3:
        print("Uso: python assinar_documento.py <caminho_documento> <caminho_chave_privada> [caminho_assinatura] [senha]")
        print("Exemplo: python assinar_documento.py documento.txt pki/usuarios/joao/joao.key [documento.assinatura]")
        sys.exit(1)
    
    caminho_documento = sys.argv[1]
    caminho_chave_privada = sys.argv[2]
    
    # Verifica se o caminho da assinatura foi fornecido
    if len(sys.argv) > 3:
        caminho_assinatura = sys.argv[3]
    else:
        # Se não, usa o nome do documento com a extensão .assinatura
        caminho_assinatura = f"{caminho_documento}.assinatura"
    
    # Verifica se os arquivos existem
    if not os.path.isfile(caminho_documento):
        print(f"Erro: O documento '{caminho_documento}' não existe.")
        sys.exit(1)
    
    if not os.path.isfile(caminho_chave_privada):
        print(f"Erro: A chave privada '{caminho_chave_privada}' não existe.")
        sys.exit(1)
    
    # Verifica se a senha foi fornecida como argumento
    senha = None
    if len(sys.argv) > 4:
        senha = sys.argv[4]
    else:
        # Solicita a senha da chave privada (se necessário)
        senha = input("Digite a senha da chave privada (deixe em branco se não houver senha): ")
        if senha == "":
            senha = None
    
    # Assina o documento
    if assinar_documento(caminho_documento, caminho_chave_privada, caminho_assinatura, senha):
        print("Processo de assinatura concluído com sucesso.")
    else:
        print("Falha no processo de assinatura.")
        sys.exit(1)

if __name__ == "__main__":
    main()