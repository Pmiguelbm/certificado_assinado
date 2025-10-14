#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import hashlib
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
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

def carregar_certificado(caminho_certificado):
    """Carrega um certificado X.509 de um arquivo."""
    with open(caminho_certificado, "rb") as cert_file:
        cert_data = cert_file.read()
        return x509.load_pem_x509_certificate(cert_data, default_backend())

def verificar_cadeia_certificacao(cert_path, ca_intermediaria_path, ca_raiz_path):
    """
    Verifica se um certificado pertence a uma cadeia de confiança válida.
    
    Args:
        cert_path: Caminho para o certificado a ser verificado
        ca_intermediaria_path: Caminho para o certificado da CA Intermediária
        ca_raiz_path: Caminho para o certificado da CA Raiz
        
    Returns:
        bool: True se a cadeia for válida, False caso contrário
    """
    try:
        # Carrega os certificados
        cert = carregar_certificado(cert_path)
        ca_intermediaria = carregar_certificado(ca_intermediaria_path)
        ca_raiz = carregar_certificado(ca_raiz_path)
        
        # Verifica se o certificado foi emitido pela CA Intermediária
        # Comparando o emissor do certificado com o sujeito da CA Intermediária
        if cert.issuer != ca_intermediaria.subject:
            print("Erro: O certificado não foi emitido pela CA Intermediária especificada.")
            return False
        
        # Verifica se a CA Intermediária foi emitida pela CA Raiz
        if ca_intermediaria.issuer != ca_raiz.subject:
            print("Erro: A CA Intermediária não foi emitida pela CA Raiz especificada.")
            return False
        
        # Verifica se a CA Raiz é autoassinada (emissor = sujeito)
        if ca_raiz.issuer != ca_raiz.subject:
            print("Erro: A CA Raiz não é autoassinada.")
            return False
        
        # Verifica a assinatura do certificado pela CA Intermediária
        try:
            ca_intermediaria.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature:
            print("Erro: A assinatura do certificado é inválida.")
            return False
        
        # Verifica a assinatura da CA Intermediária pela CA Raiz
        try:
            ca_raiz.public_key().verify(
                ca_intermediaria.signature,
                ca_intermediaria.tbs_certificate_bytes,
                padding.PKCS1v15(),
                ca_intermediaria.signature_hash_algorithm
            )
        except InvalidSignature:
            print("Erro: A assinatura da CA Intermediária é inválida.")
            return False
        
        # Verifica se os certificados estão dentro do prazo de validade
        from datetime import datetime
        now = datetime.utcnow()
        
        if now < cert.not_valid_before or now > cert.not_valid_after:
            print("Erro: O certificado está fora do prazo de validade.")
            return False
        
        if now < ca_intermediaria.not_valid_before or now > ca_intermediaria.not_valid_after:
            print("Erro: O certificado da CA Intermediária está fora do prazo de validade.")
            return False
        
        if now < ca_raiz.not_valid_before or now > ca_raiz.not_valid_after:
            print("Erro: O certificado da CA Raiz está fora do prazo de validade.")
            return False
        
        # Se todas as verificações passaram, a cadeia é válida
        return True
        
    except Exception as e:
        print(f"Erro ao verificar a cadeia de certificação: {e}")
        return False

def verificar_assinatura(caminho_documento, caminho_assinatura, caminho_certificado, 
                         ca_intermediaria_path, ca_raiz_path):
    """
    Verifica a assinatura de um documento.
    
    Args:
        caminho_documento: Caminho para o documento
        caminho_assinatura: Caminho para o arquivo de assinatura
        caminho_certificado: Caminho para o certificado do assinante
        ca_intermediaria_path: Caminho para o certificado da CA Intermediária
        ca_raiz_path: Caminho para o certificado da CA Raiz
        
    Returns:
        bool: True se a assinatura for válida, False caso contrário
    """
    try:
        # Verifica a cadeia de certificação
        print("Verificando a cadeia de certificação...")
        if not verificar_cadeia_certificacao(caminho_certificado, ca_intermediaria_path, ca_raiz_path):
            print("Falha de verificação: certificado não confiável")
            return False
        
        print("Cadeia de certificação válida.")
        
        # Calcula o hash do documento
        hash_documento = calcular_hash(caminho_documento)
        print(f"Hash SHA-256 do documento: {hash_documento.hex()}")
        
        # Carrega o certificado do assinante
        certificado = carregar_certificado(caminho_certificado)
        
        # Carrega a assinatura
        with open(caminho_assinatura, 'rb') as arquivo_assinatura:
            assinatura = arquivo_assinatura.read()
        
        # Verifica a assinatura usando a chave pública do certificado
        try:
            certificado.public_key().verify(
                assinatura,
                hash_documento,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("Assinatura válida!")
            return True
        except InvalidSignature:
            print("Falha de verificação: assinatura inválida")
            return False
            
    except Exception as e:
        print(f"Erro ao verificar a assinatura: {e}")
        return False

def main():
    """Função principal."""
    if len(sys.argv) < 6:
        print("Uso: python verificar_assinatura.py <documento> <assinatura> <certificado> <ca_intermediaria> <ca_raiz>")
        print("Exemplo: python verificar_assinatura.py documento.txt documento.txt.assinatura pki/usuarios/joao/joao.crt pki/ca-intermediaria/certs/ca-intermediaria.crt pki/raiz-ca/certs/raiz-ca.crt")
        sys.exit(1)
    
    caminho_documento = sys.argv[1]
    caminho_assinatura = sys.argv[2]
    caminho_certificado = sys.argv[3]
    ca_intermediaria_path = sys.argv[4]
    ca_raiz_path = sys.argv[5]
    
    # Verifica se os arquivos existem
    for arquivo in [caminho_documento, caminho_assinatura, caminho_certificado, ca_intermediaria_path, ca_raiz_path]:
        if not os.path.isfile(arquivo):
            print(f"Erro: O arquivo '{arquivo}' não existe.")
            sys.exit(1)
    
    # Verifica a assinatura
    if verificar_assinatura(caminho_documento, caminho_assinatura, caminho_certificado, 
                           ca_intermediaria_path, ca_raiz_path):
        print("Verificação concluída com sucesso. A assinatura é válida e o certificado é confiável.")
    else:
        print("Falha na verificação. A assinatura é inválida ou o certificado não é confiável.")
        sys.exit(1)

if __name__ == "__main__":
    main()