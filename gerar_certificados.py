#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from logger import Logger

# Inicializa o logger
logger = Logger()
from cryptography.hazmat.backends import default_backend

# Configurações gerais
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pki')
KEY_SIZE = 4096
CERT_VALIDITY_DAYS = 3650  # 10 anos para CA Raiz
INTERMEDIATE_VALIDITY_DAYS = 1825  # 5 anos para CA Intermediária
USER_VALIDITY_DAYS = 365  # 1 ano para certificados de usuário

def criar_chave_privada(caminho_chave, senha=None):
    """Gera uma chave privada RSA e a salva no caminho especificado."""
    logger.info(f"Gerando chave privada RSA {KEY_SIZE} bits: {caminho_chave}")
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
        
        # Configuração de encriptação da chave privada
        if senha:
            encryption_algorithm = serialization.BestAvailableEncryption(senha.encode())
            logger.info(f"Chave privada protegida com senha: {caminho_chave}")
        else:
            encryption_algorithm = serialization.NoEncryption()
            logger.info(f"Chave privada sem proteção de senha: {caminho_chave}")
        
        # Serializa a chave no formato PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # Salva a chave no arquivo
        with open(caminho_chave, 'wb') as key_file:
            key_file.write(pem)
        
        logger.success(f"Chave privada gerada com sucesso: {caminho_chave}")
        return private_key
    except Exception as e:
        logger.error(f"Erro ao gerar chave privada: {str(e)}")
        raise

def criar_certificado_raiz(private_key, subject_name, caminho_certificado):
    """Cria um certificado raiz autoassinado."""
    logger.info(f"Criando certificado raiz: {subject_name}")
    try:
        # Informações do sujeito
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Distrito Federal"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Brasília"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ICP-Brasil Simulada"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        # Configurações do certificado
        now = datetime.datetime.utcnow()
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Autoassinado, então o emissor é igual ao sujeito
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=CERT_VALIDITY_DAYS)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Serializa o certificado no formato PEM
        with open(caminho_certificado, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        
        logger.certificate_operation("Criação de CA Raiz", subject_name, True)
        logger.success(f"Certificado raiz criado com sucesso: {caminho_certificado}")
        return cert
    except Exception as e:
        logger.certificate_operation("Criação de CA Raiz", subject_name, False)
        logger.error(f"Erro ao criar certificado raiz: {str(e)}")
        raise

def criar_csr(private_key, common_name, country="BR", state="Distrito Federal", 
              locality="Brasília", organization="ICP-Brasil Simulada", 
              organizational_unit=None, email=None, cpf=None):
    """Cria uma solicitação de assinatura de certificado (CSR)."""
    
    # Cria os atributos do sujeito
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    
    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    
    # Cria o CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(attributes)
    )
    
    # Adiciona extensões (subjectAltName) se necessário
    san_list = []
    if email:
        san_list.append(x509.RFC822Name(email))
    
    if cpf:
        # No mundo real, usaríamos OIDs específicos da ICP-Brasil para CPF
        # Aqui estamos simulando com um DNS name para simplificar
        san_list.append(x509.DNSName(f"CPF:{cpf}"))
    
    if san_list:
        csr = csr.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
    
    # Assina o CSR com a chave privada
    signed_csr = csr.sign(private_key, hashes.SHA256(), default_backend())
    
    return signed_csr

def assinar_csr(csr, ca_cert, ca_key, caminho_certificado, is_ca=False, path_length=None, 
                validity_days=USER_VALIDITY_DAYS):
    """Assina um CSR e gera um certificado."""
    
    # Carrega o CSR se for um caminho de arquivo
    if isinstance(csr, str):
        with open(csr, "rb") as csr_file:
            csr_data = csr_file.read()
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
    
    # Configurações do certificado
    now = datetime.datetime.utcnow()
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=validity_days)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        csr.public_key()
    )
    
    # Adiciona extensões básicas
    cert = cert.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=path_length), 
        critical=True
    )
    
    # Adiciona KeyUsage apropriado
    if is_ca:
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
    else:
        cert = cert.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )
    
    # Adiciona identificadores de chave
    cert = cert.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False
    )
    
    cert = cert.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )
    
    # Copia as extensões do CSR (como subjectAltName)
    for extension in csr.extensions:
        cert = cert.add_extension(extension.value, extension.critical)
    
    # Assina o certificado
    signed_cert = cert.sign(ca_key, hashes.SHA256(), default_backend())
    
    # Serializa o certificado no formato PEM
    with open(caminho_certificado, "wb") as cert_file:
        cert_file.write(signed_cert.public_bytes(serialization.Encoding.PEM))
    
    return signed_cert

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

def carregar_certificado(caminho_certificado):
    """Carrega um certificado de um arquivo."""
    with open(caminho_certificado, "rb") as cert_file:
        cert_data = cert_file.read()
        return x509.load_pem_x509_certificate(cert_data, default_backend())

def main():
    """Função principal para gerar toda a infraestrutura de certificados."""
    
    # Caminhos para CA Raiz
    raiz_key_path = os.path.join(BASE_DIR, "raiz-ca", "private", "raiz-ca.key")
    raiz_cert_path = os.path.join(BASE_DIR, "raiz-ca", "certs", "raiz-ca.crt")
    
    # Caminhos para CA Intermediária
    inter_key_path = os.path.join(BASE_DIR, "ca-intermediaria", "private", "ca-intermediaria.key")
    inter_csr_path = os.path.join(BASE_DIR, "ca-intermediaria", "csr", "ca-intermediaria.csr")
    inter_cert_path = os.path.join(BASE_DIR, "ca-intermediaria", "certs", "ca-intermediaria.crt")
    
    # Caminhos para usuários
    joao_key_path = os.path.join(BASE_DIR, "usuarios", "joao", "joao.key")
    joao_csr_path = os.path.join(BASE_DIR, "usuarios", "joao", "joao.csr")
    joao_cert_path = os.path.join(BASE_DIR, "usuarios", "joao", "joao.crt")
    
    maria_key_path = os.path.join(BASE_DIR, "usuarios", "maria", "maria.key")
    maria_csr_path = os.path.join(BASE_DIR, "usuarios", "maria", "maria.csr")
    maria_cert_path = os.path.join(BASE_DIR, "usuarios", "maria", "maria.crt")
    
    # Caminhos para atacante (CA falsa)
    fake_ca_key_path = os.path.join(BASE_DIR, "usuarios", "atacante", "fake-ca.key")
    fake_ca_cert_path = os.path.join(BASE_DIR, "usuarios", "atacante", "fake-ca.crt")
    atacante_key_path = os.path.join(BASE_DIR, "usuarios", "atacante", "atacante.key")
    atacante_csr_path = os.path.join(BASE_DIR, "usuarios", "atacante", "atacante.csr")
    atacante_cert_path = os.path.join(BASE_DIR, "usuarios", "atacante", "atacante.crt")
    
    # 1. Gerar CA Raiz
    print("Gerando CA Raiz...")
    raiz_key = criar_chave_privada(raiz_key_path)
    raiz_cert = criar_certificado_raiz(raiz_key, "CA Raiz ICP-Brasil Simulada", raiz_cert_path)
    print(f"CA Raiz gerada: {raiz_cert_path}")
    
    # 2. Gerar CA Intermediária
    print("\nGerando CA Intermediária...")
    inter_key = criar_chave_privada(inter_key_path)
    inter_csr = criar_csr(inter_key, "CA Intermediária ICP-Brasil Simulada")
    
    # Salvar CSR
    with open(inter_csr_path, "wb") as csr_file:
        csr_file.write(inter_csr.public_bytes(serialization.Encoding.PEM))
    
    # Assinar CSR com a CA Raiz
    inter_cert = assinar_csr(
        inter_csr, raiz_cert, raiz_key, inter_cert_path, 
        is_ca=True, path_length=0, validity_days=INTERMEDIATE_VALIDITY_DAYS
    )
    print(f"CA Intermediária gerada: {inter_cert_path}")
    
    # 3. Gerar certificados de usuários
    print("\nGerando certificado para João...")
    joao_key = criar_chave_privada(joao_key_path, senha="senha123")
    joao_csr = criar_csr(
        joao_key, "João da Silva", 
        email="joao@example.com", cpf="123.456.789-00",
        organizational_unit="Pessoa Física"
    )
    
    # Salvar CSR
    with open(joao_csr_path, "wb") as csr_file:
        csr_file.write(joao_csr.public_bytes(serialization.Encoding.PEM))
    
    # Assinar CSR com a CA Intermediária
    joao_cert = assinar_csr(joao_csr, inter_cert, inter_key, joao_cert_path)
    print(f"Certificado de João gerado: {joao_cert_path}")
    
    print("\nGerando certificado para Maria...")
    maria_key = criar_chave_privada(maria_key_path, senha="senha456")
    maria_csr = criar_csr(
        maria_key, "Maria Oliveira", 
        email="maria@example.com", cpf="987.654.321-00",
        organizational_unit="Pessoa Física"
    )
    
    # Salvar CSR
    with open(maria_csr_path, "wb") as csr_file:
        csr_file.write(maria_csr.public_bytes(serialization.Encoding.PEM))
    
    # Assinar CSR com a CA Intermediária
    maria_cert = assinar_csr(maria_csr, inter_cert, inter_key, maria_cert_path)
    print(f"Certificado de Maria gerado: {maria_cert_path}")
    
    # 4. Gerar CA falsa e certificado do atacante
    print("\nGerando CA falsa e certificado do atacante...")
    fake_ca_key = criar_chave_privada(fake_ca_key_path)
    fake_ca_cert = criar_certificado_raiz(fake_ca_key, "CA Falsa", fake_ca_cert_path)
    
    atacante_key = criar_chave_privada(atacante_key_path)
    atacante_csr = criar_csr(
        atacante_key, "Atacante Malicioso", 
        email="atacante@malicious.com", cpf="111.222.333-44",
        organizational_unit="Pessoa Física"
    )
    
    # Salvar CSR
    with open(atacante_csr_path, "wb") as csr_file:
        csr_file.write(atacante_csr.public_bytes(serialization.Encoding.PEM))
    
    # Assinar CSR com a CA Falsa
    atacante_cert = assinar_csr(atacante_csr, fake_ca_cert, fake_ca_key, atacante_cert_path)
    print(f"Certificado do atacante gerado: {atacante_cert_path}")
    
    print("\nTodos os certificados foram gerados com sucesso!")

if __name__ == "__main__":
    main()