# Mini Infraestrutura ICP-Brasil

Este projeto implementa uma infraestrutura de certificação digital inspirada na ICP-Brasil para fins educacionais. A implementação inclui uma Autoridade Certificadora Raiz (CA-Raiz), uma CA Intermediária subordinada, certificados de usuários finais, e funcionalidades para assinatura e verificação de documentos.

## Estrutura do Projeto

```
/pki/
   ├── raiz-ca/
   │    ├── private/     # Chave privada da CA Raiz
   │    ├── certs/       # Certificado autoassinado da CA Raiz
   │    └── crl/         # Lista de revogação de certificados (não implementada)
   ├── ca-intermediaria/
   │    ├── private/     # Chave privada da CA Intermediária
   │    ├── certs/       # Certificado da CA Intermediária assinado pela CA Raiz
   │    └── csr/         # Requisição de assinatura de certificado da CA Intermediária
   └── usuarios/
        ├── joao/        # Certificado e chave do usuário João
        ├── maria/       # Certificado e chave da usuária Maria
        └── atacante/    # Certificado e chave falsos para teste de rejeição
```

## Requisitos

Para executar este projeto, você precisa ter instalado:

- Python 3.6 ou superior
- Biblioteca cryptography (`pip install cryptography`)

## Componentes do Projeto

### 1. Geração de Certificados (`gerar_certificados.py`)

Este script cria toda a infraestrutura de certificados:

- **CA Raiz**: Certificado autoassinado com chave RSA de 4096 bits
- **CA Intermediária**: Certificado assinado pela CA Raiz
- **Certificados de Usuários**: Certificados para João e Maria, assinados pela CA Intermediária
- **Certificado Falso**: Certificado para um "atacante", assinado por uma CA falsa não confiável

Para gerar os certificados:

```bash
python gerar_certificados.py
```

### 2. Assinatura de Documentos (`assinar_documento.py`)

Este script permite assinar documentos usando a chave privada de um usuário:

1. Calcula o hash SHA-256 do documento
2. Cifra o hash com a chave privada do usuário
3. Gera um arquivo de assinatura

Uso:

```bash
python assinar_documento.py <caminho_documento> <caminho_chave_privada> [caminho_assinatura]
```

Exemplo:

```bash
python assinar_documento.py documento.txt pki/usuarios/joao/joao.key
```

### 3. Verificação de Assinaturas (`verificar_assinatura.py`)

Este script verifica a autenticidade de uma assinatura:

1. Verifica a cadeia de certificação até a CA Raiz
2. Valida o hash do documento
3. Verifica a assinatura usando a chave pública do certificado
4. Rejeita certificados não confiáveis (fora da cadeia de confiança)

Uso:

```bash
python verificar_assinatura.py <documento> <assinatura> <certificado> <ca_intermediaria> <ca_raiz>
```

Exemplo:

```bash
python verificar_assinatura.py documento.txt documento.txt.assinatura pki/usuarios/joao/joao.crt pki/ca-intermediaria/certs/ca-intermediaria.crt pki/raiz-ca/certs/raiz-ca.crt
```

## Testes de Segurança

O projeto inclui testes para verificar o comportamento do sistema em diferentes cenários:

### Teste de Assinatura Válida

1. Crie um documento de teste
2. Assine o documento com a chave de um usuário válido (João ou Maria)
3. Verifique a assinatura usando o certificado correspondente

### Teste de Rejeição de Certificado Não Confiável

1. Crie um documento de teste
2. Assine o documento com a chave do "atacante"
3. Tente verificar a assinatura - o sistema deve rejeitar a assinatura por não confiar no certificado

## Considerações de Segurança

- Esta implementação é apenas para fins educacionais e não deve ser usada em ambientes de produção
- Em um ambiente real, as chaves privadas devem ser protegidas com medidas adicionais de segurança
- A implementação não inclui todos os requisitos e complexidades da ICP-Brasil real
- Para emissões reais de certificados digitais, deve-se envolver uma Autoridade Certificadora credenciada na ICP-Brasil

## Detalhes Técnicos

### Extensões X.509 Implementadas

- **basicConstraints**: Define se o certificado é uma CA e o comprimento máximo do caminho de certificação
- **keyUsage**: Define as operações permitidas para a chave (assinatura de certificados, CRL, etc.)
- **subjectKeyIdentifier**: Identificador único da chave do sujeito
- **authorityKeyIdentifier**: Identificador da chave da autoridade emissora
- **subjectAlternativeName**: Nomes alternativos do sujeito (email, CPF)

### Algoritmos Utilizados

- **Chaves**: RSA 4096 bits
- **Hash**: SHA-256
- **Assinatura**: PKCS#1 v1.5