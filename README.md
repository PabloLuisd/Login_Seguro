# Sistema de Login Seguro

Sistema de autenticação desenvolvido com **Python, Flask e SQLite**, utilizando Docker para facilitar sua execução.

O projeto tem como objetivo demonstrar a implementação de mecanismos básicos de segurança da informação em um sistema de cadastro e autenticação de usuários.

## Funcionalidades

- Cadastro de usuários.
- Login com validação de credenciais.
- Área restrita para usuários autenticados.
- Logout.
- Bloqueio temporário após tentativas incorretas de login.
- Recuperação e redefinição de senha por token.

## Medidas de Segurança Implementadas

### 1. Proteção de senhas com Hash (scrypt)

As senhas dos usuários não são armazenadas diretamente no banco de dados.

Foi utilizado o algoritmo **scrypt**, por meio da biblioteca Werkzeug, para transformar as senhas em hashes.

- Impede o armazenamento de senhas em texto puro.
- Dificulta a descoberta das senhas originais em caso de vazamento do banco.
- A validação acontece por meio da comparação do hash com a senha informada no login.

### 2. Proteção contra ataques de força bruta

O sistema possui um mecanismo de controle de tentativas de login.

- Permite até 5 tentativas incorretas.
- Após a quinta tentativa, o acesso é bloqueado por 15 minutos.
- Após um login bem-sucedido, o contador de tentativas é zerado.

Essa medida dificulta ataques de força bruta, nos