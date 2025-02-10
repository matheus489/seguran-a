# Sistema de Segurança com Criptografia

Este projeto é um sistema de segurança que utiliza criptografia simétrica e assimétrica para proteger dados sensíveis. Ele também possui um sistema de controle de acesso para gerenciar usuários e suas permissões.

## Funcionalidades

- **Autenticação e Autorização**: Gerenciamento de usuários com diferentes níveis de acesso.
- **Criptografia Simétrica (AES)**: Proteção de dados usando uma chave simétrica.
- **Criptografia Assimétrica (RSA)**: Proteção de dados usando chaves públicas e privadas.
- **Interface Gráfica**: Interface de usuário desenvolvida com Tkinter.
- **Registro de Logs**: Logs de atividades criptografados para segurança adicional.

## Estrutura do Projeto

- `main.py`: Arquivo principal que inicializa o sistema e a interface gráfica.
- `interface.py`: Implementação da interface gráfica e funcionalidades relacionadas.
- `encryption.py`: Implementação das classes de criptografia simétrica e assimétrica.
- `access_control.py`: Gerenciamento de usuários e controle de acesso.
- `access.log`: Arquivo de log para registrar atividades do sistema.
- `users.json`: Armazena informações dos usuários cadastrados.
- `requirements.txt`: Lista de dependências do projeto.

## Como Executar

1. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Execute o sistema**:
   ```bash
   python main.py
   ```

## Dependências

- `pycryptodome`: Biblioteca para criptografia em Python.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests.

## Licença

Este projeto está licenciado sob a [MIT License](LICENSE).
