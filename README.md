# Soccer HTB - WebSocket SQLi Extractor

Um script em Python para exploração rápida e paralela do SQL Injection Cego no WebSocket da máquina Soccer do Hack The Box.

## Pré-requisitos

1.  **Configurar o Host:** O script precisa resolver o domínio do alvo. Adicione a máquina ao seu arquivo `/etc/hosts`.

    ```bash
    # Substitua 10.10.X.X pelo IP da máquina
    echo "10.10.X.X soc-player.soccer.htb" | sudo tee -a /etc/hosts
    ```

2.  **Instalar Dependência:** O script requer a biblioteca `websocket-client`.

    ```bash
    pip install websocket-client
    ```

**Observação:** Não é necessário ter um cookie de sessão válido. O endpoint do WebSocket é acessível sem autenticação.

## Como Usar

O script funciona em duas etapas: descobrir usuários e depois extrair a senha.

### 1. Descobrir Usuários

Primeiro, use a flag `--discover-users` para listar todos os usuários no banco de dados.

```bash
python3 shura.py --discover-users
```

### 2. Extrair Senha

Depois de encontrar um nome de usuário (ex: `player`), use a flag `--get-password` para extrair a senha dele.

```bash
python3 shura.py --get-password player
```

O script irá extrair a senha e salvá-la em um arquivo `player_credentials.txt`.
