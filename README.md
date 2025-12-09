# analise-vulnerabilidades

## 1. Vulnerabilidades Identificadas no Banco de Dados

## 1.1. Análise Estática das Vulnerabilidades do Banco de Dados

### **V1 — Falta de validação/sanitização antes de escrever no banco**
O microsserviço recebe JSON arbitrário do broker MQTT e grava no banco sem verificação rigorosa. Isso permite:
- SQL Injection
- Inserção de payload malicioso
- Corrupção de logs

### **V2 — Credenciais estáticas e risco de exposição**
O captive portal não foi integrado; as credenciais são estáticas. Isso pode expor:
- `service_role`
- `anon_key`
- `DATABASE_URL`

### **V3 — Privilégios excessivos no acesso ao banco**
Se o microsserviço usa a role padrão do Supabase, ele possui permissões superiores ao necessário, aumentando impacto de um vazamento.

### **V4 — Armazenamento de dados sensíveis altamente correlacionados**
Tabelas como `users`, `cards`, `access_logs` e `service_groups` permitem reconstruir todo o comportamento dos usuários, o que pode aumentar o impacto de vazamento.

### **V5 — Possível ausência de TLS entre microsserviço e Supabase**
Sem confirmação explícita do uso obrigatório de TLS, há risco de:
- Interceptação de credenciais
- MITM (Man-in-the-Middle)
- Manipulação de requisições

### **V6 — Réplica local SQLite sem criptografia**
A réplica local não utiliza criptografia nativa, permitindo que um atacante acesse:
- Logs
- Usuários
- Permissões

*Condição:* Se obtiver acesso ao sistema de arquivos.

---

# 1.2. Ataques Identificados

Dois ataques foram selecionados por impacto e plausibilidade dentro da arquitetura atual.

---

## 1.2.1. Ataque 1 — SQL Injection via MQTT

**Título:** SQL Injection via payload MQTT → microsserviço → Supabase

**Objetivo:** Executar comandos SQL arbitrários no banco Supabase.

### Passo-a-passo:
1. Atacante descobre broker MQTT (mesma rede).
2. Prepara payload malicioso:
   ```json
   {
     "id_card": "1'); DROP TABLE users; --",
     "id_lock": 2
   }
3. Publica em qualquer tópico (microsserviço assina #).
4. Microsserviço concatena string maliciosa na query.
5. Banco executa o comando injetado.

**Probabilidade:** Média-Alta Justificativa: O microsserviço não valida JSON antes de escrever no banco.

**Impacto:** Muito Alto Consequência: Destruição de tabelas críticas, interrupção do serviço, perda de auditoria.

**Risco:** ALTO/CRÍTICO

## 1.2.2. Ataque 2 — Comprometimento de Credenciais Supabase

**Título:** Takeover completo via vazamento de service_role

**Objetivo:** Obter controle total do banco remoto (Supabase).

**Passo-a-passo:**
1. Atacante acessa container, repositório ou máquina rodando o microsserviço.
2. Extrai variáveis de ambiente (DATABASE_URL, service_role).
3. Conecta diretamente ao banco via psql.
4. Realiza dump de tabelas:

```sql
SELECT * FROM users;
SELECT * FROM cards;
SELECT * FROM access_logs;
SELECT * FROM service_groups;
```

5. Cria role atacante:

```sql
CREATE ROLE atk WITH SUPERUSER LOGIN PASSWORD '1234';
```

6. Manipula, apaga ou altera logs e permissões.

**Probabilidade:** Alta Justificativa: Chaves service_role geralmente ficam expostas em ambientes acadêmicos com Docker.

**Impacto:** Crítico Consequência: Tomada completa do banco, exfiltração total, manipulação de dados, perda de integridade.

**Risco:** CRÍTICO

---

# 1.3. Matriz de Risco

| Ataque                                              | Probabilidade | Impacto     | Risco         |
|-----------------------------------------------------|--------------|-------------|---------------|
| Comprometimento de Credenciais (Takeover Supabase) | Alta         | Altíssimo   | Crítico     |
| SQL Injection via MQTT                              | Média-Alta   | Muito Alto  | Alto/Crítico |


# 1.4. Recomendações e Contramedidas

### Ações imediatas
- Usar prepared statements (consultas parametrizadas).
- Validar estrutura e tipos do JSON antes de inserir no banco de dados.
- Reduzir privilégios da role usada pelo microsserviço (Princípio do Menor Privilégio).
- Forçar uso de TLS com verificação de certificado.
- Rotacionar chaves sensíveis (service_role, anon_key).
- Evitar o uso de assinatura MQTT com curinga (#) quando não for estritamente necessário.

### Ações de médio prazo
- Criptografar a réplica local SQLite (ex.: SQLCipher).
- Habilitar auditoria do PostgreSQL (logs detalhados de consulta).
- Implementar firewall de IP no Supabase para restringir acesso.

### Ações de longo prazo
- Reintegrar um captive portal seguro para configuração de rede.
- Implementar autenticação mútua (mTLS) entre ESP32 e o broker MQTT.