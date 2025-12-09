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

# 3 Análise do hardware

Durante a análise do sistema de alimentação do dispositivo, foram identificadas as seguintes vulnerabilidades principais:

## 3.1 Vulnerabilidade 1 - Alimentação de emergência por pilhas removíveis

O sistema utiliza pilhas como fonte de energia reserva, armazenadas em um compartimento facilmente acessível. Isso significa que qualquer pessoa com acesso físico ao dispositivo pode remover ou substituir essas pilhas sem que o sistema gere alertas ou registre a manipulação. Como a alimentação emergencial depende exclusivamente dessas pilhas, a remoção ou sabotagem delas pode comprometer completamente o funcionamento do dispositivo durante quedas de energia. Assim, são possíveis alguns casos de ataque, entre eles:

### 3.1.1 Remoção física das pilhas

Este ataque ocorre quando o indivíduo abre o compartimento e retira todas as pilhas. Após a remoção, o sistema continua funcionando normalmente enquanto a energia principal estiver disponível, o que mascara a sabotagem. Entretanto, no momento em que houver uma queda de energia, o dispositivo ficará totalmente desligado, comprometendo sua disponibilidade e afetando mecanismos dependentes dele.

A probabilidade desse ataque é alta, pois exige apenas acesso físico e nenhum conhecimento técnico. O impacto é crítico, já que o sistema falha justamente quando a energia de reserva seria necessária. O risco resultante é, portanto, alto, combinando alta probabilidade e impacto elevado.

### 3.1.2 Substituição por pilhas descarregadas ou defeituosas

Nesse ataque, o invasor abre o compartimento e substitui as pilhas corretas por unidades descarregadas, defeituosas ou com polaridade invertida. O dispositivo permanece funcionando normalmente enquanto estiver conectado à energia principal, ocultando a sabotagem. No momento em que ocorrer uma interrupção da energia externa, o sistema não terá autonomia e desligará instantaneamente.

A probabilidade desse ataque é média-alta, pois exige que o atacante tenha pilhas inadequadas consigo, algo simples de obter. O impacto é alto, pois o sistema falha em um momento crítico e sem qualquer indicação prévia de problema. O risco final também é considerado alto, uma vez que combina impacto significativo com probabilidade relevante.

### 3.1.3 Mitigação

A mitigação mais adequada consiste em substituir o uso de pilhas removíveis por uma bateria recarregável interna, integrada ao case e conectada diretamente ao sistema de alimentação principal. A bateria deve ser fixada de forma a impedir remoção manual, eliminando a possibilidade de manipulação sem desmontagem completa do case. Além disso, por ser recarregável, dispensa troca manual e reduz drasticamente o risco relacionado à sabotagem física do backup de energia.

## 3.2 Vulnerabilidade 2 - Exposição dos fios entre os cases devido à instalação externa da tubulação

O sistema conta com dois cases interligados por fios que dependem de uma tubulação externa instalada no momento da implementação. Como essa tubulação não faz parte da estrutura original dos cases e depende da qualidade da instalação, ela pode apresentar fragilidades físicas, como baixa resistência a impacto ou fácil acesso quando colocada em áreas expostas. Com isso, um atacante pode quebrar a tubulação, removê-la ou cortá-la, obtendo acesso direto aos fios de comunicação e alimentação que conectam os módulos ESP utilizados no sistema aos componentes do case. A interrupção desses fios afeta diretamente o funcionamento integrado do dispositivo, podendo resultar em falhas totais ou parciais. Assim, são possíveis alguns casos de ataque, entre eles:

### 3.2.1 Corte dos fios após ruptura da tubulação instalada

Nesse ataque, o invasor identifica a tubulação externa que contém os fios, rompe sua estrutura e, com isso, expõe a fiação. A partir desse ponto, o atacante corta completamente os fios responsáveis pela interligação dos cases. Como esses fios são responsáveis pela comunicação dos componentes com as ESPs, o corte resulta na perda imediata da comunicação entre os módulos.

A probabilidade desse ataque é média, pois depende de ferramentas simples para romper a tubulação, mas não exige conhecimento técnico. O impacto é alto, já que o corte interrompe diretamente o funcionamento do sistema, podendo causar desligamento, falha de comunicação ou indisponibilidade completa. O risco final é alto, resultante da combinação entre impacto elevado e probabilidade significativa devido à instalação exposta.

### 3.2.2 Manipulação dos fios expostos após abertura da tubulação

No segundo ataque, o invasor não apenas rompe a tubulação, mas manipula os fios expostos sem necessariamente cortá-los. Isso inclui descascar parcialmente a fiação, inverter conexões, provocar curto-circuito ou interferir no sinal utilizado entre os cases. Como a tubulação é instalada externamente e pode variar conforme o ambiente, sua remoção parcial pode ser feita discretamente, permitindo manipulações que causam falhas intermitentes, mau funcionamento, reinicializações inesperadas ou até danos físicos aos módulos ESP.

A probabilidade desse ataque é média-baixa, pois exige um pouco mais de intenção, tempo e conhecimento básico sobre fios e conexões. No entanto, o impacto permanece alto, já que a manipulação pode danificar os componentes, interromper o funcionamento ou gerar comportamentos imprevisíveis no sistema. O risco final é classificado como médio-alto, pois, embora a probabilidade seja moderada, o impacto operacional é severo.

### 3.2.3 Mitigação

A mitigação deve envolver o reforço físico da tubulação externa instalada no case. Isso pode incluir o uso de eletrodutos metálicos rígidos ou tubulação reforçada resistente a impacto, além de fixação interna dos fios com presilhas internas que minimizem o movimento mesmo se a tubulação externa for danificada. Outra camada de proteção consiste em instalar um sensor de ruptura ou desconexão, que detecta alteração no estado dos fios ou abertura da tubulação, permitindo que o sistema registre ou sinalize tentativas de sabotagem.
