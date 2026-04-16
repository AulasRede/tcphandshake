# 🔬 Laboratório: Captura e Análise do Handshake TCP com Wireshark

**Disciplina:** Redes de Computadores  
**Prof. Claudio Nunes**

---

## 📋 Sumário

1. [Objetivo](#1-objetivo)
2. [Pré-requisitos](#2-pré-requisitos)
3. [Revisão Teórica — O Handshake de Três Vias do TCP](#3-revisão-teórica--o-handshake-de-três-vias-do-tcp)
4. [Ferramentas Utilizadas](#4-ferramentas-utilizadas)
5. [Parte 1 — Instalação e Preparação do Ambiente](#5-parte-1--instalação-e-preparação-do-ambiente)
6. [Parte 2 — Descoberta do Endereço IP do Servidor](#6-parte-2--descoberta-do-endereço-ip-do-servidor)
7. [Parte 3 — Captura de Pacotes com o Wireshark](#7-parte-3--captura-de-pacotes-com-o-wireshark)
8. [Parte 4 — Aplicação de Filtros de Exibição](#8-parte-4--aplicação-de-filtros-de-exibição)
9. [Parte 5 — Identificação e Análise do Handshake TCP](#9-parte-5--identificação-e-análise-do-handshake-tcp)
10. [Parte 6 — Análise Detalhada dos Pacotes](#10-parte-6--análise-detalhada-dos-pacotes)
11. [Entregáveis](#11-entregáveis)
12. [Referências](#12-referências)

---

## 1. Objetivo

Nesta atividade prática, você irá utilizar o analisador de protocolos **Wireshark** para capturar e analisar pacotes de rede reais, com foco na compreensão do processo de **handshake de três vias (three-way handshake)** do protocolo TCP. Ao final, você será capaz de:

- Identificar os três pacotes que compõem o handshake TCP em uma captura real.
- Interpretar os campos essenciais dos cabeçalhos TCP: flags, números de sequência e de confirmação (ACK).
- Utilizar filtros de exibição (display filters) no Wireshark para isolar o tráfego de interesse.
- Compreender na prática como uma conexão TCP é estabelecida antes que qualquer dado de aplicação seja transmitido.

---

## 2. Pré-requisitos

- Computador com acesso à internet (Windows, macOS ou Linux).
- Permissões de administrador para instalação de software e captura de pacotes.
- Conhecimento básico de endereçamento IP e portas TCP.

---

## 3. Revisão Teórica — O Handshake de Três Vias do TCP

O **Transmission Control Protocol (TCP)** é um protocolo da camada de transporte orientado à conexão, definido pela RFC 793. Antes que qualquer dado de aplicação possa ser transmitido entre dois hosts, o TCP exige que uma conexão seja formalmente estabelecida. Esse processo de estabelecimento é chamado de **handshake de três vias** (three-way handshake) e envolve a troca de três segmentos:

### Passo 1 — SYN (Cliente → Servidor)

O cliente inicia a conexão enviando um segmento TCP com a flag **SYN** (Synchronize) ativada. Esse segmento contém:

- **Flag SYN = 1**: indica o desejo de estabelecer uma conexão.
- **Número de Sequência Inicial (ISN)**: um valor gerado pelo cliente (ex.: `Seq = 1000`) que será usado como referência para numerar todos os bytes que o cliente enviará ao longo da conexão.
- **Nenhum dado de aplicação**: este pacote é apenas de controle.

### Passo 2 — SYN-ACK (Servidor → Cliente)

Se o servidor aceitar a conexão, ele responde com um segmento contendo as flags **SYN** e **ACK** ativadas simultaneamente:

- **Flag SYN = 1**: o servidor também sincroniza seu próprio número de sequência.
- **Flag ACK = 1**: confirma o recebimento do SYN do cliente.
- **Número de Sequência Inicial do Servidor** (ex.: `Seq = 5000`): valor gerado pelo servidor.
- **Número de Confirmação (Acknowledgment Number)**: igual ao ISN do cliente + 1 (ex.: `Ack = 1001`), indicando que o próximo byte esperado do cliente é o 1001.

### Passo 3 — ACK (Cliente → Servidor)

O cliente finaliza o handshake enviando um segmento com a flag **ACK** ativada:

- **Flag ACK = 1**: confirma o recebimento do SYN-ACK do servidor.
- **Número de Sequência**: ISN do cliente + 1 (ex.: `Seq = 1001`).
- **Número de Confirmação**: ISN do servidor + 1 (ex.: `Ack = 5001`).

### Diagrama do Handshake

```
    Cliente                              Servidor
       |                                    |
       |  -------- SYN (Seq=x) --------->  |
       |                                    |
       |  <--- SYN-ACK (Seq=y, Ack=x+1) -- |
       |                                    |
       |  -------- ACK (Ack=y+1) -------->  |
       |                                    |
       |     ✅ Conexão Estabelecida         |
       |                                    |
```

### Por que três vias?

O handshake de três vias garante que:

1. **Ambos os lados concordam em se comunicar**: o SYN do cliente e o SYN-ACK do servidor demonstram disposição mútua.
2. **Ambos os ISNs são sincronizados**: cada lado conhece o número de sequência inicial do outro, o que é essencial para a transferência confiável de dados.
3. **Ambos os lados confirmam a capacidade de receber**: o ACK final do cliente prova ao servidor que o cliente recebeu seu SYN-ACK e está pronto para a comunicação.

### Números de Sequência Absolutos vs. Relativos

O Wireshark, por padrão, exibe os números de sequência de forma **relativa** (começando em 0) para facilitar a leitura. Nesta atividade, trabalharemos com os **números absolutos** para entender o mecanismo real do protocolo. Para visualizar os valores absolutos no Wireshark:

> **Edit → Preferences → Protocols → TCP** → Desmarque a opção **"Relative sequence numbers"**.

---

## 4. Ferramentas Utilizadas

| Ferramenta | Finalidade |
|---|---|
| **Wireshark** | Captura e análise de pacotes de rede |
| **Navegador Web** | Gerar tráfego HTTP (sem criptografia) para análise |
| **nslookup** ou **site DNSWatch** | Descobrir o endereço IP do servidor de destino |

---

## 5. Parte 1 — Instalação e Preparação do Ambiente

### 5.1 Instalação do Wireshark

1. Acesse o site oficial: [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
2. Baixe a versão adequada para o seu sistema operacional.
3. Execute o instalador. Durante a instalação no Windows, aceite a instalação do **Npcap** (driver de captura de pacotes). No Linux, pode ser necessário adicionar o seu usuário ao grupo `wireshark` para capturar sem `sudo`.
4. Após a instalação, abra o Wireshark e verifique se ele lista as interfaces de rede disponíveis na tela inicial.

### 5.2 Identificação da Interface de Rede

Na tela inicial do Wireshark, você verá uma lista de interfaces de rede. Identifique qual interface está sendo utilizada para acessar a internet:

- **Wi-Fi**: caso esteja conectado via rede sem fio.
- **Ethernet**: caso esteja conectado via cabo de rede.

> **Dica**: A interface correta geralmente é a que apresenta um gráfico de atividade oscilante na tela inicial do Wireshark.

---

## 6. Parte 2 — Descoberta do Endereço IP do Servidor

Antes de iniciar a captura, precisamos descobrir o endereço IP do servidor web que será acessado. O professor informará o endereço (URL) do site HTTP (sem criptografia) a ser utilizado nesta atividade.

> ⚠️ **Importante**: O site indicado pelo professor utiliza protocolo **HTTP** (sem criptografia TLS/HTTPS). Isso é proposital: permite que o Wireshark capture o tráfego TCP de forma legível e sem as camadas adicionais do TLS, facilitando a análise do handshake.

### Método 1 — Usando o site DNSWatch

1. Acesse [https://www.dnswatch.info](https://www.dnswatch.info) no seu navegador.
2. No campo de busca, digite o endereço do site informado pelo professor (ex.: `http://www.exemplo.com.br`).
3. Anote o endereço IP retornado (campo "A record").

### Método 2 — Usando o comando nslookup (alternativa)

Abra o terminal (Prompt de Comando no Windows, Terminal no Linux/macOS) e execute:

```bash
nslookup www.exemplo.com.br
```

Anote o endereço IP retornado na seção "Address" (ignorando o endereço do servidor DNS local).

> 📸 **EVIDÊNCIA 1**: Tire um print da tela mostrando o resultado da consulta DNS com o endereço IP do servidor descoberto (usando DNSWatch ou nslookup).

---

## 7. Parte 3 — Captura de Pacotes com o Wireshark

### 7.1 Iniciar a Captura

1. No Wireshark, selecione a interface de rede correta (identificada na Parte 1).
2. Clique no botão **azul de barbatana de tubarão** (▶) na barra de ferramentas, ou dê duplo clique na interface. A captura será iniciada e você verá pacotes surgindo em tempo real na tela.

### 7.2 Gerar o Tráfego TCP

3. Com a captura em andamento, abra o **navegador web** e acesse o site HTTP informado pelo professor. Aguarde a página carregar completamente.

### 7.3 Parar a Captura

4. Volte ao Wireshark e clique no botão **vermelho de parada** (⏹) na barra de ferramentas para encerrar a captura.

> **Dica**: Quanto menos tempo a captura ficar ativa, menos pacotes "extras" serão capturados, facilitando a análise. Tente minimizar o uso de outros aplicativos que acessem a internet durante a captura.

---

## 8. Parte 4 — Aplicação de Filtros de Exibição

Com a captura encerrada, você provavelmente terá centenas ou milhares de pacotes capturados. Para isolar apenas o tráfego entre o seu computador e o servidor web, utilizaremos **filtros de exibição** (display filters).

### 8.1 Filtro por Endereço IP

Na barra de filtros (parte superior da tela do Wireshark), digite o filtro abaixo, substituindo pelo IP descoberto na Parte 2:

```
ip.addr == X.X.X.X
```

Pressione **Enter** ou clique no botão de aplicar (→). O Wireshark agora exibirá apenas os pacotes trocados com o servidor alvo.

### 8.2 Filtro Combinado — Somente TCP (Opcional)

Se desejar refinar ainda mais e exibir apenas o tráfego TCP (excluindo pacotes DNS, ICMP, etc.):

```
ip.addr == X.X.X.X && tcp
```

### 8.3 Interpretando as Colunas

A tela principal do Wireshark exibe as seguintes colunas por padrão:

| Coluna | Significado |
|---|---|
| **No.** | Número sequencial do pacote na captura |
| **Time** | Momento da captura |
| **Source** | Endereço IP de origem |
| **Destination** | Endereço IP de destino |
| **Protocol** | Protocolo identificado (TCP, HTTP, etc.) |
| **Length** | Tamanho do pacote em bytes |
| **Info** | Resumo do conteúdo, incluindo flags TCP, portas e números de sequência |

> 📸 **EVIDÊNCIA 2**: Tire um print da tela do Wireshark mostrando o filtro aplicado e a lista de pacotes filtrados.

---

## 9. Parte 5 — Identificação e Análise do Handshake TCP

Agora vamos localizar e analisar os três pacotes do handshake TCP.

### 9.1 Identificando o Pacote SYN (1º Pacote)

Procure na lista filtrada o **primeiro pacote** cuja coluna **Info** contenha a flag **[SYN]**. Esse pacote:

- Tem como **Source** o IP do seu computador.
- Tem como **Destination** o IP do servidor.
- Na coluna Info, aparecerá algo como: `[SYN] Seq=0 Win=... Len=0`

Clique nesse pacote para selecioná-lo. No painel inferior do Wireshark, expanda a seção **"Transmission Control Protocol"** para ver todos os detalhes do cabeçalho TCP.

> 📸 **EVIDÊNCIA 3**: Tire um print da tela do Wireshark com o pacote SYN selecionado e os detalhes do cabeçalho TCP expandidos no painel inferior.

### 9.2 Identificando o Pacote SYN-ACK (2º Pacote)

O pacote imediatamente seguinte (ou próximo cronologicamente) deve conter as flags **[SYN, ACK]**:

- Tem como **Source** o IP do servidor.
- Tem como **Destination** o IP do seu computador.
- Na coluna Info: `[SYN, ACK] Seq=0 Ack=1 Win=... Len=0`

Selecione esse pacote e expanda o cabeçalho TCP.

> 📸 **EVIDÊNCIA 4**: Tire um print da tela do Wireshark com o pacote SYN-ACK selecionado e os detalhes do cabeçalho TCP expandidos.

### 9.3 Identificando o Pacote ACK (3º Pacote)

O terceiro pacote do handshake contém apenas a flag **[ACK]**:

- Tem como **Source** o IP do seu computador.
- Tem como **Destination** o IP do servidor.
- Na coluna Info: `[ACK] Seq=1 Ack=1 Win=... Len=0`

> 📸 **EVIDÊNCIA 5**: Tire um print da tela do Wireshark com o pacote ACK selecionado e os detalhes do cabeçalho TCP expandidos.

---

## 10. Parte 6 — Análise Detalhada dos Pacotes

Para cada um dos três pacotes do handshake, analise os campos do cabeçalho TCP e preencha a tabela abaixo. Lembre-se de configurar o Wireshark para exibir números de sequência **absolutos** (veja instruções na seção 3).

### Tabela de Análise do Handshake TCP

| Campo | Pacote 1 (SYN) | Pacote 2 (SYN-ACK) | Pacote 3 (ACK) |
|---|---|---|---|
| **IP de Origem** | | | |
| **IP de Destino** | | | |
| **Porta TCP de Origem** | | | |
| **Porta TCP de Destino** | | | |
| **Flag SYN** (0 ou 1) | | | |
| **Flag ACK** (0 ou 1) | | | |
| **Número de Sequência (absoluto)** | | | |
| **Número de Confirmação (Ack, absoluto)** | | | |
| **Tamanho da Janela (Window Size)** | | | |

### Perguntas de Análise

Responda às seguintes perguntas com base nos dados coletados:

**Sobre o Pacote 1 (SYN):**

a) Qual o endereço IP de origem? Esse endereço é o do cliente ou do servidor?

b) Qual a porta TCP de origem? Essa porta é uma porta bem conhecida (well-known) ou uma porta efêmera? Explique.

c) Qual a porta TCP de destino? Que serviço de aplicação está associado a esta porta?

d) Qual o número de sequência inicial (ISN) absoluto do cliente?

**Sobre o Pacote 2 (SYN-ACK):**

e) Qual o número de sequência inicial (ISN) absoluto do servidor?

f) Qual o número de confirmação (Ack)? Qual a relação entre esse valor e o ISN do cliente?

g) Por que esse pacote tem tanto a flag SYN quanto a flag ACK ativadas?

**Sobre o Pacote 3 (ACK):**

h) Qual o número de confirmação (Ack)? Qual a relação entre esse valor e o ISN do servidor?

i) Após esse pacote, a conexão está estabelecida. Qual será o próximo passo do protocolo HTTP sobre essa conexão?

---

## 11. Entregáveis

Ao final desta atividade, o aluno deverá submeter um **documento único** (formato PDF ou Word) contendo os seguintes itens:

| # | Entregável | Descrição |
|---|---|---|
| 1 | **Evidência 1** | Print da consulta DNS mostrando o IP do servidor |
| 2 | **Evidência 2** | Print do Wireshark com o filtro de exibição aplicado |
| 3 | **Evidência 3** | Print do pacote SYN com cabeçalho TCP expandido |
| 4 | **Evidência 4** | Print do pacote SYN-ACK com cabeçalho TCP expandido |
| 5 | **Evidência 5** | Print do pacote ACK com cabeçalho TCP expandido |
| 6 | **Tabela de Análise** | Tabela do handshake preenchida (seção 10) |
| 7 | **Respostas — Análise** | Respostas das perguntas **a** até **i** (seção 10) |

### Observações sobre o Documento

- Todas as capturas de tela devem estar **legíveis** e com **resolução suficiente** para que os dados possam ser verificados.
- As respostas devem ser redigidas com **suas próprias palavras**, demonstrando compreensão dos conceitos.
- O documento deve conter uma **capa** com: nome completo, matrícula e turma.

---

## 12. Referências

- **RFC 793** — Transmission Control Protocol. Disponível em: [https://www.rfc-editor.org/rfc/rfc793](https://www.rfc-editor.org/rfc/rfc793)
- **Wireshark User's Guide**. Disponível em: [https://www.wireshark.org/docs/wsug_html/](https://www.wireshark.org/docs/wsug_html/)
- **Wireshark Display Filter Reference — TCP**. Disponível em: [https://www.wireshark.org/docs/dfref/t/tcp.html](https://www.wireshark.org/docs/dfref/t/tcp.html)
- KUROSE, J. F.; ROSS, K. W. **Redes de Computadores e a Internet**: Uma Abordagem Top-Down. 8ª ed. Pearson, 2021.
- TANENBAUM, A. S.; FEAMSTER, N.; WETHERALL, D. J. **Redes de Computadores**. 6ª ed. Pearson, 2021.

---

> *Roteiro elaborado para a disciplina de Redes de Computadores — Prof. Claudio Nunes*
