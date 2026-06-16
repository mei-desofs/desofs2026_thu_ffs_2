# Software Composition Analysis (SCA) - OWASP Dependency-Check

Este documento contém uma breve análise dos resultados obtidos através da ferramenta OWASP Dependency-Check, que varreu as dependências do projeto para encontrar vulnerabilidades conhecidas (CVEs).

## Resumo do Scan
O scan foi executado usando o plugin `dependency-check-maven` (versão 10.0.4) com a base de dados do NVD (National Vulnerability Database).

- **Dependências analisadas:** 111 (76 únicas)
- **Dependências vulneráveis:** 16 (agrupadas pelos módulos principais abaixo)
- **Total de vulnerabilidades encontradas:** 105 (várias CVEs podem estar associadas à mesma biblioteca)

## Análise de Vulnerabilidades Encontradas

Abaixo estão os principais achados, agrupados pelo seu nível de severidade e componente afetado:

### 1. Eclipse Angus / Jakarta Mail (Severidade: HIGH)
Várias dependências transitivas relacionadas com o envio de emails estão a ser sinalizadas com severidade Alta.

- **Ficheiros afetados:** `angus-activation-2.0.2.jar`, `jakarta.mail-2.0.3.jar`, `angus-mail-2.0.3` (via `spring-boot-starter-mail`)
- **Vulnerabilidade Principal (CVE-2025-7962):** Existe uma falha conhecida (SMTP Injection) no Jakarta Mail 2.0.2 / 2.0.3 que permite a injeção de comandos SMTP usando caracteres `\r` e `\n` em UTF-8 para forjar mensagens separadas.
- **Plano de Remediação:** Atualizar a versão do `spring-boot-starter-mail` no `pom.xml` para uma versão mais recente do Spring Boot (que inclua o Jakarta Mail >= 2.0.4) ou forçar a resolução transitiva do `jakarta.mail` para a versão `2.0.4` (ou superior) via `<dependencyManagement>`.

### 2. Hibernate Validator (Severidade: MEDIUM)
- **Ficheiro afetado:** `hibernate-validator-8.0.2.Final.jar`
- **Plano de Remediação:** É recomendado atualizar a versão do `hibernate-validator` para a versão mais recente (`8.0.3.Final` ou superior) ou, se for trazida pelo Spring Boot, atualizar a versão do `spring-boot-starter-validation`.

## Conclusão e Próximos Passos
O principal ponto crítico identificado no backend é a injeção SMTP através do **Jakarta Mail**. Como o serviço de email é frequentemente exposto a inputs de utilizadores (como formulários de contacto ou registo), esta vulnerabilidade deve ser mitigada rapidamente. 

**Ação imediata recomendada:** 
Adicionar um bloco `<dependencyManagement>` no `pom.xml` para fixar as versões das bibliotecas vulneráveis acima listadas para versões onde as CVEs já estejam corrigidas, ou fazer o upgrade da versão do `spring-boot-starter-parent` caso já exista uma patch release que resolva isto nativamente.
