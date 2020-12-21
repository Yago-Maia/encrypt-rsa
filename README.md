### Como utilizar o arquivo Encrypt.jar:
Acesse o diretório raiz do projeto pelo terminal e execute com os comandos:
```bash
java -jar Encrypt.jar -d <textoEncriptado> <chavePrivada>      "Para descriptografar"
java -jar Encrypt.jar -c <texto> <chavePublica>                "Para criptografar"
java -jar Encrypt.jar -g                                       "Para gerar chaves Pública e Privada"
```