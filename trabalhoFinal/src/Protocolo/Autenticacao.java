package Protocolo;


public class Autenticacao extends Comum{
    
    public Autenticacao(){
        super();
        
        /* cria ou carrega a key store usada para armazenar as chaves públicas
         de quem se registrou.
         */
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        //Cliente está enviando um dado
        if (sMessage.equalsIgnoreCase("REGISTRAR")) {
            /*
             1. Verifica se cliente já foi registrado.

             2. Se cliente não foi registrado insere na keystore seu id e sua
                chave publica

             3. Se cliente já foi registrado, envia mensagem de erro;

             4. Armazena log
             */
            theOutput = new ProtocolData("Cliente registrado!");
        } 
        else if (sMessage.equalsIgnoreCase("CHAVE")) {
            /*
             1. verifica se tem entrada na key store para o id especificado.

             2. Se não tem, envia mensagem de chave não encontrada.

             3. Se tem, envia a chave encontrada.

             4. Armazena log
             */
            theOutput = new ProtocolData("Chave encontrada!");
        } else {
            theOutput = new ProtocolData("Use:\n\"REGISTRAR\" para se registrar"
                    + "\n\"BUSCAR\" para buscar uma chave pública" +
                    "\n\"SAIR\" para encenrrar a conexao");
            
        }

        super.state = CONNECTED;
    }
}
