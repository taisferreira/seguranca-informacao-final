package Protocolo;

import java.security.PublicKey;


public class Autenticacao extends Comum{
    public static final int IDNOTFOUND = 5;
    
    public Autenticacao(){
        super();
        super.idServidor = "servidorAutenticacao";
        
        /* cria ou carrega a key store usada para armazenar as chaves públicas
         de quem se registrou.
         */
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        if (sMessage.equalsIgnoreCase("REGISTRAR")) {
            /*
             1. Verifica se cliente já foi registrado.

             2. Se cliente não foi registrado insere na keystore seu id e sua
                chave publica

             3. Se cliente já foi registrado, envia mensagem de erro;

             4. Armazena log
             */
            theOutput = new ProtocolData("Cliente registrado!");
            super.state = CONNECTED;
        } 
        else if (sMessage.equalsIgnoreCase("CHAVE")) {
            /* 1. verifica se tem entrada na key store para o id especificado.*/
            PublicKey pu = null;
            
            byte[] dados = theInput.getBytes();
            dados = Cifrador.CifradorRSA.decodificar(dados, prServidor);
            String id = new String(dados);

            /* 2. Se tem, envia a chave encontrada.*/
            /*Tirar comentários quando esta classe tiver sua keystore implementada.
             Até lá qualquer id vai devolver chave==null*/
            if (/*this.keystore.containsAlias(cid)*/true) {
                /*
                 pu = (PublicKey) this.keystore.getKey(id, keyStorePassword)
                  */
                theOutput = new ProtocolData(pu);
                state = CONNECTED;
            } 
            else{/* 3. Se não tem, envia aviso de chave não encontrada.*/
                theOutput = new ProtocolData(pu);
                state = IDNOTFOUND;
            }

            /* 4. Armazena log */
            
        } else {
            theOutput = new ProtocolData("Use:\n\"REGISTRAR\" para se registrar"
                    + "\n\"BUSCAR\" para buscar uma chave pública" +
                    "\n\"SAIR\" para encenrrar a conexao");
            super.state = CONNECTED;
        }

        
    }

    @Override
    protected boolean idEhAutentico(String id, PublicKey pu) {
        /*Verificar autenticidade do id 
        1. Busca chave publica do id na keystore
        2. compara chaves: retorna false se não for igual e true se for igual*/
        return true;
    }
}
