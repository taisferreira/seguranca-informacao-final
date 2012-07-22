
package Protocolo;

public class TransferenciaArquivos extends Comum{

    public TransferenciaArquivos(){
        super();

        /*
         Verifica se está registrado no servidor de autenticação 
         ou se registra no servidor de autenticacao.
         */
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        //Cliente está enviando um dado
        if (sMessage.equalsIgnoreCase("ENVIAR")) {
            String nomeArquivo = "FAKE";

            /*
             1. Le nome e conteudo do arquivo enviados pelo cliente

             2. Se cliente não tem diretório cria um
             File diretorio = new File("c:/id_cliente");
               if(!diretorio.exists())
                  diretorio.mkdir();

             3. Salva arquivo no diretório do cliente;

             4. Armazena log
             */
            theOutput = new ProtocolData("Arquivo "+nomeArquivo+" foi salvo!");
        }
        else if (sMessage.equalsIgnoreCase("BUSCAR")) {
            /*
             1. Verifica se cliente tem diretório.
             File diretorio = new File("c:/id_cliente");
               if(!diretorio.exists())

             2. Se cliente tem diretorio, envia lista de arquivos
             File dir; dir.list()

             3. Envia arquivo com o nome especificado pelo cliente.
              

             2. Se cliente não tem diretório envia mensagem de erro.

             4. Armazena log
             */
            String nomeArquivo = "FAKE";
            theOutput = new ProtocolData("Enviei o arquivo "+nomeArquivo);
        }
        else {
            theOutput = new ProtocolData("Use:\n\"ENVIAR\" para enviar "
                    + "arquivo para o servidor\n\"BUSCAR\" para buscar" +
                    "arquivo no servidor\n\"SAIR\" para encenrrar a conexao");
        }

        super.state = CONNECTED;
    }
}