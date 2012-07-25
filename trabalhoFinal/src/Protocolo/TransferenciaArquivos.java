
package Protocolo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TransferenciaArquivos extends Comum{
    /*Para conversar com o servidor de autenticacao*/
    private final static String AUTENNAME = "localhost";
    private final static int AUTENTPORT = 6000;
    Socket autServerSocket;
    ObjectOutputStream autout;
    ObjectInputStream autin;

    public TransferenciaArquivos(){
        super();
        try {
            idServidor = "servidorArquivos";
            password = "senhaServidorArquivos";
            arquivoKeyStore = "/tais/home/servidorArquivosKeyStore";

            autServerSocket = new Socket(AUTENNAME, AUTENTPORT);
            autout = new ObjectOutputStream(autServerSocket.getOutputStream());
            autin = new ObjectInputStream(autServerSocket.getInputStream());
            /*
            Verifica se está registrado no servidor de autenticação
            ou se registra no servidor de autenticacao.
             */
            if (false == this.idEhAutentico(idServidor, puServidor)) {
                System.out.println("Servidor de arquivos tentando se registrar...");
                registrar();
            }
        } catch (UnknownHostException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        }
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
        else if (sMessage.equalsIgnoreCase("LISTAR")) {
            /*1. Verifica se cliente tem diretório.
             File diretorio = new File("c:/id_cliente");
               if(!diretorio.exists())

             2. Se cliente tem diretorio, envia lista de arquivos
             File dir; dir.list()

             3. Armazena log*/
            String listaArquivos = "FAKE1, FAKE2";
            theOutput = new ProtocolData("Lista de arquivos: "+listaArquivos);
        }
        else if (sMessage.equalsIgnoreCase("BUSCAR")) {
            /*
             1. Envia arquivo com o nome especificado pelo cliente.
              
             2. Se arquivo não existe no diretório do cliente envia mensagem
             de arquivo não encontrado. Se o arquivo existe envia o arquivo.

             3. Armazena log
             */
            String nomeArquivo = "FAKE";
            theOutput = new ProtocolData("Enviei o arquivo "+nomeArquivo);
        }
        else {
            theOutput = new ProtocolData("Use:\n\"ENVIAR\" para enviar "
                    + "arquivo para o servidor\n\"BUSCAR\" para buscar" +
                    "arquivo no servidor\n\"LISTAR\" para listar arquivos" +
                    "\n\"SAIR\" para encenrrar a conexao");
        }

        super.state = CONNECTED;
    }
    
    @Override
    /*Verificar autenticidade do idCliente*/
    protected boolean idEhAutentico(String idCliente, PublicKey puCliente) {
        /*ProtocoloCliente pc = new ProtocoloCliente(puServidor, prServidor, skeyServidor, idServidor);

        //conecta no servidor de autenticacao
        pc.do_handshaking(autout, autin);

        //1. Busca chave publica do cliente no servidor de autenticacao
        PublicKey pu = pc.buscar_chave(idCliente);

        //encerra conexão
        pc.encerrar_conexao(autout, autin);
        try {
            autServerSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        }

       // 2. compara chaves: retorna false se não for igual e true se for igual
        if(pu != null && pu.equals(puCliente)){
            System.out.println(idCliente+" foi registrado no SAut.");
            return true;
        }
        System.out.println(idCliente+" não está registrado no SAut.");
        return false;*/
        return true;/*o código acima contém bugs*/
    }

    private void registrar() {
        ProtocoloCliente pc = new ProtocoloCliente(puServidor, prServidor, skeyServidor, idServidor);

        /*conecta no servidor de autenticacao*/
        pc.do_handshaking(autout, autin);

        /*pede para se registrar*/
        pc.registrar(prServidor, cert);

        /*encerra conexão*/
        pc.encerrar_conexao(autout, autin);
        try {
            autServerSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
