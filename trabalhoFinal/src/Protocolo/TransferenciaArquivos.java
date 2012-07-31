package Protocolo;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TransferenciaArquivos extends Comum {
    /*Para conversar com o servidor de autenticacao*/

    private final static String AUTENNAME = "localhost";
    private final static int AUTENTPORT = 6000;
    private Socket autServerSocket;
    private ObjectOutputStream autout;
    private ObjectInputStream autin;
    private ProtocoloCliente pcArquivos;
    private String nomeArquivo = "FAKE";

    public TransferenciaArquivos() {
        super("TransferenciaArquivos", "servidor", "kstoreArquivos.ks");
        abrirSocketServAutenticacao();
        pcArquivos = new ProtocoloCliente();
        pcArquivos.leImprimeRespostaServidor(autin);
        if (this.pcArquivos.isNaoConectado()) {
            pcArquivos = new ProtocoloCliente(this.certServidor, this.prServidor,
                    this.skeyServidor, this.idServidor);
            pcArquivos.do_handshaking(autout, autin);
        }
        //if(registrarChave){
        //registrar nova chave no servidor
        registrar();
        //}
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        //Cliente está enviando um dado
        if (sMessage.equalsIgnoreCase("ENVIAR")) {
            byte[] arquivo = theInput.getBytes();
            File diretorio = new File(("c:\\"+this.idCliente));
            if(diretorio.exists()){
                diretorio = new File("c:\\"+this.idCliente + "\\"+nomeArquivo);
                salvarArq(arquivo,diretorio);
            }else{
                diretorio.mkdirs();
                diretorio = new File("c:\\"+this.idCliente + "\\"+nomeArquivo);
                salvarArq(arquivo,diretorio);
            }
              //String nomeArquivo = "FAKE";            
            //nomeArquivo = theInput.getBytes().toString();           
            /*
            1. Le nome e conteudo do arquivo enviados pelo cliente

            2. Se cliente não tem diretório cria um
            File diretorio = new File("c:/id_cliente");
            if(!diretorio.exists())
            diretorio.mkdir();

            3. Salva arquivo no diretório do cliente;

            4. Armazena log
             */
            System.out.println("Salvando arquivo");
            theOutput = new ProtocolData("Arquivo " + nomeArquivo + " foi salvo!");
        }else  if(sMessage.equalsIgnoreCase("CAMINHO")){
           byte[] result = Cifrador.CifradorRSA.decodificar(theInput.getBytes(), prServidor);
            nomeArquivo = new String(result);            
            System.out.println("Salvando  nome do arquivo");
            theOutput = new ProtocolData("O arquivo " + nomeArquivo + " foi salvo!");
        } else if (sMessage.equalsIgnoreCase("LISTAR")) {
            /*1. Verifica se cliente tem diretório.
            File diretorio = new File("c:/id_cliente");
            if(!diretorio.exists())

            2. Se cliente tem diretorio, envia lista de arquivos
            File dir; dir.list()

            3. Armazena log*/
            String listaArquivos = "FAKE1, FAKE2";
            theOutput = new ProtocolData("Lista de arquivos: " + listaArquivos);
        } else if (sMessage.equalsIgnoreCase("BUSCAR")) {
            /*
            1. Envia arquivo com o nome especificado pelo cliente.

            2. Se arquivo não existe no diretório do cliente envia mensagem
            de arquivo não encontrado. Se o arquivo existe envia o arquivo.

            3. Armazena log
             */
           // String nomeArquivo = "FAKE";
            theOutput = new ProtocolData("Enviei o arquivo " + nomeArquivo);
        } else if (sMessage.equalsIgnoreCase("SAIR")) {
                theOutput = new ProtocolData("Encerrando...");
                state = EXIT;
                pcArquivos.encerrar_conexao(autout, autin);
                /*Armazenar log*/
        } else {
            theOutput = new ProtocolData("Use:\n\"ENVIAR\" para enviar "
                    + "arquivo para o servidor\n\"BUSCAR\" para buscar"
                    + "arquivo no servidor\n\"LISTAR\" para listar arquivos"
                    + "\n\"SAIR\" para encenrrar a conexao");
        }

        super.state = CONNECTED;
    }

    @Override
    /*Verificar autenticidade do idCliente*/
    protected boolean idEhAutentico(String idCliente, PublicKey puCliente) {
        //1. Busca chave publica do cliente no servidor de autenticacao
        pcArquivos.setAutenticador(autin, autout, pcArquivos);
        PublicKey pu = pcArquivos.buscar_chave(idCliente);


        // 2. compara chaves: retorna false se não for igual e true se for igual
        if(pu != null && pu.equals(puCliente)){
          System.out.println(idCliente+" é confiável!");
          return true;
        }
        System.out.println(idCliente+" não é confiável.");
        return false;
        //return true;/*o código acima contém bugs*/
    }

    private void registrar() {
        /*Registrar idCliente servidor de autenticacao*/
        pcArquivos.registrar(autout, autin);
        registrarChave = false;
    }

    private void abrirSocketServAutenticacao() {
        try {
            autServerSocket = new Socket(AUTENNAME, AUTENTPORT);
            autout = new ObjectOutputStream(autServerSocket.getOutputStream());
            autin = new ObjectInputStream(autServerSocket.getInputStream());
        } catch (UnknownHostException e) {
            System.err.println(AUTENNAME + " : Unkown Host");
            System.exit(1);
        } catch (IOException e) {
            System.err.println(AUTENNAME + " : I/O Error");
            System.exit(1);
        }
    }   

    private void salvarArq(byte[] arquivo, File diretorio) {
        FileOutputStream in = null ;    
                try {
                    in = new FileOutputStream(diretorio);                 
                    in.write(arquivo);                  
                    in.close();
                } catch (IOException ex) {
                    Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
                }
    }
}
