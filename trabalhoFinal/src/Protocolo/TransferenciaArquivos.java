package Protocolo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

        if (sMessage.equalsIgnoreCase("ENVIAR")) {
            byte[] arquivo = theInput.getBytes();
            arquivo = Cifrador.CifradorAES.decodificar(arquivo, chaveSessao);

            File diretorio = new File((this.idCliente));
            if (diretorio.exists()) {
                diretorio = new File(this.idCliente + "/" + nomeArquivo);
            } else {
                diretorio.mkdirs();

                diretorio = new File(this.idCliente + "/" + nomeArquivo);

            }
            salvarArq(arquivo, diretorio);

            Comum.escreveLog("\nServidor de Arquivos\n"
                    + "Cliente: " + idCliente + "\nOperação: ENVIAR"
                    + "\nArquivo salvo em: " + diretorio+"\nCertificado do" +
                    " cliente: "+certCliente);

            String resposta = "Arquivo " + nomeArquivo + " foi salvo!";
            byte[] byteResp = Cifrador.CifradorAES.codificar(resposta.getBytes(), chaveSessao);
            theOutput = new ProtocolData(byteResp);

        } else if (sMessage.equalsIgnoreCase("CAMINHO")) {
            //byte[] result = Cifrador.CifradorRSA.decodificar(theInput.getBytes(), prServidor);
            byte[] result = Cifrador.CifradorAES.decodificar(theInput.getBytes(), chaveSessao);
            nomeArquivo = new String(result);

            String resp = "Nome do arquivo a ser salvo: " + nomeArquivo;
            byte[] respCodificada = Cifrador.CifradorAES.codificar(resp.getBytes(), chaveSessao);
            theOutput = new ProtocolData(respCodificada);

            Comum.escreveLog("\nServidor de Arquivos\n"
                    + "Cliente: " + idCliente + "\nOperação: CAMINHO"
                    + "\nNome de arquivo recebido para salvar:" +
                    " " + nomeArquivo);

        } else if (sMessage.equalsIgnoreCase("LISTAR")) {
            /*1. Verifica se cliente tem diretório
            2. Se cliente tem diretorio, envia lista de arquivos*/
            String nome = new String(Cifrador.CifradorAES.decodificar(theInput.getBytes(), chaveSessao));
            String resposta, mensagem;

            if (nome.equals(idCliente)) {
                File diretorio = new File(idCliente);

                if (!diretorio.exists() || diretorio.list().length == 0) {
                    resposta = "\nVocê não possui arquivos no servidor\n";
                    mensagem = "VAZIO";
                } else {
                    resposta = "\nSeus arquivos:\n";
                    String arqs[] = diretorio.list();
                    for (int i = 0; i < arqs.length; i++) {
                        resposta = resposta + arqs[i] + "\n";
                    }
                     mensagem = "LISTAR";
                }
            } else {
                resposta = "\nVocê não tem permissão para acessar os"
                        + " arquivos de " + nome + "\n";
                 mensagem = "VAZIO";
            }

            Comum.escreveLog("\nServidor de Arquivos\n"
                    + "Cliente: " + idCliente + "\nOperação: LISTAR" +
                    "\nCertificado do cliente: "+certCliente);

            byte[] enviar = Cifrador.CifradorAES.codificar(resposta.getBytes(), chaveSessao);
            theOutput = new ProtocolData(enviar);
            theOutput.setMessage(mensagem);
            //theOutput.setMessage("LISTAR");

        } else if (sMessage.equalsIgnoreCase("BUSCAR")) {
            /*1. Envia arquivo com o nome especificado pelo cliente.
            2. Se arquivo não existe no diretório do cliente envia mensagem
            de arquivo não encontrado. Se o arquivo existe envia o arquivo.*/
            String narquivo = new String(Cifrador.CifradorAES.decodificar(theInput.getBytes(), chaveSessao));
            String log;

            File diretorio = new File(idCliente + "/" + narquivo);
            if (!diretorio.exists()) {
                theOutput = new ProtocolData();
                theOutput.setBytes(null);
                log = "O arquivo" + narquivo + "não foi encontrado.";
            } else {
                byte[] enviar = null;
                log = "";
                try {
                    File file = new File(diretorio.getAbsolutePath());
                    if (file.isDirectory()) {
                        theOutput = new ProtocolData();
                        theOutput.setBytes(null);
                        log = narquivo + "é um diretorio.";
                    } else {
                        InputStream is = new FileInputStream(file);
                        enviar = new byte[(int) file.length()];
                        is.read(enviar);
                        log = "Enviando o arquivo " + narquivo;
                        enviar = Cifrador.CifradorAES.codificar(enviar, chaveSessao);
                        theOutput = new ProtocolData(enviar);
                    }
                } catch (IOException ex) {
                    Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            theOutput.setMessage("BUSCAR");

            Comum.escreveLog("\nServidor de Arquivos\n"
                    + "Cliente: " + idCliente + "\nOperação: BUSCAR"
                    + "\n" + log+"\nCertificado do cliente: "+certCliente);

        } else if (sMessage.equalsIgnoreCase("SAIR")) {
            byte[] resposta = "Encerrando...".getBytes();
            resposta = Cifrador.CifradorAES.codificar(resposta, chaveSessao);
            theOutput = new ProtocolData(resposta);
            state = EXIT;
            pcArquivos.encerrar_conexao(autout, autin);

            Comum.escreveLog("\nServidor de Arquivos\n"
                    + "Cliente: " + idCliente + "\nOperação: SAIR" +
                    "\nCertificado do cliente: "+certCliente);
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
        if (pu != null && pu.equals(puCliente)) {
            System.out.println(idCliente + " é confiável!");
            return true;
        }
        System.out.println(idCliente + " não é confiável.");
        return false;
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
        FileOutputStream in = null;
        try {
            in = new FileOutputStream(diretorio);
            in.write(arquivo);
            in.close();
        } catch (IOException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
