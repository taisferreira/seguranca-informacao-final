package Protocolo;

import armazemChaves.ArmazemChaves;
import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Comum {

    public static final int WAITING = 0;
    public static final int HANDSHAKING = 1;
    public static final int CONNECTED = 2;
    public static final int LOGINERROR = 3;
    public static final int EXIT = 4;

    /*Guardar a chave recebida do cliente no connect aqui*/
    protected byte[] keyMaterial;

    /*Guarda estado inicial do protocolo, inicialmente aguardando conexao*/
    protected int state = WAITING;
    protected ProtocolData theOutput;
    protected PublicKey puCliente = null;
    protected String idCliente = null;
    protected PublicKey puServidor;
    protected PrivateKey prServidor;
    protected X509Certificate certServidor;
    protected X509Certificate certCliente;
    protected SecretKey skeyServidor;
    protected String idServidor ;
    protected String password ;
    protected ArmazemChaves chaves;
    protected String arquivoKeyStore;
    protected static String logfile = "log.txt";
    protected boolean registrarChave = false;
    protected SecretKey chaveSessao;

    public Comum() {
        idServidor = "servidor";
        password = "servidor";
        arquivoKeyStore = "serverKeyStore.ks";
        init();
    }

    public Comum(String nome, String senha, String arquivoKS) {
        idServidor = nome;
        password = senha;
        arquivoKeyStore = arquivoKS;
        init();
    }

    public ProtocolData processInput(ProtocolData theInput) {
        theOutput = null;
        String sMessage;

        switch (state) {
            case LOGINERROR:
                state = HANDSHAKING;
            case WAITING:
                theOutput = new ProtocolData("Aguardando requisição");
                state = HANDSHAKING;
                break;

            case HANDSHAKING:
                sMessage = theInput.getMessage();
                if (sMessage.equalsIgnoreCase("CONECTAR")) {
                    /*1. Recebe certificado do cliente*/
                    certCliente = theInput.getCertificado();
                    puCliente = certCliente.getPublicKey();
                    idCliente = certCliente.getIssuerDN().getName().substring(3);
                    System.out.println("Id recebido no certificado do cliente: "+idCliente);

                    /* 2. Envia a seu certificado*/
                    theOutput = new ProtocolData(certServidor);

                } else if (sMessage.equalsIgnoreCase("SKEY")) {
                    System.out.println(this.idCliente+" pedindo "+theInput.toString());

                    /* 3. Verificar se cliente foi registrado*/
                    if (idEhAutentico(this.idCliente, puCliente)) {
                        /*Se cliente é autentico, envia chave a ser usada nesta sessao*/
                        chaveSessao = Cifrador.CifradorAES.gerarChaveSecreta();
                        chaveSessao = (SecretKey) new SecretKeySpec(chaveSessao.getEncoded(), "AES");
                        byte [] bidServidor = Cifrador.CifradorRSA.codificar(chaveSessao.getEncoded(), puCliente);
                        theOutput = new ProtocolData(bidServidor);
                    } else {
                        theOutput = new ProtocolData("Cliente não é confiável.");
                        state = LOGINERROR;
                    }
                } else if (sMessage.equalsIgnoreCase("OK")) {
                    /*Tudo certo no lado cliente*/
                    theOutput = new ProtocolData("Conexao estabelecida!");
                    state = CONNECTED;
                }
                else {
                    /*O cliente não aceitou a conexão*/
                    theOutput = new ProtocolData("Encerrando...");
                    state = EXIT;
                }
                break;

            case CONNECTED:
                sMessage = theInput.getMessage();

                processa_mensagem(theInput);
                
                break;

        }
        theOutput.setStatus(state);
        return theOutput;
    }

    /* Funcao que implementa o comportamento padrao do protocolo */
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        //Cliente está enviando um dado
        if (sMessage.equalsIgnoreCase("SAIR")) {
                    theOutput = new ProtocolData("Encerrando...");
                    state = EXIT;
                    /*Armazenar log*/

        } else if (sMessage.equalsIgnoreCase("ENVIAR")) {
            theOutput = new ProtocolData("Dados recebidos com sucesso!");

            /*Armazenar log*/
        } else {
            theOutput = new ProtocolData("Use\n\"ENVIAR\" para enviar "
                    + "dados ao servidor\n\"SAIR\" para encenrrar a conexao");
        }
        state = CONNECTED;
    }

    /*Comportamento padrão: não verifica autenticidade*/
    protected boolean idEhAutentico(String idCliente, PublicKey puCliente) {
        return true;
    }

    protected void init() {
        /*Cria ou carrega a keystore onde armazenou seu par de chaves.*/
        chaves = new ArmazemChaves(arquivoKeyStore, password);

        /*Se ainda não tem um par de chaves, cria e salva na keystore*/
        if(chaves.contemID(idServidor) == false){
            java.security.KeyPair kp = Cifrador.CifradorRSA.gerarParChaves();
            puServidor = kp.getPublic();
            prServidor = kp.getPrivate();
            chaves.guardaKeyPair(idServidor, password, kp);
            certServidor = chaves.pegaCertificado(idServidor);
            System.out.println("Criando chave para "+this.idServidor+"...");
            registrarChave = true;
        }
        else{
            this.certServidor = chaves.pegaCertificado(idServidor);
            this.puServidor = certServidor.getPublicKey();
            this.prServidor = chaves.pegaPrivateKey(idServidor, password);
            //System.out.println("Comum publicKey: "+this.puServidor);
            System.out.println("Chave de "+this.idServidor+" buscada com sucesso!");
        }
    }

    protected static void escreveLog(String log){
       PrintWriter w = null; 
        try {
            w = new PrintWriter(new FileWriter(logfile,true));
            Date date = new Date();
            w.println(date.toString() +" "+ log);
            w.flush();
            w.close();
        } catch (IOException ex) {
            Logger.getLogger(Comum.class.getName()).log(Level.SEVERE, null, ex);
        }finally{
            w.close();
        }
    }
}

