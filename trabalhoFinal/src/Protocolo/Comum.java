package Protocolo;

import armazemChaves.ArmazemChaves;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

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
    protected static String logfile = "D:\\logs\\log.txt";
    boolean registrarChave = false;

    public Comum() {
        idServidor = "servidor";
        password = "servidor";
        arquivoKeyStore = "/home/tais/serverKeyStore.ks";
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
                    /*1. Recebe chave pública do cliente*/
                    certCliente = theInput.getCertificado();
                    puCliente = certCliente.getPublicKey();
                    //System.out.println("PublicKeyCliente: "+puCliente);

                    /* 2. Envia a sua chave pública*/
                    //System.out.println("Chave que servidor está enviando: "+puServidor);
                    theOutput = new ProtocolData(certServidor);


                    /*Armazenar log*/
                } else if (sMessage.equalsIgnoreCase("ID")) {
                    /* 3. Decriptografar login do cliente*/
                    byte[] dados = theInput.getBytes();
                    dados = Cifrador.CifradorRSA.decodificar(dados, prServidor);
                    //dados = Cifrador.CifradorRSA.decodificar(dados, this.puCliente);

                    this.idCliente = new String(dados);
                    System.out.println("IdCliente = "+this.idCliente);

                    /* 4. Verificar cliente (Compara as chaves)*/
                    if (idEhAutentico(this.idCliente, puCliente)) {
                        /*garantir que so o cliente abre*/
                        byte [] bidServidor = Cifrador.CifradorRSA.codificar(this.idServidor.getBytes(), puCliente);
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
                    /*theOutput = new ProtocolData("Você não está conectado, "
                            + "envie \"CONECTAR\" para o servidor.");
                    state = CONNECTED;*/
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
        this.certServidor = chaves.pegaCertificado(idServidor);
        if(certServidor == null){
            java.security.KeyPair kp = Cifrador.CifradorRSA.gerarParChaves();
            puServidor = kp.getPublic();
            prServidor = kp.getPrivate();
            chaves.guardaKeyPair(idServidor, password, kp);
            certServidor = chaves.pegaCertificado(idServidor);
            System.out.println("Criando chave para "+this.idServidor+"...");
            registrarChave = true;
        }
        else{
            this.puServidor = certServidor.getPublicKey();
            this.prServidor = chaves.pegaPrivateKey(idServidor, password);
            //System.out.println("Comum publicKey: "+this.puServidor);
            System.out.println("Chave de "+this.idServidor+" buscada com sucesso!");
        }
    }

    //implementação temporária
    protected static void escreveLog(String log){
        try {
            OutputStream out = new BufferedOutputStream(new FileOutputStream(logfile));
             out.write(log.getBytes());
        } catch (IOException ex) {
            Logger.getLogger(Comum.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

