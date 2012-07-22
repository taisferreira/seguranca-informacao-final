package Protocolo;

import java.security.PrivateKey;
import java.security.PublicKey;

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
    protected String idServidor = "servidor";

    public Comum() {
        /*cria ou carrega a keystore onde armazenou seu par de chaves.
        Se ainda não tem um par de chaves, cria e salva na keystore*/

        /*Inicio codigo de teste*/
        try {/*Apagar quando construtor for implementado*/
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            java.security.KeyPair kp = kpg.generateKeyPair();

            this.puServidor = kp.getPublic();
            this.prServidor = kp.getPrivate();
        } catch (java.security.NoSuchAlgorithmException ex) {
            java.util.logging.Logger.getLogger(Comum.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        /*Fim codigo de teste*/
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
                    puCliente = theInput.getKey();

                    /* 2. Envia a sua chave pública*/
                    theOutput = new ProtocolData(puServidor);


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
                    /*theOutput = new ProtocolData("Conectado!");
                    state = CONNECTED;*/
                    theOutput = new ProtocolData("Você não está conectado, "
                            + "envie \"CONECTAR\" para o servidor.");
                }
                break;

            case CONNECTED:
                sMessage = theInput.getMessage();

                if (sMessage.equalsIgnoreCase("SAIR")) {
                    theOutput = new ProtocolData("Encerrando...");
                    state = EXIT;
                    /*Armazenar log*/
                } else {
                    processa_mensagem(theInput);
                }
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
        if (sMessage.equalsIgnoreCase("ENVIAR")) {
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
}

