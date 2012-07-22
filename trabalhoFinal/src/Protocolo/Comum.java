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
    private PublicKey puCliente = null;
    private String idCliente = null;
    private PublicKey puSAuten = null;
    private String idSAuten = null;
    private PublicKey puServArq = null;
    private PrivateKey prServArq = null;
    private String idServArq = "servidorArquivos";

    public Comum() {
        /*cria ou carrega a keystore onde armazenou seu par de chaves.
        Se ainda não tem um par de chaves, cria e salva na keystore*/
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
                    theOutput = new ProtocolData(puServArq);


                    /*Armazenar log*/
                } else if (sMessage.equalsIgnoreCase("ID")) {
                    /* 3. Decriptografar login do cliente*/

                    /* 4. Verificar cliente (Compara as chaves)*/
                    if (idEhAutentico(this.idCliente, puCliente)) {
                        theOutput = new ProtocolData(this.idServArq);
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

    private boolean idEhAutentico(String idCliente, PublicKey puCliente) {
        /*Verificar autenticidade do id do servidor de arquivos
        1. Busca chave publica do cliente no servidor de autenticacao
        2. compara chaves: retorna false se não for igual e true se for igual*/
        return true;
    }
}

