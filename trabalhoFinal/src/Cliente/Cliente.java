package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import Protocolo.ProtocolData;
import Protocolo.Comum;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

public class Cliente {

    private final static String SERVERNAME = "localhost";
    private final static int SERVERPORT = 7000;
    private boolean naoConectado = true;
    private Socket serverSocket = null;
    private ObjectOutputStream out = null;
    private ObjectInputStream in = null;
    private ProtocolData dataToServer;
    private ProtocolData dataFromServer;
    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    private SecretKey skeyCliente = null;
    private PrivateKey prkeyCliente = null;
    private PublicKey pukeyCliente = null;
    private PublicKey pukeySArq = null;
    private PublicKey pukeySAut = null;
    private String id_cliente = null;
    private String id_servArq = null;
    private String id_servAut = null;
    private boolean fecharConexao = false;

    public Cliente() {
        carrega_keystore();

        try {
            /*Inicializa socket e streams para comunicar com servidor*/
            initStreams();

            /*Lê e imprime a primeira mensagem enviada pelo servidor*/
            dataFromServer = (ProtocolData) in.readObject();
            System.out.println(dataFromServer.toString());

            while (!fecharConexao) {
                    if (naoConectado) {
                        System.out.println("digite seu login: ");
                        this.id_cliente = stdIn.readLine();

                        carrega_chaves();

                        do_handshaking("CONECTAR");

                    } else {
                        processa_mensagem();
                    }
            }
            out.close();
            in.close();
            serverSocket.close();
            System.out.println("Client: Sucessfull exit!");

        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void main(String[] args) throws IOException {
        new Cliente();
    }

    private void initStreams() {
        try {
            serverSocket = new Socket(SERVERNAME, SERVERPORT);
            out = new ObjectOutputStream(serverSocket.getOutputStream());
            in = new ObjectInputStream(serverSocket.getInputStream());
        } catch (UnknownHostException e) {
            System.err.println(SERVERNAME + " : Unkown Host");
            System.exit(1);
        } catch (IOException e) {
            System.err.println(SERVERNAME + " : I/O Error");
            System.exit(1);
        }
    }

    private void carrega_keystore() {
        /*cria ou carrega keystore que o cliente usa para salvar suas chaves*/
    }

    private void carrega_chaves() {
        /*Verifica se cliente já tem chaves salvas na keystore.

        Se tiver: pede a senha para acessar as entradas deste login e carrega
         suas as chaves.

        Caso contrário, avisar que login não foi encontrado e perguntar se
         deseja registrar o login digitado:
            => Se a resposta for sim:
              1. Pede pra digitar e confirmar uma senha que será usada para
                 proteger as entradas deste longin na keystore.
              2. Cria o par de chaves assimetricas, salva na keystore e
               inicializa as variáveis globais pukeyCliente e prkeyCliente
              3. Cria uma chave secreta (simétrica), salva na keystore e
                 inicializa a variável global skeyCliente
            => Se a resposta for não: não faça nada.
          */
    }

    private boolean idEhAutentico(String string, PublicKey pukeySArq) {
        /*Verificar autenticidade do id do servidor de arquivos
        1. Busca chave publica do servidor arquivos no de autenticacao
        2. compara chaves: retorna false se não for igual e true se for igual*/
        return true;
    }

    /*1. Enviar chave pública para o servidor*/
    private void init_handshaking(String sMessage) {
        try {

            dataToServer = new ProtocolData(pukeyCliente);
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*2. Ler chave pública do servidor*/
    private void lerServPUKEY() {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            pukeySArq = dataFromServer.getKey();
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 3. Enviar id_cliente para servidor*/
    private void enviarID(String sMessage) {
        try {
            dataToServer = new ProtocolData(this.id_cliente);
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 4. Ler id do servidor*/
    private void lerIDServ() {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            this.id_servArq = dataFromServer.toString();
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void end_handshaking(String sMessage) {
        try {
            /*5.Confirma autenticidade do servidor*/
            dataToServer = new ProtocolData();
            if (idEhAutentico(this.id_servArq, pukeySArq)) {
                /*Eh autentico envia*/
                dataToServer.setMessage(sMessage);
            } else {
                System.out.println("Servidor de Arquivos não é confiável.");
                dataToServer.setMessage("EXIT");
            }
            out.writeObject(dataToServer);

            /*6. Le resposta do servidor*/
            leImprimeRespostaServidor(dataFromServer);

        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void do_handshaking(String sMessage) {
        while (naoConectado) {
            if (sMessage != null) {
                if (sMessage.equalsIgnoreCase("CONECTAR")) {
                    init_handshaking("CONECTAR");
                    sMessage = "ID";
                } else if (sMessage.equalsIgnoreCase("ID")) {
                    lerServPUKEY();
                    enviarID("ID");
                    sMessage = "OK";
                } else if (sMessage.equalsIgnoreCase("OK")) {
                    if (dataFromServer.getStatus() != Comum.LOGINERROR) {
                        /*Servidor reconheceu cliente*/
                        lerIDServ();
                        end_handshaking("OK");
                        naoConectado = false;
                    } else {/*continua desconectado*/
                        System.out.println("Seu login não pode ser validado."
                                + "\nTente novamente ou faça login com outro id.");
                        return;/*saindo desta função volta ao começo*/
                    }

                }
            }
        }
    }

    private void processa_mensagem() {
        try {
            System.out.println("Entre com a Menssagem: ");
            String sMessage = stdIn.readLine();
            if (sMessage != null) {
                if (sMessage.equalsIgnoreCase("SAIR")) {
                    dataToServer = new ProtocolData("Sair");
                    dataToServer.setMessage(sMessage);
                    out.writeObject(dataToServer);
                    leImprimeRespostaServidor(dataFromServer);
                    fecharConexao = true;
                }
                if (sMessage.equalsIgnoreCase("ENVIAR")) {
                    /*
                     1. Pede nome do arquivo em disco a ser transferido
                     2. gera hash do conteudo do arquivo e criptografa com a
                         CHAVE PUBLICA do cliente
                     3. Concatena o hash com o arquivo
                     4. Codifica o resultado com a chave secreta do cliente (skeyCliente)
                     5. Envia para o arquivo e o nome do arquivo para servidor
                     */
                }
                else {
                    System.out.println("Entre com um dado: ");
                    String sData = stdIn.readLine();

                    dataToServer = new ProtocolData(sData);
                    dataToServer.setMessage(sMessage);
                    out.writeObject(dataToServer);
                    leImprimeRespostaServidor(dataFromServer);
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void leImprimeRespostaServidor(ProtocolData dataFromServer) {
        try {
            /*Le e imprime a resposta do servidor*/
            dataFromServer = (ProtocolData) in.readObject();
            System.out.println(dataFromServer.toString());
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
