package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import Protocolo.ProtocoloCliente;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

public class Cliente {

    /*Servidor de autenticação escuta na porta 6000*/
    private final static String AUTENNAME = "localhost";
    private final static int AUTENTPORT = 6000;
    private Socket autServerSocket = null;
    private ObjectOutputStream autout = null;
    private ObjectInputStream autin = null;
    
    /*Servidor de arquivos escuta na porta 7000*/
    private final static String SERVERNAME = "localhost";
    private final static int SERVERPORT = 7000;
    private Socket serverSocket = null;
    private ObjectOutputStream out = null;
    private ObjectInputStream in = null;

    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

    private SecretKey skeyCliente = null;
    private PrivateKey prkeyCliente = null;
    private PublicKey pukeyCliente = null;
    private String id_cliente = null;
    private ProtocoloCliente protocolo;

    public Cliente() {
        this.protocolo = new ProtocoloCliente(this.pukeyCliente,
                this.prkeyCliente, this.skeyCliente, this.id_cliente);
        carrega_keystore();

        try {
            /*Inicializa sockets e streams para comunicar com servidores*/
            initStreams();

            /*Lê e imprime a primeira mensagem enviada pelo servidor*/
            this.protocolo.leImprimeRespostaServidor(in);

            while (!this.protocolo.isFecharConexao()) {
                    if (this.protocolo.isNaoConectado()) {
                        System.out.println("digite seu login: ");
                        this.id_cliente = stdIn.readLine();

                        carrega_chaves();

                        /*Necessário para fazer autenticacao no handshaking com o servidor*/
                        this.protocolo.usarAutenticacao(this.autin, this.autout);
                        this.protocolo.do_handshaking(out, in);

                    } else {
                        this.protocolo.processa_mensagem(out, in);
                    }
            }
            out.close();
            in.close();
            serverSocket.close();
            autout.close();
            autin.close();
            autServerSocket.close();
            System.out.println("Client: Sucessfull exit!");

        } catch (IOException ex) {
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

        try{
            autServerSocket = new Socket(AUTENNAME, AUTENTPORT);
            autout = new ObjectOutputStream(autServerSocket.getOutputStream());
            autin = new ObjectInputStream(autServerSocket.getInputStream());
        }catch (UnknownHostException e) {
            System.err.println(AUTENNAME + " : Unkown Host");
            System.exit(1);
        } catch (IOException e) {
            System.err.println(AUTENNAME + " : I/O Error");
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
              4. Registra chave no ServAut: registrar(String id, PublicKey puk)
            => Se a resposta for não: não faça nada.
          */
    }

    public boolean registrar(String id, PublicKey puk)
    {
        /*Registrar id_cliente e chave publica no servidor de autenticacao*/
        return true; /*retorna true se conseguir registrar*/
    }
}
