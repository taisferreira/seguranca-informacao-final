package Cliente;

import java.net.Socket;
import java.net.UnknownHostException;

import Protocolo.ProtocoloCliente;
import armazemChaves.ArmazemChaves;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
    //Modificado pela Kamylla
    private KeyStore ks;
    private ArmazemChaves chaves;
    private File file;
    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    private SecretKey skeyCliente;
    private PrivateKey prkeyCliente;
    private PublicKey pukeyCliente;
    private X509Certificate certCliente;
    private String idCliente = null;
    private String senha = null;
    private ProtocoloCliente protocolo;
    private ProtocoloCliente pAutenticacao;
    private boolean registrarChave = false;

    public Cliente() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, InvalidKeySpecException {
        /*Inicio codigo de teste
        try {//Apagar quando carrega_chaves estiver implementado
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            java.security.KeyPair kp = kpg.generateKeyPair();
            this.pukeyCliente = kp.getPublic();
            this.prkeyCliente = kp.getPrivate();
        } catch (java.security.NoSuchAlgorithmException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
        /*Fim codigo de teste*/

        carrega_keystore();

        this.protocolo = new ProtocoloCliente();
        this.pAutenticacao = new ProtocoloCliente();

        try {
            /*Inicializa sockets e streams para comunicar com servidor*/
            initStreamsServAut();

            /*Lê e imprime a primeira mensagem enviada pelo servidor de Autenticacao*/
            this.pAutenticacao.leImprimeRespostaServidor(autin);

            while (!this.protocolo.isFecharConexao()) {
                if (this.protocolo.isNaoConectado()) {
                    carrega_chaves();

                    /*reinicia protocolo com as chaves carregadas*/
                    this.protocolo = new ProtocoloCliente(this.certCliente, this.prkeyCliente, this.skeyCliente, this.idCliente);
                    this.pAutenticacao = new ProtocoloCliente(this.certCliente, this.prkeyCliente, this.skeyCliente, this.idCliente);

                    /*Conectando no servidor de autenticacao*/
                    this.pAutenticacao.do_handshaking(autout, autin);

                    /*Se registra no servidor de Autenticacao*/
                    if(this.registrarChave){
                        registrar();
                    }
                    
                    /*Abre comunicação com servidor de arquivos*/
                    initStreamsServArq();

                    /*lê primeiro dado enviado pelo servidor de arquivos*/
                    this.protocolo.leImprimeRespostaServidor(in);

                    /*Conectando no servidor de arquivos*/
                    this.protocolo.usarAutenticacao(this.autin, this.autout, this.pAutenticacao);
                    this.protocolo.do_handshaking(out, in);

                } else {
                    this.protocolo.processa_mensagem(out, in);
                }
            }

            out.close();
            in.close();
            serverSocket.close();
            encerrarServAut();

            System.out.println("Client: Sucessfull exit!");

        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static void main(String[] args) throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeySpecException, CertificateException {
        new Cliente();
    }

    private void initStreamsServArq() {
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

    private void carrega_keystore(){
        /*
         * cria ou carrega keystore que o cliente usa para salvar suas chaves
         */
        chaves = new ArmazemChaves("myks.keystore", "cliente");
        /*ks = KeyStore.getInstance("JCEKS");
        file = new File("myks.keystore");

        if (!file.exists()) {

            //initialize empty keystore
            ks.load(null, null);
        } else {
            //loads the keystore
            FileInputStream fis = new FileInputStream(file);
            ks.load(fis, null);
            fis.close();

        }*/
    }

    private boolean confereSenhas() throws IOException {
        String senhaTemp = "teste";
        String confirmaSenha = "teste1";
        while (!(senhaTemp.equals(confirmaSenha))) {
            System.out.println("Digite a senha: ");
            senhaTemp = stdIn.readLine();
            System.out.println("Confirme a senha: ");
            confirmaSenha = stdIn.readLine();
            if(!senhaTemp.equals(confirmaSenha)){
                System.out.println("\nSenhas não conferem. Tente novamente.");
            }
        }
        senha = senhaTemp;
        return true;
    }

    private void carrega_chaves() throws IOException{
        /*
         * Verifica se cliente já tem chaves salvas na keystore.
         *
         * Se tiver: pede a senha para acessar as entradas deste login e carrega
         * suas as chaves.
         *
         */
        System.out.println("Digite seu login: ");
        this.idCliente = stdIn.readLine();

        if (chaves.contemID(idCliente)) {
            System.out.println("Digite sua senha: ");
            senha = stdIn.readLine();

            if(chaves.pegaSecretKey(idCliente, senha) == null){
                System.out.println("Senha errada! Digite novamente.");
                carrega_chaves();
            }
            else{
                skeyCliente = chaves.pegaSecretKey(idCliente, senha);
                prkeyCliente = chaves.pegaPrivateKey(idCliente, senha);
                certCliente = chaves.pegaCertificado(idCliente);
                pukeyCliente = certCliente.getPublicKey();
            }

            /*
            Caso contrário, avisar que login não foi encontrado e perguntar se
            deseja registrar o login digitado:
            => Se a resposta for sim:
              1. Pede pra digitar e confirmar uma senha que será usada para
              proteger as entradas deste login na keystore.
              2. Cria o par de chaves assimetricas, salva na keystore e
              inicializa as variáveis globais pukeyCliente e prkeyCliente
              3. Cria uma chave secreta (simétrica), salva na keystore e
              inicializa a variável global skeyCliente
              4. Registra chave no ServAut: registrar(String id, PublicKey puk)
            => Se a resposta for não: não faça nada.
             */
        } else {
            String confirma = "t";
            while (!(confirma.equals("s") || confirma.equals("n"))) {
                System.out.println("Usuário não resgistrado.");
                System.out.println("Deseja registar o login digitado?(s/n)");
                confirma = stdIn.readLine();
                if (confirma.equals("s")) {
                    this.confereSenhas();
                    
                    this.skeyCliente = Cifrador.CifradorAES.gerarChaveSecreta();
                    //salva chave simétrica
                    chaves.guardaSecretKey(idCliente, skeyCliente, senha);

                    KeyPair kp = Cifrador.CifradorRSA.gerarParChaves();
                    //salva chave privada e o certificado com a chave pública
                    chaves.guardaKeyPair(idCliente, senha, kp);
                    prkeyCliente = chaves.pegaPrivateKey(idCliente, senha);
                    certCliente = chaves.pegaCertificado(idCliente);
                    pukeyCliente = certCliente.getPublicKey();

                    registrarChave = true;
                } else {
                    System.out.println("");
                    carrega_chaves();/*Volta pra o inicio pra pedir login de novo*/
                }
            }
        }

    }

    public boolean registrar() {
        /*Registrar idCliente e chave publica no servidor de autenticacao*/
        pAutenticacao.registrar(autout, autin);
        this.registrarChave = false;
        return true;
    }

    private void encerrarServAut() {
        try {
            Protocolo.ProtocolData dataToServer = new Protocolo.ProtocolData("SAIR");
            dataToServer.setMessage("SAIR");
            autout.writeObject(dataToServer);
            pAutenticacao.leImprimeRespostaServidor(autin);

            autout.close();
            autin.close();
            autServerSocket.close();
        } catch (IOException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void initStreamsServAut() {
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
}
