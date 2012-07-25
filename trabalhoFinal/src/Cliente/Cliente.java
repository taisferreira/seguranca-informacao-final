package Cliente;

import java.net.Socket;
import java.net.UnknownHostException;

import Protocolo.ProtocoloCliente;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
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
    private File file;

    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

    private SecretKey skeyCliente = null;
    private PrivateKey prkeyCliente = null;
    private PublicKey pukeyCliente = null;
    private String id_cliente = null;
    private String senha = null;
    private ProtocoloCliente protocolo;
    private ProtocoloCliente pAutenticacao;

    public Cliente() throws IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, InvalidKeySpecException {
        /*Inicio codigo de teste*/
        try {/*Apagar quando carrega_chaves estiver implementado*/
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
            /*Inicializa sockets e streams para comunicar com servidores*/
            initStreams();

            /*Lê e imprime a primeira mensagem enviada pelo servidor*/
            this.protocolo.leImprimeRespostaServidor(in);
            this.pAutenticacao.leImprimeRespostaServidor(autin);

            while (!this.protocolo.isFecharConexao()) {
                    if (this.protocolo.isNaoConectado()) {
                        System.out.println("digite seu login: ");
                        this.id_cliente = stdIn.readLine();

                        carrega_chaves();

                        /*reinicia protocolo com as chaves carregadas*/
                        this.protocolo = new ProtocoloCliente(this.pukeyCliente, this.prkeyCliente, this.skeyCliente, this.id_cliente);
                        this.pAutenticacao = new ProtocoloCliente(this.pukeyCliente,this.prkeyCliente, this.skeyCliente, this.id_cliente);

                        /*Conectando no servidor de autenticacao*/
                        this.pAutenticacao.do_handshaking(autout, autin);

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

    private void carrega_keystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        /*
         * cria ou carrega keystore que o cliente usa para salvar suas chaves
         */
        ks = KeyStore.getInstance("JCEKS");
        file = new File("D:\\key\\myks.keystore");

        if (!file.exists()) {

            //initialize empty keystore
            ks.load(null, null);
        } else {
            //loads the keystore
            FileInputStream fis = new FileInputStream(file);
            ks.load(fis, null);
            fis.close();

        }
    }

    private boolean confereSenhas() throws IOException {
        String senhaTemp = "teste";
        String confirmaSenha = "teste1";
        while (!(senhaTemp.equals(confirmaSenha))) {
            System.out.println("Digite a senha: ");
            senhaTemp = stdIn.readLine();
            System.out.println("Confirme a senha: ");
            confirmaSenha = stdIn.readLine();
        }
        senha = senhaTemp;
        return true;
    }

    private void carrega_chaves() throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, InvalidKeySpecException {
        /*
         * Verifica se cliente já tem chaves salvas na keystore.
         *
         * Se tiver: pede a senha para acessar as entradas deste login e carrega
         * suas as chaves.
         *
         */


        if (ks.isKeyEntry(id_cliente)) {
            System.out.println("Digite sua senha: ");
            senha = stdIn.readLine();
            try{
            skeyCliente = ((SecretKey) ks.getKey(id_cliente, senha.toCharArray()));
            }catch(KeyStoreException ex ){
                
                System.out.println("Senha errada! Digite novamente.");
                carrega_chaves();
                
            }catch(NoSuchAlgorithmException ex){
                System.out.println("Senha errada! Digite novamente.");
                carrega_chaves();
            }
            catch(UnrecoverableKeyException ex){
                System.out.println("Senha errada! Digite novamente.");
                carrega_chaves();
                
            }
           
        /*
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


        } else {
            String confirma = "t";
            while (!(confirma.equals("s") || confirma.equals("n"))) {
                System.out.println("Usuário não resgistrado.");
                System.out.println("Deseja registar o login digitado?(s/n)");
                confirma = stdIn.readLine();
                if (confirma.equals("s")) {
                    this.confereSenhas();
                    //Creates a Key
                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    // inicializacao do tamanho chave
                    keygen.init(128);
                    // obtencao da chave secreta
                    this.skeyCliente = keygen.generateKey();


                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    RSAPrivateKeySpec prspec = new RSAPrivateKeySpec(new BigInteger("10967329890609126549342864618470532711138147437917320994071629574339029161633059443601031534110334331301586615879817852513135997627023895462818039264327377"), new BigInteger("5492617935968578842524551055242684661259689567836829724696263574606033464197528124830013058381482085261392561829420128039731768130847357208373866284251129"));
                    RSAPublicKeySpec puspec = new RSAPublicKeySpec(new BigInteger("10967329890609126549342864618470532711138147437917320994071629574339029161633059443601031534110334331301586615879817852513135997627023895462818039264327377"), new BigInteger("65537"));
                    prkeyCliente = (RSAPrivateKey) kf.generatePrivate(prspec);
                    pukeyCliente = (RSAPublicKey) kf.generatePublic(puspec);
                    //saves the keystore
                    ks.setKeyEntry(id_cliente, skeyCliente, senha.toCharArray(), null);
                    
                    /*
                    Tem que salvar par de chaves no keystore
                    * ks.setKeyEntry(senha, , senha.toCharArray(), null);
                    */
                    
                    
                    FileOutputStream fos = new FileOutputStream(file);
                    //saves the keystore
                    ks.store(fos, senha.toCharArray());
                    fos.close();

                    registrar(id_cliente, pukeyCliente);
                } else {
                    System.out.println("");
                }
            }
        }

    }
    
    
    public boolean registrar(String id, PublicKey puk)
    {
        /*Registrar id_cliente e chave publica no servidor de autenticacao*/
        //pAutenticacao.registrar(prkeyCliente, certificado);
        return true; /*retorna true se conseguir registrar*/
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
}
