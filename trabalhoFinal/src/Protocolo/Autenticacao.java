package Protocolo;

import Cifrador.CifradorRSA;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Autenticacao extends Comum {

    public static final int IDNOTFOUND = 5;
    // a senha e o local do key store ficam hard coded por enqto.
    private static char[] keyStorePassword = "admin".toCharArray();
    private File keyStoreFile;
    private KeyStore ks;

    public Autenticacao() {
        //super();
        super("Autenticacao", "autenticacao", "kstoreAutenticacao.ks");
        /* cria ou carrega a key store usada para armazenar as chaves públicas
        de quem se registrou.
         */
        try {
            //inicializa keystore e local do keystore
            ks = KeyStore.getInstance("JCEKS");
            keyStoreFile = new File("autenticacaoPU.keystore");
            if (!keyStoreFile.exists()) {
                //inicializa um keystore vazio
                ks.load(null, null);
                FileOutputStream fos = new FileOutputStream(keyStoreFile);
                //persiste o keyStore
                ks.store(fos, keyStorePassword);
                fos.close();
            } else {
                //carrega o keyStore
                FileInputStream fis = new FileInputStream(keyStoreFile);
                ks.load(fis, null);
                fis.close();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        X509Certificate cert = null;

        if (sMessage.equalsIgnoreCase("SAIR")) {
                    theOutput = new ProtocolData("Encerrando...");
                    state = EXIT;
                    /*Armazenar log*/

        } else if (sMessage.equalsIgnoreCase("REGISTRAR")) {
            {
                FileOutputStream fos = null;
                byte[] idByte = theInput.getBytes();
                String idAVerificar = new String(CifradorRSA.decodificar(idByte, prServidor));
                try {
                    if (ks.containsAlias(idAVerificar)) {
                        state = CONNECTED;
                        theOutput = new ProtocolData(idAVerificar + " já existe!");
                    } else {
                        //pu = theInput.getKey();//Servidor já tem a chave salva, pegou no handshking
                        cert = this.certCliente;
                        System.out.println("Registrando "+idAVerificar/*+"com certificado:\n"+cert*/);
                        ks.setCertificateEntry(idAVerificar, cert);
                        //ks.setKeyEntry(idAVerificar, pu.getEncoded(), null);
                        fos = new FileOutputStream(this.keyStoreFile);
                        ks.store(fos, this.password.toCharArray());
                        fos.close();
                        state = CONNECTED;
                        theOutput = new ProtocolData(idAVerificar + " registrado!");
                    }
                } catch (IOException ex) {
                    Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
                } catch (CertificateException ex) {
                    Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
                } catch (KeyStoreException ex) {
                    Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        } else if (sMessage.equalsIgnoreCase("CHAVE")) {
            /* 1. verifica se tem entrada na key store para o id especificado.
            2. Se tem, envia a chave encontrada.
            3. Se não tem, envia aviso de chave não encontrada.*/
            byte[] idByte = theInput.getBytes();
            String idAVerificar = new String(CifradorRSA.decodificar(idByte, prServidor));
            try {
                if (ks.containsAlias(idAVerificar)) {
                    cert = (X509Certificate) ks.getCertificate(idAVerificar);
                    System.out.println("Enviando certificado de "+idAVerificar);
                    theOutput = new ProtocolData(cert);
                } else {
                    theOutput = new ProtocolData(cert);
                    System.out.println("Certificado de "+idAVerificar+" não encontrado!");
                }
                state = CONNECTED;
            } catch (KeyStoreException ex) {
                Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else {
            theOutput = new ProtocolData("Use:\n\"REGISTRAR\" para se registrar"
                    + "\n\"BUSCAR\" para buscar uma chave pública"
                    + "\n\"SAIR\" para encenrrar a conexao");
            super.state = CONNECTED;
        }
        /*4. Armazena log*/
        escreveLog(this.idCliente+" "+sMessage+" "+ state +" "+theOutput);
    }

    @Override
    protected boolean idEhAutentico(String id, PublicKey pu) {
        return true;
    }
}
