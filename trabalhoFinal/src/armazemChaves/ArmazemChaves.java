/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package armazemChaves;

import Certificado.CertificadoX509Certificate;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

/**
 *
 * @author tais
 */
public class ArmazemChaves {

    private KeyStore ks;
    private File file;
    private String password;

    public ArmazemChaves(String pathArquivo, String keyStorePassword) {
        {
            FileInputStream fis = null;
            try {
                ks = KeyStore.getInstance("JCEKS");
                file = new File(pathArquivo);
                if (!file.exists()) {
                    ks.load(null, null);

                    //salva nova keystore
                    FileOutputStream fos = new FileOutputStream(file);
                    ks.store(fos, keyStorePassword.toCharArray());
                    fos.close();
                } else {
                    fis = new FileInputStream(file);
                    ks.load(fis, keyStorePassword.toCharArray());
                    fis.close();
                }

                this.password = keyStorePassword;
            } catch (IOException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void guardaKeyPair(String id, String senha, KeyPair kp) {
        {
            FileOutputStream fos = null;
            try {
                char[] senhaChar = null;
                if (senha != null) {
                    senhaChar = senha.toCharArray();
                }

                /*guarda chave publica*/
                X509Certificate cert = CertificadoX509Certificate.generateCertificate("CN=" + id, kp, -1, "MD5WithRSA");
                ks.setCertificateEntry(id, cert);

                /*guarda chave privada*/
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = cert;
                ks.setKeyEntry(id, kp.getPrivate(), senhaChar, chain);
                /*Atualiza arquivo da keystore no disco*/
                fos = new FileOutputStream(this.file);
                this.ks.store(fos, this.password.toCharArray());
                fos.close();
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException ex) {
                Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                    Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public X509Certificate pegaCertificado(String id) {
        try {/*Certificado não é armazenado com senha*/
            if (ks.containsAlias(id)) {
                return (X509Certificate) ks.getCertificate(id);
            } else {
                return null;
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public PrivateKey pegaPrivateKey(String id, String senha) {
        try {
            if (ks.containsAlias(id)) {
                return (PrivateKey) ks.getKey(id, senha.toCharArray());
            } else {
                return null;
            }

        } catch (KeyStoreException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public void guardaSecretKey(String id, SecretKey skey, String senhasString) {
        try {
            String alias = id + ".skey";
            char[] senhaChar = null;
            if (senhasString != null) {
                senhaChar = senhasString.toCharArray();
            }
            ks.setKeyEntry(alias, skey, senhaChar, null);

            /*Atualiza arquivo da keystore no disco*/
            FileOutputStream fos = new FileOutputStream(this.file);
            this.ks.store(fos, this.password.toCharArray());
            fos.close();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public SecretKey pegaSecretKey(String id, String senhaString) {
        try {
            String alias = id + ".skey";
            char[] senhaChar = null;
            if (senhaString != null) {
                senhaChar = senhaString.toCharArray();
            }
            if (ks.containsAlias(alias)) {
                return (SecretKey) ks.getKey(alias, senhaChar);
            } else {
                return null;
            }

        } catch (KeyStoreException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(ArmazemChaves.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
