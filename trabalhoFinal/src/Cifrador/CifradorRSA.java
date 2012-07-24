/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package Cifrador;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author tais
 */
public class CifradorRSA {

    public static byte[] codificar(byte[] texto, PrivateKey chave) {
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, chave);
            return c.doFinal(texto);

        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] codificar(byte[] texto, PublicKey chave) {
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.ENCRYPT_MODE, chave);
            return c.doFinal(texto);

        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] decodificar(byte[] texto, PrivateKey chave) {
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.DECRYPT_MODE, chave);
            return c.doFinal(texto);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] decodificar(byte[] texto, PublicKey chave) {
        try {
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.DECRYPT_MODE, chave);
            return c.doFinal(texto);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static java.security.KeyPair gerarParChaves() {
        java.security.KeyPair kp = null;
        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return kp;
    }
}
