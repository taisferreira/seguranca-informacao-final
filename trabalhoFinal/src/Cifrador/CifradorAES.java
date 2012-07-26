/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package Cifrador;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

/**
 *
 * @author LauraMundim
 * 
 * Criei essa classe pra hora de cifrar com a chave secreta e garantir a confidencialidade
 * porem usei umas coisas da classe CifradorRSA q eu nao conheço, entao nao sei se ta certo
 * 
 */
public class CifradorAES {
    public static byte[] codificar(byte[] texto, SecretKey chave) {
        try {
            Cipher c = Cipher.getInstance("AES");
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
    public static byte[] decodificar(byte[] texto, SecretKey chave) {
        try {
            Cipher c = Cipher.getInstance("AES");
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
    public static javax.crypto.SecretKey gerarChaveSecreta() {
        javax.crypto.SecretKey pk = null;
        try {
            javax.crypto.KeyGenerator pkg = javax.crypto.KeyGenerator.getInstance("AES");
            pkg.init(128);
            pk = pkg.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return pk;
    }
    
}
