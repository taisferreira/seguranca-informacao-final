/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package Cifrador;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author estagiario01
 */
public class CifradorHASH {
    
    public static byte[] hashArq(byte[] arquivo){
        MessageDigest md;  
        byte[] digest = "".getBytes();
        try {
            md = MessageDigest.getInstance("SHA-512");
            digest = md.digest(arquivo); 
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradorHASH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return digest;
    }
    
    
}
