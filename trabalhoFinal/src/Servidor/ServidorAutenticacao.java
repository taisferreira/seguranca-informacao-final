/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package Servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author tais
 */
public class ServidorAutenticacao extends Servidor{

    public ServidorAutenticacao(){
        super("localhost", 6000);
    }
    
    public static void main(String[] args){
        new ServidorAutenticacao();
    }

    @Override
    public void initThread(ServerSocket serverSocket) {
        /*Lanca Thread que usa protocolo Autenticacao*/
        try {
            System.out.println("ServidorAutenticacao.initThread");
            new ThreadServidorAutenticacao(serverSocket.accept()).start();
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
