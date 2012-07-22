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
public class ServidorArquivos extends Servidor{
    public ServidorArquivos(){
        super();
    }

    public static void main(String[] args){
        new ServidorArquivos();
    }

    @Override
    public void initThread(ServerSocket serverSocket) {
        /*Lanca Thread que usa protocolo TransferenciaArquivos*/
        try {
            System.out.println("ServidorArquivos.initThread");
            new ThreadServidorArquivos(serverSocket.accept()).start();
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
