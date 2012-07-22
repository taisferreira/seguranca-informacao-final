package Servidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Servidor {

    private String SERVERNAME = "localhost";
    private int SERVERPORT = 7000;

    public Servidor() {
        init_servidor();
    }

    public Servidor(String servidor, int porta) {
        this.SERVERNAME = servidor;
        this.SERVERPORT = porta;
        init_servidor();
    }

    private void init_servidor(){
        ServerSocket serverSocket = null;
        boolean listening = true;

        try {
            serverSocket = new ServerSocket(SERVERPORT);
            System.out.println("Starting Sever: " + SERVERNAME + "Port: " + SERVERPORT);

            while (listening) {
                initThread(serverSocket);
            }
            serverSocket.close();

        } catch (IOException e) {
            System.err.println("Server Error: " + "I/O error while connecting to port " + SERVERPORT);
            System.exit(-1);
        }
    }

    public static void main(String[] args) {
        new Servidor();
    }

    /*Função que deve ser sobrescrita para mudar o comportamento do servidor
    Se este código não for sobrescrito o servidor vai funcionar com o
    protolo Comum*/
    public void initThread(ServerSocket serverSocket) {
        try {
            System.out.println("Servidor.initThread");
            new ThreadServidor(serverSocket.accept()).start();
        } catch (IOException ex) {
            Logger.getLogger(Servidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}







