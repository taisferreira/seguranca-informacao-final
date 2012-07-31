package Servidor;

import Protocolo.ProtocolData;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import Protocolo.Comum;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ThreadServidor extends Thread {
    protected ObjectOutputStream out = null;
    protected ObjectInputStream in = null;
    protected ProtocolData input, output;
    protected Comum protocolo;

    private Socket socket = null;

    public ThreadServidor(Socket socket) {
        super("ThreadServidor");
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            iniciaProtocolo();
            
            output = protocolo.processInput(null);
            out.writeObject(output);
            
            boolean continua = true;
            while (continua) {
                input = (ProtocolData) in.readObject();
                output = protocolo.processInput(input);

                out.writeObject(output);

                if (output.getStatus() == Comum.EXIT) {
                    continua = false;
                }
            }
            out.close();
            in.close();
            socket.close();
            System.out.println("Encerrando conexão com o cliente.");

        } catch (IOException e) {
            //e.printStackTrace();
            try {
                out.close();
                in.close();
                socket.close();
                System.out.println("Encerrando conexão com o cliente.");
            } catch (IOException ex) {
                Logger.getLogger(ThreadServidor.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    /*Sobrescrever para trocar de protocolo. Caso contrario o servidor vai
     usar o protocolo Comum por padrão*/
    protected void iniciaProtocolo() {
        System.out.println("ThreadServidor.initProtocolo");
        protocolo = new Comum();
    }
}
