package Servidor;

import Protocolo.TransferenciaArquivos;
import java.net.Socket;

public class ThreadServidorArquivos extends ThreadServidor {

    public ThreadServidorArquivos(Socket socket) {
        super(socket);
    }

    @Override
    protected void iniciaProtocolo() {
        System.out.println("ThreadServidorArquivos.initProtocolo");
        super.protocolo = new TransferenciaArquivos();
    }
}
