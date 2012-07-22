package Servidor;

import Protocolo.Autenticacao;
import java.net.Socket;

public class ThreadServidorAutenticacao extends ThreadServidor {

    public ThreadServidorAutenticacao(Socket socket) {
        super(socket);
    }

    @Override
    protected void iniciaProtocolo() {
        System.out.println("ThreadServidorAutenticacao.initProtocolo");
        super.protocolo = new Autenticacao();
    }
}
