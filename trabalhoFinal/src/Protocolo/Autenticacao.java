package Protocolo;

import Cifrador.CifradorRSA;
import armazemChaves.ArmazemChaves;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class Autenticacao extends Comum {

    public static final int IDNOTFOUND = 5;
    // a senha e o local do key store ficam hard coded por enqto.
    private String keyStorePassword = "admin";
    private ArmazemChaves chavesCliente;

    public Autenticacao() {
        super("Autenticacao", "autenticacao", "kstoreAutenticacao.ks");

        /* cria ou carrega a key store usada para armazenar as chaves públicas
        dos clientes registrados. */
        chavesCliente = new ArmazemChaves("autenticacaoPU.keystore", keyStorePassword);
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();

        if (sMessage.equalsIgnoreCase("SAIR")) {
            theOutput = new ProtocolData("Encerrando...");
            state = EXIT;

        } else if (sMessage.equalsIgnoreCase("REGISTRAR")) {
            byte[] idByte = theInput.getBytes();
            String idAVerificar = new String(CifradorRSA.decodificar(idByte, prServidor));

            if (chavesCliente.contemID(idAVerificar)) {
                theOutput = new ProtocolData(idAVerificar + " já está registrado.");

            } else if (!idAVerificar.equals(idCliente)) {
                theOutput = new ProtocolData("Não foi possível"
                        + " registrar " + idAVerificar + ", não confere com"
                        + " id do certificado.");
                
            } else {
                System.out.println("Registrando " + idAVerificar);
                chavesCliente.guardaCertificado(idAVerificar, this.certCliente);
                theOutput = new ProtocolData(idAVerificar + " registrado!");
            }
            state = CONNECTED;
        } else if (sMessage.equalsIgnoreCase("CHAVE")) {
            /* 1. verifica se tem entrada na key store para o id especificado.
            2. Se tem, envia o certificado encontrado.
            3. Se não tem, envia null*/
            X509Certificate cert = null;
            byte[] idByte = theInput.getBytes();
            String idAVerificar = new String(CifradorRSA.decodificar(idByte, prServidor));

            if (chavesCliente.contemID(idAVerificar)) {
                cert = (X509Certificate) chavesCliente.pegaCertificado(idAVerificar);
                System.out.println("Enviando certificado de " + idAVerificar);
                theOutput = new ProtocolData(cert);

            } else {
                theOutput = new ProtocolData(cert);
                System.out.println("Certificado de " + idAVerificar + " não encontrado!");
            }

            state = CONNECTED;

        } else {
            theOutput = new ProtocolData("Use:\n\"REGISTRAR\" para se registrar"
                    + "\n\"BUSCAR\" para buscar uma chave pública"
                    + "\n\"SAIR\" para encenrrar a conexao");
            super.state = CONNECTED;
        }
        /*4. Armazena log*/
        escreveLog(this.idCliente + " " + sMessage + " " + state + " " + theOutput);
    }

    @Override
    protected boolean idEhAutentico(String id, PublicKey pu) {
        return true;
    }
}
