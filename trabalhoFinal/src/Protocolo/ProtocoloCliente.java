package Protocolo;

import Cifrador.CifradorAES;
import Cifrador.CifradorRSA;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import Cifrador.CifradorHASH;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloCliente {

    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    private SecretKey skeyCliente = null;
    private PublicKey puCliente;
    private PrivateKey prCliente;
    private PublicKey puServidor;
    private X509Certificate certCliente;
    private X509Certificate certServidor;
    private String idCliente;
    private String idServidor;
    private ProtocolData dataToServer;
    private ProtocolData dataFromServer;
    private boolean naoConectado = true;
    private boolean fecharConexao = false;
    private ProtocoloCliente autenticador;
    private SecretKey chaveSessao;
    private int tamanhoHashCifrado;

    public boolean isFecharConexao() {
        return fecharConexao;
    }

    public boolean isNaoConectado() {
        return naoConectado;
    }

    public PublicKey getPuServidor() {
        return this.puServidor;
    }

    public SecretKey getChaveSessao() {
        return this.chaveSessao;
    }
    private boolean verificarAutenticidade = false;
    private ObjectOutputStream outAutenticacao;
    private ObjectInputStream inAutenticacao;

    public ProtocoloCliente(X509Certificate certificado, PrivateKey prcliente,
            SecretKey skeycliente, String idcliente) {
        this.certCliente = certificado;
        this.puCliente = certificado.getPublicKey();
        this.prCliente = prcliente;
        this.idCliente = idcliente;
        this.skeyCliente = skeycliente;

        byte[] hash = Cifrador.CifradorHASH.hashArq("string".getBytes());
        hash = Cifrador.CifradorRSA.codificar(hash, puCliente);
        this.tamanhoHashCifrado = hash.length;
    }

    public ProtocoloCliente() {
    }

    public void do_handshaking(ObjectOutputStream out, ObjectInputStream in) {
        String mensagem = "CONECTAR";
        while (naoConectado) {
            if (mensagem != null) {
                if (mensagem.equalsIgnoreCase("CONECTAR")) {
                    init_handshaking(out, mensagem);
                    mensagem = "SKEY";
                } else if (mensagem.equalsIgnoreCase("SKEY")) {
                    lerServCert(in);
                    pedirSKEY(out, mensagem);
                    mensagem = "OK";
                } else if (mensagem.equalsIgnoreCase("OK")) {
                    if (dataFromServer.getStatus() != Comum.LOGINERROR) {
                        /*
                         * Servidor reconheceu cliente
                         */
                        lerSKEYServ(in);

                        if (this.verificarAutenticidade) {
                            if (false == idEhAutentico(this.idServidor, this.puServidor)) {
                                System.out.println("Servidor não é confiável.");
                                mensagem = "SAIR";
                                this.fecharConexao = true;
                            } else {
                                System.out.println("Servidor de Arquivos é confiável. Abrindo conexão ...");
                            }
                        }
                        end_handshaking(out, mensagem);
                        leImprimeRespostaServidor(in);
                        naoConectado = false;
                    } else {/*
                         * continua desconectado
                         */
                        System.out.println("Seu login não pode ser validado."
                                + "\nTente novamente ou faça login com outro id.");
                        return;/*
                         * saindo desta função volta ao ponto que pede login
                         */
                    }

                }
            }
        }
    }

    public void processa_mensagem(ObjectOutputStream out, ObjectInputStream in) {
        try {
            System.out.println("Entre com a Menssagem: ");
            String mensagem = stdIn.readLine();
            if (mensagem != null) {
                if (mensagem.equalsIgnoreCase("SAIR")) {
                    dataToServer = new ProtocolData("SAIR");
                    dataToServer.setMessage(mensagem);
                    out.writeObject(dataToServer);
                    decodificaImprimeRespostaServidor(in);
                    fecharConexao = true;
                } else if (mensagem.equalsIgnoreCase("ENVIAR")) {
                    boolean status = true;
                    String nomeArq, msg = "";
                    String caminho = "";
                    msg = "ENVIAR";
                    while (status) {
                        if (msg != null) {
                            if (msg.equalsIgnoreCase("ENVIAR")) {
                                System.out.println("Digite o nome do Arquivo: ");
                                nomeArq = stdIn.readLine();

                                System.out.println("Digite caminho do arquivo(com extensao): ");
                                caminho = stdIn.readLine();

                                File testeCaminho = new File(caminho);
                                while(!testeCaminho.isFile()){
                                    System.out.println("\nCaminho inválido...\n");
                                    System.out.println("Digite caminho do arquivo " +
                                            "que deseja enviar, incluindo seu nome e extensao: ");
                                    caminho = stdIn.readLine();
                                    testeCaminho = new File(caminho);
                                }

                                if(nomeArq == null || nomeArq.isEmpty()){
                                    nomeArq = pegaNomeArquivo(caminho);
                                }
                                else{
                                    nomeArq = nomeArq + pegaExtensaoArquivo(caminho);
                                }

                                enviarNomeArq(out, nomeArq);
                                decodificaImprimeRespostaServidor(in);
                                msg = "CAMINHO";
                            } else if (msg.equalsIgnoreCase("CAMINHO")) {
                                enviarArqCifrado(out, caminho);
                                decodificaImprimeRespostaServidor(in);
                                status = false;
                            }
                        }
                    }
                } else if (mensagem.equalsIgnoreCase("LISTAR")) {
                    listarArquivos(in, out);
                } else if (mensagem.equalsIgnoreCase("BUSCAR")) {
                    if (listarArquivos(in, out)) {
                        buscarArquivo(in, out);
                    }
                } else {
                    dataToServer = new ProtocolData();
                    dataToServer.setMessage(mensagem);
                    out.writeObject(dataToServer);
                    leImprimeRespostaServidor(in);
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 1. Enviar chave pública para o servidor
     */
    private void init_handshaking(ObjectOutputStream out, String mensagem) {
        try {
            dataToServer = new ProtocolData(this.certCliente);
            dataToServer.setMessage(mensagem);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 2. Le certificado do servidor
     */
    private void lerServCert(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            this.certServidor = dataFromServer.getCertificado();
            this.puServidor = certServidor.getPublicKey();
            this.idServidor = certServidor.getIssuerDN().getName().substring(3);
            System.out.println("Id recebido no certificado do servidor: " + idServidor);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 3. Pedir chave secreta ao servidor
     */
    private void pedirSKEY(ObjectOutputStream out, String sMessage) {
        try {
            dataToServer = new ProtocolData("Secret Key");
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 4. Ler id do servidor
     */
    private void lerSKEYServ(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            byte[] dados = dataFromServer.getBytes();
            dados = Cifrador.CifradorRSA.decodificar(dados, prCliente);

            chaveSessao = (SecretKey) new SecretKeySpec(dados, "AES");
            System.out.println("IdServidor = " + this.idServidor);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 5.Confirma autenticidade do servidor
     */
    private void end_handshaking(ObjectOutputStream out, String sMessage) {
        try {
            dataToServer = new ProtocolData();
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 6. Le e imprime a resposta do servidor
     */
    public void leImprimeRespostaServidor(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            System.out.println(dataFromServer.toString());
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void decodificaImprimeRespostaServidor(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            byte[] resposta = Cifrador.CifradorAES.decodificar(dataFromServer.getBytes(), chaveSessao);
            String imprimir = new String(resposta);
            System.out.println(imprimir);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * Verificar autenticidade do id do servidor de arquivos
     */
    public boolean idEhAutentico(String id, PublicKey pukey) {
        /*
         * 1. Busca chave publica do servidor arquivos no de autenticacao
         */
        PublicKey chave = buscar_chave(id);

        /*
         * 2. compara chaves: retorna false se não for igual e true se for igual
         */
        if (chave != null && chave.equals(pukey)) {
            return true;
        } else {
            return false;
        }

    }

    public void usarAutenticacao(ObjectInputStream in, ObjectOutputStream out,
            ProtocoloCliente pAutenticao) {
        this.verificarAutenticidade = true;
        this.outAutenticacao = out;
        this.inAutenticacao = in;
        this.autenticador = pAutenticao;
    }

    public void setAutenticador(ObjectInputStream in, ObjectOutputStream out,
            ProtocoloCliente pAutenticao) {
        this.outAutenticacao = out;
        this.inAutenticacao = in;
        this.autenticador = pAutenticao;

    }

    public PublicKey buscar_chave(String id) {
        PublicKey puid = null;
        X509Certificate certid;
        try {
            //Pede chave do id ao servidor de autenticacao
            //byte[] bytesid = CifradorRSA.codificar(id.getBytes(), autenticador.getPuServidor());
            byte[] bytesid = Cifrador.CifradorAES.codificar(id.getBytes(), autenticador.getChaveSessao());
            dataToServer = new ProtocolData(bytesid);
            dataToServer.setMessage("CHAVE");
            outAutenticacao.writeObject(dataToServer);

            // Se servidor de autenticacao tem chave, retorna a chave
            //Se não, retorna null

            boolean continua = true;
            int tentativas = 0;
            while (continua) {
                dataFromServer = (ProtocolData) inAutenticacao.readObject();

                if (dataFromServer == null) {
                    tentativas++;
                } else {
                    if (dataFromServer.getMessage().equals("CHAVE")) {
                        byte[] certcod = dataFromServer.getBytes();
                        if (certcod == null) {
                            System.out.println(id + "não é confiável.");
                        } else {
                            certcod = Cifrador.CifradorAES.decodificar(certcod, autenticador.getChaveSessao());
                            dataFromServer.setBytes(certcod);
                            certid = dataFromServer.getCertificado();
                            System.out.println("Certificado de " + id + " encontrado!");
                            puid = certid.getPublicKey();
                        }
                        continua = false;
                    } else {
                        tentativas++;
                        if (tentativas > 1000) {
                            continua = false;
                            System.out.println("Servidor não está respondendo.");
                        }
                    }
                }
            }
            dataFromServer = null;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }

        return puid;
    }

    public void encerrar_conexao(ObjectOutputStream autout, ObjectInputStream autin) {
        try {
            dataToServer = new Protocolo.ProtocolData();
            dataToServer.setMessage("SAIR");
            autout.writeObject(dataToServer);
            decodificaImprimeRespostaServidor(autin);
            autout.close();
            autin.close();
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void registrar(ObjectOutputStream autout, ObjectInputStream autin) {
        /*
         * Registrar idCliente no servidor de autenticacao
         */
        try {//garantir que so o servidor abre
            //enviando id do cliente cifrado com a chave publica do servidor para registrar.
            //byte[] idByte = CifradorRSA.codificar(idCliente.getBytes(), puServidor);
            byte[] idByte = Cifrador.CifradorAES.codificar(idCliente.getBytes(), chaveSessao);
            dataToServer = new ProtocolData(idByte);
            dataToServer.setMessage("REGISTRAR");
            autout.writeObject(dataToServer);
            decodificaImprimeRespostaServidor(autin);

        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
     * 1. Pede para servidor listar arquivos. 
     * 2. Le lista recebida e imprime na tela
     */
    private boolean listarArquivos(ObjectInputStream in, ObjectOutputStream out) {
        boolean retorno = false;
        try {
            byte[] idByte = Cifrador.CifradorAES.codificar(idCliente.getBytes(), chaveSessao);
            dataToServer = new ProtocolData(idByte);
            dataToServer.setMessage("LISTAR");
            out.writeObject(dataToServer);

            boolean continua = true;
            int tentativas = 0;
            while (continua) {
                dataFromServer = (ProtocolData) in.readObject();
                if (dataFromServer == null) {
                    //System.out.println("Lendo entrada de novo");
                    dataFromServer = (ProtocolData) in.readObject();
                } else if (dataFromServer.getMessage().equals("LISTAR")) {
                    byte[] listaarquivos = dataFromServer.getBytes();
                    listaarquivos = Cifrador.CifradorAES.decodificar(listaarquivos, chaveSessao);
                    String arquivos = new String(listaarquivos);
                    System.out.println(arquivos);
                    continua = false;
                    retorno = true;
                } else if (dataFromServer.getMessage().equals("VAZIO")) {
                    byte[] listaarquivos = dataFromServer.getBytes();
                    listaarquivos = Cifrador.CifradorAES.decodificar(listaarquivos, chaveSessao);
                    String arquivos = new String(listaarquivos);
                    System.out.println(arquivos);
                    continua = false;
                    retorno = false;
                } else {
                    if (tentativas > 1000) {
                        continua = false;
                        retorno = false;
                        System.out.println("Servidor não está respondendo.");
                    }
                    tentativas++;
                }
            }
            dataFromServer = null;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
        return retorno;
    }

    /*
     * 1. Le nome do arquivo do teclado e envia BUSCAR para o servidor de
     * arquivos 2. Le arquivo (sequencia de bytes) enviado pelo servidor 3.
     * Decriptografa com chave de sessão e skeycliente. 4. Separa bytes do
     * arquivo dos bytes do hash 5. Descriptografa hash com prCliente 6. gera
     * hash dos bytes do arquivo e compara. 7. Se o hash for o mesmo, salva o
     * arquivo em uma pasta de downloads
     */
    private void buscarArquivo(ObjectInputStream in, ObjectOutputStream out) {
        try {
            System.out.println("Digite o nome do arquivo que deseja buscar:");
            String arquivo = stdIn.readLine();

            if (arquivo == null || arquivo.isEmpty()) {
                System.out.println("Não consegui ler o nome do arquivo.\n");
                return;
            }
            byte[] bytesArquivo = Cifrador.CifradorAES.codificar(arquivo.getBytes(), chaveSessao);
            dataToServer = new ProtocolData(bytesArquivo);
            dataToServer.setMessage("BUSCAR");
            out.writeObject(dataToServer);

            boolean continua = true;
            int tentativas = 0;
            while (continua) {
                dataFromServer = (ProtocolData) in.readObject();
                if (dataFromServer == null) {
                    dataFromServer = (ProtocolData) in.readObject();
                } else if (dataFromServer.getMessage().equals("BUSCAR")) {
                    bytesArquivo = dataFromServer.getBytes();

                    if (bytesArquivo == null) {
                        System.out.println("Servidor não encontrou arquivo com "
                                + "nome " + arquivo + "\n");
                        return;
                    } else {
                        bytesArquivo = Cifrador.CifradorAES.decodificar(bytesArquivo, chaveSessao);

                        bytesArquivo = Cifrador.CifradorAES.decodificar(bytesArquivo, skeyCliente);

                        //separa o hash do conteudo do arquivo
                        InputStream is = new ByteArrayInputStream(bytesArquivo, 0, tamanhoHashCifrado);
                        byte[] hashrec = new byte[tamanhoHashCifrado];
                        is.read(hashrec);
                        hashrec = Cifrador.CifradorRSA.decodificar(hashrec, prCliente);

                        //bytesArquivo = new byte[(bytesArquivo.length-tamanhoHashCifrado)];
                        is = new ByteArrayInputStream(bytesArquivo, tamanhoHashCifrado, bytesArquivo.length);
                        byte[] salvar = new byte[bytesArquivo.length - tamanhoHashCifrado];
                        is.read(salvar);
                        //gera novo hash e compara
                        byte[] novohash = Cifrador.CifradorHASH.hashArq(salvar);

                        if (java.util.Arrays.equals(hashrec, novohash)) {
                            System.out.println("Arquivo integro!\n");
                        } else {
                            System.out.println("O arquivo enviado pelo servidor"
                                    + " está corrompido.\n Saindo sem salvar.\n");
                            return;
                        }

                        //salvar arquivo baixado
                        System.out.println("Em qual diretório devo salvar seu arquivo:");
                        String diretorio = stdIn.readLine();

                        if (diretorio == null || diretorio.isEmpty()) {
                            diretorio = idCliente + "/downloads/";
                        } else {
                            if (!diretorio.substring(diretorio.length() - 1).equals("/")) {
                                diretorio = diretorio + "/";
                            }
                        }

                        File file = new File(diretorio);
                        if (file.exists() && file.canWrite()) {
                            diretorio = diretorio + arquivo;
                            file = new File(diretorio);
                            int i = 1;
                            while (!file.createNewFile()) {/*já existe arquivo com este nome no diretorio*/
                                file = new File(diretorio + i);
                                i++;
                            }

                            FileOutputStream fos = new FileOutputStream(file);
                            fos.write(salvar);
                            fos.close();
                            System.out.println("Seu arquivo foi salvo "
                                    + "em: " + file.getAbsolutePath());

                        } else {
                            System.out.println("Infelizmente, não consegui salvar "
                                    + "o seu arquivo no diretório especificado:\n"
                                    + "Diretorio não existe ou não permite acesso\n");

                            /*Para evitar que o arquivo buscado seja perdido
                            salva no diretório padrão*/
                            file = new File(idCliente);
                            if (!file.exists()) {
                                file.mkdir();
                            }

                            file = new File(idCliente + "/downloads");
                            if (!file.exists()) {
                                file.mkdir();
                            }

                            diretorio = idCliente + "/downloads/" + arquivo;
                            file = new File(diretorio);
                            int i = 1;
                            while (!file.createNewFile()) {
                                file = new File(diretorio + i);
                                i++;
                            }

                            FileOutputStream fos = new FileOutputStream(file);
                            fos.write(salvar);
                            fos.close();
                            System.out.println("Seu arquivo foi salvo "
                                    + "em: " + file.getAbsolutePath());
                        }
                    }
                    continua = false;
                } else {
                    if (tentativas > 1000) {
                        continua = false;
                        System.out.println("Servidor não está respondendo.");
                    }
                    tentativas++;
                }
            }

            dataFromServer = null;
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void enviarNomeArq(ObjectOutputStream out, String nomeArq) {
        //byte[] nome = CifradorRSA.codificar(nomeArq.getBytes(), this.puServidor);
        byte[] nome = Cifrador.CifradorAES.codificar(nomeArq.getBytes(), chaveSessao);
        dataToServer = new ProtocolData(nome);
        try {
            dataToServer.setMessage("CAMINHO");
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void enviarArqCifrado(ObjectOutputStream out, String caminho) throws IOException {
        byte[] hashCifrado;
        byte[] enviar;
        /*
         * String texto = ""; BufferedReader arquivo;
         *
         * arquivo = new BufferedReader(new FileReader(caminho)); while
         * (arquivo.ready()) { texto = texto + arquivo.readLine();
        }
         */
        byte[] texto = null;

        try {
            File file = new File(caminho);
            InputStream is = new FileInputStream(file);
            texto = new byte[(int) file.length()];
            is.read(texto);
        } catch (IOException ex) {
            Logger.getLogger(TransferenciaArquivos.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] arqHash = CifradorHASH.hashArq(texto/*.getBytes()*/);
        hashCifrado = CifradorRSA.codificar(arqHash, puCliente);

        /*concatenar hash com arquivo*/
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(hashCifrado);
        outputStream.write(texto);
        enviar = outputStream.toByteArray();

        /*enviar = new byte[hashCifrado.length + texto.length];
        for (int i = 0; i < hashCifrado.length; i++) {
            enviar[i] = hashCifrado[i];
        }
        byte[] bytesArq = texto;
        for (int i = 0; i < texto.length; i++) {
            enviar[i + hashCifrado.length] = bytesArq[i];
        }*/

        byte[] arqEnviar = CifradorAES.codificar(enviar, skeyCliente);
        arqEnviar = CifradorAES.codificar(arqEnviar, chaveSessao);
        dataToServer = new Protocolo.ProtocolData(arqEnviar);
        dataToServer.setMessage("ENVIAR");
        try {
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private String pegaNomeArquivo(String caminho) {
        String[] path = caminho.split("/");
        return path[path.length-1];
    }

    private String pegaExtensaoArquivo(String caminho) {
        String nome = pegaNomeArquivo(caminho);
        //String[] extensao = nome.split(".");
        String retorno = "";
        int idx = nome.indexOf(".");

        if(idx > -1 && idx < nome.length()){
            retorno = nome.substring(idx);
        }

        return retorno;
    }
}
