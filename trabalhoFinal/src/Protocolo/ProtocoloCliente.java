package Protocolo;

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

    /*public ProtocoloCliente(PublicKey pucliente, PrivateKey prcliente,
    SecretKey skeycliente, String idcliente) {
    this.puCliente = pucliente;
    this.prCliente = prcliente;
    this.idCliente = idcliente;
    this.skeyCliente = skeycliente;
    }*/
    public ProtocoloCliente(X509Certificate certificado, PrivateKey prcliente,
            SecretKey skeycliente, String idcliente) {
        this.certCliente = certificado;
        this.puCliente = certificado.getPublicKey();
        this.prCliente = prcliente;
        this.idCliente = idcliente;
        this.skeyCliente = skeycliente;
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
                        /*Servidor reconheceu cliente*/
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
                    } else {/*continua desconectado*/
                        System.out.println("Seu login não pode ser validado."
                                + "\nTente novamente ou faça login com outro id.");
                        return;/*saindo desta função volta ao ponto que pede login*/
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
                    leImprimeRespostaServidor(in);
                    fecharConexao = true;
                } else if (mensagem.equalsIgnoreCase("ENVIAR")) {
                    byte[] hashCifrado;
                    String texto = "";
                    System.out.println("Digite caminho do arquivo(com extensao): ");
                    String caminho = stdIn.readLine();
                    File arquivo = new File("" + caminho);
                    byte[] arqHash = CifradorHASH.hashArq(arquivo.toString().getBytes());
                    hashCifrado = CifradorRSA.codificar(arqHash, puCliente);
                    texto = (arquivo + "" + hashCifrado).trim();
                    byte[] arqEnviar = CifradorRSA.codificar(texto.getBytes(), puServidor);
                    Protocolo.ProtocolData dataToServer = new Protocolo.ProtocolData(arqEnviar);
                    dataToServer.setMessage("ENVIAR");
                    out.writeObject(dataToServer);
                    /*
                    1. Pede nome do arquivo em disco a ser transferido
                    2. gera hash do conteudo do arquivo e criptografa com a
                    CHAVE PUBLICA do cliente
                    3. Concatena o hash com o arquivo
                    4. Codifica o resultado com a chave secreta do cliente (skeyCliente)
                    5. Envia para o arquivo e o nome do arquivo para servidor
                     */
                } else if (mensagem.equalsIgnoreCase("BUSCAR")) {
                    /*
                    1. Pede para servidor listar arquivos(envia LISTAR).
                    2. Le lista recebida e imprime na tela
                    3. Le nome do arquivo do teclado e envia BUSCAR para o servidor de arquivos
                    4. Le arquivo (sequencia de bytes) enviado pelo servidor
                    5. Decriptografa com skeycliente.
                    6. Separa bytes do arquivo dos bytes do hash
                    7. Descriptografa hash com prCliente
                    8. gera hash dos bytes do arquivo e compara.
                    9. Se o hash for o mesmo, salva o arquivo em uma pasta de downloads
                     */
                } else {
                    System.out.println("Entre com um dado: ");
                    String sData = stdIn.readLine();

                    dataToServer = new ProtocolData(sData);
                    dataToServer.setMessage(mensagem);
                    out.writeObject(dataToServer);
                    leImprimeRespostaServidor(in);
                }

            }
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*1. Enviar chave pública para o servidor*/
    private void init_handshaking(ObjectOutputStream out, String mensagem) {
        try {
            dataToServer = new ProtocolData(this.certCliente);
            dataToServer.setMessage(mensagem);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*2. Le certificado do servidor*/
    private void lerServCert(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            this.certServidor = dataFromServer.getCertificado();
            this.puServidor = certServidor.getPublicKey();
            this.idServidor = certServidor.getIssuerDN().getName().substring(3);
            System.out.println("Id recebido no certificado do servidor: "+idServidor);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 3. Pedir chave secreta ao servidor*/
    private void pedirSKEY(ObjectOutputStream out, String sMessage) {
        try {            
            dataToServer = new ProtocolData("Secret Key");
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 4. Ler id do servidor*/
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

    /*5.Confirma autenticidade do servidor*/
    private void end_handshaking(ObjectOutputStream out, String sMessage) {
        try {
            dataToServer = new ProtocolData();
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*6. Le e imprime a resposta do servidor*/
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

    /*Verificar autenticidade do id do servidor de arquivos*/
    public boolean idEhAutentico(String id, PublicKey pukey) {
        /* 1. Busca chave publica do servidor arquivos no de autenticacao*/
        PublicKey chave = buscar_chave(id);

        /* 2. compara chaves: retorna false se não for igual e true se for igual*/
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
        System.out.println("busca_chave(" + id + ")");
        PublicKey puid = null;
        X509Certificate certid;
        try {
            //Pede chave do id ao servidor de autenticacao
            byte[] bytesid = CifradorRSA.codificar(id.getBytes(), autenticador.getPuServidor());
            dataToServer = new ProtocolData(bytesid);
            dataToServer.setMessage("CHAVE");
            outAutenticacao.writeObject(dataToServer);

            // Se servidor de autenticacao tem chave, retorna a chave
            //Se não, retorna null
            dataFromServer = (ProtocolData) inAutenticacao.readObject();
            certid = dataFromServer.getCertificado();

            if (certid == null) {
                System.out.println("Servidor de autenticação não achou " + id + ".");
            } else {
                System.out.println("Certificado de " + id + " encontrado!");
                puid = certid.getPublicKey();
            }
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }

        return puid;
        //return this.puServidor; /*código de teste*/
    }

    public void encerrar_conexao(ObjectOutputStream autout, ObjectInputStream autin) {
        try {
            dataToServer = new Protocolo.ProtocolData("Encerrando");
            dataToServer.setMessage("SAIR");
            autout.writeObject(dataToServer);
            leImprimeRespostaServidor(autin);
            autout.close();
            autin.close();
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
