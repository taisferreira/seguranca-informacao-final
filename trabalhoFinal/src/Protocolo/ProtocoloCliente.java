package Protocolo;

import Cifrador.CifradorRSA;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

public class ProtocoloCliente {
    private BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
    private SecretKey skeyCliente = null;
    private PublicKey puCliente;
    private PrivateKey prCliente;
    private PublicKey puServidor;
    private String idCliente;
    private String idServidor;
    private ProtocolData dataToServer;
    private ProtocolData dataFromServer;
    private boolean naoConectado = true;
    private boolean fecharConexao = false;

    public boolean isFecharConexao() {
        return fecharConexao;
    }

    public boolean isNaoConectado() {
        return naoConectado;
    }

    private boolean verificarAutenticidade = false;
    private ObjectOutputStream outAutenticacao;
    private ObjectInputStream inAutenticacao;

    public ProtocoloCliente(PublicKey pucliente, PrivateKey prcliente,
            SecretKey skeycliente, String idcliente) {
        this.puCliente = pucliente;
        this.prCliente = prcliente;
        this.idCliente = idcliente;
        this.skeyCliente = skeycliente;
    }
    public ProtocoloCliente(){}

    public void do_handshaking(ObjectOutputStream out, ObjectInputStream in)
    {
        String mensagem = "CONECTAR";
        while (naoConectado) {
            if (mensagem != null) {
                if (mensagem.equalsIgnoreCase("CONECTAR")) {
                    init_handshaking(out, mensagem);
                    mensagem = "ID";
                } else if (mensagem.equalsIgnoreCase("ID")) {
                    lerServPUKEY(in);
                    enviarID(out, mensagem);
                    mensagem = "OK";
                } else if (mensagem.equalsIgnoreCase("OK")) {
                    if (dataFromServer.getStatus() != Comum.LOGINERROR) {
                        /*Servidor reconheceu cliente*/
                        lerIDServ(in);

                        if (this.verificarAutenticidade) {
                            if (false == idEhAutentico(this.idServidor, this.puServidor)) {
                                System.out.println("Servidor de Arquivos não é confiável.");
                                mensagem = "EXIT";
                            }
                            else{
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
                }
                else if (mensagem.equalsIgnoreCase("ENVIAR")) {
                    /*
                     1. Pede nome do arquivo em disco a ser transferido
                     2. gera hash do conteudo do arquivo e criptografa com a
                         CHAVE PUBLICA do cliente
                     3. Concatena o hash com o arquivo
                     4. Codifica o resultado com a chave secreta do cliente (skeyCliente)
                     5. Envia para o arquivo e o nome do arquivo para servidor
                     */
                }
                else if (mensagem.equalsIgnoreCase("BUSCAR")) {
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
                }
                else {
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
            dataToServer = new ProtocolData(this.puCliente);
            dataToServer.setMessage(mensagem);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*2. Ler chave pública do servidor*/
    private void lerServPUKEY(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            this.puServidor = dataFromServer.getKey();
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 3. Enviar id_cliente para servidor*/
    private void enviarID(ObjectOutputStream out, String sMessage) {
        try {/*garantir que so o servidor abre*/
            byte [] id = CifradorRSA.codificar(this.idCliente.getBytes(), this.puServidor);
            dataToServer = new ProtocolData(id);
            dataToServer.setMessage(sMessage);
            out.writeObject(dataToServer);
        } catch (IOException ex) {
            Logger.getLogger(ProtocoloCliente.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /* 4. Ler id do servidor*/
    private void lerIDServ(ObjectInputStream in) {
        try {
            dataFromServer = (ProtocolData) in.readObject();
            byte[] dados = dataFromServer.getBytes();
            dados = Cifrador.CifradorRSA.decodificar(dados, prCliente);
            this.idServidor = new String(dados);
            System.out.println("IdServidor = "+this.idServidor);
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

    /*precisa de handshaking aqui?*/
    private boolean idEhAutentico(String string, PublicKey pukeySArq) {
        /*Verificar autenticidade do id do servidor de arquivos
        1. Busca chave publica do servidor arquivos no de autenticacao
           buscar_chave(this.idServidor);
        2. compara chaves: retorna false se não for igual e true se for igual*/
        return true;
    }

    public void usarAutenticacao(ObjectInputStream in, ObjectOutputStream out)
    {
        this.verificarAutenticidade = true;
        this.outAutenticacao = out;
        this.inAutenticacao = in;
    }

    public PublicKey buscar_chave(String id)
    {
        /*Pede chave do id ao servidor de autenticacao
         Se servidor de autenticacao tem chave, retorna a chave
         Se não, retorna null*/
        return null;
    }
}
