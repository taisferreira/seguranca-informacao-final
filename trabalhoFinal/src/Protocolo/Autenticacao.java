package Protocolo;

import Cifrador.CifradorRSA;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Autenticacao extends Comum{
    public static final int IDNOTFOUND = 5;
     // a senha e o local do key store ficam hard coded por enqto.
    private static char[] keyStorePassword = "admin".toCharArray();
    private File keyStoreFile;
    private KeyStore ks;
 
    
    public Autenticacao(){
        super();
        super.idServidor = "servidorAutenticacao";       
        
        /* cria ou carrega a key store usada para armazenar as chaves pъblicas
         de quem se registrou.
         */       
        
        try {
                        //inicializa keystore e local do keystore
			ks = KeyStore.getInstance("JCEKS");
			keyStoreFile = new File("D:\\key\\autenticacaoPU.keystore");
                        
                        
			if (!keyStoreFile.exists()) {
				//inicializa um keystore vazio
				ks.load(null, null);                     
				
                                FileOutputStream fos = new FileOutputStream(keyStoreFile);
				//persiste o keyStore
				ks.store(fos, keyStorePassword);
				fos.close();	
			}
			else {
				//carrega o keyStore
				FileInputStream fis = new FileInputStream(keyStoreFile);
				ks.load(fis,null);
				fis.close();				
			}
		
                } catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		
		}
    }

    @Override
    protected void processa_mensagem(ProtocolData theInput) {
        String sMessage;
        sMessage = theInput.getMessage();
        
        PublicKey pu = null;
        byte [] idByte = theInput.getBytes();
        String idAVerificar =new String(CifradorRSA.decodificar(idByte, prServidor));
        
        
        if (sMessage.equalsIgnoreCase("REGISTRAR")) {
            try {
           
                if(!ks.isKeyEntry(idAVerificar)){
                      super.state = LOGINERROR; 
                      theOutput = new ProtocolData("Cliente já existe!");
                }  else {
                    pu = theInput.getKey();
                    ks.setKeyEntry(idAVerificar, pu.getEncoded(), null);
                    state = CONNECTED;
                    theOutput = new ProtocolData("Cliente registrado!");
                }
               
                 
                
            } catch (KeyStoreException ex) {
                Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
            }
        } 
        else if (sMessage.equalsIgnoreCase("CHAVE")) {
            try {
                if(ks.isKeyEntry(idAVerificar)) {
                    pu = (PublicKey) this.ks.getKey(idAVerificar, keyStorePassword); 
                    theOutput = new ProtocolData(pu);
                    state = CONNECTED;
                } 
                else{/* 3. Se não tem, envia aviso de chave não encontrada.*/
                    theOutput = new ProtocolData("chave não encontrada");
                    state = IDNOTFOUND;
                }
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnrecoverableKeyException ex) {
                Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException ex) {
                Logger.getLogger(Autenticacao.class.getName()).log(Level.SEVERE, null, ex);
            }

            
            
        } else {
            theOutput = new ProtocolData("Use:\n\"REGISTRAR\" para se registrar"
                    + "\n\"BUSCAR\" para buscar uma chave pública" +
                    "\n\"SAIR\" para encenrrar a conexao");
            super.state = CONNECTED;
        }
         escreveLog(idAVerificar+" "+sMessage+" "+ state +" "+theOutput);

        
    }

    @Override
    protected boolean idEhAutentico(String id, PublicKey pu) {
        /*Verificar autenticidade do id 
        1. Busca chave publica do id na keystore
        2. compara chaves: retorna false se não for igual e true se for igual*/
        return true;
    }
}
