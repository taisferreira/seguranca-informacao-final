package Protocolo;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.X509CertImpl;

public class ProtocolData implements Serializable {

    private static final long serialVersionUID = 1L;
    private byte[] bytes;
    //private X509Certificate certificado;
    private int status;
    private String message;

    public ProtocolData() {
    }

    public ProtocolData(byte[] bytes) {
        super();
        this.bytes = bytes;
    }

    public ProtocolData(String data) {
        super();
        this.bytes = data.getBytes();
    }

    public ProtocolData(X509Certificate data) {
        super();
        try {
            if(data == null){
                this.bytes = null;
            }else{
                this.bytes = data.getEncoded();
            }
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(ProtocolData.class.getName()).log(Level.SEVERE, null, ex);
        }
        //certificado = data;
    }

    @Override
    public String toString() {
        if(bytes == null){
            return " ";
        }
        return new String(bytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public X509Certificate getCertificado() {
        X509Certificate certificado = null;
        try {
            if(bytes != null){
                certificado = new X509CertImpl(bytes);
            }
        } catch (CertificateException ex) {
            Logger.getLogger(ProtocolData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return certificado;
    }
}