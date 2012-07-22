package Protocolo;

import java.io.Serializable;
import java.security.Key;
import java.security.PublicKey;

public class ProtocolData implements Serializable {
	
	private static final long serialVersionUID = 1L;
	
	private byte[] bytes;
        private PublicKey puk;
	private int status;
	private String message;
	
	public ProtocolData() {
		
	}
	
	public ProtocolData(byte[] bytes) {
		super();
		this.bytes = bytes;
                this.puk = null;
	}

	public ProtocolData(String data) {
		super();
		this.bytes = data.getBytes();
                this.puk = null;
	}

        public ProtocolData(PublicKey data) {
		super();
		this.bytes = null;
                this.puk = data;
	}
	
    @Override
	public String toString(){
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

        public PublicKey getKey() {
		return this.puk;
	}
}
