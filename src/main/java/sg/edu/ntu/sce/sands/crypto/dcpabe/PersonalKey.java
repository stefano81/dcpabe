package sg.edu.ntu.sce.sands.crypto.dcpabe;
import java.io.Serializable;


public class PersonalKey implements Serializable {
	private static final long serialVersionUID = 1L;
	private final String attribute;
	private final byte[] key;
	private byte[] preprocess;
	
	public PersonalKey(String attribute, byte[] key) {
		this.attribute = attribute;
		this.key = key;
	}

	public String getAttribute() {
		return attribute;
	}

	public byte[] getKey() {
		return key;
	}
	
	public byte[] getKeyPreprocessed(){
		return preprocess;
	}
	public void setKeyPreprocessed(byte[] preprocess){
		this.preprocess=preprocess;
	}
}
