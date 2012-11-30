package sg.edu.ntu.sce.sands.crypto.dcpabe;
import java.io.Serializable;

public class PublicKey implements Serializable {
	private static final long serialVersionUID = 1L;
	private final byte[] eg1g1ai;
	private final byte[] g1yi;
	private final byte[] g1yi_preprocess;
	private final Integer[] g1yi_preprocess_offset;
	
	public PublicKey(byte[] eg1g1ai, byte[] g1yi, byte[] g1yi_preprocess, Integer[] g1yi_preprocess_offset) {
		this.eg1g1ai = eg1g1ai;
		this.g1yi = g1yi;
		this.g1yi_preprocess=g1yi_preprocess;
		this.g1yi_preprocess_offset=g1yi_preprocess_offset;
	}

	public byte[] getEg1g1ai() {
		return eg1g1ai;
	}

	public byte[] getG1yi() {
		return g1yi;
	}
	
	public byte[] getG1yi_preprocess() {
		return g1yi_preprocess;
	}
	
	public Integer[] getG1yi_preprocess_offset() {
		return g1yi_preprocess_offset;
	}
}
