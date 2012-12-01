package sg.edu.ntu.sce.sands.crypto.dcpabe;
import java.io.Serializable;

public class PublicKey implements Serializable {
	private static final long serialVersionUID = 1L;
	private final byte[] eg1g1ai;
	private final byte[] g1yi;
	private final byte[] g1yi_preprocess;
	
	public PublicKey(byte[] eg1g1ai, byte[] g1yi, byte[] g1yi_preprocess) {
		this.eg1g1ai = eg1g1ai;
		this.g1yi = g1yi;
		this.g1yi_preprocess=g1yi_preprocess;
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

}
