package sg.edu.ntu.sce.sands.crypto.dcpabe.key;

import java.io.Serializable;


public class SecretKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] ai;
    private byte[] yi;

    public SecretKey(byte[] ai, byte[] yi) {
        this.ai = ai;
        this.yi = yi;
    }

    public byte[] getAi() {
        return ai;
    }

    public byte[] getYi() {
        return yi;
    }
}
