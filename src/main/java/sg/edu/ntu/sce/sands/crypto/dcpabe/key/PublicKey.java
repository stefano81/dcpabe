package sg.edu.ntu.sce.sands.crypto.dcpabe.key;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Arrays;

public class PublicKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private final byte[] eg1g1ai;
    private final byte[] g1yi;

    @JsonCreator
    public PublicKey(
            @JsonProperty("eg1g1ai") byte[] eg1g1ai,
            @JsonProperty("g1yi") byte[] g1yi) {
        this.eg1g1ai = eg1g1ai;
        this.g1yi = g1yi;
    }

    public byte[] getEg1g1ai() {
        return eg1g1ai;
    }

    public byte[] getG1yi() {
        return g1yi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKey publicKey = (PublicKey) o;
        return Arrays.equals(getEg1g1ai(), publicKey.getEg1g1ai()) &&
                Arrays.equals(getG1yi(), publicKey.getG1yi());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(getEg1g1ai());
        result = 31 * result + Arrays.hashCode(getG1yi());
        return result;
    }
}
