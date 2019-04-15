package sg.edu.ntu.sce.sands.crypto.dcpabe.key;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Arrays;


public class SecretKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private byte[] ai;
    private byte[] yi;

    @JsonCreator
    public SecretKey(
            @JsonProperty("ai") byte[] ai,
            @JsonProperty("yi") byte[] yi) {
        this.ai = ai;
        this.yi = yi;
    }

    public byte[] getAi() {
        return ai;
    }

    public byte[] getYi() {
        return yi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecretKey secretKey = (SecretKey) o;
        return Arrays.equals(getAi(), secretKey.getAi()) &&
                Arrays.equals(getYi(), secretKey.getYi());
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(getAi());
        result = 31 * result + Arrays.hashCode(getYi());
        return result;
    }
}
