package sg.edu.ntu.sce.sands.crypto.dcpabe.key;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;


public class PersonalKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String attribute;
    private final byte[] key;

    @JsonCreator
    public PersonalKey(
            @JsonProperty("attribute") String attribute,
            @JsonProperty("key") byte[] key) {
        this.attribute = attribute;
        this.key = key;
    }

    public String getAttribute() {
        return attribute;
    }

    public byte[] getKey() {
        return key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PersonalKey that = (PersonalKey) o;
        return Objects.equals(getAttribute(), that.getAttribute()) &&
                Arrays.equals(getKey(), that.getKey());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(getAttribute());
        result = 31 * result + Arrays.hashCode(getKey());
        return result;
    }
}
