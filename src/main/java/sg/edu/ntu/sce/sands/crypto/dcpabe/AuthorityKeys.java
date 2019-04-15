package sg.edu.ntu.sce.sands.crypto.dcpabe;

import com.fasterxml.jackson.annotation.JsonProperty;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


public class AuthorityKeys implements Serializable {
    private static final long serialVersionUID = 1L;

    @JsonProperty("authorityID")
    private String authorityID;
    @JsonProperty("publicKeys")
    private Map<String, PublicKey> publicKeys;
    @JsonProperty("secretKeys")
    private Map<String, SecretKey> secretKeys;

    public AuthorityKeys(String authorityID) {
        this.authorityID = authorityID;
        publicKeys = new HashMap<>();
        secretKeys = new HashMap<>();
    }

    private AuthorityKeys() {
    }

    public String getAuthorityID() {
        return authorityID;
    }

    public Map<String, PublicKey> getPublicKeys() {
        return publicKeys;
    }

    public Map<String, SecretKey> getSecretKeys() {
        return secretKeys;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorityKeys that = (AuthorityKeys) o;
        return Objects.equals(getAuthorityID(), that.getAuthorityID()) &&
                Objects.equals(getPublicKeys(), that.getPublicKeys()) &&
                Objects.equals(getSecretKeys(), that.getSecretKeys());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getAuthorityID(), getPublicKeys(), getSecretKeys());
    }
}
