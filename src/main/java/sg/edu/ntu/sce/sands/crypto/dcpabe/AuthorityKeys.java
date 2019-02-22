package sg.edu.ntu.sce.sands.crypto.dcpabe;

import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;


public class AuthorityKeys implements Serializable {
    private static final long serialVersionUID = 1L;
    private String authorityID;
    private Map<String, PublicKey> publicKeys;
    private Map<String, SecretKey> secretKeys;

    public AuthorityKeys(String authorityID) {
        this.authorityID = authorityID;
        publicKeys = new HashMap<String, PublicKey>();
        secretKeys = new HashMap<String, SecretKey>();
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
}
