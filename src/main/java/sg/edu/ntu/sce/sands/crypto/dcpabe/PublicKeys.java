package sg.edu.ntu.sce.sands.crypto.dcpabe;

import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;

import java.util.HashMap;
import java.util.Map;


public class PublicKeys {
    private Map<String, PublicKey> publicKeys;

    public PublicKeys() {
        publicKeys = new HashMap<String, PublicKey>();
    }

    public void subscribeAuthority(Map<String, PublicKey> pks) {
        publicKeys.putAll(pks);
    }

    public PublicKey getPK(String attribute) {
        return publicKeys.get(attribute);
    }
}
