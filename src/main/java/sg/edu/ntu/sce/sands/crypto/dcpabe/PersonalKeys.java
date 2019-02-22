package sg.edu.ntu.sce.sands.crypto.dcpabe;

import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class PersonalKeys {
    private String userID;
    private Map<String, PersonalKey> personalKeys;

    public PersonalKeys(String userID) {
        this.userID = userID;
        personalKeys = new HashMap<>();
    }

    public void addKey(PersonalKey pkey) {
        personalKeys.put(pkey.getAttribute(), pkey);
    }

    public String getUserID() {
        return userID;
    }

    public Collection<String> getAttributes() {
        return personalKeys.keySet();
    }

    public PersonalKey getKey(String attribute) {
        return personalKeys.get(attribute);
    }
}
