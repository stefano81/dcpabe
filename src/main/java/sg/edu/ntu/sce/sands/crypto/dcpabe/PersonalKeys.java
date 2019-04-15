package sg.edu.ntu.sce.sands.crypto.dcpabe;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PersonalKeys {
    @JsonProperty("userID")
    private String userID;
    @JsonProperty("personalKeys")
    private Map<String, PersonalKey> personalKeys;

    public PersonalKeys(String userID) {
        this.userID = userID;
        personalKeys = new HashMap<>();
    }

    private PersonalKeys() {
    }

    public void addKey(PersonalKey pkey) {
        personalKeys.put(pkey.getAttribute(), pkey);
    }

    public String getUserID() {
        return userID;
    }

    @JsonIgnore
    public Collection<String> getAttributes() {
        return personalKeys.keySet();
    }

    @JsonIgnore
    public PersonalKey getKey(String attribute) {
        return personalKeys.get(attribute);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PersonalKeys that = (PersonalKeys) o;
        return Objects.equals(getUserID(), that.getUserID()) &&
                Objects.equals(personalKeys, that.personalKeys);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getUserID(), personalKeys);
    }
}
