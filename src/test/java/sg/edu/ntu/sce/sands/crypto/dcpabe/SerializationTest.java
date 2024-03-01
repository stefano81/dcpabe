package sg.edu.ntu.sce.sands.crypto.dcpabe;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SerializationTest {
    private static final ObjectMapper mapper = new ObjectMapper();

    @Test
    public void serializeGlobalParameters() throws Exception {
        GlobalParameters gp = DCPABE.globalSetup(160);

        String serializedValue = mapper.writeValueAsString(gp);

        assertNotNull(serializedValue);

        GlobalParameters deserialized = mapper.readValue(serializedValue, GlobalParameters.class);

        assertNotNull(deserialized);
        assertEquals(gp, deserialized);
    }

    @Test
    public void serializeAuthorityKeys() throws Exception {
        AuthorityKeys authorityKeys = new AuthorityKeys("fooo");

        String serializedValue = mapper.writeValueAsString(authorityKeys);

        assertNotNull(serializedValue);

        AuthorityKeys deserialized = mapper.readValue(serializedValue, AuthorityKeys.class);

        assertNotNull(deserialized);
        assertEquals(authorityKeys, deserialized);
    }

    @Test
    public void serializeAccessStructure() throws Exception {
        AccessStructure ac = AccessStructure.buildFromPolicy("or and a b c");

        String serializedValue = mapper.writeValueAsString(ac);

        assertNotNull(serializedValue);

        AccessStructure deserialized = mapper.readValue(serializedValue, AccessStructure.class);

        assertNotNull(deserialized);
        assertEquals(ac.toString(), deserialized.toString());
    }

    @Test
    public void serializeMessage() throws Exception {
        Message message = new Message("foot".getBytes());

        String serializedValue = mapper.writeValueAsString(message);

        assertNotNull(serializedValue);

        Message deserialized = mapper.readValue(serializedValue, Message.class);

        assertNotNull(deserialized);
        assertEquals(message, deserialized);
    }

    @Test
    public void serializePersonalKey() throws Exception {
        PersonalKey personalKey = new PersonalKey("attribute", "encryptionMaterial".getBytes());

        String serializedValue = mapper.writeValueAsString(personalKey);

        assertNotNull(serializedValue);

        PersonalKey deserialized = mapper.readValue(serializedValue, PersonalKey.class);

        assertNotNull(deserialized);
        assertEquals(personalKey, deserialized);
    }

    @Test
    public void serializePublicKey() throws Exception {
        PublicKey publicKey = new PublicKey("eg1g1ai".getBytes(), "g1yi".getBytes());

        String serializedValue = mapper.writeValueAsString(publicKey);

        assertNotNull(serializedValue);

        PublicKey deserialized = mapper.readValue(serializedValue, PublicKey.class);

        assertNotNull(deserialized);
        assertEquals(publicKey, deserialized);
    }

    @Test
    public void serializeSecretKey() throws Exception {
        SecretKey secretKey = new SecretKey("ai".getBytes(), "yi".getBytes());

        String serializedValue = mapper.writeValueAsString(secretKey);

        assertNotNull(serializedValue);

        SecretKey deserialized = mapper.readValue(serializedValue, SecretKey.class);

        assertNotNull(deserialized);
        assertEquals(secretKey, deserialized);
    }

    @Test
    public void serializePersonalKeys() throws Exception {
        PersonalKeys personalKeys = new PersonalKeys("user");
        personalKeys.addKey(new PersonalKey("a", "key".getBytes()));

        String serializedValue = mapper.writeValueAsString(personalKeys);

        assertNotNull(serializedValue);

        PersonalKeys deserialized = mapper.readValue(serializedValue, PersonalKeys.class);

        assertNotNull(deserialized);
        assertEquals(personalKeys, deserialized);
    }

    @Test
    public void serializePublicKeys() throws Exception {
        PublicKeys publicKeys = new PublicKeys();
        publicKeys.subscribeAuthority(
                Collections.singletonMap("attribute", new PublicKey("eg1g1ai".getBytes(), "g1yi".getBytes()))
        );

        String serializedValue = mapper.writeValueAsString(publicKeys);

        assertNotNull(serializedValue);

        PublicKeys deserialized = mapper.readValue(serializedValue, PublicKeys.class);

        assertNotNull(deserialized);
        assertEquals(publicKeys, deserialized);
    }
}
