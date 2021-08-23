import org.apache.commons.io.IOUtils;
import org.junit.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.*;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.utility.Utility;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;

public class ProgrammaticAccessTest {
    @Test
    public void testKeyCorrectlyDecrypted() throws IOException {
        GlobalParameters GP = DCPABE.globalSetup(160);
        AccessStructure accessStructure = AccessStructure.buildFromPolicy("A");

        AuthorityKeys authorityKeys = DCPABE.authoritySetup("auth1", GP, "A", "B", "C", "D");

        Message message = DCPABE.generateRandomMessage(GP);

        PublicKeys publicKeys = new PublicKeys();
        publicKeys.subscribeAuthority(authorityKeys.getPublicKeys());

        Ciphertext encryptedMessage = DCPABE.encrypt(message, accessStructure, GP, publicKeys);

        PersonalKeys personalKeys = new PersonalKeys("myID");
        personalKeys.addKey(DCPABE.keyGen("myID", "A", authorityKeys.getSecretKeys().get("A"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "B", authorityKeys.getSecretKeys().get("B"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "C", authorityKeys.getSecretKeys().get("C"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "D", authorityKeys.getSecretKeys().get("D"), GP));

        Message decryptedMessage = DCPABE.decrypt(encryptedMessage, personalKeys, GP);

        assertArrayEquals(message.getM(), decryptedMessage.getM());
    }

    @Test
    public void testMessageCorrectlyDecrypted() throws IOException {
        GlobalParameters GP = DCPABE.globalSetup(160);
        AccessStructure accessStructure = AccessStructure.buildFromPolicy("A");

        AuthorityKeys authorityKeys = DCPABE.authoritySetup("auth1", GP, "A", "B", "C", "D");

        byte[] fileBytes;
        try (
                InputStream inputStream = getClass().getResourceAsStream("/test_decryption.txt");
        ) {
            fileBytes = IOUtils.toByteArray(inputStream);
        }

        Message message = DCPABE.generateRandomMessage(GP);

        byte[] encryptedPayload;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(fileBytes)) {
            encryptedPayload = Utility.encryptAndDecrypt(message.getM(), true, bais);
        }

        PublicKeys publicKeys = new PublicKeys();
        publicKeys.subscribeAuthority(authorityKeys.getPublicKeys());

        Ciphertext encryptedMessage = DCPABE.encrypt(message, accessStructure, GP, publicKeys);

        PersonalKeys personalKeys = new PersonalKeys("myID");
        personalKeys.addKey(DCPABE.keyGen("myID", "A", authorityKeys.getSecretKeys().get("A"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "B", authorityKeys.getSecretKeys().get("B"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "C", authorityKeys.getSecretKeys().get("C"), GP));
        personalKeys.addKey(DCPABE.keyGen("myID", "D", authorityKeys.getSecretKeys().get("D"), GP));

        Message decryptedMessage = DCPABE.decrypt(encryptedMessage, personalKeys, GP);

        assertArrayEquals(message.getM(), decryptedMessage.getM());

        byte[] decryptedPayload;
        try (ByteArrayInputStream bais = new ByteArrayInputStream(encryptedPayload)) {
            decryptedPayload =Utility.encryptAndDecrypt(message.getM(), false, bais);
        }

        assertArrayEquals(fileBytes, decryptedPayload);
    }
}
