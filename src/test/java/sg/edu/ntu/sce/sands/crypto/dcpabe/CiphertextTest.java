package sg.edu.ntu.sce.sands.crypto.dcpabe;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;


public class CiphertextTest {
    private static GlobalParameters gp;
    private static AuthorityKeys authority;
    private AccessStructure arho;
    private PublicKeys pks;

    @BeforeAll
    public static void init() {
        gp = DCPABE.globalSetup(160);
        authority = DCPABE.authoritySetup("authority", gp, "A", "B", "C", "D");
    }

    @BeforeEach
    public void setUp() {
        arho = AccessStructure.buildFromPolicy("and A or D and C B");
        pks = new PublicKeys();
        pks.subscribeAuthority(authority.getPublicKeys());
    }

    @Test
    public void testSerialization() throws Exception {
        Ciphertext ct = DCPABE.encrypt(DCPABE.generateRandomMessage(gp), arho, gp, pks);
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);) {
            oos.writeObject(ct);

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));) {
                Ciphertext ct1 = (Ciphertext) ois.readObject();

                assertArrayEquals(ct.getC0(), ct1.getC0());

                assertEquals(ct.getAccessStructure(), ct1.getAccessStructure());

                assertEquals(ct.getAccessStructure().getL(), ct1.getAccessStructure().getL());
                assertEquals(ct.getAccessStructure().getN(), ct1.getAccessStructure().getN());

                for (int i = 0; i < ct.getAccessStructure().getL(); i++) {
                    assertArrayEquals(ct.getC1(i), ct1.getC1(i), "differ on C1" + i);
                    assertArrayEquals(ct.getC2(i), ct1.getC2(i), "differ on C2" + i);
                    assertArrayEquals(ct.getC3(i), ct1.getC3(i), "differ on C3" + i);
                }
            }
        }
    }
}
