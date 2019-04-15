package sg.edu.ntu.sce.sands.crypto.dcpabe;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CiphertextTest {
    private static GlobalParameters gp;
    private static AuthorityKeys authority;
    private AccessStructure arho;
    private PublicKeys pks;

    @BeforeClass
    public static void init() {
        gp = DCPABE.globalSetup(160);
        authority = DCPABE.authoritySetup("authority", gp, "A", "B", "C", "D");
    }

    @Before
    public void setUp() {
        arho = AccessStructure.buildFromPolicy("and A or D and C B");
        pks = new PublicKeys();
        pks.subscribeAuthority(authority.getPublicKeys());
    }

    @Test
    public void testSerialization() throws Exception {
        Ciphertext ct = DCPABE.encrypt(DCPABE.generateRandomMessage(gp), arho, gp, pks);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);

        oos.writeObject(ct);

        oos.close();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));

        Ciphertext ct1 = (Ciphertext) ois.readObject();

        assertArrayEquals("C0", ct.getC0(), ct1.getC0());

        assertEquals("access structure differ", ct.getAccessStructure(), ct1.getAccessStructure());

        assertEquals("differ on l", ct.getAccessStructure().getL(), ct1.getAccessStructure().getL());
        assertEquals("differ on n", ct.getAccessStructure().getN(), ct1.getAccessStructure().getN());

        for (int i = 0; i < ct.getAccessStructure().getL(); i++) {
            assertArrayEquals("differ on C1" + i, ct.getC1(i), ct1.getC1(i));
            assertArrayEquals("differ on C2" + i, ct.getC2(i), ct1.getC2(i));
            assertArrayEquals("differ on C3" + i, ct.getC3(i), ct1.getC3(i));
        }
    }
}
