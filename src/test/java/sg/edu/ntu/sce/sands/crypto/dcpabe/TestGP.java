package sg.edu.ntu.sce.sands.crypto.dcpabe;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.Assert.assertTrue;

public class TestGP {

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testSerialization() throws Exception {
        GlobalParameters gp = DCPABE.globalSetup(160);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);

        oos.writeObject(gp);
        oos.close();
        baos.close();

        byte[] bytes = baos.toByteArray();

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
        GlobalParameters gp1 = (GlobalParameters) ois.readObject();

        assertTrue(gp.equals(gp1));
    }

}
