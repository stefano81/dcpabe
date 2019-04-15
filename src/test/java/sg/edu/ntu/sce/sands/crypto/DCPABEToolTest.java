package sg.edu.ntu.sce.sands.crypto;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class DCPABEToolTest {
    private static File gpFile;
    private static File resFile;

    private File apFileS;
    private File apFileP;
    private File encFile;
    private File resFile2;
    private File key1AFile;
    private File key1DFile;
    private static final String policy = "and a or d and b c";

    @BeforeClass
    public static void beforeAll() throws Exception {
        gpFile = File.createTempFile("dcpabe", "gp");

        String[] args = {"gsetup", gpFile.getAbsolutePath()};
        DCPABETool.main(args);

        resFile = new File(DCPABEToolTest.class.getResource("/testResource.txt").toURI());
    }

    @Before
    public void setUp() throws Exception {
        apFileS = File.createTempFile("authority", "sk");
        apFileS.deleteOnExit();

        apFileP = File.createTempFile("authority", "pk");
        apFileP.deleteOnExit();

        encFile = File.createTempFile("res", "enc");
        encFile.deleteOnExit();

        resFile2 = File.createTempFile("res", "dec");
        resFile2.deleteOnExit();

        key1AFile = File.createTempFile("user1_a", "key");
        key1AFile.deleteOnExit();

        key1DFile = File.createTempFile("user1_d", "key");
        key1DFile.deleteOnExit();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testDecryptOk() throws Exception {
                String[] asetup = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};

                DCPABETool.main(asetup);

            String[] enc = {"enc", resFile.getAbsolutePath(), policy, encFile.getAbsolutePath(), gpFile.getAbsolutePath(), apFileP.getAbsolutePath()};

            DCPABETool.main(enc);


            String[] keyGenA = {"keyGen", "user1", "a", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1AFile.getAbsolutePath()};

            DCPABETool.main(keyGenA);


            String[] keyGenD = {"keyGen", "user1", "d", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1DFile.getAbsolutePath()};

            DCPABETool.main(keyGenD);


        String[] args = {"dec", "user1", encFile.getAbsolutePath(), resFile2.getAbsolutePath(), gpFile.getAbsolutePath(), key1AFile.getAbsolutePath(), key1DFile.getAbsolutePath()};

        DCPABETool.main(args);

        assertTrue(key1AFile.exists());
        assertTrue(key1DFile.exists());
        assertTrue(resFile2.exists());

        assertThat(resFile.length(), is(resFile2.length()));
    }

    @Test
    public void testCheck() throws Exception {
        String[] asetup = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};

        DCPABETool.main(asetup);


        String[] keyGenA = {"keyGen", "user1", "a", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1AFile.getAbsolutePath()};

        DCPABETool.main(keyGenA);

        String[] keyGenD = {"keyGen", "user1", "d", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1DFile.getAbsolutePath()};

        DCPABETool.main(keyGenD);

        //check <username> <resource> <policy> <gpfile> m <authority 1>...<authority m> n <keyfile 1> ... <keyfile n>
        String[] args = {"check", "user1", policy, gpFile.getAbsolutePath(), "1", apFileP.getAbsolutePath(), "2", key1AFile.getAbsolutePath(), key1DFile.getAbsolutePath()};

        DCPABETool.main(args);
    }

    @Test
    public void testEncrypt() {
        String[] asetupArgs = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};

        DCPABETool.main(asetupArgs);

        String[] args = {"enc", resFile.getAbsolutePath(), policy, encFile.getAbsolutePath(), gpFile.getAbsolutePath(), apFileP.getAbsolutePath()};

        DCPABETool.main(args);

        assertTrue(apFileP.exists());
        assertTrue(encFile.exists());
    }

    @Test
    public void testKeyGen() {
        String[] asetupArgs = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};
        DCPABETool.main(asetupArgs);

        assertTrue(apFileS.exists());

        String[] args = {"keyGen", "user1", "a", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1AFile.getAbsolutePath()};

        DCPABETool.main(args);

        assertTrue(apFileS.exists());
        assertTrue(key1AFile.exists());
    }

    @Test
    public void testAsetup() {
        if (apFileP.exists()) {
            assertTrue(apFileP.delete());
        }
        if (apFileS.exists()) {
            assertTrue(apFileS.delete());
        }

        assertFalse(apFileP.exists());
        assertFalse(apFileS.exists());

        String[] args = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};

        DCPABETool.main(args);

        assertTrue(apFileP.exists());
        assertTrue(apFileS.exists());
    }

    @Test
    public void testGSetup() throws IOException {
        File gpFile = File.createTempFile("testGlobalSetup", "gp");

        if (gpFile.exists()) {
            assertTrue(gpFile.delete());
        }
        assertFalse(gpFile.exists());

        String[] args = {"gsetup", gpFile.getAbsolutePath()};

        DCPABETool.main(args);

        assertTrue(gpFile.exists());
    }
}
