package sg.edu.ntu.sce.sands.crypto;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DCPABEToolTest {
    private static CommandLine cmd;
    private static File gpFile;
    private static File resFile;

    private File apFileS;
    private File apFileP;
    private File encFile;
    private File resFile2;
    private File key1AFile;
    private File key1DFile;
    private File fakeOutput;
    private PrintWriter fakeCmdOutput;

    private static final String policy = "and a or d and b c";

    @BeforeAll
    public static void beforeAll() throws Exception {
        gpFile = Files.createTempFile("dcpabe", "gp").toFile();
        cmd = new CommandLine(new DCPABETool());
        cmd.execute("gsetup", "-f", gpFile.getPath());
        resFile = new File(Objects.requireNonNull(DCPABEToolTest.class.getResource("/testResource.txt")).toURI());
    }

    @BeforeEach
    public void setUp() throws Exception {
        fakeOutput = Files.createTempFile("fake", "output").toFile();
        fakeOutput.deleteOnExit();
        fakeCmdOutput = new PrintWriter(fakeOutput);
        cmd.setErr(fakeCmdOutput);
        cmd.setOut(fakeCmdOutput);

        apFileS = Files.createTempFile("fake", "apFileS").toFile();
        apFileS.deleteOnExit();
        apFileP = Files.createTempFile("fake", "apFileP").toFile();
        apFileP.deleteOnExit();
        encFile = Files.createTempFile("fake", "encFile").toFile();
        encFile.deleteOnExit();
        resFile2 = Files.createTempFile("fake", "resFile2").toFile();
        resFile2.deleteOnExit();
        key1AFile = Files.createTempFile("fake", "key1AFile").toFile();
        key1AFile.deleteOnExit();
        key1DFile = Files.createTempFile("fake", "key1DFile").toFile();
        key1DFile.deleteOnExit();
    }

    @AfterEach
    public void tearDown() {
        fakeCmdOutput.close();
    }

    @Test
    public void testDecryptWorks() throws Exception {
        cmd.execute("asetup", "-f", gpFile.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d");
        cmd.execute("enc", "-f", gpFile.getPath(), resFile.getPath(), policy, encFile.getPath(), apFileP.getPath());
        cmd.execute("keygen", "-f", gpFile.getPath(), "user1", "a", apFileS.getPath(), key1AFile.getPath());
        cmd.execute("keygen", "-f", gpFile.getPath(), "user1", "d", apFileS.getPath(), key1DFile.getPath());

        int exitCode = cmd.execute("dec", "-f", gpFile.getPath(), "user1", encFile.getPath(), resFile2.getPath(),
                key1AFile.getPath(), key1DFile.getPath());

        assertEquals(0, exitCode);
        assertTrue(resFile2.exists());
        assertEquals(resFile.length(), resFile2.length());
    }

    @Test
    public void testCheckWorks() throws Exception {
        cmd.execute("asetup", "-f", gpFile.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d");
        cmd.execute("keygen", "-f", gpFile.getPath(), "user1", "a", apFileS.getPath(), key1AFile.getPath());
        cmd.execute("keygen", "-f", gpFile.getPath(), "user1", "d", apFileS.getPath(), key1DFile.getPath());
        String userKeys = String.join(",", key1AFile.getPath(), key1DFile.getPath());
        int exitCode = cmd.execute("check", gpFile.getPath(), "user1", policy, apFileP.getPath(), userKeys);

        assertEquals(0, exitCode);
    }

    @Test
    public void testEncryptWorks() {
        cmd.execute("asetup", "-f", gpFile.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d");

        int exitCode = cmd.execute("enc", gpFile.getPath(), resFile.getPath(), policy, encFile.getPath(),
                apFileP.getPath(), "-f");

        assertEquals(0, exitCode);
        assertTrue(apFileP.exists());
        assertTrue(encFile.exists());
    }

    @Test
    public void testKeyGenWorks() {
        cmd.execute("asetup", "-f", gpFile.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d");

        int exitCode = cmd.execute("keygen", "-f", gpFile.getPath(), "user1", "a", apFileS.getPath(),
                key1AFile.getPath());

        assertEquals(0, exitCode);
        assertTrue(apFileS.exists());
        assertTrue(key1AFile.exists());
    }

    @Test
    public void testASetupWorks() {
        int exitCode = cmd.execute("asetup", "-f", gpFile.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d");

        assertEquals(0, exitCode);
        assertTrue(apFileP.exists());
        assertTrue(apFileS.exists());
    }

    @Test
    public void testGSetupWorks() throws IOException {
        File gpFile = Files.createTempFile("testGlobalSetup", "gp").toFile();
        gpFile.deleteOnExit();

        int exitCode = cmd.execute("gsetup", gpFile.getPath());

        assertEquals(0, exitCode);
        assertTrue(gpFile.exists());
    }

    @Test
    public void testASetupFailsWhenMissingArgs() {
        assertTrue(apFileS.delete());
        assertTrue(apFileP.delete());

        List<String> args = new ArrayList<>();
        args.addAll(Arrays.asList("asetup", "authority1", gpFile.getPath(), apFileS.getPath(), apFileP.getPath(),
                "attribute1"));
        for (int i = 1; i < args.size(); i++) {
            String missingArgs = args.remove(i);
            int exitCode = cmd.execute(args.toArray(new String[0]));
            args.add(i, missingArgs);

            assertEquals(2, exitCode);
            assertFalse(apFileS.exists());
            assertFalse(apFileP.exists());
        }
    }

    @Test
    public void testCheckFailsWhenMissingArgs() {

        List<String> args = new ArrayList<>();
        args.addAll(Arrays.asList("check", gpFile.getPath(), "user1", policy, "--pk", apFileP.getPath(), "--ek", key1AFile.getPath()));
        for (int i = 1; i < args.size(); i++) {
            String missingArgs = args.remove(i);
            int exitCode = cmd.execute(args.toArray(new String[0]));
            args.add(i, missingArgs);

            assertEquals(2, exitCode);
        }
    }

    @Test
    public void testDecryptFailsWhenMissingArgs() {

        List<String> args = new ArrayList<>();
        args.addAll(Arrays.asList("dec", gpFile.getPath(), "user1", encFile.getPath(), resFile2.getPath(),
                key1AFile.getPath()));
        for (int i = 1; i < args.size(); i++) {
            String missingArgs = args.remove(i);
            int exitCode = cmd.execute(args.toArray(new String[0]));
            args.add(i, missingArgs);

            assertEquals(2, exitCode);
        }
    }

    @Test
    public void testEncryptFailsWhenMissingArgs() {
        assertTrue(encFile.delete());

        List<String> args = new ArrayList<>();
        args.addAll(Arrays.asList("enc", gpFile.getPath(), resFile.getPath(), policy, encFile.getPath(),
                apFileP.getPath()));
        for (int i = 1; i < args.size(); i++) {
            String missingArgs = args.remove(i);
            int exitCode = cmd.execute(args.toArray(new String[0]));
            args.add(i, missingArgs);

            assertEquals(2, exitCode);
            assertFalse(encFile.exists());
        }
    }

    @Test
    public void testGSetupFailsWhenMissingArgs() {
        int exitCode = cmd.execute("gsetup");

        assertEquals(2, exitCode);
    }

    @Test
    public void testKeyGenFailsWhenMissingArgs() {
        assertTrue(key1AFile.delete());

        List<String> args = new ArrayList<>(Arrays.asList("keygen", gpFile.getPath(), "user1", "a", apFileS.getPath(), key1AFile.getPath()));
        for (int i = 1; i < args.size(); i++) {
            String missingArgs = args.remove(i);
            int exitCode = cmd.execute(args.toArray(new String[0]));
            args.add(i, missingArgs);

            assertEquals(2, exitCode);
            assertFalse(key1AFile.exists());
        }
    }

    @Test
    public void testPrintsVersion() throws IOException {
        String version_expected = "1.2.0";

        int exitCode = cmd.execute("--version");
        String version = null;
        try (Stream<String> output = Files.lines(fakeOutput.toPath())) {
            version = output.iterator().next();
        }

        assertEquals(0, exitCode);
        assertNotNull(version);
        assertEquals("DCPABE version: " + version_expected, version.trim());
    }

    @Test
    public void testCommandFailsWhenInputFileDoesNotExist() throws IOException {
        PrintStream systemErr = System.err;
        try (PrintStream errorStream = new PrintStream(fakeOutput)) {
            System.setErr(errorStream);
            File gpFile_ = Files.createTempFile("fake", "gpFile").toFile();
            gpFile.deleteOnExit();
            gpFile_.delete();
            String[][] commands = {
                {"asetup", "-f", gpFile_.getPath(), "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d"},
                {"dec", gpFile_.getPath(), "user1", encFile.getPath(), resFile2.getPath(),
                key1AFile.getPath()},
                {"enc", gpFile_.getPath(), resFile.getPath(), policy, encFile.getPath(),
                apFileP.getPath()},
                {"keygen", gpFile_.getPath(), "user1", "a", apFileS.getPath(), key1AFile.getPath()}
            };
            int exitCode_expected = 2;

            for (String[] command : commands) {
                int exitCode = cmd.execute(command);

                String msg = String.format("command \"%s\" output %d exitCode. Expected: %d.", command[0], exitCode, exitCode_expected);
                assertEquals(exitCode_expected, exitCode, msg);
            }
        }
        System.setErr(systemErr);
    }

    @Test
    public void testCommandFailsWhenInputFilePathIsInvalid() {
        String invalidGpPath = "some//folder\\\\gpfile:,?!";
        String[][] commands = {
            {"asetup", "-f", invalidGpPath, "authority1", apFileS.getPath(), apFileP.getPath(), "a", "b", "c", "d"},
            {"dec", invalidGpPath, "user1", encFile.getPath(), resFile2.getPath(),
            key1AFile.getPath()},
            {"enc", invalidGpPath, resFile.getPath(), policy, encFile.getPath(),
            apFileP.getPath()},
            {"keygen", invalidGpPath, "user1", "a", apFileS.getPath(), key1AFile.getPath()}
        };
        int exitCode_expected = 2;

        for (String[] command : commands) {
            int exitCode = cmd.execute(command);

            String msg = String.format("command \"%s\" output %d exitCode. Expected: %d.", command[0], exitCode, exitCode_expected);
            assertEquals(exitCode_expected, exitCode, msg);
        }
    }
}
