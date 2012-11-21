package sg.edu.ntu.sce.sands.crypto;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileWriter;

import org.junit.Test;

public class TestDCPABETool {
	File gpFile = new File("/tmp/mygp.gp");
	File apFileS = new File("/tmp/authority1.sk");
	File apFileP = new File("/tmp/authority1.pk");
	File encFile = new File("/tmp/res.enc");
	File resFile = new File("/tmp/res.orig");
	File resFile2 = new File("/tmp/res.dec");
	File key1AFile = new File("/tmp/user1_a.key");
	File key1DFile = new File("/tmp/user1_d.key");
	File key2AFile = new File("/tmp/user2_a.key");
	String policy = "and a or d and b c";

	@Test
	public void testDecryptOk() throws Exception {
		if (!gpFile.exists()) {
			String[] args = {"gsetup", "/tmp/mygp.gp"};
			
			DCPABETool.main(args);
		}
		boolean enc = false;
		if (!resFile.exists()) {
			assertTrue(resFile.createNewFile());
			FileWriter fw = new FileWriter(resFile);
			fw.append("This is a test file\n");
			fw.flush();
			fw.close();
			enc = true;
		}
		if (!encFile.exists() || enc) {
			String[] args = {"enc", resFile.getAbsolutePath(), policy, encFile.getAbsolutePath(), gpFile.getAbsolutePath(), apFileP.getAbsolutePath()};
			
			DCPABETool.main(args);
		}
		if (!key1AFile.exists()) {
			String[] args = {"keygen", "user1", "a", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1AFile.getAbsolutePath()};
			
			DCPABETool.main(args);
		}
		if (!key1DFile.exists()) {
			String[] args = {"keygen", "user1", "d", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1DFile.getAbsolutePath()};
			
			DCPABETool.main(args);
		}
		if (resFile2.exists()) {
			assertTrue(resFile2.delete());
		}
		
		
		assertTrue(gpFile.exists());
		assertTrue(resFile.exists());
		assertTrue(key1AFile.exists());
		assertTrue(key1DFile.exists());
		assertFalse(resFile2.exists());
		
		String[] args = {"dec", "user1", encFile.getAbsolutePath(), resFile2.getAbsolutePath(), gpFile.getAbsolutePath(), key1AFile.getAbsolutePath(), key1DFile.getAbsolutePath()};
		
		DCPABETool.main(args);
		
		assertTrue(gpFile.exists());
		assertTrue(resFile.exists());
		assertTrue(key1AFile.exists());
		assertTrue(key1DFile.exists());
		assertTrue(resFile2.exists());
		
		assertEquals("Files differ on size", resFile.length(), resFile2.length());
	}
	
	@Test
	public void testEncrypt() throws Exception {
		if (!gpFile.exists()) {
			String[] args = {"gsetup", gpFile.getAbsolutePath()};
			
			DCPABETool.main(args);
		}
		if (!apFileP.exists()) {
			String[] args = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};
			
			DCPABETool.main(args);
		}
		if (!resFile.exists()) {
			assertTrue(resFile.createNewFile());
			FileWriter fw = new FileWriter(resFile);
			fw.append("This is a test file\n");
			fw.flush();
			fw.close();
		}
		if (encFile.exists()) {
			assertTrue(encFile.delete());
		}
		
		assertTrue(apFileS.exists());
		assertTrue(gpFile.exists());
		assertTrue(resFile.exists());
		assertFalse(encFile.exists());
		
		String[] args = {"enc", resFile.getAbsolutePath(), policy, encFile.getAbsolutePath(), gpFile.getAbsolutePath(), apFileP.getAbsolutePath()};
		
		DCPABETool.main(args);
		
		assertTrue(apFileP.exists());
		assertTrue(gpFile.exists());
		assertTrue(resFile.exists());
		assertTrue(encFile.exists());
	}
	
	@Test
	public void testKeyGen() {
		
		if (!gpFile.exists()) {
			String[] args = {"gsetup", "/tmp/mygp.gp"};
			
			DCPABETool.main(args);
		}
		if (!apFileS.exists()) {
			String[] args = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};
			
			DCPABETool.main(args);
		}
		if (key1AFile.exists()) {
			assertTrue(key1AFile.delete());
		}
		
		assertTrue(apFileS.exists());
		assertTrue(gpFile.exists());
		assertFalse(key1AFile.exists());
		
		String[] args = {"keygen", "user1", "a", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), key1AFile.getAbsolutePath()};
		
		DCPABETool.main(args);
		
		assertTrue(apFileS.exists());
		assertTrue(gpFile.exists());
		assertTrue(key1AFile.exists());
	}
	
	@Test
	public void testAsetup() {
		if (!gpFile.exists()) {
			String[] args = {"gsetup", "/tmp/mygp.gp"};
			
			DCPABETool.main(args);
		}
		if (apFileP.exists()) {
			assertTrue(apFileP.delete());
		}
		if (apFileS.exists()) {
			assertTrue(apFileS.delete());
		}
		
		assertFalse(apFileP.exists());
		assertFalse(apFileS.exists());
		assertTrue(gpFile.exists());
		
		String[] args = {"asetup", "authority1", gpFile.getAbsolutePath(), apFileS.getAbsolutePath(), apFileP.getAbsolutePath(), "a", "b", "c", "d"};
		
		DCPABETool.main(args);
		
		assertTrue(apFileP.exists());
		assertTrue(apFileS.exists());
		assertTrue(gpFile.exists());
	}

	@Test
	public void testGSetup() {
		if (gpFile.exists()) {
			assertTrue(gpFile.delete());
		}
		assertFalse(gpFile.exists());
		
		String[] args = {"gsetup", gpFile.getAbsolutePath()};
		
		DCPABETool.main(args);
		
		assertTrue(gpFile.exists() );
	}

}
