package sg.edu.ntu.sce.sands.crypto.dcpabe;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

public class TestCiphertext {
	static GlobalParameters gp;
	static AuthorityKeys authority;
	Ciphertext ct;
	Message m;
	AccessStructure arho;
	PublicKeys pks;
	
	@BeforeClass
	public static void init() {
		gp = DCPABE.globalSetup(160);
		authority = DCPABE.authoritySetup("authority", gp, "A", "B", "C", "D");
	}
	
	@Before
	public void setUp() throws Exception {
		m = new Message();
		arho = AccessStructure.buildFromPolicy("and A or D and C B");
		pks = new PublicKeys();
		pks.subscribeAuthority(authority.getPublicKeys());
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSerialization() throws Exception {
		Ciphertext ct = DCPABE.encrypt(m, arho, gp, pks);
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
			assertArrayEquals("differ on C1"+i, ct.getC1(i), ct1.getC1(i));
			assertArrayEquals("differ on C2"+i, ct.getC2(i), ct1.getC2(i));
			assertArrayEquals("differ on C3"+i, ct.getC3(i), ct1.getC3(i));
		}
	}
}
