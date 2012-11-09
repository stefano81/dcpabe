import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;
import java.util.Random;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;

import sg.edu.ntu.sce.sands.crypto.dcpabe.AuthorityKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.Ciphertext;
import sg.edu.ntu.sce.sands.crypto.dcpabe.DCPABE;
import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;
import sg.edu.ntu.sce.sands.crypto.dcpabe.Message;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PersonalKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.PublicKeys;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;


@RunWith(JUnit4.class)
public class Testing {

	@Test
	public void testSerialization() {
		GlobalParameters gp = DCPABE.globalSetup(160);
		
		String serialized = gp.toString();
		//System.out.println(serialized);
		
		GlobalParameters gp1 = DCPABE.loadParameters(serialized);
	}

	public void testDCPABE2() {

		GlobalParameters gp = DCPABE.globalSetup(160);

		System.out.println("Global parameters generated");

		PublicKeys publicKeys = new PublicKeys();

		AuthorityKeys authority1 = DCPABE.authoritySetup("a1", gp, "a", "b");

		System.out.printf("Authority \"%s\" keys generated\n", authority1.getAuthorityID());

		publicKeys.subscribeAuthority(authority1.getPublicKeys());

		AuthorityKeys authority2 = DCPABE.authoritySetup("a2", gp, "c", "d");

		System.out.printf("Authority \"%s\" keys generated\n", authority2.getAuthorityID());

		publicKeys.subscribeAuthority(authority2.getPublicKeys());
		
		PersonalKeys pkeys = new PersonalKeys("user");
		pkeys.addKey(DCPABE.keyGen("user", "a", authority1.getSecretKeys().get("a"), gp));
		pkeys.addKey(DCPABE.keyGen("user", "d", authority2.getSecretKeys().get("d"), gp));

		AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c", gp);

		Message message = new Message(); 
		Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);
		
		Message dmessage = DCPABE.decrypt(ct, pkeys, gp);
		
		System.out.println(dmessage.m.isEqual(message.m));
	}


	public void testDCPABE1() {
		GlobalParameters gp = DCPABE.globalSetup(160);

		System.out.println("Global parameters generated");

		PublicKeys publicKeys = new PublicKeys();

		AuthorityKeys authority0 = DCPABE.authoritySetup("a1", gp, "a", "b", "c", "d");
		publicKeys.subscribeAuthority(authority0.getPublicKeys());

		System.out.printf("Authority \"%s\" keys generated\n", authority0.getAuthorityID());

		AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c", gp);
		
		PersonalKeys pkeys = new PersonalKeys("user");
		PersonalKey k_user_a  = DCPABE.keyGen("user", "a", authority0.getSecretKeys().get("a"), gp);
		PersonalKey k_user_d  = DCPABE.keyGen("user", "d", authority0.getSecretKeys().get("d"), gp);
		pkeys.addKey(k_user_a);
		pkeys.addKey(k_user_d);
		

		Message message = new Message(); 
		Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);

		Message dMessage = DCPABE.decrypt(ct, pkeys, gp);
		
		assertEquals(message.m, dMessage.m);
	}

	@Test
	public void testAS() {
		GlobalParameters gp = DCPABE.globalSetup(160);

		AccessStructure as1 = AccessStructure.buildFromPolicy("and a or d and b c", gp);
		as1.printPolicy();
		as1.printMatrix();
		
		ArrayList<String> attributes = new ArrayList<String>();
		attributes.add("a");
		attributes.add("d");
		
//		System.out.println(as1.getIndexesList(attributes));
		
		AccessStructure as2 = AccessStructure.buildFromPolicy("and or d and b c a", gp);
		as2.printPolicy();
		as2.printMatrix();
		
//		System.out.println(as2.getIndexesList(attributes));
		
		AccessStructure as3 = AccessStructure.buildFromPolicy("and or a b and c d", gp);
		as3.printPolicy();
		as3.printMatrix();
	}

	@Test
	public void testBilinearity() {
		Random random = new Random(123456);
		Pairing pairing = PairingFactory.getPairing("/Users/stefano/Projects/jpbc/params/a_181_603.properties", random);

		Element g1 = pairing.getG1().newRandomElement().getImmutable();
		Element g2 = pairing.getG2().newRandomElement().getImmutable();

		Element a = pairing.getZr().newRandomElement().getImmutable();
		Element b = pairing.getZr().newRandomElement().getImmutable();

		Element ga = g1.powZn(a);
		Element gb = g2.powZn(b);

		Element gagb = pairing.pairing(ga, gb);

		Element ggab = pairing.pairing(g1, g2).powZn(a.mulZn(b));

		assertTrue(gagb.isEqual(ggab));	
	}

}
