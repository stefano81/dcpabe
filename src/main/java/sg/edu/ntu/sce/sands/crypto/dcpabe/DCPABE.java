package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

import java.util.List;
import java.util.Vector;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;

public class DCPABE {
	public static GlobalParameters loadParameters(String string) {
		GlobalParameters params = new GlobalParameters();
		
		return params;
	}
	
	public static GlobalParameters globalSetup(int lambda) {
		GlobalParameters params = new GlobalParameters();
		
		params.setCurveParams(new TypeA1CurveGenerator(3, lambda).generate());
		Pairing pairing = PairingFactory.getPairing(params.getCurveParams());
		
		params.setG1(pairing.getG1().newRandomElement().getImmutable());
		
		return params;
	}
	
	public static AuthorityKeys authoritySetup(String authorityID, GlobalParameters GP, String ... attributes) {
		AuthorityKeys authorityKeys = new AuthorityKeys(authorityID);
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		for (String attribute : attributes) {
			Element ai = pairing.getZr().newRandomElement().getImmutable();
			Element yi = pairing.getZr().newRandomElement().getImmutable();
			
			authorityKeys.getPublicKeys().put(attribute, new PublicKey(
					pairing.pairing(GP.getG1(), GP.getG1()).powZn(ai).getImmutable(), 
					GP.getG1().powZn(yi).getImmutable()));
			
			authorityKeys.getSecretKeys().put(attribute, new SecretKey(ai, yi));
		}
		
		return authorityKeys;
	}

	public static Ciphertext encrypt(Message message, AccessStructure arho, GlobalParameters GP, PublicKeys pks) {
		Ciphertext ct = new Ciphertext();
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element M = pairing.getGT().newRandomElement().getImmutable();
		message.m = M;
		
		Element s = pairing.getZr().newRandomElement().getImmutable();
		
		Vector<Element> v = new Vector<Element>(arho.getL());
		
		v.add(s);
		
		for (int i = 1; i < arho.getL(); i++) {
			v.add(pairing.getZr().newRandomElement().getImmutable());
		}
		
		Vector<Element> w = new Vector<Element>();
		w.add(pairing.getZr().newZeroElement().getImmutable());
		for (int i = 1; i < arho.getL(); i++) {
			w.add(pairing.getZr().newRandomElement().getImmutable());
		}
		
		ct.setAccessStructure(arho);
		
		ct.setC0(M.mul(pairing.pairing(GP.getG1(), GP.getG1()).powZn(s))); // C_0
		
		for (int x = 0; x < arho.getN(); x++) {
			Element lambdax = dotProduct(arho.getRow(x), v, pairing.getZr().newZeroElement());
			Element wx = dotProduct(arho.getRow(x), w, pairing.getZr().newZeroElement());
			
			Element rx = pairing.getZr().newRandomElement().getImmutable();
			
			Element c1x1 = pairing.pairing(GP.getG1(), GP.getG1()).powZn(lambdax);
			Element c1x2 = pks.getPK(arho.rho(x)).getEg1g1ai().powZn(rx);
			
			ct.setC1(c1x1.mul(c1x2));
			
			ct.setC2(GP.getG1().powZn(rx));
			
			ct.setC3(pks.getPK(arho.rho(x)).getG1yi().powZn(rx).mul(GP.getG1().powZn(wx)));
		}
		
		return ct;
	}
	
	public static Message decrypt(Ciphertext CT, PersonalKeys pks, GlobalParameters GP) {
		List<Integer> toUse = CT.getAccessStructure().getIndexesList(pks.getAttributes());
		
		if (null == toUse || toUse.isEmpty()) throw new IllegalArgumentException("not satisfying");
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element HGID = pairing.getG1().newElement();
		HGID.setFromHash(pks.getUserID().getBytes(), 0, pks.getUserID().getBytes().length);
		HGID = HGID.getImmutable();

		Element t = pairing.getGT().newOneElement();
		
		for (Integer x : toUse) {
			Element p1 = pairing.pairing(HGID, CT.getC3(x));
			Element p2 = pairing.pairing(pks.getKey(CT.getAccessStructure().rho(x)).getKey(), CT.getC2(x));
			
			t.mul(CT.getC1(x).mul(p1).mul(p2.invert()));
		}
		
		Element M = CT.getC0().mul(t.invert());
		
		return new Message(M);
	}
	
	public static PersonalKey keyGen(String userID, String attribute, SecretKey sk, GlobalParameters GP) {
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element HGID = pairing.getG1().newElement();
		HGID.setFromHash(userID.getBytes(), 0, userID.getBytes().length);
		
		return new PersonalKey(attribute, GP.getG1().powZn(sk.getAi()).mul(HGID.powZn(sk.getYi())).getImmutable());
	}
	
	private static Element dotProduct(Vector<Element> v1, Vector<Element> v2, Element element) {
		if (v1.size() != v2.size()) throw new IllegalArgumentException("different length");
		if (element.isImmutable()) throw new IllegalArgumentException("immutable");
		
		if (!element.isZero())
			element.setToZero();
		
		for (int i = 0; i < v1.size(); i++) {
			element.add(v1.get(i).getImmutable().mul(v2.get(i).getImmutable()));
		}
		
		return element.getImmutable();
	}

}
