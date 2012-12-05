package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1TateNafProjectiveMillerPairingMap;

import java.util.List;
import java.util.Vector;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure.MatrixElement;

public class DCPABE {
	public static GlobalParameters globalSetup(int lambda) {
		GlobalParameters params = new GlobalParameters();
		
		params.setCurveParams(new TypeA1CurveGenerator(3, lambda).generate());
		Pairing pairing = PairingFactory.getPairing(params.getCurveParams());
		
		params.setG1(pairing.getG1().newRandomElement().getImmutable());
		
		Element eg1g1 = pairing.pairing(params.getG1(), params.getG1());
		byte[] data = new AbstractElementPowPreProcessing_Fast(
				eg1g1).toBytes();
		params.set_eg1g1_preprocess(data);
		
		byte[] data_g1 = new AbstractElementPowPreProcessing_Fast(
				params.getG1()).toBytes();
		params.setg1_preprocess(data_g1);
		
		return params;
	}
	
	public static AuthorityKeys authoritySetup(String authorityID, GlobalParameters GP, String ... attributes) {
		AuthorityKeys authorityKeys = new AuthorityKeys(authorityID);
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		for (String attribute : attributes) {
			Element ai = pairing.getZr().newRandomElement().getImmutable();
			Element yi = pairing.getZr().newRandomElement().getImmutable();
			
			Element G1_yi= GP.getG1().powZn(yi);
			
			byte[] data = new AbstractElementPowPreProcessing_Fast(G1_yi).toBytes();
			
			authorityKeys.getPublicKeys().put(attribute, new PublicKey(
					pairing.pairing(GP.getG1(), GP.getG1()).powZn(ai).toBytes(), 
					G1_yi.toBytes(),
					data)
					);
			
			authorityKeys.getSecretKeys().put(attribute, new SecretKey(ai.toBytes(), yi.toBytes()));
		}
		
		return authorityKeys;
	}

	public static Ciphertext encrypt(Message message, AccessStructure arho, GlobalParameters GP, PublicKeys pks) {
		
		Ciphertext ct = new Ciphertext();
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());

		AbstractElementPowPreProcessing_Fast eg1g1_preprocess = 
				new AbstractElementPowPreProcessing_Fast(
						pairing.getGT(),
						GP.geteg1g1_preprocess());
		
		AbstractElementPowPreProcessing_Fast g1_preprocess = 
				new AbstractElementPowPreProcessing_Fast(
						pairing.getG1(),
						GP.getg1_preprocess());
		
		Element M = pairing.getGT().newRandomElement().getImmutable();
		message.m = M.toBytes();
		
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
		
		ct.setC0(M.mul(eg1g1_preprocess.powZn(s)).toBytes()); // C_0
		
		ct = internal_loop
				(ct, GP, arho, pks, pairing, eg1g1_preprocess, g1_preprocess, w, v);
		
		return ct;
	}

	private static Ciphertext internal_loop(Ciphertext ct, GlobalParameters GP,
			AccessStructure arho, PublicKeys pks, Pairing pairing, 
			AbstractElementPowPreProcessing_Fast eg1g1_preprocess, 
			AbstractElementPowPreProcessing_Fast g1_preprocess, 
			Vector<Element> w, Vector<Element> v) {
		
		for (int x = 0; x < arho.getN(); x++) {
			Element lambdax = dotProduct(arho.getRow(x), v, pairing.getZr().newZeroElement(), pairing);
			Element wx = dotProduct(arho.getRow(x), w, pairing.getZr().newZeroElement(), pairing);
			
			Element rx = pairing.getZr().newRandomElement().getImmutable();
			
			Element c1x1 = eg1g1_preprocess.powZn(lambdax);
			Element c1x2 = pairing.getGT().newElement();
			c1x2.setFromBytes(pks.getPK(arho.rho(x)).getEg1g1ai());
			c1x2.powZn(rx);
			
			ct.setC1(c1x1.mul(c1x2).toBytes());
			
			Element GP_rx=GP.getG1().getImmutable();
			Element GP_wx=GP.getG1().getImmutable();
			
			GP_rx = g1_preprocess.powZn(rx).getImmutable();
			GP_wx = g1_preprocess.powZn(wx).getImmutable();
			
			ct.setC2(GP_rx.toBytes());

			AbstractElementPowPreProcessing_Fast preprocess_c3x = 
					new AbstractElementPowPreProcessing_Fast(
							pairing.getG1(),
							pks.getPK(arho.rho(x)).getG1yi_preprocess());
			
			ct.setC3(preprocess_c3x.powZn(rx).mul(GP_wx).toBytes());
		}
		
		return ct;
	}

	public static Message decrypt(Ciphertext CT, PersonalKeys pks, GlobalParameters GP) {
		//List<Integer> toUse = CT.getAccessStructure().getIndexesList(pks.getAttributes());
		List<Integer> toUse = CT.getAccessStructure().getIndexesList_Breadth(pks.getAttributes());
		
		if (null == toUse || toUse.isEmpty()) {
			//throw new IllegalArgumentException("not satisfying");
			return null;
		}
		
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element HGID = pairing.getG1().newElement();
		HGID.setFromHash(pks.getUserID().getBytes(), 0, pks.getUserID().getBytes().length);
		HGID = HGID.getImmutable();
		
		PairingPreProcessing eHGID = pairing.pairing(HGID);

		Element t = pairing.getGT().newOneElement();
		
		for (Integer x : toUse) {
			Element c3x = pairing.getG1().newElement();
			c3x.setFromBytes(CT.getC3(x));
			Element p1 = eHGID.pairing(c3x);
			
			PairingPreProcessing eKey = pairing.pairing(
					pks.getKey(CT.getAccessStructure().rho(x))
					.getKeyPreprocessed());
			
			Element c2x = pairing.getG1().newElement();
			c2x.setFromBytes(CT.getC2(x));
			Element p2 = eKey.pairing(c2x);
			
			Element c1x = pairing.getGT().newElement();
			c1x.setFromBytes(CT.getC1(x));
			t.mul(c1x.mul(p1).mul(p2.invert()));
		}
		
		Element c0 = pairing.getGT().newElement();
		c0.setFromBytes(CT.getC0());
		c0.mul(t.invert());
		
		return new Message(c0.toBytes());
	}
	
	public static PersonalKey keyGen(String userID, String attribute, SecretKey sk, GlobalParameters GP) {
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element HGID = pairing.getG1().newElement();
		HGID.setFromHash(userID.getBytes(), 0, userID.getBytes().length);
		Element ai = pairing.getZr().newElement();
		ai.setFromBytes(sk.getAi());
		Element yi = pairing.getZr().newElement();
		yi.setFromBytes(sk.getYi());
		
		Element key = GP.getG1().powZn(ai).mul(HGID.powZn(yi));
		
		PersonalKey pk = new PersonalKey(attribute, key.toBytes());
		
		pk.setKeyPreprocessed(pairing.pairing(key).toBytes());
		
		return pk;
	}
	
	private static Element dotProduct(Vector<MatrixElement> v1, Vector<Element> v2, Element element, Pairing pairing) {
		if (v1.size() != v2.size()) throw new IllegalArgumentException("different length");
		if (element.isImmutable()) throw new IllegalArgumentException("immutable");
		
		if (!element.isZero())
			element.setToZero();
		
		for (int i = 0; i < v1.size(); i++) {
			Element e = pairing.getZr().newElement();
			switch (v1.get(i)) {
			case MINUS_ONE:
				e.setToOne().negate();
				break;
			case ONE:
				e.setToOne();
				break;
			case ZERO:
				e.setToZero();
				break;
			}
			element.add(e.mul(v2.get(i).getImmutable()));
		}
		
		return element.getImmutable();
	}

}
