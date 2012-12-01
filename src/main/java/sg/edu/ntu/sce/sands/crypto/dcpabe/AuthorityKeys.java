package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;


public class AuthorityKeys implements Serializable {
	private static final long serialVersionUID = 1L;
	private String authorityID;
	private Map<String, PublicKey> publicKeys;
	private Map<String, SecretKey> secretKeys;
	
	public AuthorityKeys(String authorityID) {
		this.authorityID = authorityID;
		publicKeys = new HashMap<String, PublicKey>();
		secretKeys = new HashMap<String, SecretKey>();
	}
	
	public String getAuthorityID() {
		return authorityID;
	}
	
	public Map<String, PublicKey> getPublicKeys() {
		return publicKeys;
	}
	
	public Map<String, SecretKey> getSecretKeys() {
		return secretKeys;
	}
	
	public AuthorityKeys addAttribute(GlobalParameters GP, String attribute){
		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());
		
		Element ai = pairing.getZr().newRandomElement().getImmutable();
		Element yi = pairing.getZr().newRandomElement().getImmutable();
		
		Element G1_yi= GP.getG1().powZn(yi);
		
		byte[] data = new AbstractElementPowPreProcessing_Fast(G1_yi).toBytes();
		
		publicKeys.put(attribute, new PublicKey(
				pairing.pairing(GP.getG1(), GP.getG1()).powZn(ai).toBytes(), 
				G1_yi.toBytes(),
				data)
				);
		
		secretKeys.put(attribute, new SecretKey(ai.toBytes(), yi.toBytes()));
		
		return this;
	}
}
