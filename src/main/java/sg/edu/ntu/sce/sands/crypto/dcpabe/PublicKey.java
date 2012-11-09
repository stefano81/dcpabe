package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;


public class PublicKey {
	private final Element eg1g1ai;
	private final Element g1yi;
	
	public PublicKey(Element eg1g1ai, Element g1yi) {
		this.eg1g1ai = eg1g1ai.getImmutable();
		this.g1yi = g1yi.getImmutable();
	}

	public Element getEg1g1ai() {
		return eg1g1ai;
	}

	public Element getG1yi() {
		return g1yi;
	}
}
