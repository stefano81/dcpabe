package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;


public class SecretKey {
	private final Element ai;
	private final Element yi;
	
	public SecretKey(Element ai, Element yi) {
		this.ai = ai.getImmutable();
		this.yi = yi.getImmutable();
	}

	public Element getAi() {
		return ai;
	}

	public Element getYi() {
		return yi;
	}
}
