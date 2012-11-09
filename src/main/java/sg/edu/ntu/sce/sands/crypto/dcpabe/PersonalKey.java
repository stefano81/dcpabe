package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.Element;


public class PersonalKey {
	private final String attribute;
	private final Element key;
	
	public PersonalKey(String attribute, Element key) {
		this.attribute = attribute;
		this.key = key.getImmutable();
	}

	public String getAttribute() {
		return attribute;
	}

	public Element getKey() {
		return key;
	}
}
