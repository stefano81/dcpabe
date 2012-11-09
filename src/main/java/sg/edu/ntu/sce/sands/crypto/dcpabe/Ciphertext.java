package sg.edu.ntu.sce.sands.crypto.dcpabe;
import java.util.ArrayList;
import java.util.List;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;


import it.unisa.dia.gas.jpbc.Element;


public class Ciphertext {
	private Element c0;
	private List<Element> c1;
	private List<Element> c2;
	private List<Element> c3;
	private AccessStructure accessStructure;
	
	public Ciphertext() {
		c1 = new ArrayList<Element>();
		c2 = new ArrayList<Element>();
		c3 = new ArrayList<Element>();
	}

	public Element getC0() {
		return c0;
	}

	public void setC0(Element c0) {
		this.c0 = c0.getImmutable();
	}

	public Element  getC1(int x) {
		return c1.get(x);
	}

	public void setC1(Element c1x) {
		c1.add(c1x.getImmutable());
	}

	public Element getC2(int x) {
		return c2.get(x);
	}

	public void setC2(Element c2x) {
		c2.add(c2x.getImmutable());
	}

	public Element getC3(int x) {
		return c3.get(x);
	}

	public void setC3(Element c3x) {
		c3.add(c3x.getImmutable());
	}

	public void setAccessStructure(AccessStructure accessStructure) {
		this.accessStructure = accessStructure;
	}
	
	public AccessStructure getAccessStructure() {
		return accessStructure;
	}
}
