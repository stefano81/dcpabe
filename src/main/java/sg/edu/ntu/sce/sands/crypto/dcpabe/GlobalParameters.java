package sg.edu.ntu.sce.sands.crypto.dcpabe;
import java.io.IOException;
import java.io.Serializable;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


public class GlobalParameters implements Serializable {
	private static final long serialVersionUID = 1L;
	private CurveParameters curveParams;
	private byte[] eg1g1_preprocess;
	private Element g1;
	private byte[] g1_preprocess;
	
	public CurveParameters getCurveParams() {
		return curveParams;
	}
	public void setCurveParams(CurveParameters curveParams) {
		this.curveParams = curveParams;
	}
	public Element getG1() {
		return g1;
	}
	public void setG1(Element g1) {
		this.g1 = g1;
	}
	public byte[] geteg1g1_preprocess(){
		return eg1g1_preprocess;
	}
	public void set_eg1g1_preprocess(byte[] eg1g1_preprocess){
		this.eg1g1_preprocess = eg1g1_preprocess;
	}
	public byte[] getg1_preprocess(){
		return g1_preprocess;
	}
	public void setg1_preprocess(byte[] g1_preprocess){
		this.g1_preprocess = g1_preprocess;
	}
	
	private void writeObject(java.io.ObjectOutputStream out) throws IOException {
		out.writeObject(curveParams);
		out.writeObject(g1.toBytes());
		out.writeObject(eg1g1_preprocess);
		out.writeObject(g1_preprocess);
	}
	
	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException {
		curveParams = (CurveParameters) in.readObject();
		Pairing pairing = PairingFactory.getPairing(curveParams);
		g1 = pairing.getG1().newElement();
		g1.setFromBytes((byte[]) in.readObject());
		g1 = g1.getImmutable();
		eg1g1_preprocess = (byte[]) in.readObject();
		g1_preprocess = (byte[]) in.readObject();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (null != obj)
			if (obj instanceof GlobalParameters) {
				GlobalParameters other = (GlobalParameters) obj;
				if (curveParams.equals(other.curveParams))
					if (g1.isEqual(other.g1))
						return true;
			}
		return false;
	}
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(curveParams.toString());
		sb.append(g1.toString());

		return sb.toString();
	}
}
