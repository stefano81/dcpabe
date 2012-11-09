package sg.edu.ntu.sce.sands.crypto.dcpabe;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;


public class GlobalParameters {
	private CurveParameters curveParams;
	private Element g1;
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
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(curveParams.toString());
		sb.append(g1.toString());

		return sb.toString();
	}
}
