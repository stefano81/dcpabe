package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import java.io.Serializable;

public abstract class TreeNode implements Serializable {
	private static final long serialVersionUID = 1L;
	protected String label;
	protected int sat;
	
	abstract String getName();
	
	public int getSat() {
		return sat;
	}
	
	public void setSat(int i) {
		this.sat = i;
	}
	
	public String getLabel() {
		return label;
	}
	
	public void setLabel(String label) {
		this.label = label;
	}
}