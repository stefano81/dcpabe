package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public abstract class TreeNode {
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