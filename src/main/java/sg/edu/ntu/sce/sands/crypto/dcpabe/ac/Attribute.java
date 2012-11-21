package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public class Attribute extends TreeNode {
	private static final long serialVersionUID = 1L;
	private String name;
	private int x;
	
	public Attribute(String name) {
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}

	public void setX(int x) {
		this.x = x;
	}
	
	public int getX() {
		return x;
	}
}
