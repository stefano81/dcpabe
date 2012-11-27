package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public class MutableNode extends InternalNode {

	int type=0;
	
	public int getType() {
		return type;
	}

	public void setType(int _type) {
		type=_type;
	}
	
	public MutableNode getRight() {
		return (MutableNode) right;
	}
	
	public MutableNode getLeft() {
		return (MutableNode) left;
	}

	@Override
	String getName() {
		return null;
	}
}
