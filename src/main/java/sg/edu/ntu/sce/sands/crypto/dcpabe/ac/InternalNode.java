package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public abstract class InternalNode extends TreeNode {
	private static final long serialVersionUID = 1L;
	protected TreeNode left;
	protected TreeNode right;
	
	public TreeNode getLeft() {
		return left;
	}
	public void setLeft(TreeNode left) {
		this.left = left;
	}
	public TreeNode getRight() {
		return right;
	}
	public void setRight(TreeNode right) {
		this.right = right;
	}
}
