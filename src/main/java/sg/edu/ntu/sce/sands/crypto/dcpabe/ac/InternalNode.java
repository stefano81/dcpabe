package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public abstract class InternalNode extends TreeNode {
    private static final long serialVersionUID = 1L;
    private TreeNode left;
    private TreeNode right;

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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((left == null) ? 0 : left.hashCode());
        result = prime * result + ((right == null) ? 0 : right.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof InternalNode))
            return false;
        InternalNode other = (InternalNode) obj;
        if (left == null) {
            if (other.left != null)
                return false;
        } else if (!left.equals(other.left))
            return false;
        if (right == null) {
            return other.right == null;
        } else return right.equals(other.right);
    }
}
