package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import java.io.Serializable;

public abstract class TreeNode implements Serializable {
    private static final long serialVersionUID = 1L;
    private String label;
    private int sat;

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

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((label == null) ? 0 : label.hashCode());
        result = prime * result + sat;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof TreeNode))
            return false;
        TreeNode other = (TreeNode) obj;
        if (label == null) {
            if (other.label != null)
                return false;
        } else if (!label.equals(other.label))
            return false;
        return sat == other.sat;
    }
}