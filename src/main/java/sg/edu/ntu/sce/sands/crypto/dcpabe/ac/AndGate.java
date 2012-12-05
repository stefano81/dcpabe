package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

public class AndGate extends InternalNode {
	private static final long serialVersionUID = 1L;

	@Override
	public String getName() {
		return "and";
	}
	
	transient public boolean satisfied_left = false;
	transient public boolean satisfied_right = false;
	
	//TODO: find some other alternative, right now using hard-coded theoretical maximum
	transient public int satisfied_num_left = 2147483647;
	transient public int satisfied_num_right = 2147483647;
	
	public boolean canSatisfy(TreeNode node){
		boolean updated = false;
		
		if (node==left){
			if (node.satisfied_num < satisfied_num_left){
				satisfied_num_left = node.satisfied_num;
				satisfied_left = true;
				updated = true;
			}
		}else if (node==right){
			if (node.satisfied_num < satisfied_num_right){
				satisfied_num_right = node.satisfied_num;
				satisfied_right = true;
				updated = true;
			}
		}else throw new IllegalArgumentException("Not supposed to be here!");
		
		if (satisfied_left && satisfied_right && updated){
			satisfied_num = satisfied_num_left + satisfied_num_right;
			full_satisfied=node;
			return true;
		}
		
		return false;
	}
}