package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Vector;

public class AccessStructure implements Serializable {
	public enum MatrixElement {
		MINUS_ONE,
		ZERO,
		ONE
	}
	
	private static final long serialVersionUID = 1L;
	private Map<Integer, String> rho;
	private Vector<Vector<MatrixElement>> A;
	private TreeNode policyTree;

	private int partsIndex;


	protected AccessStructure() {
		A = new Vector<Vector<MatrixElement>>();
		rho = new HashMap<Integer, String>();
	}

	public Vector<MatrixElement> getRow(int row) {
		return A.get(row);
	}

	public int getL() {
		return A.get(0).size();
	}

	public int getN() {
		return A.size();
	}

	public String rho(int i) {
		return rho.get(i);
	}

	private boolean findIfSAT(TreeNode node) {
		if (node instanceof Attribute)
			return 1 == node.getSat();
		else {
			boolean b;
			if (node instanceof AndGate) {
				b = findIfSAT(((AndGate) node).getLeft());
				b &= findIfSAT(((AndGate) node).getRight());
			} else if (node instanceof OrGate) {
				b = findIfSAT(((OrGate) node).getLeft());
				b |= findIfSAT(((OrGate) node).getRight());
			} else
				throw new IllegalArgumentException("Unknown node type");
			node.setSat(b ? 1 : -1);
			return b;
		}
	}

	public List<Integer> getIndexesList(Collection<String> pKeys) {
		// initialize
		Queue<TreeNode> queue = new LinkedList<TreeNode>();
		queue.add(policyTree);

		while (!queue.isEmpty()) {
			TreeNode t = queue.poll();

			if (t instanceof Attribute) {
				t.setSat(pKeys.contains(t.getName()) ? 1 : -1);
			} else	if (t instanceof InternalNode) {
				t.setSat(0);
				queue.add(((InternalNode) t).getLeft());
				queue.add(((InternalNode) t).getRight());
			}
		}

		// find if satisfiable
		if (!findIfSAT(policyTree))
			return null;

		// populate the list
		List<Integer> list = new LinkedList<Integer>();
		queue.add(policyTree);
		while (!queue.isEmpty()) {
			TreeNode t = queue.poll();
			
			if (1 == t.getSat()) {
				if (t instanceof AndGate) {
					queue.add(((AndGate) t).getLeft());
					queue.add(((AndGate) t).getRight());
				} else if (t instanceof OrGate) {
					if (1 == ((OrGate) t).getLeft().getSat()) {
						queue.add(((OrGate) t).getLeft());
					} else if (1 == ((OrGate) t).getRight().getSat()) {
						queue.add(((OrGate) t).getRight());
					}
				} else if (t instanceof Attribute) {
					list.add(((Attribute) t).getX());
				}
			}
		}

		// return
		return list;
	}

	public static AccessStructure buildFromPolicy(String policy) {
		AccessStructure arho = new AccessStructure();

		arho.generateTree(policy);

		arho.generateMatrix();

		return arho;
	}

	private void generateMatrix() {
		int c = computeLabels(policyTree);

		Queue<TreeNode> queue = new LinkedList<TreeNode>();
		queue.add(policyTree);

		while (!queue.isEmpty()) {
			TreeNode node = queue.poll();

			if (node instanceof InternalNode) {
				queue.add(((InternalNode) node).getLeft());
				queue.add(((InternalNode) node).getRight());
			} else {
				rho.put(A.size(), node.getName());
				((Attribute) node).setX(A.size());
				Vector<MatrixElement> Ax = new Vector<MatrixElement>(c);

				for (int i = 0; i < node.getLabel().length(); i++) {
					switch (node.getLabel().charAt(i)) {
					case '0':
						Ax.add(MatrixElement.ZERO);
						break;
					case '1':
						Ax.add(MatrixElement.ONE);
						break;
					case '*':
						Ax.add(MatrixElement.MINUS_ONE);
						break;
					}
				}

				while (c > Ax.size())
					Ax.add(MatrixElement.ZERO);
				A.add(Ax);
			}
		}
	}

	private int computeLabels(TreeNode root) {
		Queue<TreeNode> queue = new LinkedList<TreeNode>();
		StringBuffer sb = new StringBuffer();
		int c = 1;
		
		root.setLabel("1");
		queue.add(root);

		while (!queue.isEmpty()) {
			TreeNode node = queue.poll();

			if (node instanceof Attribute)
				continue;
			
			if (node instanceof OrGate) {
				((OrGate) node).getLeft().setLabel(node.getLabel());
				queue.add(((OrGate) node).getLeft());
				((OrGate) node).getRight().setLabel(node.getLabel());
				queue.add(((OrGate) node).getRight());
			} else if (node instanceof AndGate) {
				sb.delete(0, sb.length());

				sb.append(node.getLabel());

				while (c > sb.length())
					sb.append('0');
				sb.append('1');
				((AndGate) node).getLeft().setLabel(sb.toString());
				queue.add(((AndGate) node).getLeft());

				sb.delete(0, sb.length());

				while (c > sb.length())
					sb.append('0');
				sb.append('*');

				((AndGate) node).getRight().setLabel(sb.toString());
				queue.add(((AndGate) node).getRight());

				c++;
			}
		}
		
		return c;
	}

	private TreeNode generateTree(String[] policyParts) {
		partsIndex++;

		TreeNode node;

		if ("and".equals(policyParts[partsIndex])) {
			node = new AndGate();
		} else if ("or".equals(policyParts[partsIndex])) {
			node = new OrGate();
		} else {
			node = new Attribute(policyParts[partsIndex]);
		}
		
		if (node instanceof InternalNode) {
			((InternalNode) node).setLeft(generateTree(policyParts).setParent(node));
			((InternalNode) node).setRight(generateTree(policyParts).setParent(node));
		}

		return node;
	}

	private void generateTree(String policy) {
		partsIndex = -1;

		String[] policyParts = policy.split(" ");	

		policyTree = generateTree(policyParts);
	}

	public void printMatrix() {
		for (int x = 0; x < A.size(); x++) {
			Vector<MatrixElement> Ax = A.get(x);
			System.out.printf("%s: [", rho.get(x));
			for (int i = 0; i < Ax.size(); i++) {
				switch(Ax.get(i)) {
				case ONE:
					System.out.print("  1");
					break;
				case MINUS_ONE:
					System.out.print(" -1");
					break;
				case ZERO:
					System.out.print("  0");
					break;
				}
			}
			System.out.println("]");
		}
	}
	
	private void printPolicy(TreeNode node) {
		System.out.print(" " + node.getName());
		if (node instanceof InternalNode) {
			printPolicy(((InternalNode) node).getLeft());
			printPolicy(((InternalNode) node).getRight());
		}
	}

	public void printPolicy() {
		 printPolicy(policyTree);
		 System.out.println();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((A == null) ? 0 : A.hashCode());
		result = prime * result + partsIndex;
		result = prime * result
				+ ((policyTree == null) ? 0 : policyTree.hashCode());
		result = prime * result + ((rho == null) ? 0 : rho.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof AccessStructure))
			return false;
		AccessStructure other = (AccessStructure) obj;
		if (A == null) {
			if (other.A != null)
				return false;
		} else if (!A.equals(other.A))
			return false;
		if (partsIndex != other.partsIndex)
			return false;
		if (policyTree == null) {
			if (other.policyTree != null)
				return false;
		} else if (!policyTree.equals(other.policyTree))
			return false;
		if (rho == null) {
			if (other.rho != null)
				return false;
		} else if (!rho.equals(other.rho))
			return false;
		return true;
	}

	public List<Integer> getIndexesList_Breadth(Collection<String> pKeys) {
		
		List<Integer> selrows = null;

		LinkedList<TreeNode> queue_attributes = new LinkedList<TreeNode>();
		LinkedList<TreeNode> queue2 = new LinkedList<TreeNode>();
		
		int node_count=1;
		queue2.add(policyTree);
		while (!queue2.isEmpty()) {
			TreeNode t = queue2.poll();
			t.setIndex(node_count);
			node_count++;

			if (t instanceof Attribute) {
				if (pKeys.contains(t.getName()))
					queue_attributes.offer(t);
			} else	if (t instanceof InternalNode) {
				queue2.add(((InternalNode) t).getLeft());
				queue2.add(((InternalNode) t).getRight());
			}
		}
		
		boolean [] satisfied_left=new boolean[node_count+1];
		boolean [] satisfied_right=new boolean[node_count+1];
		int [] full_satisfied=new int[node_count+1];	//if satisfied, returns satisfied by who (tree index)
		int [] satisfied_num =new int[node_count+1];	//if satisfied, by how many attributes
		int [] satisfied_num_left =new int[node_count+1];
		int [] satisfied_num_right =new int[node_count+1];
		
		Arrays.fill(satisfied_left, false);
		Arrays.fill(satisfied_right, false);
		Arrays.fill(full_satisfied, -1);
		Arrays.fill(satisfied_num, node_count+1);
		Arrays.fill(satisfied_num_left, node_count+1);
		Arrays.fill(satisfied_num_right, node_count+1);
		
		for (TreeNode i : queue_attributes){
			satisfied_num[i.getIndex()]=1;
		}
		
		boolean reached=false;
		while (!queue_attributes.isEmpty()){
			TreeNode node=queue_attributes.remove();
			if (node==policyTree){	//reached root
				reached=true;
			}
			TreeNode parent=node.getParent();
			if (parent instanceof AndGate){
				if (full_satisfied[parent.getIndex()]==-1){		//we reached first
					
					if (node==((AndGate) parent).getLeft()){
						satisfied_num_left[parent.getIndex()] = satisfied_num[node.getIndex()];
					}else if (node==((AndGate) parent).getRight()){
						satisfied_num_right[parent.getIndex()] = satisfied_num[node.getIndex()];
					}else new IllegalArgumentException("Not supposed to be here!");
					
					if (!satisfied_left[parent.getIndex()] && node==((AndGate) parent).getLeft()){
						satisfied_left[parent.getIndex()]=true;
					}
					
					if (!satisfied_right[parent.getIndex()] && node==((AndGate) parent).getRight()){
						satisfied_right[parent.getIndex()]=true;
					}
					
					if (satisfied_right[parent.getIndex()] && satisfied_left[parent.getIndex()]){
						full_satisfied[parent.getIndex()]=node.getIndex();
						queue_attributes.offer(parent);
						
						satisfied_num[parent.getIndex()] = 
								satisfied_num_left[parent.getIndex()] +
								satisfied_num_right[parent.getIndex()];
					}
					
				}else{	//will accept if uses less attributes
					if (node==((AndGate) parent).getLeft()){
						if (satisfied_num[node.getIndex()]<satisfied_num_left[parent.getIndex()]){
							satisfied_num_left[parent.getIndex()] = satisfied_num[node.getIndex()];
							
							satisfied_num[parent.getIndex()] = 
									satisfied_num_left[parent.getIndex()] +
									satisfied_num_right[parent.getIndex()];
							
							full_satisfied[parent.getIndex()]=node.getIndex();
							queue_attributes.offer(parent);
						}
					}else if (node==((AndGate) parent).getRight()){
						if (satisfied_num[node.getIndex()]<satisfied_num_right[parent.getIndex()]){
							satisfied_num_right[parent.getIndex()] = satisfied_num[node.getIndex()];
							
							satisfied_num[parent.getIndex()] = 
									satisfied_num_left[parent.getIndex()] +
									satisfied_num_right[parent.getIndex()];
							
							full_satisfied[parent.getIndex()]=node.getIndex();
							queue_attributes.offer(parent);
						}
					}else new IllegalArgumentException("Not supposed to be here!");
				}
			}else{
				if (parent instanceof OrGate){
					if (satisfied_num[node.getIndex()]<satisfied_num[parent.getIndex()]){
						full_satisfied[parent.getIndex()]=node.getIndex();
						satisfied_num[parent.getIndex()] = satisfied_num[node.getIndex()];
						queue_attributes.offer(parent);
					}
				}
			}
		}
		
		if (reached){
			selrows=new Vector<Integer>();
			queue_attributes.clear();
			
			queue_attributes.offer(policyTree);
			while (!queue_attributes.isEmpty()){
				TreeNode node=queue_attributes.remove();
				
				if (node instanceof Attribute){
					selrows.add(((Attribute) node).getX());
					continue;
				}
				
				if (node instanceof AndGate){
					queue_attributes.offer(((InternalNode)node).getLeft());
					queue_attributes.offer(((InternalNode)node).getRight());
					continue;
				}

				if (node instanceof OrGate){
					int index=full_satisfied[node.getIndex()];
					if (((OrGate)node).getLeft().getIndex()==index)
						queue_attributes.offer(((OrGate)node).getLeft());
					else
						queue_attributes.offer(((OrGate)node).getRight());
				}
			}
			
		}else{
			//Not satisfiable!!!
			return null;
		}
		
		return selrows;
	}
}
