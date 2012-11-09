package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Vector;

import sg.edu.ntu.sce.sands.crypto.dcpabe.GlobalParameters;


public class AccessStructure {
	private Map<Integer, String> rho;
	private Vector<Vector<Element>> A;
	private TreeNode policyTree;

	private int partsIndex;


	protected AccessStructure() {
		A = new Vector<Vector<Element>>();
		rho = new HashMap<Integer, String>();
	}

	public Vector<Element> getRow(int row) {
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

	public static AccessStructure buildFromPolicy(String policy, GlobalParameters GP) {
		AccessStructure arho = new AccessStructure();

		Pairing pairing = PairingFactory.getPairing(GP.getCurveParams());

		Element one = pairing.getZr().newOneElement().getImmutable();
		Element zero = pairing.getZr().newZeroElement().getImmutable();
		Element mOne = pairing.getZr().newOneElement().negate().getImmutable();

		arho.generateTree(policy);

		arho.generateMatrix(one, zero, mOne);

		return arho;
	}

	private void generateMatrix(Element one, Element zero, Element mOne) {
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
				Vector<Element> Ax = new Vector<Element>(c);

				for (int i = 0; i < node.getLabel().length(); i++) {
					switch (node.getLabel().charAt(i)) {
					case '0':
						Ax.add(zero);
						break;
					case '1':
						Ax.add(one);
						break;
					case '*':
						Ax.add(mOne);
						break;
					}
				}

				while (c > Ax.size())
					Ax.add(zero);
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

			if (node instanceof Attribute) {
//				System.out.printf("attribute: %s %s\n", node.getName(), node.getLabel());
				continue;
			}
			if (node instanceof OrGate) {
//				System.out.printf("or: label children as myself: %s\n", node.getLabel());
				((OrGate) node).getLeft().setLabel(node.getLabel());
				queue.add(((OrGate) node).getLeft());
				((OrGate) node).getRight().setLabel(node.getLabel());
				queue.add(((OrGate) node).getRight());
			} else if (node instanceof AndGate) {
//				System.out.printf("and: %s label children differently\n", node.getLabel());
				sb.delete(0, sb.length());

				sb.append(node.getLabel());

				while (c > sb.length())
					sb.append('0');
				sb.append('1');
//				System.out.printf("left: %s\n", sb.toString());
				((AndGate) node).getLeft().setLabel(sb.toString());
				queue.add(((AndGate) node).getLeft());

				sb.delete(0, sb.length());

				while (c > sb.length())
					sb.append('0');
				sb.append('*');
//				System.out.printf("right: %s\n", sb.toString());
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
			((InternalNode) node).setLeft(generateTree(policyParts));
			((InternalNode) node).setRight(generateTree(policyParts));
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
			Vector<Element> Ax = A.get(x);
			System.out.printf("%s: [", rho.get(x));
			for (int i = 0; i < Ax.size(); i++) {
				Element e = Ax.get(i);
				if (e.isOne())
					System.out.print("  1");
				else if (e.isZero())
					System.out.print("  0");
				else
					System.out.print(" -1");
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
}
