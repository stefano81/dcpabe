package sg.edu.ntu.sce.sands.crypto;
import java.util.LinkedList;
import java.util.Random;
import java.util.Vector;

import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.MutableNode;

public class AttributeGen {
	
	static final int AND_OP=-1;
	static final int OR_OP=-2;
	static final int ATT_OP=0;
	static final int DUMMY_OP=12345;	//used only by mutable node
	
	Vector<String> attrlist = null, backup_attrlist = null;
	Random rnd = null;
	int attr_num=0;

	@SuppressWarnings("unchecked")
	public Vector<String> gen(int in1, int in2, int num_pass) {
		int attr_pol_num=0;
		
		attr_num = in1;
		attr_pol_num = in2;
		Vector<String> orig_attrlist=genAttrList(attr_num);
		Vector<String> formula_group=new Vector<String>();
		
		for (int i=0; i<num_pass; i++){
		
			attrlist=(Vector<String>) orig_attrlist.clone();
			backup_attrlist = (Vector<String>) attrlist.clone();
			
			MutableNode root = new MutableNode();
			root.setType(DUMMY_OP);
			
			rnd=new Random();
			
			constructTree(root, attr_pol_num);
			
			String formula = null;
			try {
				formula = preorder(root);
			} catch (Exception e) {
				e.printStackTrace();
			}
			formula_group.add(formula);
		}
		
		return formula_group;
	}
	
	private void constructTree(MutableNode root, int attr_num) {
		LinkedList<MutableNode> queue = new LinkedList<MutableNode>();
		queue.offer(root);
		int avail_slots=1;
		
		//construct a random access tree
		while (!queue.isEmpty()){
			MutableNode curr=queue.remove();
			if (avail_slots==attr_num){		//place attribute only
				curr.setType(ATT_OP);
				attr_num--;
				avail_slots--;
			}else{
				if ((avail_slots!=1) && rnd.nextBoolean()){	//place attribute
					curr.setType(ATT_OP);
					attr_num--;
					avail_slots--;
				}else{	//place operator
					MutableNode left=new MutableNode();
					MutableNode right=new MutableNode();
					left.setType(DUMMY_OP);
					right.setType(DUMMY_OP);
					curr.setType(rnd.nextBoolean()?AND_OP:OR_OP);
					curr.setLeft(left);
					curr.setRight(right);
					queue.offer(left);
					queue.offer(right);
					avail_slots++;
				}
			}
		}
	}

	private String preorder(MutableNode root) throws Exception {
		if (root.getType()<0){	//operator
			if (root.getType()==AND_OP){
				return "and "+preorder(root.getLeft())+" "+preorder(root.getRight());
			}else{
				return "or "+preorder(root.getLeft())+" "+preorder(root.getRight());
			}
		}else{					//attribute
			if (root.getType()==DUMMY_OP) throw new Exception();		//not supposed to be dummy
			return pullAttribute();
		}
	}

	private String pullAttribute() {
		if (!attrlist.isEmpty()){
			return attrlist.remove(rnd.nextInt(attrlist.size()));
		}else{
			return backup_attrlist.elementAt(rnd.nextInt(attr_num));
		}
	}

	Vector<String> genAttrList(int attrnum){
		int count=0;
		Vector<String> attrlist = new Vector<String>();
		
		for (int i=1; count<attrnum; i++){
			String attr = genAttr(i);
			if (attr==null) continue;
			attrlist.add(attr);
			count++;
		}
		
		return attrlist;
	}
	
	String genAttr(int index){

		String tmpresult = new String();
		int remainder;
		char charremainder;
		
		while(index!=0)
		{
			remainder = index%27;
			if (remainder==0) return null;
			remainder+=96;
			charremainder = (char)remainder;
			char [] chararray = {charremainder};
			tmpresult=new String(chararray)+tmpresult;
			index/=27;
		}
		
		return tmpresult;
	}
	
}
