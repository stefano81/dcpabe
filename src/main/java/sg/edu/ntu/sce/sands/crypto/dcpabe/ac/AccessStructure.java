package sg.edu.ntu.sce.sands.crypto.dcpabe.ac;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.io.IOException;
import java.io.Serializable;
import java.util.*;

@JsonSerialize(using = AccessStructure.Serialize.class)
@JsonDeserialize(using = AccessStructure.Deserialize.class)
public class AccessStructure implements Serializable {
    private static final long serialVersionUID = 1L;
    private Map<Integer, String> rho;
    private List<List<MatrixElement>> A;
    private TreeNode policyTree;
    private int partsIndex;

    private AccessStructure() {
        A = new ArrayList<>();
        rho = new HashMap<>();
    }

    public static AccessStructure buildFromPolicy(String policy) {
        AccessStructure aRho = new AccessStructure();

        aRho.generateTree(policy);

        aRho.generateMatrix();

        return aRho;
    }

    public List<MatrixElement> getRow(int row) {
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
            } else if (t instanceof InternalNode) {
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

    private void generateMatrix() {
        int c = computeLabels(policyTree);

        Queue<TreeNode> queue = new LinkedList<>();
        queue.add(policyTree);

        while (!queue.isEmpty()) {
            TreeNode node = queue.poll();

            if (node instanceof InternalNode) {
                queue.add(((InternalNode) node).getLeft());
                queue.add(((InternalNode) node).getRight());
            } else {
                rho.put(A.size(), node.getName());
                ((Attribute) node).setX(A.size());
                List<MatrixElement> Ax = new ArrayList<>(c);

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
        Queue<TreeNode> queue = new LinkedList<>();
        StringBuilder sb = new StringBuilder();
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

        String policyAtIndex = policyParts[partsIndex];
        TreeNode node = generateNodeAtIndex(policyAtIndex);

        if (node instanceof InternalNode) {
            ((InternalNode) node).setLeft(generateTree(policyParts));
            ((InternalNode) node).setRight(generateTree(policyParts));
        }

        return node;
    }

    private TreeNode generateNodeAtIndex(String policyAtIndex) {
        switch (policyAtIndex) {
            case "and":
                return new AndGate();
            case "or":
                return new OrGate();
            default:
                return new Attribute(policyAtIndex);
        }
    }

    /**
     * Generates and stores in memory the binary tree representation of a policy.
     * The tree is built with instances of TreeNode child classes.
     *
     * @param policy a policy written as a monotonic boolean formula over attributes
     *               labels. The policy can be written in both infix or polish
     *               notation.
     */
    private void generateTree(String policy) {
        String[] policyParts;
        partsIndex = -1;

        // policy has infix notation if logic operators aren't at the beginning of string
        if (!(policy.toLowerCase().startsWith("and") || policy.toLowerCase().startsWith("or"))) {
            policy = policy.replace("(", "( ").replace(")", " )");
            policyParts = infixNotationToPolishNotation(policy.split("\\s+"));
        } else {
            policyParts = policy.split("\\s+");
        }
        policyTree = generateTree(policyParts);
    }

    /**
     * Finds the Normal Polish Notation of a policy in its infix form, by
     * implementing the Shunting-yard Algorithm (https://w.wiki/BmY)
     *
     * @param policy a array of tokens of a policy written in its infix form.
     *               Parentheses must be represented as whole tokens.
     * @return a array of tokens of the same policy in its Normal Polish Notation.
     */
    private String[] infixNotationToPolishNotation(String[] policy) {
        Map<String, Integer> precedence = new HashMap<>();
        precedence.put("and", 2);
        precedence.put("or", 1);
        precedence.put("(", 0);

        Stack<String> rpn = new Stack<String>(); //rpn stands for Reverse Polish Notation
        Stack<String> operators = new Stack<String>();

        for (String token : policy) {
            if (token.equals("(")) {
                operators.push(token);
            } else if (token.equals(")")) {
                while (!operators.peek().equals("(")) {
                    rpn.add(operators.pop());
                }
                operators.pop();
            } else if (precedence.containsKey(token)) {
                while (!operators.empty() && precedence.get(token) <= precedence.get(operators.peek())) {
                    rpn.add(operators.pop());
                }
                operators.push(token);
            } else {
                rpn.add(token);
            }
        }
        while (!operators.isEmpty()) {
            rpn.add(operators.pop());
        }

        // reversing the result to obtain Normal Polish Notation
        List<String> polishNotation = new ArrayList<String>(rpn);
        Collections.reverse(polishNotation);
        return polishNotation.toArray(new String[] {});
    }

    public String getMatrixAsString() {
        StringBuilder sb = new StringBuilder(2*getN() + getL()*getN());
        for (int x = 0; x < A.size(); x++) {
            List<MatrixElement> Ax = A.get(x);
            sb.append(String.format("%s: [", rho.get(x)));
            for (MatrixElement aAx : Ax) {
                switch (aAx) {
                    case ONE:
                        sb.append("  1");
                        break;
                    case MINUS_ONE:
                        sb.append(" -1");
                        break;
                    case ZERO:
                        sb.append("  0");
                        break;
                }
            }
            sb.append("]\n");
        }
        sb.delete(sb.length() - 1, sb.length());
        return sb.toString();
    }

    private void toString(StringBuilder builder, TreeNode node) {
        if (builder.length() != 0) builder.append(" ");

        if (node instanceof InternalNode) {
            builder.append(node.getName());
            toString(builder, ((InternalNode) node).getLeft());
            toString(builder, ((InternalNode) node).getRight());
        } else {
            builder.append(node.getName());
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        toString(builder, policyTree);
        return builder.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccessStructure that = (AccessStructure) o;
        return partsIndex == that.partsIndex &&
                Objects.equals(rho, that.rho) &&
                Objects.equals(A, that.A) &&
                Objects.equals(policyTree, that.policyTree);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rho, A, policyTree, partsIndex);
    }

    public enum MatrixElement {
        MINUS_ONE,
        ZERO,
        ONE
    }

    static class Serialize extends JsonSerializer {
        @Override
        public void serialize(Object o, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeStartObject();
            jsonGenerator.writeStringField("policy", o.toString());
            jsonGenerator.writeEndObject();
        }
    }

    static class Deserialize extends JsonDeserializer {
        @Override
        public Object deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JsonProcessingException {
            JsonNode node = jsonParser.getCodec().readTree(jsonParser);

            if (!node.isObject()) throw new RuntimeException("Unable to de-serialize AccessStructure, not an object");

            String policy = null;

            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                final Map.Entry<String, JsonNode> field = it.next();

                final String fieldName = field.getKey();
                final JsonNode fieldValue = field.getValue();

                if (fieldName.equals("policy")) {
                    policy = fieldValue.asText();
                } else {
                    throw new RuntimeException("Unable to deserialize AccessStructure: unknown field " + fieldName);
                }
            }

            if (policy == null) throw new RuntimeException("Unable to de-serialize AccessStructure, not an object");

            return AccessStructure.buildFromPolicy(policy);
        }
    }
}
