// Licensed under the MIT License, see LICENCE file for details.

package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

//Content represents the data that is stored and verified by the tree. A type that
//implements this interface can be used as an item in the tree.
type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

//MerkleTree is the container for the tree. It holds a pointer to the root of the tree,
//a list of pointers to the leaf nodes, and the merkle root.
type MerkleTree struct {
	Root         *Node
	merkleRoot   []byte
	Leafs        []*Node
	hashStrategy func() hash.Hash
}

//Node represents a node, root, or leaf in the tree. It stores pointers to its immediate
//relationships, a hash, the content stored if it is a leaf, and other metadata.
type Node struct {
	Tree   *MerkleTree
	Parent *Node
	Left   *Node
	Right  *Node
	leaf   bool
	dup    bool
	Hash   []byte
	C      Content
	Height int64 //The height of the node, the height of the leaf node is 0
	Index  int64 //The serial number of the node in this layer, the serial number of the leftmost node is 0
}

type NodeSerializable struct {
	Hash   []byte
	Height int64
	Index  int64
}

//verifyNode walks down the tree until hitting a leaf, calculating the hash at each level
//and returning the resulting hash of Node n.
func (n *Node) verifyNode() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}
	rightBytes, err := n.Right.verifyNode()
	if err != nil {
		return nil, err
	}

	leftBytes, err := n.Left.verifyNode()
	if err != nil {
		return nil, err
	}

	h := n.Tree.hashStrategy()
	if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//calculateNodeHash is a helper function that calculates the hash of the node.
func (n *Node) calculateNodeHash() ([]byte, error) {
	if n.leaf {
		return n.C.CalculateHash()
	}

	h := n.Tree.hashStrategy()
	if _, err := h.Write(append(n.Left.Hash, n.Right.Hash...)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//NewTree creates a new Merkle Tree using the content cs.
func NewTree(cs []Content) (*MerkleTree, error) {
	var defaultHashStrategy = sha256.New
	t := &MerkleTree{
		hashStrategy: defaultHashStrategy,
	}
	root, leafs, err := buildWithContent(cs, t, 0, 0)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

//NewTreeWithHashStrategy creates a new Merkle Tree using the content cs using the provided hash
//strategy. Note that the hash type used in the type that implements the Content interface must
//match the hash type profided to the tree.
func NewTreeWithHashStrategy(cs []Content, hashStrategy func() hash.Hash) (*MerkleTree, error) {
	t := &MerkleTree{
		hashStrategy: hashStrategy,
	}
	root, leafs, err := buildWithContent(cs, t, 0, 0)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

// GetMerklePath: Get Merkle path and indexes(left leaf or right leaf)
func (m *MerkleTree) GetMerklePath(content Content) ([][]byte, []int64, error) {
	for _, current := range m.Leafs {
		ok, err := current.C.Equals(content)
		if err != nil {
			return nil, nil, err
		}

		if ok {
			currentParent := current.Parent
			var merklePath [][]byte
			var index []int64
			for currentParent != nil {
				if bytes.Equal(currentParent.Left.Hash, current.Hash) {
					merklePath = append(merklePath, currentParent.Right.Hash)
					index = append(index, 1) // right leaf
				} else {
					merklePath = append(merklePath, currentParent.Left.Hash)
					index = append(index, 0) // left leaf
				}
				current = currentParent
				currentParent = currentParent.Parent
			}
			return merklePath, index, nil
		}
	}
	return nil, nil, nil
}

func GetContentMap(indexs []int64) *map[int64]struct{} {
	content := make(map[int64]struct{}, len(indexs))
	for _, i := range indexs {
		content[i] = struct{}{}
	}
	return &content
}

//RebuildNodeListWithTree use map to describe the hierarchical relationship of each node participating in the construction of the tree
//auxiliary: the list of auxiliary nodes, and the list of original nodes can be traced back to the Root node
//original: a list of original nodes, and a list of auxiliary nodes can be traced back to the Root node
func (t *MerkleTree) RebuildNodeListWithTree(auxiliary map[int64][]int64, leaf []int64) ([][]*Node, error) {
	var maxHeight int64
	for k, _ := range auxiliary {
		if k > maxHeight {
			maxHeight = k
		}
	}

	ProofList := make([][]*Node, maxHeight+1)
	//The array subscript is equal to the node height of the node
	for i, _ := range ProofList {
		EachHeight := make([]*Node, 0)
		list, ok := auxiliary[int64(i)]
		if ok {
			for _, index := range list {
				node, err := t.GetNodeFromCoordinate(int64(i), index)
				if err != nil {
					return nil, err
				}
				EachHeight = append(EachHeight, node)
			}
		}
		ProofList[i] = EachHeight
	}

	//put original node in
	for _, index := range leaf {
		node, err := t.GetNodeFromCoordinate(0, index)
		if err != nil {
			return nil, err
		}
		ProofList[0] = append(ProofList[0], node)
	}
	return ProofList, nil
}

func RebuildNodeList(nodes *[]NodeSerializable) [][]*Node {
	var maxHeight int64
	for _, n := range *nodes {
		if n.Height > maxHeight {
			maxHeight = n.Height
		}
	}
	ProofList := make([][]*Node, maxHeight+1)
	for _, n := range *nodes {
		var node Node
		node.Hash = n.Hash
		node.Index = n.Index
		node.Height = n.Height
		ProofList[n.Height] = append(ProofList[n.Height], &node)
	}
	return ProofList
}

// GetMerkleAuxiliaryNode: Get Merkle path ,merkle path map and list of auxiliary node
func (m *MerkleTree) GetMerkleAuxiliaryNode(content *map[int64]struct{}) ([][]byte, map[int64][]int64, []*Node, error) {
	if len(*content) == 0 {
		return nil, nil, nil, errors.New("The length of the content parameter cannot be 0")
	}

	for _, current := range m.Leafs {
		//Check whether the tree (subtree) has these leaf nodes
		if _, ok := (*content)[current.Index]; ok {
			currentParent := current.Parent
			var merklePath [][]byte
			var nodeList []*Node

			for currentParent != nil {
				//if bytes.Equal(currentParent.Left.Hash, current.Hash){}
				if currentParent.Left.Index == current.Index {
					if _, ok = (*content)[currentParent.Right.Index]; !ok && currentParent.Right.leaf {
						merklePath = append(merklePath, currentParent.Right.Hash)
						nodeList = append(nodeList, currentParent.Right)
					}

					if !currentParent.Right.leaf {
						subtreeMHT, err := GenerateSubtreeMHT(*currentParent.Right)
						if err != nil {
							return nil, nil, nil, err
						}
						subtreePath, _, nodes, err := subtreeMHT.GetMerkleAuxiliaryNode(content)
						if err != nil {
							return nil, nil, nil, err
						}
						merklePath = append(merklePath, subtreePath...)
						nodeList = append(nodeList, nodes...)
					}

				} else {
					if _, ok = (*content)[currentParent.Left.Index]; !ok && currentParent.Left.leaf {
						merklePath = append(merklePath, currentParent.Left.Hash)
						nodeList = append(nodeList, currentParent.Left)
					}
					if !currentParent.Left.leaf {
						subtreeMHT, err := GenerateSubtreeMHT(*currentParent.Left)
						if err != nil {
							return nil, nil, nil, err
						}
						subtreePath, _, nodes, err := subtreeMHT.GetMerkleAuxiliaryNode(content)
						if err != nil {
							return nil, nil, nil, err
						}
						merklePath = append(merklePath, subtreePath...)
						nodeList = append(nodeList, nodes...)
					}

				}
				current = currentParent
				currentParent = currentParent.Parent
			}

			//for Auxiliary Node Serialization
			merkleMap := make(map[int64][]int64)
			for k := 0; k < len(nodeList); k++ {
				merkleMap[nodeList[k].Height] = append(merkleMap[nodeList[k].Height], nodeList[k].Index)
			}
			return merklePath, merkleMap, nodeList, nil
		}
	}

	//If the leaf in the list does not exist in this MHT, then return the ROOT of this MHT
	var merklePath [][]byte
	var nodeList []*Node
	merklePath = append(merklePath, m.merkleRoot)
	nodeList = append(nodeList, m.Root)

	return merklePath, nil, nodeList, nil
}

//GenerateSubtreeMHT Construct an MHT with a branch node as the root node
func GenerateSubtreeMHT(subTreeRoot Node) (*MerkleTree, error) {
	subTreeRoot.Parent = nil

	var subtreeLeafs []Content
	PostOrder(&subTreeRoot, &subtreeLeafs)

	//directly find the leftmost node number of the leaf nodes of these subtrees
	currentNode := subTreeRoot.Left
	var farLeftIndex int64
	for {
		if currentNode.leaf {
			farLeftIndex = currentNode.Index
			break
		} else {
			currentNode = currentNode.Left
		}
	}

	//construct a subtree using consecutive sibling leaves of the subtree, with the number of the leftmost leaf
	subtreeMHT, err := NewTreeWithIndexAndHeight(subtreeLeafs, farLeftIndex, 0)
	if err != nil {
		return nil, err
	}

	return subtreeMHT, err
}

//NewTreeWithIndexAndHeight Used when constructing subtrees, create a tree through consecutive nodes of any height, but retain the index of its leaf nodes
//index:the index of the first node of consecutive leaf nodes
func NewTreeWithIndexAndHeight(cs []Content, index, height int64) (*MerkleTree, error) {
	var defaultHashStrategy = sha256.New
	t := &MerkleTree{
		hashStrategy: defaultHashStrategy,
	}
	root, leafs, err := buildWithContent(cs, t, index, height)
	if err != nil {
		return nil, err
	}
	t.Root = root
	t.Leafs = leafs
	t.merkleRoot = root.Hash
	return t, nil
}

func PostOrder(tree *Node, subtreeLeafs *[]Content) {
	if tree == nil {
		return
	}
	MidOrder(tree.Left, subtreeLeafs)

	MidOrder(tree.Right, subtreeLeafs)

}

func MidOrder(tree *Node, subtreeLeafs *[]Content) {
	if tree == nil {
		return
	}
	MidOrder(tree.Left, subtreeLeafs)
	if tree.leaf {
		*subtreeLeafs = append(*subtreeLeafs, tree.C)
	}
	MidOrder(tree.Right, subtreeLeafs)
}

func (m *MerkleTree) GetNodeFromCoordinate(Height, Index int64) (*Node, error) {

	currentNode := Node{}
	var virtualNode bool
	min := 1 << uint(Height) * Index
	if min > m.Leafs[len(m.Leafs)-1].Index {
		min = m.Leafs[len(m.Leafs)-1].Index
		virtualNode = true
		Index -= 1
	}

	for _, v := range m.Leafs {
		if v.Index == min {
			currentNode = *v
			for !(currentNode.Index == Index && currentNode.Height == Height) {
				if currentNode.Parent == nil {
					return nil, errors.New("the coordinate does not exist in the tree！")
				} else {
					currentNode = *currentNode.Parent
				}
			}
			if virtualNode {
				currentNode.Index += 1
			}
			return &currentNode, nil
		}
	}
	return nil, errors.New("the coordinate cannot exist in this tree！")
}

func NewTreeWithAuxiliaryNode(evidence [][]*Node, hashStrategy func() hash.Hash) (*Node, error) {
	var subTreeRootList []*Node
	for k, v := range evidence {

		SortNodeIndex(&v)
		//todo:it is necessary to judge whether the number of nodes in each layer is matched. For example, if the index is 0, then a node with an index of 1 is needed, otherwise panic
		list, err := buildBulkNodesParentsList(v, hashStrategy)
		if err != nil {
			return nil, err
		}
		if k != len(evidence)-1 {
			//put the hash list calculated by the obtained bulk child nodes into the list of the parent generation, and sort them according to the index
			evidence[k+1] = append(evidence[k+1], list...)
		} else {
			//when the maximum height of the supplementary node is reached, the loop exits, and the root hash can be calculated according to the subTreeRootList
			subTreeRootList = append(subTreeRootList, list...)
		}
	}
	SortNodeIndex(&subTreeRootList)
	//calculate the root node and return directly
	if len(subTreeRootList) == 1 {
		return subTreeRootList[0], nil
	}
	return buildIntermediateWithNodes(subTreeRootList, hashStrategy)
}

// SortNodeIndex: Bubble Sort
func SortNodeIndex(nodes *[]*Node) {
	if len(*nodes) <= 1 {
		return
	}
	for e := len(*nodes) - 1; e > 0; e-- {
		for i := 0; i < e; i++ {
			if (*nodes)[i].Index > (*nodes)[i+1].Index {
				Swap(nodes, i, i+1)
			}
		}
	}
	return
}
func Swap(arr *[]*Node, i, j int) {
	temp := (*arr)[j]
	(*arr)[j] = (*arr)[i]
	(*arr)[i] = temp
}

//buildBulkNodesParentsList Calculate the list of parent nodes of bulk nodes,The premise is that the indexes of these nodes are ordered and paired
func buildBulkNodesParentsList(nodes []*Node, hashStrategy func() hash.Hash) ([]*Node, error) {
	leafs := make([]*Node, 0)
	for i := 0; i < len(nodes); i += 2 {
		h := hashStrategy()
		var left, right int = i, i + 1
		chash := append(nodes[left].Hash, nodes[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:   nodes[left],
			Right:  nodes[right],
			Hash:   h.Sum(nil),
			Index:  nodes[left].Index / 2,
			Height: nodes[left].Height + 1,
		}
		leafs = append(leafs, n)
	}
	return leafs, nil
}

func buildIntermediateWithNodes(nodes []*Node, hashStrategy func() hash.Hash) (*Node, error) {
	leafs := make([]*Node, 0)
	for i := 0; i < len(nodes); i += 2 {
		h := hashStrategy()
		var left, right int = i, i + 1
		chash := append(nodes[left].Hash, nodes[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:   nodes[left],
			Right:  nodes[right],
			Hash:   h.Sum(nil),
			Index:  nodes[left].Index / 2,
			Height: nodes[left].Height + 1,
		}
		leafs = append(leafs, n)
	}
	if len(leafs) == 1 {
		return leafs[0], nil
	} else {
		root, err := buildIntermediateWithNodes(nodes, hashStrategy)
		if err != nil {
			return nil, err
		}
		return root, nil
	}
}

//buildWithContent is a helper function that for a given set of Contents, generates a
//corresponding tree and returns the root node, a list of leaf nodes, and a possible error.
//Returns an error if cs contains no Contents.
func buildWithContent(cs []Content, t *MerkleTree, index, height int64) (*Node, []*Node, error) {
	if len(cs) == 0 {
		return nil, nil, errors.New("error: cannot construct tree with no content")
	}
	var leafs []*Node
	for i, c := range cs {
		hash, err := c.CalculateHash()
		if err != nil {
			return nil, nil, err
		}

		leafs = append(leafs, &Node{
			Hash:   hash,
			C:      c,
			leaf:   true,
			Tree:   t,
			Index:  int64(i) + index,
			Height: height,
		})
	}
	if len(leafs)%2 == 1 {
		duplicate := &Node{
			Hash:   leafs[len(leafs)-1].Hash,
			C:      leafs[len(leafs)-1].C,
			leaf:   true,
			dup:    true,
			Tree:   t,
			Index:  leafs[len(leafs)-1].Index + 1,
			Height: 0,
		}
		leafs = append(leafs, duplicate)
	}
	root, err := buildIntermediate(leafs, t, index/2, height+1)
	if err != nil {
		return nil, nil, err
	}

	return root, leafs, nil
}

//buildIntermediate is a helper function that for a given list of leaf nodes, constructs
//the intermediate and root levels of the tree. Returns the resulting root node of the tree.
func buildIntermediate(nl []*Node, t *MerkleTree, index, height int64) (*Node, error) {
	var nodes []*Node
	var count int64
	for i := 0; i < len(nl); i += 2 {
		h := t.hashStrategy()
		var left, right int = i, i + 1
		if i+1 == len(nl) {
			right = i
		}
		chash := append(nl[left].Hash, nl[right].Hash...)
		if _, err := h.Write(chash); err != nil {
			return nil, err
		}
		n := &Node{
			Left:   nl[left],
			Right:  nl[right],
			Hash:   h.Sum(nil),
			Tree:   t,
			Index:  index + count,
			Height: height,
		}
		count += 1
		nodes = append(nodes, n)
		nl[left].Parent = n
		nl[right].Parent = n
		if len(nl) == 2 {
			return n, nil
		}
	}
	return buildIntermediate(nodes, t, index/2, height+1)
}

//MerkleRoot returns the unverified Merkle Root (hash of the root node) of the tree.
func (m *MerkleTree) MerkleRoot() []byte {
	return m.merkleRoot
}

//RebuildTree is a helper function that will rebuild the tree reusing only the content that
//it holds in the leaves.
func (m *MerkleTree) RebuildTree() error {
	var cs []Content
	for _, c := range m.Leafs {
		cs = append(cs, c.C)
	}
	root, leafs, err := buildWithContent(cs, m, 0, 0)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

//RebuildTreeWith replaces the content of the tree and does a complete rebuild; while the root of
//the tree will be replaced the MerkleTree completely survives this operation. Returns an error if the
//list of content cs contains no entries.
func (m *MerkleTree) RebuildTreeWith(cs []Content) error {
	root, leafs, err := buildWithContent(cs, m, 0, 0)
	if err != nil {
		return err
	}
	m.Root = root
	m.Leafs = leafs
	m.merkleRoot = root.Hash
	return nil
}

//VerifyTree verify tree validates the hashes at each level of the tree and returns true if the
//resulting hash at the root of the tree matches the resulting root hash; returns false otherwise.
func (m *MerkleTree) VerifyTree() (bool, error) {
	calculatedMerkleRoot, err := m.Root.verifyNode()
	if err != nil {
		return false, err
	}

	if bytes.Compare(m.merkleRoot, calculatedMerkleRoot) == 0 {
		return true, nil
	}
	return false, nil
}

//VerifyContent indicates whether a given content is in the tree and the hashes are valid for that content.
//Returns true if the expected Merkle Root is equivalent to the Merkle root calculated on the critical path
//for a given content. Returns true if valid and false otherwise.
func (m *MerkleTree) VerifyContent(content Content) (bool, error) {
	for _, l := range m.Leafs {
		ok, err := l.C.Equals(content)
		if err != nil {
			return false, err
		}

		if ok {
			currentParent := l.Parent
			for currentParent != nil {
				h := m.hashStrategy()
				rightBytes, err := currentParent.Right.calculateNodeHash()
				if err != nil {
					return false, err
				}

				leftBytes, err := currentParent.Left.calculateNodeHash()
				if err != nil {
					return false, err
				}

				if _, err := h.Write(append(leftBytes, rightBytes...)); err != nil {
					return false, err
				}
				if bytes.Compare(h.Sum(nil), currentParent.Hash) != 0 {
					return false, nil
				}
				currentParent = currentParent.Parent
			}
			return true, nil
		}
	}
	return false, nil
}

//String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("%t %t %v %s", n.leaf, n.dup, hex.EncodeToString(n.Hash), n.C)
}

//String returns a string representation of the tree. Only leaf nodes are included
//in the output.
func (m *MerkleTree) String() string {
	s := ""
	for _, l := range m.Leafs {
		s += fmt.Sprint(l)
		s += "\n"
	}
	return s
}
