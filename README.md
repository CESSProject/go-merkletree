# go-merkletree
The mht implemented for the podr2 algorithm can find the auxiliary nodes through several leaf nodes. mht root can be restored using leaf nodes and auxiliary nodes

```shell
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/CESSProject/go-merkletree"
	"log"
)

//TestContent implements the Content interface provided by merkletree and represents the content stored in the tree.
type TestContent struct {
	x string
}

//CalculateHash hashes the values of a TestContent
func (t TestContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other merkletree.Content) (bool, error) {
	return t.x == other.(TestContent).x, nil
}

func main() {
	//Build list of Content to build tree
	var list []merkletree.Content
	list = append(list, TestContent{x: "Dog"})
	list = append(list, TestContent{x: "Cat"})
	list = append(list, TestContent{x: "Bird"})
	list = append(list, TestContent{x: "Panda"})
	list = append(list, TestContent{x: "Wolf"})
	list = append(list, TestContent{x: "Dolphin"})
	list = append(list, TestContent{x: "Geoduck"})
	list = append(list, TestContent{x: "Eagle"})
	list = append(list, TestContent{x: "Giraffe"})
	//Create a new Merkle Tree from the list of Content
	t, err := merkletree.NewTree(list)
	if err != nil {
		log.Fatal(err)
	}

	//The index of the incoming leaf node.
	testLeafs := []int64{0,9}
	_, nodeMap, nodes, _ := t.GetMerkleAuxiliaryNode(merkletree.GetContentMap(testLeafs))

	for k := 0; k < len(nodes); k++ {
		log.Printf(" merkle path , %v is %s ,nodes location is:(%v;%v)\n", k, hex.EncodeToString(nodes[k].Hash), nodes[k].Height, nodes[k].Index)
	}

	//Get the structure of the reconstructed node, the incoming leaf node and its auxiliary node.
	ProofList,err:=t.GetRebuildNodeList(nodeMap,testLeafs)
	if err!=nil{
		log.Fatal(err)
	}

	//rebuild tree ,get root node
	root,err:=merkletree.NewTreeWithAuxiliaryNode(ProofList,sha256.New)
	log.Println("Rebuild MHT ROOT Hash is:", hex.EncodeToString(root.Hash))

	//Get the Merkle Root of the tree.
	mr := t.MerkleRoot()
	log.Println("MHT ROOT Hash is:", hex.EncodeToString(mr))

	//String representation
	log.Println(t)
}
```

