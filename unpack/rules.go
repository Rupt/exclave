package main

// synthesise makes what the packages' maintainer scripts would have made, without running them
// (10.1): the rules of unpack/rules.py, which the port has yet to carry over.
func synthesise(rootPath string, packages []*Package, log Log) error {
	log("synthesis rules applied: none")
	return nil
}

// notes is what the packages' trigger interests say the tree lacks, which no rule makes (10.1).
func notes(packages []*Package) ([]string, error) {
	return nil, nil
}
