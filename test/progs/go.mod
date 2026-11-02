// A module of its own, so that the repository's `go vet ./...` and `go build ./...` leave this
// directory out: it holds the C exercisers beside go_paths.go, which test/tree.py builds by file.
module go_paths

go 1.22
