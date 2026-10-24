// Command porch-vet runs Porch's custom analyzers. Use with: go vet -vettool=$(which porch-vet) ./...
package main

import (
	"golang.org/x/tools/go/analysis/unitchecker"

	"github.com/aurimasniekis/go-porch/tools/analyzers/txscope"
)

func main() {
	unitchecker.Main(txscope.Analyzer)
}
