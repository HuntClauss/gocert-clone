package main

import (
	"fmt"
	"gocert-clone/clone"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: %s <domain>:<443>\n", os.Args[0])
		os.Exit(1)
	}

	addr := os.Args[1]
	if err := clone.Visit(addr); err != nil {
		fmt.Printf("cannot clone certs from %s: %v\n", addr, err)
		os.Exit(1)
	}
	fmt.Println("Successfully cloned certs from:", addr)
}
