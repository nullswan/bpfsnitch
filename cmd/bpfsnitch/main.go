package main

import (
	"log"

	"github.com/nullswan/bpfsnitch/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
