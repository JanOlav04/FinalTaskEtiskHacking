package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

func decodeBase64NTimes(data []byte, times int) error {
	current := data

	for i := 0; i < times; i++ {
		decoded, err := base64.StdEncoding.DecodeString(string(current))
		if err != nil {
			return fmt.Errorf("decode failed at iteration %d: %w", i+1, err)
		}

		current = decoded

		// Print the intermediate decoded result
		fmt.Printf("After decode %d:\n%s\n\n", i+1, current)
	}

	return nil
}

func main() {
	// Read Base64 content from file
	input, err := os.ReadFile("b64_out.bin")
	if err != nil {
		fmt.Println("Error reading b64_out.bin:", err)
		return
	}

	// Change this number to decode more or fewer times
	const decodeTimes = 100

	err = decodeBase64NTimes(input, decodeTimes)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
