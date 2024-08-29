package main

import (
	"fmt"
	"math/big"
)

var hexConvertion = map[byte]int64{
	'0': 0,
	'1': 1,
	'2': 2,
	'3': 3,
	'4': 4,
	'5': 5,
	'6': 6,
	'7': 7,
	'8': 8,
	'9': 9,
	'a': 10,
	'b': 11,
	'c': 12,
	'd': 13,
	'e': 14,
	'f': 15,
}

func main() {
	var input string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	c := convertHex2BigInt(input)
	fmt.Println(c)
}

func convertHex2BigInt(hex string) *big.Int {
	c := big.NewInt(0)
	for i := len(hex) - 1; i >= 0; i-- {
		sixteenExp := new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(len(hex)-i-1)), nil)
		c.Add(c, new(big.Int).Mul(sixteenExp, big.NewInt(hexConvertion[hex[i]])))
	}
	return c
}
