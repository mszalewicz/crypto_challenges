package main

import (
	"fmt"
	"log"
	"math/big"
	"slices"
	"strconv"
	"strings"
)

func main() {

	{ // Challenge 1
		challenge1Input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

		binaryRepresentation := hex_decode(challenge1Input)
		base64Representation := base64_encode(binaryRepresentation)

		fmt.Println("---------------------------------------------------------------------------------------------------------------")
		fmt.Printf(":: Challenge 1 ::\n\n")
		fmt.Println("expect:", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
		fmt.Println("result:", base64Representation)
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

	{ // Challenge 2
		input1 := "1c0111001f010100061a024b53535009181c"
		input2 := "686974207468652062756c6c277320657965"

		bin1 := hex_decode(input1)
		bin2 := hex_decode(input2)

		var result []byte

		for i := range len(bin1) {
			result = append(result, bin1[i]^bin2[i])
		}

		fmt.Printf(":: Challenge 2 ::\n\n")
		fmt.Println("expect:", base64_encode(hex_decode("746865206b696420646f6e277420706c6179")))
		fmt.Println("result:", base64_encode(result))
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

}

func hex_decode(input string) []byte {
	if len(input)%2 != 0 {
		log.Fatal("Provided hex string has odd length. Please provide valid hex string.")
	}

	conversion := "0123456789abcdef"

	var number []byte
	for i := 0; i < len(input)-1; i += 2 {
		number = append(number, byte(strings.Index(conversion, string(input[i])))<<4|byte(strings.Index(conversion, string(input[i+1]))))
	}
	return number
}

func base64_encode(input []byte) string {
	conversion := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	index := 0
	result := ""
	if len(input) >= 3 {
		for i := 0; i < len(input)-2; i += 3 {
			index = int(input[i] >> 2)
			result += string(conversion[index])

			index = int(((input[i] << 6) >> 2) | (input[i+1] >> 4))
			result += string(conversion[index])

			index = int(((input[i+1] << 4) >> 2) | (input[i+2] >> 6))
			result += string(conversion[index])

			index = int((input[i+2] << 2) >> 2)
			result += string(conversion[index])
		}
	}
	return result
}

func convertHex2BigInt(hex string) *big.Int {
	var hexConversionTable = map[byte]int64{'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}

	c := big.NewInt(0)
	for i := len(hex) - 1; i >= 0; i-- {
		sixteenExp := new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(len(hex)-i-1)), nil)
		c.Add(c, new(big.Int).Mul(sixteenExp, big.NewInt(hexConversionTable[hex[i]])))
	}
	return c
}

func convertBigInt2Base64(number *big.Int) string {
	var base64ConversionTable = map[int]string{0: "A", 1: "B", 2: "C", 3: "D", 4: "E", 5: "F", 6: "G", 7: "H", 8: "I", 9: "J", 10: "K", 11: "L", 12: "M", 13: "N", 14: "O", 15: "P", 16: "Q", 17: "R", 18: "S", 19: "T", 20: "U", 21: "V", 22: "W", 23: "X", 24: "Y", 25: "Z", 26: "a", 27: "b", 28: "c", 29: "d", 30: "e", 31: "f", 32: "g", 33: "h", 34: "i", 35: "j", 36: "k", 37: "l", 38: "m", 39: "n", 40: "o", 41: "p", 42: "q", 43: "r", 44: "s", 45: "t", 46: "u", 47: "v", 48: "w", 49: "x", 50: "y", 51: "z", 52: "0", 53: "1", 54: "2", 55: "3", 56: "4", 57: "5", 58: "6", 59: "7", 60: "8", 61: "9", 62: "+", 63: "/"}

	var (
		reminders []big.Int
		quotient  big.Int
		tmp       big.Int  = *number
		z         *big.Int = &tmp
		result    string   = ""
	)

	for {
		m := big.NewInt(0)
		z.DivMod(z, big.NewInt(64), m)
		quotient = *z
		reminders = append(reminders, *m)

		if z.Cmp(big.NewInt(64)) == -1 {
			break
		}
	}

	result += string(base64ConversionTable[int(quotient.Uint64())])

	for _, val := range slices.Backward(reminders) {
		convertedInt, err := strconv.Atoi(val.String())
		if err != nil {
			log.Fatal(err)
		}
		result += string(base64ConversionTable[convertedInt])
	}

	return result
}
