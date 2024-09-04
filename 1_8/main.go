package main

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
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
		fmt.Println("expect:", "746865206b696420646f6e277420706c6179")
		fmt.Printf("result: %x\n", result)
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

	{ // Challenge 3
		input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
		decoded := hex_decode(input)
		result, _ := byte_attack(decoded)

		fmt.Printf(":: Challenge 3 ::\n\n")
		fmt.Println("result:", result)
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

	{ // Challenge 4
		file, err := os.ReadFile("./input_challenge_4.txt")
		if err != nil {
			log.Fatal(err)
		}

		bestScore := math.MaxFloat64
		bestResult := ""
		input := strings.Fields(string(file))
		for _, line := range input {
			decoded := hex_decode(line)
			result, _ := byte_attack(decoded)
			score := score_string(result)
			if score < bestScore {
				bestScore = score
				bestResult = result
			}
		}

		fmt.Printf(":: Challenge 4 ::\n\n")
		fmt.Print("result: ", bestResult)
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

	{ // Challenge 5
		input := "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"

		key := []byte("ICE")
		keyRotationBookkeeping := 0
		result := make([]byte, len(input))

		for i, letter := range input {
			result[i] = byte(letter) ^ key[keyRotationBookkeeping]
			if keyRotationBookkeeping == len(key)-1 {
				keyRotationBookkeeping = 0
			} else {
				keyRotationBookkeeping++
			}
		}

		fmt.Printf(":: Challenge 5 ::\n\n")
		fmt.Println("expect:", "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
		fmt.Printf("result: %x\n", result)
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}

	{ // Challenge 6
		file, err := os.ReadFile("./input_challenge_6.txt")
		if err != nil {
			log.Fatal(err)
		}

		input, err := b64.StdEncoding.DecodeString(string(file))
		if err != nil {
			log.Fatal(err)
		}

		smallestScore := math.MaxInt
		mostProbableKeySize := 0

		for KEYSIZE := 2; KEYSIZE <= 40; KEYSIZE++ {
			result := 0

			for position := 0; position < 20*KEYSIZE; position += KEYSIZE {
				result += hamming_distance(input[position:position+KEYSIZE], input[position+KEYSIZE:position+2*KEYSIZE])
			}

			score := result / KEYSIZE

			if score < smallestScore {
				smallestScore = score
				mostProbableKeySize = KEYSIZE
			}
		}

		blocks := make([][]byte, 0)
		{ // Partition original input into lines of length KEYSIZE - done for the best candidate key size
			bookmark := 0
			howManyPartitions := int(math.Ceil((float64(len(input)) / float64(mostProbableKeySize))))

			for partition := range howManyPartitions {
				line := make([]byte, 0)

				switch {
				case partition == howManyPartitions-1:
					line = input[bookmark:]
				default:
					line = input[bookmark : bookmark+mostProbableKeySize]
					bookmark = bookmark + mostProbableKeySize
				}
				blocks = append(blocks, line)
			}
		}

		tableTransposed := make([][]byte, 0)
		{ // Transpose set to calulate histograms of original columns

			for longColumnPosition := range len(blocks[len(blocks)-1]) {
				columnTransposed := make([]byte, len(blocks))

				for columnLevel := range len(blocks) {
					columnTransposed[columnLevel] = blocks[columnLevel][longColumnPosition]
				}
				tableTransposed = append(tableTransposed, columnTransposed)
			}

			if len(blocks[0]) != len(blocks[len(blocks)-1]) {
				for shortColumnPosition := len(blocks[len(blocks)-1]); shortColumnPosition <= len(blocks[0])-1; shortColumnPosition++ {
					columnTransposed := make([]byte, len(blocks)-1)

					for columnLevel := range len(blocks) - 1 {
						columnTransposed[columnLevel] = blocks[columnLevel][shortColumnPosition]
					}
					tableTransposed = append(tableTransposed, columnTransposed)
				}
			}
		}

		finalKey := make([]byte, 0)
		{ // Calculate histograms
			decryptedKey := make([]byte, 0)
			for _, transposedColumn := range tableTransposed {
				_, keyChar := byte_attack(transposedColumn)
				decryptedKey = append(decryptedKey, keyChar)
			}
			finalKey = decryptedKey
		}

		keyRotationBookkeeping := 0
		result := make([]byte, len(input))

		for i, letter := range input {
			result[i] = byte(letter) ^ finalKey[keyRotationBookkeeping]
			if keyRotationBookkeeping == len(finalKey)-1 {
				keyRotationBookkeeping = 0
			} else {
				keyRotationBookkeeping++
			}
		}

		fmt.Printf(":: Challenge 6 ::\n\n")
		fmt.Println("found key:", string(finalKey))
		// fmt.Println("decrypted file:")
		// fmt.Println(string(result))
		fmt.Println("---------------------------------------------------------------------------------------------------------------")
	}
}

func hamming_distance(input, compare []byte) int {
	if len(input) != len(compare) {
		log.Fatal("Strings inputs for hamming distance calculation differ in size.")
	}

	difference := 0
	for i := range input {
		for xored := input[i] ^ compare[i]; xored != 0; xored &= xored - 1 {
			difference++
		}
	}

	return difference
}

func encrypt_with_repeating_key(input string, key string) {
	keyBytes := []byte(key)
	keyRotationBookkeeping := 0
	result := make([]byte, len(input))

	for i, letter := range input {
		result[i] = byte(letter) ^ keyBytes[keyRotationBookkeeping]
		if keyRotationBookkeeping == 2 {
			keyRotationBookkeeping = 0
		} else {
			keyRotationBookkeeping++
		}
	}

	printable := fmt.Sprintf("%x", result)
	whenToNewLine := 0
	everyTwoLetterBreak := 0

	for _, letter := range printable {
		fmt.Print(string(letter))
		if everyTwoLetterBreak%2 == 1 {
			fmt.Print(" ")
		}
		whenToNewLine++
		if whenToNewLine == (len(key))*2 {
			fmt.Println()
			whenToNewLine = 0
		}
		everyTwoLetterBreak++
	}
}

func byte_attack(input []byte) (string, byte) {
	letterScores := make([]float64, 26)
	realWorldProbabilities := []float64{0.117, 0.44, 0.52, 0.32, 0.28, 0.4, 0.16, 0.42, 0.73, 0.051, 0.086, 0.24, 0.38, 0.23, 0.76, 0.43, 0.022, 0.28, 0.67, 0.16, 0.12, 0.082, 0.55, 0.0045, 0.076, 0.0045}

	xored := make([]byte, len(input))
	bestResult := make([]byte, len(input))
	bestPreviousScore := math.MaxFloat64
	keyChar := byte(0)
	for charByte := byte(0); ; charByte++ {
		// 1. XOR input with every possible byte value.
		// 2. Penalize results that are not valid character.
		// 3. Compare distribution of XORed values with letter probabillity for english and note the difference.
		// 4. The smaller the final score, the better the result.

		finalScore := 0.0

		for i, decodedByte := range input {
			xored[i] = decodedByte ^ charByte

			switch {
			case int(xored[i]) >= 65 && int(xored[i]) <= 90:
				letterScores[int(xored[i])-65] += 1
			case int(xored[i]) >= 97 && int(xored[i]) <= 122:
				letterScores[int(xored[i])-97] += 1
			case int(xored[i]) == 32:
			case slices.Contains([]int{33, 39, 44, 45, 46, 58, 59, 96}, int(xored[i])): // check if byte represent space or interpunction signs
				finalScore += 1 // arbitrary tuning to penalize interpunction slightly; needed in case input include many interpunction signs, e.x. "Onv!ui`u!uid!q`sux!hr!ktlqhof"
			default:
				finalScore += 100
			}
		}

		for i, val := range letterScores {
			if val == 0 {
				continue
			}

			finalScore += math.Abs(realWorldProbabilities[i] - val/float64(len(xored)))
		}

		if finalScore < bestPreviousScore {
			bestPreviousScore = finalScore
			bestResult = slices.Clone(xored)
			keyChar = charByte
		}

		if charByte == byte(255) {
			break
		}
	}

	return string(bestResult), keyChar
}

func score_string(input string) float64 {
	letterScores := make([]float64, 26)
	realWorldProbabilities := []float64{0.117, 0.44, 0.52, 0.32, 0.28, 0.4, 0.16, 0.42, 0.73, 0.051, 0.086, 0.24, 0.38, 0.23, 0.76, 0.43, 0.022, 0.28, 0.67, 0.16, 0.12, 0.082, 0.55, 0.0045, 0.076, 0.0045}

	// 1. XOR input with every possible byte value.
	// 2. Penalize results that are not valid character.
	// 3. Compare distribution of XORed values with letter probabillity for english and note the difference.
	// 4. The smaller the final score, the better the result.

	finalScore := 0.0

	for _, char := range input {

		switch {
		case char >= 65 && char <= 90:
			letterScores[char-65] += 1
		case int(char) >= 97 && int(char) <= 122:
			letterScores[int(char)-97] += 1
		case int(char) == 32:
		case slices.Contains([]int{33, 39, 44, 45, 46, 58, 59, 96}, int(char)): // check if byte represent space or interpunction signs
			finalScore += 0.5 // arbitrary tuning to penalize interpunction slightly; needed in case input include many interpunction signs, e.x. "Onv!ui`u!uid!q`sux!hr!ktlqhof"
		default:
			finalScore += 10
		}
	}

	for i, val := range letterScores {
		if val == 0 {
			continue
		}

		finalScore += math.Abs(realWorldProbabilities[i] - val/float64(len(input)))
	}

	return finalScore
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
