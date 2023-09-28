package crypto

import (
	"errors"
	"math"

	"github.com/hashicorp/vault/shamir"
)

func KeySplit(ksType string, key []byte, numKs int) ([][]byte, error) {
	switch ksType {
	case "split":
		return xorSplit(key, numKs), nil
		// XOR Split
	case "shamir":
		return shamirSplit(key, numKs)
		// Shamir Split
	default:
		return nil, errors.New("unsupported key split type")
	}

}

func KeyMerge(ksType string, keySplits [][]byte) ([]byte, error) {
	switch ksType {
	case "split":
		return xorMerge(keySplits), nil
		// XOR Merge
	case "shamir":
		return shamirMerge(keySplits)
		// Shamir Merge
	default:
		return nil, errors.New("unsupported key split type")
	}
}

func shamirSplit(key []byte, splits int) ([][]byte, error) {
	var shares [][]byte
	threshold := math.Floor((float64(splits) * .75) + 0.5)
	if threshold < 2 {
		shares = append(shares, []byte(key))
		return shares, nil
	}
	// Need to do some checks around number of clients and thresholds
	shares, err := shamir.Split(key, splits, int(threshold))
	if err != nil {
		return nil, errors.Join(errors.New("failed to generate shmair shares from key"), err)
	}
	return shares, nil
}

func shamirMerge(splits [][]byte) ([]byte, error) {
	if len(splits) == 1 {
		return splits[0], nil
	}
	return shamir.Combine(splits)
}

func xorSplit(key []byte, splits int) [][]byte {
	keyLength := len(key)
	var keySplits [][]byte
	for i := 0; i < splits-1; i++ {
		nonce, _ := generateKey(keyLength)
		// XOR the keys together
		for i, b := range nonce {
			key[i] ^= b
		}
		keySplits = append(keySplits, nonce)
	}
	keySplits = append(keySplits, key)
	return keySplits
}

func xorMerge(splits [][]byte) []byte {
	var key = splits[0]
	for _, split := range splits[1:] {
		for i, b := range split {
			key[i] ^= b
		}
	}
	return key
}
