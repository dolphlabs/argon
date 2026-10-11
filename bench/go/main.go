package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	iterations = 20
	memoryKiB  = 19456
	timeCost   = 2
	parallel   = 1
	tagBytes   = 32
)

var (
	password = []byte("benchmark-password")
	salt     = []byte("bench-salt-12345")
)

func hashWithSalt(password, salt []byte, m, t, p uint32) []byte {
	return argon2.IDKey(password, salt, t, m, uint8(p), tagBytes)
}

func hashPassword(password []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	tag := hashWithSalt(password, salt, memoryKiB, timeCost, parallel)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memoryKiB, timeCost, parallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(tag)), nil
}

func verify(password []byte, encoded string) (bool, error) {
	if len(encoded) == 0 || len(encoded) > 512 {
		return false, fmt.Errorf("invalid PHC size")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, fmt.Errorf("invalid PHC format")
	}
	costs := strings.Split(parts[3], ",")
	if len(costs) != 3 || !strings.HasPrefix(costs[0], "m=") ||
		!strings.HasPrefix(costs[1], "t=") || !strings.HasPrefix(costs[2], "p=") {
		return false, fmt.Errorf("invalid PHC costs")
	}
	m, err := strconv.ParseUint(strings.TrimPrefix(costs[0], "m="), 10, 32)
	if err != nil || m < 8 || m > 262144 {
		return false, fmt.Errorf("memory outside benchmark limits")
	}
	t, err := strconv.ParseUint(strings.TrimPrefix(costs[1], "t="), 10, 32)
	if err != nil || t < 1 || t > 10 {
		return false, fmt.Errorf("iterations outside benchmark limits")
	}
	p, err := strconv.ParseUint(strings.TrimPrefix(costs[2], "p="), 10, 32)
	if err != nil || p < 1 || p > 4 || m < 8*p {
		return false, fmt.Errorf("parallelism outside benchmark limits")
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 ||
		base64.RawStdEncoding.EncodeToString(salt) != parts[4] {
		return false, fmt.Errorf("invalid salt")
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 ||
		base64.RawStdEncoding.EncodeToString(want) != parts[5] {
		return false, fmt.Errorf("invalid tag")
	}
	got := argon2.IDKey(password, salt, uint32(t), uint32(m), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func sample(label string, f func() error) {
	values := make([]int64, 0, iterations)
	startedBatch := time.Now()
	for i := 0; i < iterations; i++ {
		started := time.Now()
		if err := f(); err != nil {
			panic(err)
		}
		values = append(values, time.Since(started).Nanoseconds())
	}
	batch := time.Since(startedBatch).Nanoseconds()
	fmt.Printf("B %s %d\n", label, batch)
	for _, ns := range values {
		fmt.Printf("%s %d\n", label, ns)
	}
}

func main() {
	raw := hashWithSalt(password, salt, memoryKiB, timeCost, parallel)
	fmt.Printf("RAW %s\n", hex.EncodeToString(raw))
	token, err := hashPassword(password)
	if err != nil {
		panic(err)
	}
	if ok, err := verify(password, token); err != nil || !ok {
		panic("verification setup failed")
	}
	checksum := 0

	sample("R", func() error {
		got := hashWithSalt(password, salt, memoryKiB, timeCost, parallel)
		checksum += int(got[0])
		return nil
	})
	sample("H", func() error {
		encoded, err := hashPassword(password)
		checksum += len(encoded)
		return err
	})
	sample("V", func() error {
		ok, err := verify(password, token)
		if err != nil || !ok {
			return fmt.Errorf("verification failed: %v", err)
		}
		checksum++
		return nil
	})
	fmt.Printf("C %d\n", checksum)
}
