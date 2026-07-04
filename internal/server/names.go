package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Connect instances get random memorable subdomains like "crimson-fox-42".
// Random-only (no vanity claims) keeps lookalike phishing names
// (paypal.<host>) impossible by construction.

var nameAdjectives = []string{
	"amber", "azure", "bold", "brave", "bright", "brisk", "calm", "cedar",
	"clever", "cobalt", "copper", "coral", "crimson", "deep", "dusty",
	"eager", "early", "ember", "fleet", "gentle", "golden", "green",
	"hazel", "humble", "indigo", "iron", "ivory", "jade", "keen", "kind",
	"late", "lively", "lunar", "mellow", "misty", "noble", "north",
	"ochre", "olive", "opal", "pale", "plain", "proud", "quick", "quiet",
	"rapid", "rosy", "rustic", "sable", "sandy", "scarlet", "silent",
	"silver", "sleek", "solar", "spry", "steady", "stone", "swift",
	"tidal", "umber", "violet", "vivid", "warm", "wild",
}

var nameNouns = []string{
	"badger", "bear", "beetle", "bison", "crane", "crow", "deer",
	"dolphin", "eagle", "falcon", "ferret", "finch", "fox", "gull",
	"hare", "hawk", "heron", "hound", "ibis", "koala", "lark", "lemur",
	"llama", "lynx", "marten", "mole", "moose", "moth", "newt", "otter",
	"owl", "panda", "pika", "puffin", "quail", "rabbit", "raven",
	"robin", "salmon", "seal", "shrew", "sparrow", "stoat", "stork",
	"swan", "swift", "tapir", "tern", "toad", "trout", "turtle",
	"vole", "walrus", "weasel", "whale", "wolf", "wombat", "wren",
	"yak", "zebra",
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return int(v.Int64())
}

// randInt64 returns a crypto-random value in [0, n). Used for backoff jitter,
// where n is an int64 nanosecond duration that must not be narrowed to int
// (32-bit truncation could go negative and panic rand.Int). Returns 0 for
// n <= 0 rather than panicking.
func randInt64(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return v.Int64()
}

// randomInstanceName returns a name like "crimson-fox-42".
func randomInstanceName() string {
	return fmt.Sprintf("%s-%s-%d",
		nameAdjectives[randInt(len(nameAdjectives))],
		nameNouns[randInt(len(nameNouns))],
		randInt(90)+10)
}
