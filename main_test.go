package main

import (
	"math"
	"strconv"
	"testing"
)

func TestFloatEnvRejectsNonFiniteValues(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-Inf"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TEST_FLOAT", value)
			if _, err := floatEnv("TEST_FLOAT", 1); err == nil {
				t.Fatalf("floatEnv accepted %q", value)
			}
		})
	}
}

func TestBoolEnvIsStrict(t *testing.T) {
	t.Setenv("TEST_BOOL", "not-a-bool")
	if _, err := boolEnv("TEST_BOOL", false); err == nil {
		t.Fatal("boolEnv accepted an invalid value")
	}
}

func TestContainerIdentityEnvRequiresPositiveIntegers(t *testing.T) {
	for _, value := range []string{"0", "-1", "not-an-id"} {
		t.Setenv("TEST_ID", value)
		if _, err := intEnv("TEST_ID", 65532); err == nil {
			t.Fatalf("intEnv accepted container id %q", value)
		}
	}
}

func TestBoundedIntEnvRejectsPortOverflow(t *testing.T) {
	for _, value := range []string{"0", "65536", "9223372036854775807"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TEST_PORT", value)
			if _, err := boundedIntEnv("TEST_PORT", 8080, 65535); err == nil {
				t.Fatalf("boundedIntEnv accepted port %q", value)
			}
		})
	}
	t.Setenv("TEST_PORT", "65535")
	if got, err := boundedIntEnv("TEST_PORT", 8080, 65535); err != nil || got != 65535 {
		t.Fatalf("max port = %d err=%v", got, err)
	}
}

func TestBoundedIntEnvRejectsPlatformIntOverflow(t *testing.T) {
	if strconv.IntSize == 32 {
		t.Setenv("TEST_QUEUE", "2147483648")
		if _, err := boundedIntEnv("TEST_QUEUE", 8, math.MaxInt); err == nil {
			t.Fatal("boundedIntEnv accepted a value above 32-bit int")
		}
		return
	}
	// Exercise the same bound check on a 64-bit builder with a smaller policy
	// ceiling; values above MaxInt64 are already rejected by strconv.ParseInt.
	t.Setenv("TEST_QUEUE", "9")
	if _, err := boundedIntEnv("TEST_QUEUE", 8, 8); err == nil {
		t.Fatal("boundedIntEnv accepted a value above its integer ceiling")
	}
}
