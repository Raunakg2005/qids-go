package qids

import (
	"errors"
	"math"
)

// SprtState represents the decision state of the sequential hypothesis test.
type SprtState int

const (
	SprtContinue SprtState = iota
	SprtAcceptH0
	SprtAcceptH1
)

func (s SprtState) String() string {
	switch s {
	case SprtContinue:
		return "CONTINUE"
	case SprtAcceptH0:
		return "ACCEPT_H0"
	case SprtAcceptH1:
		return "ACCEPT_H1"
	default:
		return "UNKNOWN"
	}
}

// SequentialTest implements the Wald Sequential Probability Ratio Test.
type SequentialTest struct {
	P0        float64
	P1        float64
	Alpha     float64
	Beta      float64
	LLR       float64
	NSamples  int
	NErrors   int
	State     SprtState
	StoppedAt int

	logErrRatio float64
	logOkRatio  float64
	upperBound  float64
	lowerBound  float64
}

// NewSequentialTest constructs a new SPRT detector.
func NewSequentialTest(p0, p1, alpha, beta float64) (*SequentialTest, error) {
	if !(0.0 <= p0 && p0 < p1 && p1 <= 1.0) {
		return nil, errors.New("requirement failed: 0.0 <= p0 < p1 <= 1.0")
	}
	if !(0.0 < alpha && alpha < 1.0 && 0.0 < beta && beta < 1.0) {
		return nil, errors.New("requirement failed: alpha and beta must be in (0, 1)")
	}

	q0 := math.Max(p0, 1e-6)
	q1 := math.Min(p1, 1.0-1e-6)

	logErr := math.Log(q1 / q0)
	logOk := math.Log((1.0 - q1) / (1.0 - q0))
	upper := math.Log((1.0 - beta) / alpha)
	lower := math.Log(beta / (1.0 - alpha))

	return &SequentialTest{
		P0:          p0,
		P1:          p1,
		Alpha:       alpha,
		Beta:        beta,
		LLR:         0.0,
		NSamples:    0,
		NErrors:     0,
		State:       SprtContinue,
		StoppedAt:   0,
		logErrRatio: logErr,
		logOkRatio:  logOk,
		upperBound:  upper,
		lowerBound:  lower,
	}, nil
}

// Update feeds a single observation (true = error, false = match).
func (t *SequentialTest) Update(isError bool) SprtState {
	if t.State != SprtContinue {
		return t.State
	}

	t.NSamples++
	if isError {
		t.NErrors++
		t.LLR += t.logErrRatio
	} else {
		t.LLR += t.logOkRatio
	}

	if t.LLR >= t.upperBound {
		t.State = SprtAcceptH1
		t.StoppedAt = t.NSamples
	} else if t.LLR <= t.lowerBound {
		t.State = SprtAcceptH0
		t.StoppedAt = t.NSamples
	}

	return t.State
}

// Feed processes an array of boolean error observations.
func (t *SequentialTest) Feed(errors []bool) SprtState {
	for _, err := range errors {
		if t.Update(err) != SprtContinue {
			break
		}
	}
	return t.State
}

// Reset clears accumulated test state for reuse.
func (t *SequentialTest) Reset() {
	t.LLR = 0.0
	t.NSamples = 0
	t.NErrors = 0
	t.State = SprtContinue
	t.StoppedAt = 0
}
