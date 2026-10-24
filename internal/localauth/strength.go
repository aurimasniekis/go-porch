package localauth

import (
	"math"
	"strings"
	"unicode/utf8"

	"github.com/trustelem/zxcvbn"

	"github.com/aurimasniekis/go-porch/internal/apperr"
)

// Pair is a recovery title and its answer.
type Pair struct {
	Title  string `json:"title"`
	Answer string `json:"answer"`
}

// StrengthPolicy bounds enrollment.
type StrengthPolicy struct {
	MinPairs         int
	MaxPairs         int
	MinPasswordLen   int
	MinPasswordScore int     // zxcvbn score 0..4
	MinCombinedLog10 float64 // zxcvbn log10(guesses) of password + answers together
	MinAnswersLog10  float64 // the answers alone (they are what protects a leaked password)
	MinAnswerRunes   int
	MaxTitleRunes    int
	MaxAnswerRunes   int
}

// DefaultStrength is the enrollment policy (ADR-0009).
var DefaultStrength = StrengthPolicy{MinPairs: 3, MaxPairs: 12, MinPasswordLen: 12, MinPasswordScore: 3, MinCombinedLog10: 14, MinAnswersLog10: 8,
	MinAnswerRunes: 3, MaxTitleRunes: 120, MaxAnswerRunes: 200}

// Estimate is the strength report shown to the user.
type Estimate struct {
	PasswordScore   int     `json:"password_score"`
	CombinedLog10   float64 `json:"combined_log10_guesses"`
	CombinedBitsEst float64 `json:"combined_bits_estimate"`
	Note            string  `json:"note"`
}

// CheckEnrollment validates a credential against the policy. userInputs (name, email, handle) count against strength.
func CheckEnrollment(p StrengthPolicy, password string, pairs []Pair, confirm []string, userInputs []string) (Estimate, error) {
	var v apperr.Validation
	if n := utf8.RuneCountInString(password); n < p.MinPasswordLen {
		v.Add("password", "must be at least %d characters", p.MinPasswordLen)
	}
	if len(pairs) < p.MinPairs || len(pairs) > p.MaxPairs {
		v.Add("pairs", "need %d..%d recovery answers", p.MinPairs, p.MaxPairs)
	}
	if len(confirm) != len(pairs) {
		v.Add("confirm", "re-type every answer to confirm")
	}
	canonPW := CanonicalAnswer(password)
	titles := map[string]bool{}
	answers := map[string]bool{}
	inputs := append([]string{}, userInputs...)
	for i, pr := range pairs {
		t := strings.TrimSpace(pr.Title)
		tn := utf8.RuneCountInString(t)
		if tn == 0 || tn > p.MaxTitleRunes {
			v.Add("pairs", "title %d must be 1..%d characters", i+1, p.MaxTitleRunes)
		}
		tc := CanonicalAnswer(t)
		if titles[tc] {
			v.Add("pairs", "title %d repeats another title", i+1)
		}
		titles[tc] = true
		a := CanonicalAnswer(pr.Answer)
		an := utf8.RuneCountInString(a)
		switch {
		case an < p.MinAnswerRunes || an > p.MaxAnswerRunes:
			v.Add("pairs", "answer %d must be %d..%d characters (punctuation is ignored)", i+1, p.MinAnswerRunes, p.MaxAnswerRunes)
		case answers[a]:
			v.Add("pairs", "answer %d repeats another answer", i+1)
		case a == tc || strings.Contains(tc, a):
			v.Add("pairs", "answer %d must not appear in its title", i+1)
		case canonPW != "" && (strings.Contains(canonPW, a) || strings.Contains(a, canonPW)):
			v.Add("pairs", "answer %d must not contain or be contained in the password", i+1)
		}
		answers[a] = true
		if i < len(confirm) && CanonicalAnswer(confirm[i]) != a {
			v.Add("confirm", "answer %d does not match its confirmation", i+1)
		}
		inputs = append(inputs, t)
	}
	if err := v.Err(); err != nil {
		return Estimate{}, err
	}
	pw := zxcvbn.PasswordStrength(password, inputs)
	// Each answer is estimated on its own (answers are independent), with every title and user attribute as known
	// context: an answer an attacker could derive from its hint should not count. Joining answers with spaces would
	// let zxcvbn score "red dog cat" as brute force.
	ansLog10 := 0.0
	for _, pr := range pairs {
		r := zxcvbn.PasswordStrength(CanonicalAnswer(pr.Answer), inputs)
		ansLog10 += math.Log10(math.Max(r.Guesses, 1))
	}
	l10 := math.Log10(math.Max(pw.Guesses, 1)) + ansLog10
	est := Estimate{PasswordScore: pw.Score, CombinedLog10: math.Round(l10*10) / 10, CombinedBitsEst: math.Round(l10*math.Log2(10)*10) / 10,
		Note: "Estimate only: answers you chose yourself are usually much weaker than random words."}
	if pw.Score < p.MinPasswordScore {
		v.Add("password", "is too guessable (strength %d/4, need %d)", pw.Score, p.MinPasswordScore)
	}
	if al := ansLog10; al < p.MinAnswersLog10 {
		v.Add("pairs", "the answers are too guessable on their own (≈%.0f bits, need ≈%.0f); use longer or less obvious answers, or the random-word suggestion",
			al*math.Log2(10), p.MinAnswersLog10*math.Log2(10))
	}
	if l10 < p.MinCombinedLog10 {
		v.Add("pairs", "password and answers together are too guessable (≈%.0f bits, need ≈%.0f); use longer or less obvious answers, or the random-word suggestion",
			est.CombinedBitsEst, p.MinCombinedLog10*math.Log2(10))
	}
	return est, v.Err()
}
