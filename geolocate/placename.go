package geolocate

import (
	"strings"
	"unicode"
)

// This file implements place-name matching: deciding whether two free
// geolocation sources describing the SAME ip are naming the same city or
// region, when they spell it differently.
//
// It exists because exact normalized string equality throws away real
// agreement. A probe of a German provider returned city "" from ip.pn,
// "Frankfurt am Main (Innenstadt I)" from freeipapi and "Frankfurt am Main"
// from ipinfo: two sources agreed on Frankfurt in substance, exact matching
// saw two different cities, and the whole city result was discarded.
//
// The matcher is deliberately small and lexical. It has no gazetteer, no
// geometry and no network access, and it must stay standard-library-only like
// the rest of this package.

// latinFoldGroups maps accented Latin letters to their ASCII skeleton. Each
// entry lists every (lowercase) rune that folds to the same replacement.
//
// This is an explicit table rather than Unicode normalization on purpose:
// golang.org/x/text is not available to this package, and full decomposition
// is far more machinery than the problem needs. The coverage target is
// Latin-1 Supplement and Latin Extended-A -- the letters that actually appear
// in European and Latin American place names these sources return
// (Logroño, Málaga, Zürich, São Paulo). Runes outside the table are
// left alone, so non-Latin scripts still compare exactly, which is safe: two
// sources spelling a city in the same script still match, they just do not
// get accent folding.
var latinFoldGroups = []struct{ from, to string }{
	{"àáâãäåāăą", "a"},
	{"æ", "ae"},
	{"çćĉċč", "c"},
	{"ďđ", "d"},
	{"èéêëēĕėęě", "e"},
	{"ĝğġģ", "g"},
	{"ĥħ", "h"},
	{"ìíîïĩīĭįı", "i"},
	{"ĳ", "ij"},
	{"ĵ", "j"},
	{"ķĸ", "k"},
	{"ĺļľŀł", "l"},
	{"ñńņňŉŋ", "n"},
	{"òóôõöøōŏő", "o"},
	{"œ", "oe"},
	{"ŕŗř", "r"},
	{"śŝşšſ", "s"},
	{"ß", "ss"},
	{"ţťŧ", "t"},
	{"ðþ", "th"},
	{"ùúûüũūŭůűų", "u"},
	{"ŵ", "w"},
	{"ýÿŷ", "y"},
	{"źżž", "z"},
}

var latinFold = func() map[rune]string {
	m := make(map[rune]string)
	for _, g := range latinFoldGroups {
		for _, r := range g.from {
			m[r] = g.to
		}
	}
	return m
}()

// stripParentheticals removes every parenthesized group and the parentheses
// themselves: "Frankfurt am Main (Innenstadt I)" -> "Frankfurt am Main ".
//
// Parenthesized text in these feeds is a qualifier -- a city district, a
// disambiguator, an abbreviation -- that only some sources emit, so it cannot
// participate in agreement. Nesting is tracked with a depth counter, an
// unclosed "(" swallows the rest of the string, and a stray ")" is dropped;
// none of those shapes panic or drop the un-parenthesized text before them.
func stripParentheticals(s string) string {
	if !strings.ContainsAny(s, "()") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if 0 < depth {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// PlaceTokens normalizes a place name into the token sequence used for
// matching: parentheticals stripped, case-folded to lower, accented Latin
// letters folded to ASCII, punctuation and separators turned into spaces,
// runs of whitespace collapsed. It returns nil for a name with no tokens.
//
// The tokens are for comparison only -- never for display. See PlaceDisplay.
func PlaceTokens(s string) []string {
	s = strings.ToLower(stripParentheticals(s))

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
			// A combining mark from a decomposed input ("n" + U+0303).
			// Drop it rather than treat it as a separator, which would
			// split one word into two tokens.
		case r < unicode.MaxASCII && ('a' <= r && r <= 'z' || '0' <= r && r <= '9'):
			b.WriteRune(r)
		default:
			if folded, ok := latinFold[r]; ok {
				b.WriteString(folded)
				continue
			}
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				b.WriteRune(r)
				continue
			}
			// Everything else -- "," "." "-" "/" "'" and any other
			// punctuation, symbol or space -- separates tokens.
			b.WriteByte(' ')
		}
	}
	tokens := strings.Fields(b.String())
	if len(tokens) == 0 {
		// Distinguish "no place named" from "one empty token": callers test
		// len() == 0, and a nil return makes that unambiguous.
		return nil
	}
	return tokens
}

// PlaceDisplay renders a place name for storage and display: parentheticals
// removed and whitespace collapsed, but casing and diacritics preserved
// ("Logroño" stays "Logroño", not "logrono").
//
// The parenthetical is dropped here too, not just in PlaceTokens, because it
// is the part of the name the agreeing sources did NOT corroborate: keeping
// "Frankfurt am Main (Innenstadt I)" as the stored name would assert a city
// district on the authority of a single source. The server canonicalizes and
// permanently stores whatever name is submitted, so that assertion would be
// durable.
func PlaceDisplay(s string) string {
	return strings.Join(strings.Fields(stripParentheticals(s)), " ")
}

// tokensPrefixOrEqual reports whether short is equal to, or a proper prefix
// of, long -- compared token by token, never by raw substring. Empty token
// sequences never match anything, including each other: a source that named
// no place cannot corroborate one that did.
func tokensPrefixOrEqual(short, long []string) bool {
	if len(short) == 0 || len(long) == 0 || len(long) < len(short) {
		return false
	}
	for i, tok := range short {
		if tok != long[i] {
			return false
		}
	}
	return true
}

// tokensMatch reports whether two token sequences describe the same place:
// they are equal, or one is a proper prefix of the other.
//
// Token-by-token prefixing is the entire safety property. It is what makes
// "Frankfurt" match "Frankfurt am Main" while "York" does NOT match
// "New York" (a suffix, not a prefix) and "Frank" does NOT match "Frankfurt"
// (a substring of a token, not a token). Sources are all describing one ip,
// so a shorter name that leads the longer one is read as the same place
// described less specifically -- not as a different place.
func tokensMatch(a, b []string) bool {
	return tokensPrefixOrEqual(a, b) || tokensPrefixOrEqual(b, a)
}

// PlaceNamesMatch reports whether two raw place names from different sources
// describe the same place. It is the exported form of tokensMatch; see there
// for the rule and its rationale.
func PlaceNamesMatch(a, b string) bool {
	return tokensMatch(PlaceTokens(a), PlaceTokens(b))
}
