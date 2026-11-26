package logclassify

import (
	"context"
	"fmt"
	"sort"
)

// Engine runs commercial-grade multi-layer log classification using OWASP Coraza WAF v3 + CRS v4,
// embedded SigmaHQ-standard Sigma rules, and batch IP/service behavioral burst correlation.
type Engine struct {
	coraza *corazaInspector
	sigma  *sigmaInspector
}

// NewEngine initializes the embedded Coraza WAF + OWASP CRS v4 and Sigma rule engine.
func NewEngine() (*Engine, error) {
	cor, err := newCorazaInspector()
	if err != nil {
		return nil, err
	}
	sig, err := newSigmaInspector()
	if err != nil {
		return nil, err
	}
	return &Engine{
		coraza: cor,
		sigma:  sig,
	}, nil
}

// Info returns metadata about the initialized rule engine.
func (e *Engine) Info() RuleEngineInfo {
	sigmaCount := 0
	if e != nil && e.sigma != nil {
		sigmaCount = e.sigma.count()
	}
	return RuleEngineInfo{
		CorazaVersion:  "v3",
		CRSVersion:     "OWASP CRS v4.25.0",
		SigmaRules:     sigmaCount,
		BurstDetection: true,
	}
}

// ClassifyBatch evaluates all entries concurrently-safely across OWASP CRS v4, Sigma, and burst rules,
// stopping early if ctx is canceled.
func (e *Engine) ClassifyBatch(ctx context.Context, entries []LogEntry) ([]RuleResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	bursts := correlateBursts(entries)
	results := make([]RuleResult, len(entries))

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var matches []RuleMatch
		if e != nil && e.coraza != nil {
			matches = append(matches, e.coraza.inspect(entry)...)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e != nil && e.sigma != nil {
			matches = append(matches, e.sigma.inspect(entry)...)
		}
		if bMatches, ok := bursts[i]; ok {
			matches = append(matches, bMatches...)
		}
		results[i] = finalizeRuleResult(matches)
	}
	return results, nil
}

func finalizeRuleResult(rawMatches []RuleMatch) RuleResult {
	if len(rawMatches) == 0 {
		return RuleResult{
			Verdict:  VerdictClean,
			Category: CategoryClean,
			Score:    0,
		}
	}

	dedup := make(map[string]RuleMatch, len(rawMatches))
	for _, m := range rawMatches {
		key := m.Engine + ":" + m.RuleID
		if prev, exists := dedup[key]; !exists || m.weight > prev.weight {
			dedup[key] = m
		}
	}

	unique := make([]RuleMatch, 0, len(dedup))
	totalScore := 0
	maxRank := 0
	engineSet := make(map[string]struct{}, 3)
	for _, m := range dedup {
		unique = append(unique, m)
		totalScore += m.weight
		if r := severityRank(m.Severity); r > maxRank {
			maxRank = r
		}
		engineSet[m.Engine] = struct{}{}
	}

	sort.Slice(unique, func(i, j int) bool {
		a, b := unique[i], unique[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.weight != b.weight {
			return a.weight > b.weight
		}
		if ea, eb := engineRank(a.Engine), engineRank(b.Engine); ea != eb {
			return ea > eb
		}
		if ca, cb := categoryPriority(a.Category), categoryPriority(b.Category); ca != cb {
			return ca > cb
		}
		return a.RuleID < b.RuleID
	})

	topCategory := pickTopCategory(unique)
	if len(unique) > maxMatchesPerEntry {
		unique = unique[:maxMatchesPerEntry]
	}

	verdict := verdictFromScoreAndSeverity(maxRank, totalScore)
	engines := make([]string, 0, len(engineSet))
	for _, eng := range []string{EngineOWASPCRS, EngineSigma, EngineBurst} {
		if _, ok := engineSet[eng]; ok {
			engines = append(engines, eng)
		}
	}

	return RuleResult{
		Verdict:  verdict,
		Category: topCategory,
		Score:    totalScore,
		Engines:  engines,
		Matches:  unique,
	}
}

func pickTopCategory(matches []RuleMatch) string {
	type catStat struct {
		totalWeight int
		maxSev      int
		maxEngine   int
	}
	stats := make(map[string]*catStat, len(matches))
	for _, m := range matches {
		st, ok := stats[m.Category]
		if !ok {
			st = &catStat{}
			stats[m.Category] = st
		}
		st.totalWeight += m.weight
		if sr := severityRank(m.Severity); sr > st.maxSev {
			st.maxSev = sr
		}
		if er := engineRank(m.Engine); er > st.maxEngine {
			st.maxEngine = er
		}
	}
	bestCat := matches[0].Category
	best := stats[bestCat]
	for cat, st := range stats {
		if st.maxSev != best.maxSev {
			if st.maxSev > best.maxSev {
				bestCat, best = cat, st
			}
			continue
		}
		if st.totalWeight != best.totalWeight {
			if st.totalWeight > best.totalWeight {
				bestCat, best = cat, st
			}
			continue
		}
		if st.maxEngine != best.maxEngine {
			if st.maxEngine > best.maxEngine {
				bestCat, best = cat, st
			}
			continue
		}
		if categoryPriority(cat) > categoryPriority(bestCat) {
			bestCat, best = cat, st
		}
	}
	return bestCat
}

func verdictFromScoreAndSeverity(maxSevRank, score int) string {
	switch {
	case maxSevRank >= 4 || score >= 8:
		return VerdictCritical
	case maxSevRank == 3 || score >= 6:
		return VerdictHigh
	case maxSevRank == 2 || score >= 3:
		return VerdictMedium
	case maxSevRank == 1 || score >= 1:
		return VerdictLow
	default:
		return VerdictClean
	}
}

// BuildSummary computes aggregate counts across a batch of classified log entries.
func BuildSummary(results []EntryClassification) ClassifySummary {
	summary := ClassifySummary{
		Total:      len(results),
		ByVerdict:  make(map[string]int),
		ByCategory: make(map[string]int),
		ByAmber:    make(map[string]int),
	}
	for _, r := range results {
		ruleFlagged := false
		amberFlagged := false
		if r.Rule != nil {
			summary.ByVerdict[r.Rule.Verdict]++
			summary.ByCategory[r.Rule.Category]++
			if r.Rule.Verdict != VerdictClean {
				summary.RuleFlagged++
				ruleFlagged = true
			}
		}
		if r.Amber != nil && r.Amber.Evaluated && r.Amber.Error == "" && r.Amber.Choice != "" {
			summary.ByAmber[r.Amber.Choice]++
			if r.Amber.Choice != "normal" {
				summary.AmberFlagged++
				amberFlagged = true
			}
		}
		if ruleFlagged || amberFlagged {
			summary.FlaggedTotal++
		}
	}
	return summary
}

// FormatClassificationMode validates and normalizes the classification mode parameter.
func FormatClassificationMode(raw string) (string, error) {
	switch raw {
	case "rules", "amber", "both":
		return raw, nil
	default:
		return "", fmt.Errorf("invalid classification mode %q (expected rules, amber, or both)", raw)
	}
}
