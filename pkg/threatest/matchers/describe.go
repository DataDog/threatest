package matchers

import "fmt"

var eventSummaryKeys = []string{"message", "eventName", "eventSource", "service", "status", "host", "awsRegion", "title"}

func DescribeEvent(e ThreatestEvent) string {
	for _, k := range eventSummaryKeys {
		if v, ok := e.Attributes[k]; ok {
			return fmt.Sprintf("%s=%v", k, v)
		}
	}
	raw := string(e.Body)
	if len(raw) > 200 {
		raw = raw[:200]
	}
	return raw
}
