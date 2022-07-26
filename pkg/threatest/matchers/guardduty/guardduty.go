package guardduty

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"log"
	"os"
	"strings"
	"time"
)

// AlertGeneratedMatcher is an interface that every integration should implement to verify whether an expected
// security alert was created
type AlertGeneratedMatcher interface {
	// HasExpectedAlert verifies on a third-party service whether an alert was properly generated for the given detonation UUID
	HasExpectedAlert(uuid string) (bool, error)

	// String returns the textual, user-friendly representation of the matcher
	String() string

	// Cleanup closes the generated alerts of a given detonation on a third-party service
	Cleanup(uuid string) error
}

type GuardDutyFindingFilter struct {
	FindingType    string
	DetonationTime time.Time
}

func (m *GuardDutyFindingFilter) Matches(finding types.Finding) bool {
	if finding.Type == nil || m.FindingType != *finding.Type {
		return false
	}

	// If the field 'service.eventLastSeen' is present, it should be within 2 minutes of the actual detonation
	// Note: We cannot filter by this field when querying findings
	if finding.Service != nil {
		if lastSeen := finding.Service.EventLastSeen; lastSeen != nil {
			const dateTimeFormat = "2006-01-02T15:04:05.000Z"
			lastSeenTime, err := time.Parse(dateTimeFormat, *lastSeen)
			if err == nil && (lastSeenTime.Before(m.DetonationTime.Add(-5*time.Minute)) || lastSeenTime.After(m.DetonationTime.Add(5*time.Minute))) {
				return false
			}
		}
	}
	return true
}

type GuardDutyMatcher struct {
	guardDuty          GuardDutyAPI
	detectorId         string
	currentAccessKeyId string
	Filter             GuardDutyFindingFilter
}

func GuardDutyFinding(findingType string) *GuardDutyMatcher {
	matcher, err := NewGuardDutyMatcher(findingType)
	if err != nil {
		fmt.Println(err)
		os.Exit(1) //TODO: How can we make it better?
		return nil
	}
	return matcher
}

func NewGuardDutyMatcher(findingType string) (*GuardDutyMatcher, error) {
	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AWS config in GuardDuty matcher: %v", err)
	}

	matcher := &GuardDutyMatcher{
		guardDuty: guardduty.NewFromConfig(awsConfig),
		Filter: GuardDutyFindingFilter{
			FindingType: findingType,
		},
	}
	if err := matcher.init(); err != nil {
		return nil, fmt.Errorf("unable to initialize GuardDuty matcher: %v", err)
	}

	return matcher, nil
}

func (m *GuardDutyMatcher) init() error {
	detectors, err := m.guardDuty.ListDetectors(context.Background(), &guardduty.ListDetectorsInput{})
	if err != nil {
		return fmt.Errorf("unable to list detectors: %v", err)
	}
	if numDetectors := len(detectors.DetectorIds); numDetectors == 0 {
		return fmt.Errorf("no GuardDuty detector found in current region - is GuardDuty enabled")
	} else if numDetectors > 1 {
		return fmt.Errorf("unexpected case: multiple GuardDuty detectors found in current region")
	}

	m.detectorId = detectors.DetectorIds[0]
	log.Println("Using detector " + m.detectorId)
	m.Filter.DetonationTime = time.Now()
	return nil
}

func (m *GuardDutyMatcher) HasExpectedAlert(string) (bool, error) {
	findingIds, err := m.getFindingIds()
	if err != nil {
		return false, err
	}

	if len(findingIds) == 0 {
		return false, nil
	}

	findings, err := m.guardDuty.GetFindings(context.Background(), &guardduty.GetFindingsInput{
		DetectorId: aws.String(m.detectorId),
		FindingIds: findingIds,
	})
	if err != nil {
		return false, fmt.Errorf("unable to retrieve GuardDuty findings: %v", err)
	}

	for _, finding := range findings.Findings {
		if m.Filter.Matches(finding) {
			return true, nil
		}
	}

	return false, nil
}

func (m *GuardDutyMatcher) Cleanup(string) error {
	findingIds, err := m.getFindingIds()
	if err != nil {
		return fmt.Errorf("unable to list guardduty findings: %v", err)
	}

	log.Printf("Archiving GuardDuty findings " + strings.Join(findingIds, ", "))
	_, err = m.guardDuty.ArchiveFindings(context.Background(), &guardduty.ArchiveFindingsInput{
		DetectorId: aws.String(m.detectorId),
		FindingIds: findingIds,
	})
	if err != nil {
		return fmt.Errorf("unable to archive findings: %v", err)
	}
	return nil
}

func (m *GuardDutyMatcher) getFindingIds() ([]string, error) {
	criteria := &types.FindingCriteria{
		Criterion: map[string]types.Condition{
			"service.archived": {Equals: []string{"false"}},
			"updatedAt":        {GreaterThan: time.Now().Add(-2 * time.Hour).Unix()},
			"type":             {Equals: []string{m.Filter.FindingType}},
		},
	}
	findingIds, err := m.guardDuty.ListFindings(context.Background(), &guardduty.ListFindingsInput{
		DetectorId:      aws.String(m.detectorId),
		FindingCriteria: criteria,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list GuardDuty findings: %v", err)
	}

	return findingIds.FindingIds, nil
}

func (m *GuardDutyMatcher) String() string {
	return fmt.Sprintf("GuardDuty finding '%s'", "foo")
}
