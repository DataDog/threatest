package guardduty

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
)

type GuardDutyAPI interface {
	ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(options *guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(options *guardduty.Options)) (*guardduty.ListFindingsOutput, error)
	GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(options *guardduty.Options)) (*guardduty.GetFindingsOutput, error)
	ArchiveFindings(context.Context, *guardduty.ArchiveFindingsInput, ...func(options *guardduty.Options)) (*guardduty.ArchiveFindingsOutput, error)
}
