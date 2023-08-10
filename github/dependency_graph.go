package github

import (
	"context"
	"fmt"
	"time"
)

type DependencyService service

type Sbom struct {
	Sbom *SbomInfo `json:"sbom,omitempty"`
}

type CreationInfo struct {
	Created  *time.Time `json:"created,omitempty"`
	Creators []*string  `json:"creators,omitempty"`
}

type RepoDependencies struct {
	Spdxid           *string `json:"SPDXID,omitempty"`
	Name             *string `json:"name,omitempty"`
	VersionInfo      *string `json:"versionInfo,omitempty"`
	DownloadLocation *string `json:"downloadLocation,omitempty"`
	FilesAnalyzed    *bool   `json:"filesAnalyzed,omitempty"`
	LicenseConcluded *string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  *string `json:"licenseDeclared,omitempty"`
}

type SbomInfo struct {
	Spdxid            *string             `json:"SPDXID,omitempty"`
	SpdxVersion       *string             `json:"spdxVersion,omitempty"`
	CreationInfo      *CreationInfo       `json:"creationInfo,omitempty"`
	Name              *string             `json:"name,omitempty"`
	DataLicense       *string             `json:"dataLicense,omitempty"`
	DocumentDescribes []*string           `json:"documentDescribes,omitempty"`
	DocumentNamespace *string             `json:"documentNamespace,omitempty"`
	Packages          []*RepoDependencies `json:"packages,omitempty"`
}

// GetSbom fetches the Software bill of materials for a repository.
//
// GitHub API docs: https://docs.github.com/en/rest/dependency-graph/sboms
func (s *DependencyService) GetSbom(ctx context.Context, owner string, repo string) (*Sbom, *Response, error) {
	u := fmt.Sprintf("repos/%s/%s/dependency-graph/sbom", owner, repo)

	req, err := s.client.NewRequest("GET", u, nil)
	if err != nil {
		return nil, nil, err
	}

	var sbom *Sbom
	resp, err := s.client.Do(ctx, req, &sbom)
	if err != nil {
		return nil, resp, err
	}

	return sbom, resp, nil
}
