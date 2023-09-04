package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	frontierv1beta1 "github.com/raystack/frontier/proto/v1beta1"
	"net/http"
	"net/url"
	"strings"
)

// CheckAccess uses frontier api to check if user has access to perform action on resource
func CheckAccess(ctx context.Context, client HTTPClient, frontierHost *url.URL, headers http.Header,
	resourceID string, permission string) (bool, error) {
	requestBodyBytes, err := json.Marshal(&frontierv1beta1.CheckResourcePermissionRequest{
		Resource:   resourceID,
		Permission: permission,
	})
	if err != nil {
		return false, err
	}

	// send the request to auth server
	checkAccessRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		frontierHost.ResolveReference(&url.URL{Path: CheckAccessPath}).String(),
		bytes.NewBuffer(requestBodyBytes),
	)
	if err != nil {
		return false, err
	}
	checkAccessRequest.Header = headers
	resp, err := client.Do(checkAccessRequest)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// check if action allowed
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	checkRequestResponse := &frontierv1beta1.CheckResourcePermissionResponse{}
	if err := json.NewDecoder(resp.Body).Decode(checkRequestResponse); err != nil {
		return false, err
	}
	return checkRequestResponse.Status, nil
}

// SplitResourceID splits resourceID into namespace and id
func SplitResourceID(resourceID string) (string, string) {
	split := strings.Split(resourceID, ":")
	if len(split) != 2 {
		return "", ""
	}
	return split[0], split[1]
}
