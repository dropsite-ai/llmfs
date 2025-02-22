package callbacks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	c "github.com/dropsite-ai/config"
	"github.com/dropsite-ai/llmfs/config"
)

// postToCallbackEndpoints sends the callback JSON to each endpoint defined in the callback’s .Endpoints array.
// If any fail for a PRE callback => we abort. For POST => we just record an error.
func postToCallbackEndpoints(cb c.CallbackDefinition, reqBody []byte) error {
	// Gather real URLs from the config:
	for _, endpointName := range cb.Endpoints {
		url, ok := config.Variables.Endpoints[endpointName]
		if !ok || url == "" {
			return fmt.Errorf("callback '%s' references unknown endpoint '%s'", cb.Name, endpointName)
		}
		if err := doPost(url, reqBody); err != nil {
			return err
		}
	}
	return nil
}

// doPost is a simple helper to send the JSON body to a single endpoint
func doPost(url string, body []byte) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Expect a JSON response with "status":"ok" or "status":"error"
	var respBody struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	respBytes, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBytes, &respBody)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("callback endpoint returned status %d: %s", resp.StatusCode, string(respBytes))
	}
	if respBody.Status == "error" {
		return errors.New(respBody.Message)
	}
	return nil
}
