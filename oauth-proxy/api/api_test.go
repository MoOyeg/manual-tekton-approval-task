package api

import (
	"github.com/bitly/go-simplejson"
	"github.com/bmizerany/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testBackend(response_code int, payload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(response_code)
			w.Write([]byte(payload))
		}))
}

func TestRequest(t *testing.T) {
	backend := testBackend(200, "{\"foo\": \"bar\"}")
	defer backend.Close()

	req, _ := http.NewRequest("GET", backend.URL, nil)
	response, err := Request(req)
	assert.Equal(t, nil, err)
	result, err := response.Get("foo").String()
	assert.Equal(t, nil, err)
	assert.Equal(t, "bar", result)
}

func TestRequestFailure(t *testing.T) {
	// Create a backend to generate a test URL, then close it to cause a
	// connection error.
	backend := testBackend(200, "{\"foo\": \"bar\"}")
	backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
	if !strings.Contains(err.Error(), "refused") {
		t.Error("expected error when a connection fails: ", err)
	}
}

func TestHttpErrorCode(t *testing.T) {
	backend := testBackend(404, "{\"foo\": \"bar\"}")
	defer backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
}

func TestJsonParsingError(t *testing.T) {
	backend := testBackend(200, "not well-formed JSON")
	defer backend.Close()

	req, err := http.NewRequest("GET", backend.URL, nil)
	assert.Equal(t, nil, err)
	resp, err := Request(req)
	assert.Equal(t, (*simplejson.Json)(nil), resp)
	assert.NotEqual(t, nil, err)
}

// Parsing a URL practically never fails, so we won't cover that test case.
func TestRequestUnparsedResponseUsingAccessTokenParameter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			token := r.FormValue("access_token")
			if r.URL.Path == "/" && token == "my_token" {
				w.WriteHeader(200)
				w.Write([]byte("some payload"))
			} else {
				w.WriteHeader(403)
			}
		}))
	defer backend.Close()

	response, err := RequestUnparsedResponse(
		backend.URL+"?access_token=my_token", nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	assert.Equal(t, nil, err)
	response.Body.Close()
	assert.Equal(t, "some payload", string(body))
}

func TestRequestUnparsedResponseUsingAccessTokenParameterFailedResponse(t *testing.T) {
	backend := testBackend(200, "some payload")
	// Close the backend now to force a request failure.
	backend.Close()

	response, err := RequestUnparsedResponse(
		backend.URL+"?access_token=my_token", nil)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, (*http.Response)(nil), response)
}

func TestRequestUnparsedResponseUsingHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" && r.Header["Auth"][0] == "my_token" {
				w.WriteHeader(200)
				w.Write([]byte("some payload"))
			} else {
				w.WriteHeader(403)
			}
		}))
	defer backend.Close()

	headers := make(http.Header)
	headers.Set("Auth", "my_token")
	response, err := RequestUnparsedResponse(backend.URL, headers)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, response.StatusCode)
	body, err := ioutil.ReadAll(response.Body)
	assert.Equal(t, nil, err)
	response.Body.Close()
	assert.Equal(t, "some payload", string(body))
}
