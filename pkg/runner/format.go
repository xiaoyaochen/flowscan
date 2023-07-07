package runner

import "github.com/projectdiscovery/tlsx/pkg/tlsx/clients"

type Result struct {
	Ip   string `json:"ip"`
	Host string `json:"host"`
	Port int    `json:"port"`

	Raw              string `json:"-"`
	TLS              bool   `json:"tls,omitempty"`
	ProbeName        string `json:"probeName,omitempty"`
	MatchRegexString string `json:"match_regex_string,omitempty"`

	Service         string `json:"service,omitempty"`
	ProductName     string `json:"product_name,omitempty"`
	Version         string `json:"version,omitempty"`
	Info            string `json:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OperatingSystem string `json:"os,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`

	URL           string            `json:"url,omitempty"`
	Title         string            `json:"title,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"`
	Apps          []string          `json:"apps,omitempty"`
	TLSData       *clients.Response `json:"tls_data,omitempty"`
	Words         int               `json:"words,omitempty"`
	ContentLength int               `json:"content_length,omitempty"`
	Status        string            `json:"status,omitempty"`
}

type CrackResult struct {
	Ip       string   `json:"ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	UserPass []string `json:"user_pass"`
}
