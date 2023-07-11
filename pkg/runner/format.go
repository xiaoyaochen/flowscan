package runner

import "github.com/projectdiscovery/tlsx/pkg/tlsx/clients"

type Result struct {
	Ip   string `json:"ip" bson:"ip"`
	Host string `json:"host" bson:"host"`
	Port int    `json:"port" bson:"port"`

	Raw              string `json:"-" bson:"raw"`
	TLS              bool   `json:"tls,omitempty" bson:"tls,omitempty"`
	ProbeName        string `json:"probeName,omitempty" bson:"probeName,omitempty"`
	MatchRegexString string `json:"match_regex_string,omitempty" bson:"match_regex_string,omitempty"`

	Service         string `json:"service,omitempty" bson:"service,omitempty"`
	ProductName     string `json:"product_name,omitempty" bson:"product_name,omitempty"`
	Version         string `json:"version,omitempty" bson:"version,omitempty"`
	Info            string `json:"info,omitempty" bson:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty" bson:"hostname,omitempty"`
	OperatingSystem string `json:"os,omitempty" bson:"os,omitempty"`
	DeviceType      string `json:"device_type,omitempty" bson:"device_type,omitempty"`

	URL           string            `json:"url,omitempty"  bson:"url,omitempty"`
	Title         string            `json:"title,omitempty"  bson:"title,omitempty"`
	StatusCode    int               `json:"status_code,omitempty"  bson:"status_code,omitempty"`
	Apps          []string          `json:"apps,omitempty"  bson:"apps,omitempty"`
	TLSData       *clients.Response `json:"tls_data,omitempty"  bson:"tls_data,omitempty"`
	Words         int               `json:"words,omitempty"  bson:"words,omitempty"`
	ContentLength int               `json:"content_length,omitempty"  bson:"content_length,omitempty"`
	Status        string            `json:"status,omitempty"  bson:"status,omitempty"`
}

type CrackResult struct {
	Ip       string   `json:"ip" bson:"ip"`
	Port     int      `json:"port" bson:"port"`
	Protocol string   `json:"protocol" bson:"protocol"`
	UserPass []string `json:"user_pass" bson:"user_pass"`
}
