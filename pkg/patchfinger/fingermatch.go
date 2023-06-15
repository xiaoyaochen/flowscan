package patchfinger

import (
	"encoding/json"
	"net/textproto"
	"regexp"
	"strings"
)

type Packjson struct {
	Fingerprint   []Fingerprint
	Servicefinger []Fingerprint
}

type Fingerprint struct {
	Cms      string
	Method   string
	Location string
	Keyword  []string
}

func NewFingerprint() (*Packjson, error) {
	var pk Packjson
	err := json.Unmarshal([]byte(Eholefinger), &pk)
	if err != nil {
		return nil, err
	}
	return &pk, nil
}

func (pj *Packjson) RunFingerprint(headers map[string][]string, body []byte, title string) ([]string, string) {
	strheaders := MapToJson(headers)
	contentType := strings.ToLower(textproto.MIMEHeader(headers).Get("Content-Type"))
	strbody := toUtf8(string(body), contentType)
	var cms []string
	for _, finp := range pj.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(strbody, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(strbody, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(strheaders, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(strheaders, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}
	cms = RemoveDuplicatesAndEmpty(cms)
	var service string
	for _, finp := range pj.Servicefinger {
		if finp.Location == "body" {
			if finp.Method == "keyword" {
				if iskeyword(strbody, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
			if finp.Method == "regular" {
				if isregular(strbody, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
		}
		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if iskeyword(strheaders, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
			if finp.Method == "regular" {
				if isregular(strheaders, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
		}
		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if iskeyword(title, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
			if finp.Method == "regular" {
				if isregular(title, finp.Keyword) {
					service = finp.Cms
					break
				}
			}
		}
	}
	return cms, service
}
func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}
func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func iskeyword(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		if strings.Contains(str, k) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func isregular(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		if re.Match([]byte(str)) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}
