package runner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type CsvServiceCommand struct {
	Debug       bool
	JsonDecoder *json.Decoder `kong:"-"`

	CsvOutput string `short:"o" help:"json to write output results eg.result.csv" default:"result.csv"`
}

func (cmd *CsvServiceCommand) Run() error {
	if !cmd.Debug {
		log.SetOutput(io.Discard)
	}
	cmd.JsonDecoder = json.NewDecoder(os.Stdin)
	file, err := os.Create(cmd.CsvOutput)
	if err != nil {
		log.Fatal("无法创建输出文件：", err)
	}
	defer file.Close()
	// 创建一个 CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()
	data := []map[string]interface{}{}
	for {
		result := make(map[string]interface{})
		err := cmd.JsonDecoder.Decode(&result)

		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatal(err)
		}
		data = append(data, result)
	}
	headers := getHeaders(data)
	// 写入CSV文件的表头
	err = writer.Write(headers)
	if err != nil {
		log.Println("写入CSV文件时出错：", err)
	}

	// 将每个map的数据写入CSV文件
	for _, mp := range data {
		record := make([]string, 0)
		for _, header := range headers {
			record = append(record, strings.TrimRight(fmt.Sprintln(mp[header]), "\n"))
		}

		err := writer.Write(record)
		if err != nil {
			log.Println("写入CSV文件时出错：", err)
		}
	}

	return nil
}

// 获取所有map数据中的唯一键作为表头
func getHeaders(data []map[string]interface{}) []string {
	headerSet := make(map[string]bool)
	for _, mp := range data {
		for key := range mp {
			headerSet[key] = true
		}
	}

	headers := make([]string, 0)
	for header := range headerSet {
		headers = append(headers, header)
	}

	return headers
}
