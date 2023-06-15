package db

import (
	"log"
	"net/url"
	"strings"
)

type DB interface {
	Push(string, []byte) error
	Close() error
}

type DbOpt struct {
	Addr    string
	DbName  string
	ColName string
}

func NewMqProducer(dbInfo string) DB {
	dbopt := strings.Split(dbInfo, "+")
	addr := dbopt[0]
	db_name := dbopt[1]
	col_name := dbopt[2]

	var db DB
	schema := GetSchema(addr)
	switch schema {
	case "mongodb":
		db = NewMongoProducer(addr, db_name, col_name)
		return db
	default:
		return nil
	}
}

func GetSchema(Url string) string {
	u, err := url.Parse(Url)
	if err != nil {
		log.Println(err)
		return ""
	}
	return u.Scheme
}
