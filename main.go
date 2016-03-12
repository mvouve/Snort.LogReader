package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/gorp.v1"
)

const l = "06/25-00:07:15.545982  [**] [1:524:8] BAD-TRAFFIC tcp port 0 traffic [**] [Classification: Misc activity] [Priority: 3] {TCP} 173.180.6.172:44779 -> 24.86.161.95:0"

type Log struct {
	Time           time.Time
	TypeCode       string
	Type           string
	Classification string
	Priority       int
	Protocol       string
	SrcIP          string
	SrcPort        string
	DstIP          string
	DstPort        string
}

func main() {
	for _, alertFile := range os.Args[1:] {
		parseAlert(alertFile)
	}
}

func parseAlert(alertFile string) {
	file, err := os.Open(alertFile)
	if err != nil {
		log.Println("File: ", alertFile, " could not be opened: ", err)
		return
	}
	buf := bufio.NewReader(file)
	if err != nil {
		log.Println("Could not build buffer for: ", alertFile, " ", err)
		return
	}
	for line, err := buf.ReadString('\n'); err == nil; line, err = buf.ReadString('\n') {
		fmt.Println(line)
	}
}

func handleLine(line string) {

}

func perror(str string, err error) {
	if err != nil {
		log.Println(str, ":", err)
	}
}

func initDb() {
	db, err := sql.Open("pg", "")
	if err != nil {
		log.Fatalln("Could not open db")
	}
	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.PostgresDialect{}}
}
