package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/gorp.v1"
)

const l = "06/25-00:07:15.545982  [**] [1:524:8] BAD-TRAFFIC tcp port 0 traffic [**] [Classification: Misc activity] [Priority: 3] {TCP} 173.180.6.172:44779 -> 24.86.161.95:0"
const timeParse = `01/02-15:04:05.000000`

var regexpStr = map[string]string{
	"timeRegex":                 `\d{1,2}\/\d{1,2}-\d{1,2}:\d{1,2}:\d{1,2}\.\d+`,
	"hostRegex":                 `\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d*`,
	"ipFromHostRegex":           `\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}`,
	"portFromHostRegex":         `\d+$`,
	"protoRegex":                `\{\w+\}`,
	"protoSecondRegex":          `\w+`,
	"typeRegex":                 `\[\*\*\].+\[\*\*\]`,
	"typeCodeRegex":             `\d+:\d+:\d+`,
	"typeDescRegex":             `[A-Za-z][\ a-zA-Z\-0-9]+`,
	"classificationRegex":       `\[Classification:\D+\]`,
	"classificationSecondRegex": `\D+`,
	"priorityRegex":             `\[Priority: \d+\]`,
	"prioritySecondRegex":       `\d+`,
	"hostToHostRegex":           `\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d* -> \d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d*`,
}

var database *gorp.DbMap
var regexs map[string]*regexp.Regexp

// Entry is a structure that represents a snort log
type Entry struct {
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

func init() {
	regexs = make(map[string]*regexp.Regexp)
	for idx, r := range regexpStr {
		regexs[idx] = regexp.MustCompile(r)
	}
	database = initDb(os.Args[1])
}

func main() {
	for _, alertFile := range os.Args[2:] {
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
		go handleLine(line)
	}
}

func handleLine(line string) {
	newEntry := Entry{}
	newEntry.readTime(line)
	newEntry.readType(line)
	newEntry.getHosts(line)
	newEntry.getProtocol(line)
	fmt.Println(newEntry)
	database.Insert(newEntry)

}

func (e *Entry) readTime(line string) {
	var err error
	timeString := regexs["timeRegex"].FindString(line)
	e.Time, err = time.Parse(timeParse, timeString)
	perror("could not parse string "+timeString, err)
}

func (e *Entry) readType(line string) {
	typeString := regexs["typeRegex"].FindString(line)
	e.TypeCode = regexs["typeCodeRegex"].FindString(typeString)
	e.Type = regexs["typeDescRegex"].FindString(typeString)
}

func (e *Entry) getHosts(line string) {
	defer func() { // dont let it crash from a index out of bounds
		if r := recover(); r != nil {
			log.Println(line)
		}
	}()
	hostToHost := regexs["hostToHostRegex"].FindString(line)
	hosts := regexs["hostRegex"].FindAllString(hostToHost, 2)
	e.SrcIP = regexs["ipFromHostRegex"].FindString(hosts[0])
	e.SrcPort = regexs["portFromHostRegex"].FindString(hosts[0])

	e.DstIP = regexs["ipFromHostRegex"].FindString(hosts[1])
	e.DstPort = regexs["portFromHostRegex"].FindString(hosts[1])

}

func (e *Entry) getProtocol(line string) {
	s := regexs["protoRegex"].FindString(line)
	e.Protocol = regexs["protoSecondRegex"].FindString(s)
}

func (e *Entry) getClassification(line string) {
	e.Classification = regexs["classificationRegex"].FindString(line)
	e.Classification = regexs["classificationSecondRegex"].FindString(line)
}

func (e *Entry) getPriority(line string) {
	var err error
	str := regexs["priorityRegex"].FindString(line)
	str = regexs["prioritySecondRegex"].FindString(str)
	e.Priority, err = strconv.Atoi(str)
	perror("Can't read priority", err)
}

func perror(str string, err error) {
	if err != nil {
		log.Println(str, ":", err)
	}
}

func initDb(name string) *gorp.DbMap {
	db, err := sql.Open("sqlite3", name)
	if err != nil {
		log.Fatalln("Could not open db")
	}
	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}

	dbmap.AddTableWithName(Entry{}, "Log")
	err = dbmap.CreateTablesIfNotExists()
	ferror("Create Tables Failed", err)

	return dbmap
}

func ferror(str string, err error) {
	if err != nil {
		log.Fatalln(str, err)
	}
}
