package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/gorp.v1"
)

const l = "06/25-00:07:15.545982  [**] [1:524:8] BAD-TRAFFIC tcp port 0 traffic [**] [Classification: Misc activity] [Priority: 3] {TCP} 173.180.6.172:44779 -> 24.86.161.95:0"
const timeParse = `01/02-15:04:05.000000`

var regexpStr = map[string][]string{
	"timeRegex":           {`\d{1,2}\/\d{1,2}-\d{1,2}:\d{1,2}:\d{1,2}\.\d+`},
	"hostRegex":           {`\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d*`},
	"ipFromHostRegex":     {`\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}`},
	"portFromHostRegex":   {`\d+$`},
	"protoRegex":          {`\{\w+\}`, `\w+`},
	"typeRegex":           {`\[\*\*\].+\[\*\*\]`},
	"typeCodeRegex":       {`\d+:\d+:\d+`},
	"typeDescRegex":       {`[A-Za-z][\ a-zA-Z\-0-9]+`},
	"classificationRegex": {`Classification:[\s\w]+`, `:[\w\s]+`, `[\w\s]+`},
	"priorityRegex":       {`\[Priority: \d+\]`, `\d+`},
	"hostToHostRegex":     {`\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d* -> \d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}:{0,1}\d*`},
}

var regexs map[string][]*regexp.Regexp
var database *gorp.DbMap

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
	regexs = make(map[string][]*regexp.Regexp)
	for idx, a := range regexpStr {
		regexs[idx] = make([]*regexp.Regexp, 0, 3)
		for i, r := range a {

			regexs[idx] = append(regexs[idx], regexp.MustCompile(r))
			fmt.Println(idx, i, regexs[idx])
		}
	}
}

func main() {
	infoChan := make(chan Entry, 200)
	countChan := make(chan int, 200)
	count := 0
	done := 0
	buffer := make([]interface{}, 0, 1000)
	database = initDb(os.Args[1])
	defer database.Db.Close()
	for _, alertFile := range os.Args[2:] {
		go parseAlert(alertFile, infoChan, countChan)
	}
	for {

		select {
		case _ = <-countChan:
			count++
			fmt.Println("Inserted ", done, "/", count)
		case temp := <-infoChan:
			done++
			insertEntries(buffer, temp)
			fmt.Println("Inserted ", done, "/", count)
			if done >= count {
				select { // race condition work around
				case <-time.After(time.Second):
					err := database.Insert(buffer...)
					perror("Error on insert", err)
					return
				case _ = <-countChan:
					count++
				}
			}
		}
	}
}

// bulk insert
func insertEntries(buffer []interface{}, temp Entry) {
	buffer = append(buffer, &temp)
	if len(buffer) > 999 {
		err := database.Insert(buffer...)
		perror("Error on insert", err)
	}
}

func parseAlert(alertFile string, info chan Entry, count chan int) {
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
		count <- 1
		go handleLine(line, info)
	}
}

func handleLine(line string, info chan Entry) {
	newEntry := Entry{}
	newEntry.readTime(line)
	newEntry.readType(line)
	newEntry.getHosts(line)
	newEntry.getProtocol(line)
	newEntry.getClassification(line)
	newEntry.getPriority(line)
	info <- newEntry
}

func (e *Entry) readTime(line string) {
	var err error
	timeString := regexs["timeRegex"][0].FindString(line)
	e.Time, err = time.Parse(timeParse, timeString)
	perror("could not parse string "+timeString, err)
}

func (e *Entry) readType(line string) {
	typeString := regexs["typeRegex"][0].FindString(line)
	e.TypeCode = regexs["typeCodeRegex"][0].FindString(typeString)
	e.Type = regexs["typeDescRegex"][0].FindString(typeString)
}

func (e *Entry) getHosts(line string) {
	defer func() { // dont let it crash from a index out of bounds
		if r := recover(); r != nil {
			log.Println(line)
		}
	}()
	hosts := regexs["hostRegex"][0].FindAllString(line, 2)
	e.SrcIP = regexs["ipFromHostRegex"][0].FindString(hosts[0])
	e.SrcPort = regexs["portFromHostRegex"][0].FindString(hosts[0])

	e.DstIP = regexs["ipFromHostRegex"][0].FindString(hosts[1])
	e.DstPort = regexs["portFromHostRegex"][0].FindString(hosts[1])

}

func (e *Entry) getProtocol(line string) {
	e.Protocol = regexs["protoRegex"][0].FindString(line)
	e.Protocol = regexs["protoRegex"][1].FindString(e.Protocol)
}

func (e *Entry) getClassification(line string) {
	e.Classification = line
	for _, reg := range regexs["classificationRegex"] {
		e.Classification = reg.FindString(e.Classification)
	}
	e.Classification = strings.Trim(e.Classification, " ")
}

func (e *Entry) getPriority(line string) {
	var err error
	str := regexs["priorityRegex"][0].FindString(line)
	str = regexs["priorityRegex"][1].FindString(str)
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
