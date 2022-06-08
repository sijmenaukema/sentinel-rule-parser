package main

import (
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type securityEvent struct {
	Name     string
	Query    string
	EventIDs []int
}

var (
	files          []string
	securityEvents []securityEvent
)

func main() {

	directory, err := getDirectory()
	if err != nil {
		fmt.Println(err)
	}

	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if len(path) > 5 && path[len(path)-5:] == ".yaml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}

	for _, fileDirectory := range files {
		file, err := ioutil.ReadFile(fileDirectory)
		if err != nil {
			fmt.Println(err)
		}
		s := securityEvent{}

		err = yaml.Unmarshal([]byte(file), &s)
		if err != nil {
			log.Fatal(err)
		}

		var reSingle = regexp.MustCompile(`EventID == '(\d{1,4})?'`)
		indexMatch := reSingle.FindAllString(s.Query, 10)
		for _, eventID := range indexMatch {
			stringID := eventID[12 : len(eventID)-1]
			intID, err := strconv.Atoi(stringID)
			if err != nil {
				fmt.Println(err)
			}
			s.EventIDs = append(s.EventIDs, intID)
		}

		var reMany = regexp.MustCompile(`EventID in \((\d{1,4})(.{1,2}(\d{1,4})){1,}`)
		indexMatch = reMany.FindAllString(s.Query, 10)
		for _, eventID := range indexMatch {
			stringArray := eventID[12:]
			stringIDs := strings.Split(stringArray, ",")
			for _, stringID := range stringIDs {
				stringID := strings.TrimSpace(stringID)
				intID, err := strconv.Atoi(stringID)
				if err != nil {
					fmt.Println(err)
				}
				s.EventIDs = append(s.EventIDs, intID)
			}
		}

		s.EventIDs = getDistinct(s.EventIDs)
		securityEvents = append(securityEvents, s)
	}

	file, err := createFile("sentinelRules.csv")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	var data [][]string
	for _, securityEvent := range securityEvents {
		eventIDString := strings.Trim(strings.Replace(fmt.Sprint(securityEvent.EventIDs), "", "", -1), "[ ]")
		row := []string{securityEvent.Name, eventIDString}
		data = append(data, row)
	}
	writer.WriteAll(data)
}

func getDirectory() (string, error) {
	directory, err := os.Getwd()
	directory = fmt.Sprintf("%s/Files", directory)
	if err != nil {
		return "", err
	}
	return directory, nil
}

func getDistinct(intSlice []int) []int {
	keys := make(map[int]bool)
	list := []int{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func createFile(fileName string) (*os.File, error) {
	file, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}
	return file, nil
}
