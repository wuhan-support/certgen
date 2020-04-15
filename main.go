package main

import (
	"bytes"
	"encoding/csv"
	"github.com/cheggaaa/pb/v3"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"time"
)
import "github.com/mohae/struct2csv"

type Record struct {
	Name string
	Email string
	Group string

	CertID string
	CertSignMessage string
	CertSignedMessage string
}

var Records []Record

func main() {
	file, err := os.Open("data.csv")
	if err != nil {
		panic(err)
	}

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()

	bar := pb.New(len(records))
	bar.SetRefreshRate(time.Millisecond * 33)
	bar.Start()

	// unmarshal data from csv, generate CertID and message, then sign it
	for _, record := range records {
		r := Record{
			Name: sanitize(record[0]),
			Email: sanitize(record[1]),
			Group: sanitize(record[2]),
		}

		r.CertID = GenerateCertID(r)
		r.CertSignMessage = GenerateSignMessage(r)
		r.CertSignedMessage = PGPSignString(r.CertSignMessage)

		spew.Dump(r)

		Records = append(Records, r)
		bar.Increment()
	}

	bar.Finish()

	buff := &bytes.Buffer{}
	w := struct2csv.NewWriter(buff)
	err = w.WriteStructs(Records)
	if err != nil {
		panic(err)
	}
	w.Flush()

	dat, err := ioutil.ReadAll(buff)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("result.csv", dat, 0644)
	if err != nil {
		panic(err)
	}

	// write cert data to a csv and use photoshop to generate it
}
