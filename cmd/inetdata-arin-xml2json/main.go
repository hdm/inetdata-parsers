package main

// Convert ARIN Bulk XML into JSONL output

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
)

// ARIN POC Record

type ARIN_POC_emails struct {
	Email string `xml:"email,omitempty" json:"email,omitempty"`
}

type ARIN_POC_iso3166_1 struct {
	Code2 string `xml:"code2,omitempty" json:"code2,omitempty"`
	Code3 string `xml:"code3,omitempty" json:"code3,omitempty"`
	E164  string `xml:"e164,omitempty" json:"e164,omitempty"`
	Name  string `xml:"name,omitempty" json:"name,omitempty"`
}

type ARIN_POC_line struct {
	Number string `xml:"number,attr"  json:",omitempty"`
	Text   string `xml:",chardata" json:",omitempty"`
}

type ARIN_POC_name struct {
	Text string `xml:",chardata" json:",omitempty"`
}

type ARIN_POC_number struct {
	PhoneNumber string `xml:"phoneNumber,omitempty" json:"phoneNumber,omitempty"`
	PhoneType   string `xml:"phoneType,omitempty" json:"phoneType,omitempty"`
	PocHandle   string `xml:"pocHandle,omitempty" json:"pocHandle,omitempty"`
}

type ARIN_POC_phone struct {
	Number *ARIN_POC_number `xml:"number,omitempty" json:"number,omitempty"`
	Type   *ARIN_POC_type   `xml:"type,omitempty" json:"type,omitempty"`
}

type ARIN_POC_phones struct {
	Phone *ARIN_POC_phone `xml:"phone,omitempty" json:"phone,omitempty"`
}

type ARIN_POC_poc struct {
	ARIN_Type        string                  `xml:"arin,omitempty" json:"arin,omitempty"`
	City             string                  `xml:"city,omitempty" json:"city,omitempty"`
	Emails           *ARIN_POC_emails        `xml:"emails,omitempty" json:"emails,omitempty"`
	FirstName        string                  `xml:"firstName,omitempty" json:"firstName,omitempty"`
	Handle           string                  `xml:"handle,omitempty" json:"handle,omitempty"`
	IsRoleAccount    string                  `xml:"isRoleAccount,omitempty" json:"isRoleAccount,omitempty"`
	Iso3166_1        *ARIN_POC_iso3166_1     `xml:"iso3166-1,omitempty" json:"iso3166-1,omitempty"`
	Iso3166_2        string                  `xml:"iso3166-2,omitempty" json:"iso3166-2,omitempty"`
	LastName         string                  `xml:"lastName,omitempty" json:"lastName,omitempty"`
	Phones           *ARIN_POC_phones        `xml:"phones,omitempty" json:"phones,omitempty"`
	PostalCode       string                  `xml:"postalCode,omitempty" json:"postalCode,omitempty"`
	Ref              string                  `xml:"ref,omitempty" json:"ref,omitempty"`
	RegistrationDate string                  `xml:"registrationDate,omitempty" json:"registrationDate,omitempty"`
	StreetAddress    *ARIN_POC_streetAddress `xml:"streetAddress,omitempty" json:"streetAddress,omitempty"`
	UpdateDate       *string                 `xml:"updateDate,omitempty" json:"updateDate,omitempty"`
}

type ARIN_POC_streetAddress struct {
	Line []*ARIN_POC_line `xml:"line,omitempty" json:"line,omitempty"`
}

type ARIN_POC_type struct {
	Code        string `xml:"code,omitempty" json:"code,omitempty"`
	Description string `xml:"description,omitempty" json:"description,omitempty"`
}

// ARIN Organization Record

type ARIN_ORG_iso3166_1 struct {
	Code2 string `xml:"code2,omitempty" json:"code2,omitempty"`
	Code3 string `xml:"code3,omitempty" json:"code3,omitempty"`
	E164  string `xml:"e164,omitempty" json:"e164,omitempty"`
	Name  string `xml:"name,omitempty" json:"name,omitempty"`
}

type ARIN_ORG_line struct {
	Number string `xml:"number,attr"  json:",omitempty"`
	Text   string `xml:",chardata" json:",omitempty"`
}

type ARIN_ORG_org struct {
	ARIN_Type        string                  `xml:"arin,omitempty" json:"arin,omitempty"`
	City             string                  `xml:"city,omitempty" json:"city,omitempty"`
	Customer         string                  `xml:"customer,omitempty" json:"customer,omitempty"`
	Handle           string                  `xml:"handle,omitempty" json:"handle,omitempty"`
	Iso3166_1        *ARIN_ORG_iso3166_1     `xml:"iso3166-1,omitempty" json:"iso3166-1,omitempty"`
	Iso3166_2        string                  `xml:"iso3166-2,omitempty" json:"iso3166-2,omitempty"`
	Name             string                  `xml:"name,omitempty" json:"name,omitempty"`
	PocLinks         *ARIN_ORG_pocLinks      `xml:"pocLinks,omitempty" json:"pocLinks,omitempty"`
	PostalCode       string                  `xml:"postalCode,omitempty" json:"postalCode,omitempty"`
	Ref              string                  `xml:"ref,omitempty" json:"ref,omitempty"`
	RegistrationDate string                  `xml:"registrationDate,omitempty" json:"registrationDate,omitempty"`
	StreetAddress    *ARIN_ORG_streetAddress `xml:"streetAddress,omitempty" json:"streetAddress,omitempty"`
	UpdateDate       string                  `xml:"updateDate,omitempty" json:"updateDate,omitempty"`
}

type ARIN_ORG_pocLink struct {
	Description string `xml:"description,attr"  json:",omitempty"`
	Function    string `xml:"function,attr"  json:",omitempty"`
	Handle      string `xml:"handle,attr"  json:",omitempty"`
}

type ARIN_ORG_pocLinks struct {
	PocLink []*ARIN_ORG_pocLink `xml:"pocLink,omitempty" json:"pocLink,omitempty"`
}

type ARIN_ORG_streetAddress struct {
	Line []*ARIN_ORG_line `xml:"line,omitempty" json:"line,omitempty"`
}

// ARIN Network Record

type ARIN_NET_net struct {
	ARIN_Type        string              `xml:"arin,omitempty" json:"arin,omitempty"`
	EndAddress       string              `xml:"endAddress,omitempty" json:"endAddress,omitempty"`
	Handle           string              `xml:"handle,omitempty" json:"handle,omitempty"`
	Name             string              `xml:"name,omitempty" json:"name,omitempty"`
	NetBlocks        *ARIN_NET_netBlocks `xml:"netBlocks,omitempty" json:"netBlocks,omitempty"`
	OrgHandle        string              `xml:"orgHandle,omitempty" json:"orgHandle,omitempty"`
	ParentNetHandle  string              `xml:"parentNetHandle,omitempty" json:"parentNetHandle,omitempty"`
	PocLinks         *ARIN_NET_pocLinks  `xml:"pocLinks,omitempty" json:"pocLinks,omitempty"`
	Ref              string              `xml:"ref,omitempty" json:"ref,omitempty"`
	RegistrationDate string              `xml:"registrationDate,omitempty" json:"registrationDate,omitempty"`
	StartAddress     string              `xml:"startAddress,omitempty" json:"startAddress,omitempty"`
	UpdateDate       string              `xml:"updateDate,omitempty" json:"updateDate,omitempty"`
	Version          string              `xml:"version,omitempty" json:"version,omitempty"`
}

type ARIN_NET_netBlock struct {
	CidrLength   string `xml:"cidrLength,omitempty" json:"cidrLength,omitempty"`
	EndAddress   string `xml:"endAddress,omitempty" json:"endAddress,omitempty"`
	StartAddress string `xml:"startAddress,omitempty" json:"startAddress,omitempty"`
	Type         string `xml:"type,omitempty" json:"type,omitempty"`
}

type ARIN_NET_netBlocks struct {
	NetBlock *ARIN_NET_netBlock `xml:"netBlock,omitempty" json:"netBlock,omitempty"`
}

type ARIN_NET_pocLinks struct {
}

// ARIN ASN Record

type ARIN_ASN_asn struct {
	ARIN_Type        string             `xml:"arin,omitempty" json:"arin,omitempty"`
	ARIN_ASN_comment *ARIN_ASN_comment  `xml:"comment,omitempty" json:"comment,omitempty"`
	EndAsNumber      string             `xml:"endAsNumber,omitempty" json:"endAsNumber,omitempty"`
	Handle           string             `xml:"handle,omitempty" json:"handle,omitempty"`
	Name             string             `xml:"name,omitempty" json:"name,omitempty"`
	OrgHandle        string             `xml:"orgHandle,omitempty" json:"orgHandle,omitempty"`
	PocLinks         *ARIN_ASN_pocLinks `xml:"pocLinks,omitempty" json:"pocLinks,omitempty"`
	Ref              string             `xml:"ref,omitempty" json:"ref,omitempty"`
	RegistrationDate string             `xml:"registrationDate,omitempty" json:"registrationDate,omitempty"`
	StartAsNumber    string             `xml:"startAsNumber,omitempty" json:"startAsNumber,omitempty"`
	UpdateDate       string             `xml:"updateDate,omitempty" json:"updateDate,omitempty"`
}

type ARIN_ASN_comment struct {
	Line []*ARIN_ASN_line `xml:"line,omitempty" json:"line,omitempty"`
}

type ARIN_ASN_line struct {
	Number string `xml:"number,attr"  json:",omitempty"`
	Text   string `xml:",chardata" json:",omitempty"`
}

type ARIN_ASN_pocLink struct {
	Description string `xml:"description,attr"  json:",omitempty"`
	Function    string `xml:"function,attr"  json:",omitempty"`
	Handle      string `xml:"handle,attr"  json:",omitempty"`
}

type ARIN_ASN_pocLinks struct {
	PocLink []*ARIN_ASN_pocLink `xml:"pocLink,omitempty" json:"pocLink,omitempty"`
}

func processRecord(decoder *xml.Decoder, el *xml.StartElement, rtype string, value interface{}) {
	decoder.DecodeElement(&value, el)
	if value == nil {
		fmt.Fprintf(os.Stderr, "Could not decode record type %s\n", rtype)
		return
	}

	b, e := json.Marshal(value)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Could not marshal type: %s\n", e.Error())
		return
	}
	fmt.Println(string(b))
}

func processFile(name string) {
	xmlFile, err := os.Open(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open file: %s\n", err.Error())
		return
	}
	defer xmlFile.Close()

	decoder := xml.NewDecoder(xmlFile)
	var inElement string
	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			inElement = se.Name.Local
			switch inElement {
			case "poc":
				processRecord(decoder, &se, inElement, &ARIN_POC_poc{})
			case "net":
				processRecord(decoder, &se, inElement, &ARIN_NET_net{})
			case "org":
				processRecord(decoder, &se, inElement, &ARIN_ORG_org{})
			case "asn":
				processRecord(decoder, &se, inElement, &ARIN_ASN_asn{})
			}
		default:
		}
	}
}

func main() {
	flag.Parse()
	for i := range flag.Args() {
		processFile(flag.Args()[i])
	}
}
