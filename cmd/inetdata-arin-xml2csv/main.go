package main

// Convert ARIN Bulk XML into CSV output

import (
	"encoding/csv"
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ARIN POC Record

type ARIN_POC_emails struct {
	Email []string `xml:"email,omitempty" json:"email,omitempty"`
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
	Phone []*ARIN_POC_phone `xml:"phone,omitempty" json:"phone,omitempty"`
}

type ARIN_POC_poc struct {
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
	CidrLenth    string `xml:"cidrLenth,omitempty" json:"cidrLenth,omitempty"`
	EndAddress   string `xml:"endAddress,omitempty" json:"endAddress,omitempty"`
	StartAddress string `xml:"startAddress,omitempty" json:"startAddress,omitempty"`
	Type         string `xml:"type,omitempty" json:"type,omitempty"`
}

type ARIN_NET_netBlocks struct {
	NetBlock *ARIN_NET_netBlock `xml:"netBlock,omitempty" json:"netBlock,omitempty"`
}

type ARIN_NET_pocLink struct {
	Description string `xml:"description,attr"  json:",omitempty"`
	Function    string `xml:"function,attr"  json:",omitempty"`
	Handle      string `xml:"handle,attr"  json:",omitempty"`
}

type ARIN_NET_pocLinks struct {
	PocLink []*ARIN_NET_pocLink `xml:"pocLink,omitempty" json:"pocLink,omitempty"`
}

// ARIN ASN Record

type ARIN_ASN_asn struct {
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

func escapeBackslashes(s string) string {
	return strings.Replace(s, "\\", "\\\\", -1)
}

func scrubHighAscii(s string) string {
	re := regexp.MustCompile("[\u007f-\u00ff]")
	return re.ReplaceAllString(s, "?")
}

func escapeCell(s string) string {
	s = escapeBackslashes(s)
	s = scrubHighAscii(s)
	return s
}

func processFile(name string) {
	xmlFile, err := os.Open(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open file: %s\n", err.Error())
		return
	}
	defer xmlFile.Close()

	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

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
				value := ARIN_POC_poc{}

				decoder.DecodeElement(&value, &se)
				if value.Handle == "" {
					fmt.Fprintf(os.Stderr, "Could not decode record type %s\n", inElement)
					continue
				}

				record := []string{
					value.Handle,
					"", // Email1 - 1
					"", // Email2 - 2
					"", // Email3 - 3
					value.FirstName,
					value.LastName,
					value.IsRoleAccount,
					"", // StreetAddress - 7
					value.City,
					value.Iso3166_2,
					value.PostalCode,
					value.Iso3166_1.Name,
					value.Iso3166_1.Code2,
					value.Iso3166_1.Code3,
					value.Iso3166_1.E164,
					"", // Phone1 - 13
					"", // Phone2 - 14
					"", // Phone3 - 15
					value.RegistrationDate,
					string(*value.UpdateDate),
				}

				if record[7] == "N" {
					record[7] = "false"
				} else {
					record[7] = "true"
				}

				// Extract the email addresses
				if value.Emails != nil && value.Emails.Email != nil {
					for ei := range value.Emails.Email {
						if ei > 2 {
							break
						}
						record[1+ei] = value.Emails.Email[ei]
					}
				}

				// Extract the street address
				if value.StreetAddress != nil && value.StreetAddress.Line != nil {
					address := ""
					for ei := range value.StreetAddress.Line {
						line := strings.Replace(value.StreetAddress.Line[ei].Text, "\t", " ", -1)
						if address == "" {
							address = line
						} else {
							address = address + "\t" + line
						}
					}
					record[7] = address
				}

				// Extract the phone numbers
				if value.Phones != nil && value.Phones.Phone != nil {
					for ei := range value.Phones.Phone {
						if value.Phones.Phone[ei] == nil {
							break
						}
						if ei > 2 {
							break
						}
						phone := value.Phones.Phone[ei]
						record[13+ei] = phone.Number.PhoneNumber
					}
				}

				// Sanitize the records
				for i := range record {
					record[i] = escapeCell(record[i])
				}

				// Output CSV
				if err := writer.Write(record); err != nil {
					fmt.Fprintf(os.Stderr, "Could not write CSV: %v\n", record)
					continue
				}

			case "org":
				value := ARIN_ORG_org{}

				decoder.DecodeElement(&value, &se)
				if value.Handle == "" {
					fmt.Fprintf(os.Stderr, "Could not decode record type %s\n", inElement)
					continue
				}

				record := []string{
					value.Handle,
					value.Name,
					value.Customer,
					"", // StreetAddress - 3
					value.City,
					value.Iso3166_2,
					value.PostalCode,
					value.Iso3166_1.Name,
					value.Iso3166_1.Code2,
					value.Iso3166_1.Code3,
					value.Iso3166_1.E164,
					"", // Admin POC - 11
					"", // NOC POC
					"", // Tech POC
					"", // Abuse POC
					value.RegistrationDate,
					value.UpdateDate,
				}

				if record[7] == "N" {
					record[7] = "false"
				} else {
					record[7] = "true"
				}

				// Extract the street address
				if value.StreetAddress != nil && value.StreetAddress.Line != nil {
					address := ""
					for ei := range value.StreetAddress.Line {
						line := strings.Replace(value.StreetAddress.Line[ei].Text, "\t", " ", -1)
						if address == "" {
							address = line
						} else {
							address = address + "\t" + line
						}
					}
					record[3] = address
				}

				// Extract the POC handles
				if value.PocLinks != nil && value.PocLinks.PocLink != nil {
					for ei := range value.PocLinks.PocLink {
						if value.PocLinks.PocLink[ei] == nil {
							continue
						}
						poc := value.PocLinks.PocLink[ei]

						switch poc.Description {
						case "Admin":
							record[11] = poc.Handle
						case "NOC":
							record[12] = poc.Handle
						case "Tech":
							record[13] = poc.Handle
						case "Abuse":
							record[14] = poc.Handle
						}
					}
				}

				// Sanitize the records
				for i := range record {
					record[i] = escapeCell(record[i])
				}

				// Output CSV
				if err := writer.Write(record); err != nil {
					fmt.Fprintf(os.Stderr, "Could not write CSV: %v\n", record)
					continue
				}

			case "net":
				value := ARIN_NET_net{}

				decoder.DecodeElement(&value, &se)
				if value.Handle == "" {
					fmt.Fprintf(os.Stderr, "Could not decode record type %s\n", inElement)
					continue
				}

				record := []string{
					value.Handle,
					value.ParentNetHandle,
					value.OrgHandle,
					value.Name,
					value.StartAddress,
					value.EndAddress,
					"", // Admin POC - 6
					"", // NOC POC
					"", // Tech POC
					"", // Abuse POC
					value.RegistrationDate,
					value.UpdateDate,
					value.Version,
				}

				// Extract the POC handles
				if value.PocLinks != nil && value.PocLinks.PocLink != nil {
					for ei := range value.PocLinks.PocLink {
						if value.PocLinks.PocLink[ei] == nil {
							continue
						}
						poc := value.PocLinks.PocLink[ei]

						switch poc.Description {
						case "Admin":
							record[6] = poc.Handle
						case "NOC":
							record[7] = poc.Handle
						case "Tech":
							record[8] = poc.Handle
						case "Abuse":
							record[9] = poc.Handle
						}
					}
				}

				// Sanitize the records
				for i := range record {
					record[i] = escapeCell(record[i])
				}

				// Output CSV
				if err := writer.Write(record); err != nil {
					fmt.Fprintf(os.Stderr, "Could not write CSV: %v\n", record)
					continue
				}

			case "asn":
				value := ARIN_ASN_asn{}

				decoder.DecodeElement(&value, &se)
				if value.Handle == "" {
					fmt.Fprintf(os.Stderr, "Could not decode record type %s\n", inElement)
					continue
				}

				record := []string{
					value.Handle,
					value.OrgHandle,
					value.Name,
					value.StartAsNumber,
					value.EndAsNumber,
					"", // Admin POC - 5
					"", // NOC POC
					"", // Tech POC
					"", // Abuse POC
					"", // AS Comments - 9
					value.RegistrationDate,
					value.UpdateDate,
				}

				// Extract the POC handles
				if value.PocLinks != nil && value.PocLinks.PocLink != nil {
					for ei := range value.PocLinks.PocLink {
						if value.PocLinks.PocLink[ei] == nil {
							continue
						}
						poc := value.PocLinks.PocLink[ei]

						switch poc.Description {
						case "Admin":
							record[5] = poc.Handle
						case "NOC":
							record[6] = poc.Handle
						case "Tech":
							record[7] = poc.Handle
						case "Abuse":
							record[8] = poc.Handle
						}
					}
				}

				// Extract the comments field
				if value.ARIN_ASN_comment != nil && value.ARIN_ASN_comment.Line != nil {
					comment := ""
					for ei := range value.ARIN_ASN_comment.Line {
						line := strings.Replace(value.ARIN_ASN_comment.Line[ei].Text, "\t", " ", -1)
						if comment == "" {
							comment = line
						} else {
							comment = comment + "\t" + line
						}
					}
					record[9] = comment
				}

				// Sanitize the records
				for i := range record {
					record[i] = escapeCell(record[i])
				}

				// Output CSV
				if err := writer.Write(record); err != nil {
					fmt.Fprintf(os.Stderr, "Could not write CSV: %v\n", record)
					continue
				}

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
