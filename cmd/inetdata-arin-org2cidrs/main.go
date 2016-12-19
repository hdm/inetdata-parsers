package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type ARIN_OrgNets struct {
	Nets struct {
		InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
		TermsOfUse          string `json:"@termsOfUse"`
		LimitExceeded       struct {
			Limit string `json:"@limit"`
			Value string `json:"$"`
		} `json:"limitExceeded"`
		NetRef []struct {
			EndAddress   string `json:"@endAddress"`
			StartAddress string `json:"@startAddress"`
			Handle       string `json:"@handle"`
			Name         string `json:"@name"`
			Value        string `json:"$"`
		} `json:"netRef"`
	} `json:"nets"`
}

type ARIN_OrgNet struct {
	Nets struct {
		InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
		TermsOfUse          string `json:"@termsOfUse"`
		LimitExceeded       struct {
			Limit string `json:"@limit"`
			Value string `json:"$"`
		} `json:"limitExceeded"`
		NetRef struct {
			EndAddress   string `json:"@endAddress"`
			StartAddress string `json:"@startAddress"`
			Handle       string `json:"@handle"`
			Name         string `json:"@name"`
			Value        string `json:"$"`
		} `json:"netRef"`
	} `json:"nets"`
}

type ARIN_Nets struct {
	Net struct {
		InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
		TermsOfUse          string `json:"@termsOfUse"`
		RegistrationDate    struct {
			Value string `json:"$"`
		} `json:"registrationDate"`
		Ref struct {
			Value string `json:"$"`
		} `json:"ref"`
		EndAddress struct {
			Value string `json:"$"`
		} `json:"endAddress"`
		Handle struct {
			Value string `json:"$"`
		} `json:"handle"`
		Name struct {
			Value string `json:"$"`
		} `json:"name"`
		NetBlocks []struct {
			NetBlock struct {
				CidrLength struct {
					Value string `json:"$"`
				} `json:"cidrLength"`
				EndAddress struct {
					Value string `json:"$"`
				} `json:"endAddress"`
				Description struct {
					Value string `json:"$"`
				} `json:"description"`
				Type struct {
					Value string `json:"$"`
				} `json:"type"`
				StartAddress struct {
					Value string `json:"$"`
				} `json:"startAddress"`
			} `json:"netBlock"`
		} `json:"netBlocks"`
		Resources struct {
			InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
			TermsOfUse          string `json:"@termsOfUse"`
			LimitExceeded       struct {
				Limit string `json:"@limit"`
				Value string `json:"$"`
			} `json:"limitExceeded"`
		} `json:"resources"`
		OrgRef struct {
			Handle string `json:"@handle"`
			Name   string `json:"@name"`
			Value  string `json:"$"`
		} `json:"orgRef"`
		ParentNetRef struct {
			Handle string `json:"@handle"`
			Name   string `json:"@name"`
			Value  string `json:"$"`
		} `json:"parentNetRef"`
		StartAddress struct {
			Value string `json:"$"`
		} `json:"startAddress"`
		UpdateDate struct {
			Value string `json:"$"`
		} `json:"updateDate"`
		Version struct {
			Value string `json:"$"`
		} `json:"version"`
	} `json:"net"`
}

type ARIN_Net struct {
	Net struct {
		InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
		TermsOfUse          string `json:"@termsOfUse"`
		RegistrationDate    struct {
			Value string `json:"$"`
		} `json:"registrationDate"`
		Ref struct {
			Value string `json:"$"`
		} `json:"ref"`
		EndAddress struct {
			Value string `json:"$"`
		} `json:"endAddress"`
		Handle struct {
			Value string `json:"$"`
		} `json:"handle"`
		Name struct {
			Value string `json:"$"`
		} `json:"name"`
		NetBlocks struct {
			NetBlock struct {
				CidrLength struct {
					Value string `json:"$"`
				} `json:"cidrLength"`
				EndAddress struct {
					Value string `json:"$"`
				} `json:"endAddress"`
				Description struct {
					Value string `json:"$"`
				} `json:"description"`
				Type struct {
					Value string `json:"$"`
				} `json:"type"`
				StartAddress struct {
					Value string `json:"$"`
				} `json:"startAddress"`
			} `json:"netBlock"`
		} `json:"netBlocks"`
		Resources struct {
			InaccuracyReportURL string `json:"@inaccuracyReportUrl"`
			TermsOfUse          string `json:"@termsOfUse"`
			LimitExceeded       struct {
				Limit string `json:"@limit"`
				Value string `json:"$"`
			} `json:"limitExceeded"`
		} `json:"resources"`
		OrgRef struct {
			Handle string `json:"@handle"`
			Name   string `json:"@name"`
			Value  string `json:"$"`
		} `json:"orgRef"`
		ParentNetRef struct {
			Handle string `json:"@handle"`
			Name   string `json:"@name"`
			Value  string `json:"$"`
		} `json:"parentNetRef"`
		StartAddress struct {
			Value string `json:"$"`
		} `json:"startAddress"`
		UpdateDate struct {
			Value string `json:"$"`
		} `json:"updateDate"`
		Version struct {
			Value string `json:"$"`
		} `json:"version"`
	} `json:"net"`
}

func LookupOrgNets(org string) ([]string, error) {
	handles := []string{}

	safe_org := url.QueryEscape(org)
	u := fmt.Sprintf("http://whois.arin.net/rest/org/%s/nets", safe_org)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return handles, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return handles, err
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return handles, err
	}

	var nets ARIN_OrgNets

	if err := json.Unmarshal(content, &nets); err == nil {
		for i := range nets.Nets.NetRef {
			handles = append(handles, nets.Nets.NetRef[i].Handle)
		}
	} else {
		// Try to decode as a single-net organization
		var net ARIN_OrgNet
		if err := json.Unmarshal(content, &net); err != nil {
			return handles, err
		}

		handles = append(handles, net.Nets.NetRef.Handle)
	}

	return handles, nil
}

func LookupNetCidrs(handle string) ([]string, error) {
	cidrs := []string{}

	safe_handle := url.QueryEscape(handle)
	u := fmt.Sprintf("http://whois.arin.net/rest/net/%s", safe_handle)

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return cidrs, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return cidrs, err
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return cidrs, err
	}

	var nets ARIN_Nets

	if err := json.Unmarshal(content, &nets); err == nil {
		for i := range nets.Net.NetBlocks {
			cidrs = append(cidrs, fmt.Sprintf("%s/%s", nets.Net.NetBlocks[i].NetBlock.StartAddress.Value, nets.Net.NetBlocks[i].NetBlock.CidrLength.Value))
		}
	} else {
		// Try to decode as a single-block network
		var net ARIN_Net
		if err := json.Unmarshal(content, &net); err != nil {
			return cidrs, err
		}
		cidrs = append(cidrs, fmt.Sprintf("%s/%s", net.Net.NetBlocks.NetBlock.StartAddress.Value, net.Net.NetBlocks.NetBlock.CidrLength.Value))
	}

	return cidrs, nil
}

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Usage: inetdata-arin-org2nets <org-handle>\n")
		os.Exit(1)
	}

	org := os.Args[1]

	handles, he := LookupOrgNets(org)
	if he != nil {
		log.Fatal("Error: ", he)
		os.Exit(1)
	}

	for i := range handles {
		cidrs, e := LookupNetCidrs(handles[i])
		if e != nil {
			log.Fatal("Error: ", e)
			os.Exit(1)
		}
		fmt.Println(strings.Join(cidrs, "\n"))
	}
}
