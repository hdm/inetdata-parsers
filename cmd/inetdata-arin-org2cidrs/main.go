package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var IsCustomerHandle = regexp.MustCompile(`^C[A-F0-9]{8}$`)

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
		NetBlocks struct {
			NetBlock []struct {
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

	u := ""

	// Organizations are split into Customers and Non-Customers, which
	// determines which API endpoint to use. Fortunately we can tell
	// which one is what based on the naming convention.
	if IsCustomerHandle.Match([]byte(org)) {
		u = fmt.Sprintf("http://whois.arin.net/rest/customer/%s/nets", safe_org)
	} else {
		u = fmt.Sprintf("http://whois.arin.net/rest/org/%s/nets", safe_org)
	}

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

	// No network handles associated with this organization
	if strings.Contains(string(content), "No related resources were found for the handle provided") {
		return handles, nil
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
		for i := range nets.Net.NetBlocks.NetBlock {
			cidrs = append(cidrs, fmt.Sprintf("%s/%s", nets.Net.NetBlocks.NetBlock[i].StartAddress.Value, nets.Net.NetBlocks.NetBlock[i].CidrLength.Value))
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
		fmt.Println("Usage: inetdata-arin-org2nets <org-handle>")
		os.Exit(1)
	}

	org := os.Args[1]

	handles, e := LookupOrgNets(org)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Could not list network handles: %s", e.Error())
		os.Exit(1)
	}

	for i := range handles {
		cidrs, e := LookupNetCidrs(handles[i])
		if e != nil {
			fmt.Fprintf(os.Stderr, "Could not list CIDRs for %s: %s", handles[i], e.Error())
			continue
		}
		fmt.Println(strings.Join(cidrs, "\n"))
	}
}
