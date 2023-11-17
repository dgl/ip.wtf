package main

type IPResult struct {
	// e.g. "192.0.2.1" or "2001:db8::1"
	IP       string     `json:"ip"`
	Location IPLocation `json:"location"`
	AS       struct {
		Number int    `json:"number"`
		Name   string `json:"name"`
		// e.g. "192.0.2.0/24" or "2001:db8::/32"
		// TODO: MaxMind doesn't provide, switch to bgp.tools data source?
		// Announcement string `json:"announcement"`
	} `json:"as"`
}

type IPLocation struct {
	Source         string   `json:"source"`
	Continent      string   `json:"continent"`
	ContinentName  string   `json:"continent_name"`
	Country        string   `json:"country"`
	CountryName    string   `json:"country_name"`
	Region         string   `json:"region"`
	RegionName     string   `json:"region_name"`
	City           string   `json:"city"`
	Latitude       *float64 `json:"latitude,omitempty"`
	Longitude      *float64 `json:"longitude,omitempty"`
	AccuracyRadius *uint16  `json:"accuracy_radius,omitempty"`
	Timezone       struct {
		Name   string `json:"name"`
		Offset *int   `json:"offset,omitempty"`
	} `json:"timezone"`
}
