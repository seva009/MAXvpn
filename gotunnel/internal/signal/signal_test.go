package signal

import (
	"encoding/json"
	"testing"
)

func TestParseParticipantID(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		wantVal  interface{}
		wantStr  string
	}{
		{
			name:    "int64",
			input:   int64(1125900261030239),
			wantVal: int64(1125900261030239),
			wantStr: "1125900261030239",
		},
		{
			name:    "json.Number",
			input:   json.Number("1125900261030239"),
			wantVal: int64(1125900261030239),
			wantStr: "1125900261030239",
		},
		{
			name:    "float64",
			input:   float64(1125900261030239),
			wantVal: int64(1125900261030239),
			wantStr: "1125900261030239",
		},
		{
			name:    "scientific string",
			input:   "1.125900261030239e+15",
			wantVal: int64(1125900261030239),
			wantStr: "1125900261030239",
		},
		{
			name:    "normal string",
			input:   "513427806",
			wantVal: int64(513427806),
			wantStr: "513427806",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, strVal := parseParticipantID(tt.input)
			if val != tt.wantVal {
				t.Errorf("val = %v (%T), want %v (%T)", val, val, tt.wantVal, tt.wantVal)
			}
			if strVal != tt.wantStr {
				t.Errorf("strVal = %v, want %v", strVal, tt.wantStr)
			}
		})
	}
}
