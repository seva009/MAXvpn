package main
import (
	"encoding/hex"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
)
func main() {
	data, _ := hex.DecodeString("000000000528bc3a")
	var inner interface{}
	err := msgpack.Unmarshal(data, &inner)
	fmt.Printf("Go Unmarshal: val=%v, type=%T, err=%v\n", inner, inner, err)
}
