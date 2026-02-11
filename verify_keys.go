package main
import (
"encoding/base64"
"encoding/hex"
"fmt"
)
func main() {
b64 := "sMtQjMMCEuaNqMtHEpGUKSLEGruRivUenEoZegzqe1g="
bytes, _ := base64.StdEncoding.DecodeString(b64)
fmt.Printf("Hex: %s\n", hex.EncodeToString(bytes))
}
