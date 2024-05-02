# go-iptables
Go bindings for iptables

## Examples
### Flush Chain

```go
package main

import (
	"fmt"
	"github.com/exsver/go-iptables"
)

// !!! Requires root privileges
//
// Create and fill new chain
// iptables -N FlushTest
// iptables -A FlushTest -s 192.168.1.1/32 -j ACCEPT
func main() {
	config := iptables.Config{
		Path:  "/usr/sbin/iptables",
		Chain: "FlushTest",
	}

	// Flush rules in Chain FlushTest
	err := config.Flush()
	fmt.Println(err)
}
```
