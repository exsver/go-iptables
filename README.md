# go-iptables
Go bindings for iptables

## Examples
### Append Rule

```go
package main

import (
	"log"
	"os"

	"github.com/exsver/go-iptables"
)

// !!! Requires root privileges
//
// Create new chain
// iptables -N AddRuleTest
func main() {
	// Create config: path to iptables bin and name of chain.
	config, err := iptables.NewConfig("/usr/sbin/iptables", "AddRuleTest")
	if err != nil {
		log.Fatal(err)
	}

	// Optional: Set debug logger
	config.SetLogger(log.New(os.Stdout, "Debug: ", 0))

	// Prepare rule config
	rule := iptables.Rule{
		Source:      "192.168.1.10/32",
		Destination: "192.168.1.20/32",
		Jump:        "DROP",
	}

	// Exec iptables
	err = config.Append(rule)
	if err != nil {
		log.Fatal(err)
	}
}
```

### Flush Chain

```go
package main

import (
	"log"
	"os"

	"github.com/exsver/go-iptables"
)

// !!! Requires root privileges
//
// Create and fill new chain
// iptables -N FlushTest
// iptables -A FlushTest -s 192.168.1.1/32 -j ACCEPT
func main() {
	// Create config: path to iptables bin and name of chain.
	config, err := iptables.NewConfig("/usr/sbin/iptables", "FlushTest")
	if err != nil {
		log.Fatal(err)
	}

	// Optional: Set debug logger
	config.SetLogger(log.New(os.Stdout, "Debug: ", 0))

	// Flush rules in Chain FlushTest
	err := config.Flush()
	if err != nil {
		log.Fatal(err)
	}
}
```
