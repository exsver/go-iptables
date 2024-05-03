# go-iptables
Go bindings for iptables

## Examples
### Add Rule

```go
package main

import (
	"log"

	"github.com/exsver/go-iptables"
)

// !!! Requires root privileges
//
// Create new chain
// iptables -N AddRuleTest
func main() {
	config := iptables.Config{
		Path:  "/usr/sbin/iptables",
		Chain: "AddRuleTest",
	}

	rule := iptables.Rule{
		Command:     "append",
		Source:      "192.168.1.10/32",
		Destination: "192.168.1.20/32",
		Jump:        "DROP",
	}

	args, err := rule.GenArgs()
	if err != nil {
		log.Fatal(err)
	}

	err = config.Do(args)
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
	config := iptables.Config{
		Path:  "/usr/sbin/iptables",
		Chain: "FlushTest",
	}

	// Set debug logger
	config.SetLogger(log.New(os.Stdout, "Debug: ", 0))

	// Flush rules in Chain FlushTest
	err := config.Flush()
	if err != nil {
		log.Fatal(err)
	}
}
```
