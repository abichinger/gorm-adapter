Gorm Adapter
====

[![Go Report Card](https://goreportcard.com/badge/github.com/abichinger/gorm-adapter)](https://goreportcard.com/report/github.com/abichinger/gorm-adapter)
[![Godoc](https://godoc.org/github.com/abichinger/gorm-adapter?status.svg)](https://godoc.org/github.com/abichinger/gorm-adapter)
[![Release](https://img.shields.io/github/release/abichinger/gorm-adapter.svg)](https://github.com/abichinger/gorm-adapter/releases/latest)

Gorm Adapter is the [Gorm](https://gorm.io/gorm) adapter for [FastAC](https://github.com/abichinger/fastac). With this library, Casbin can load policy from Gorm supported database or save policy to it.

Based on [Officially Supported Databases](https://v1.gorm.io/docs/connecting_to_the_database.html#Supported-Databases), The current supported databases are:

- MySQL
- PostgreSQL
- SQL Server
- SqLite3

You may find other 3rd-party supported DBs in Gorm website or other places.

## Installation

    go get github.com/abichinger/gorm-adapter/v3

## Simple Example

```go
package main

import (
	"github.com/abichinger/fastac"
	gormadapter "github.com/abichinger/grom-adapter"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use "fastac_rules" as the default table name.
	// If it doesn't exist, the adapter will create the table automatically.
	dsn := "user:pass@tcp(127.0.0.1:3306)/dbname?charset=utf8mb4&parseTime=True&loc=Local"
  	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	a, _ := gormadapter.NewAdapter(db)
	//a := gormadapter.NewAdapterWithTable(db, "my_tablename") //It is also possible to specify your own table name
	e, _ := fastac.NewEnforcer("examples/rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
