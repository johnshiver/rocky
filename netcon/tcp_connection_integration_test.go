package netcon

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"

	_ "github.com/lib/pq"
	"github.com/ory/dockertest"
)

var resource *dockertest.Resource

type testDockerImage struct {
	name    string
	version string
	args    []string
}

func TestMain(m *testing.M) {

	testDbImage := testDockerImage{
		name:    "postgres",
		version: "11.4",
		args: []string{
			"POSTGRES_USER=test",
			"POSTGRES_PASSWORD=test",
			"POSTGRES_DB=test",
		},
	}

	// uses default docker, might need some sort of configuration in the future
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	// pull postgres image
	resource, err = pool.Run(testDbImage.name, testDbImage.version, testDbImage.args)
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	resource.Expire(60)

	// check that container is able to open a database connection using the stdlib driver
	if err := pool.Retry(func() error {

		var err error
		db, err := sql.Open("postgres",
			fmt.Sprintf("postgres://test:test@localhost:%s/test?sslmode=disable",
				resource.GetPort("5432/tcp")))
		if err != nil {
			return err
		}
		return db.Ping()

	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func TestConnectTCPSuccess(t *testing.T) {
	_, err := ConnectTCP(resource.GetHostPort("5432/tcp"))
	if err != nil {
		t.Error(err)
	}
}
