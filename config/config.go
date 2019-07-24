package main

import (
	"strings"

	"github.com/spf13/viper"
)

var c PGBorgSettings

const DEFAULT_CAPACITY = 5

type BackendHostSetting struct {
	// DB settings
	Name     string
	Port     string
	Username string
	Password string
	Database string

	// Proxy settings
	ProxyPort int
	Capacity  int

	// TODO: add options for the startup message
	Options map[string]string
}

type RockyProxySettings struct {
	// Port that Rocky Proxy will bind to
	HostPort     string
	BackendHosts []*BackendHostSetting
}

func init() {

	pLogger := GetLogInstance()

	// TODO: create some config validation, checking for things like ports defined multiple times
	// TODO: eventually set config to database and only draw from toml if nothing is in the db or some override
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		pLogger.Println(err)
	}

	rockyHostPort := viper.GetString("rocky_proxy_settings.host_port")

	var backendHosts []*BackendHostSetting
	c = RockyProxySettings{
		HostPort:     rockyHostPort,
		BackendHosts: backendHosts,
	}

	settings := viper.AllSettings()
	for setting, _ := range settings {
		if strings.HasPrefix(setting, "backend_") {
			backendHostPort := viper.GetString(setting + ".host_port")
			username := viper.GetString(setting + ".username")
			password := viper.GetString(setting + ".password")
			database := viper.GetString(setting + ".database")
			proxyPort := viper.GetInt(setting + ".proxy_port")
			c.BackendHosts = append(c.BackendHosts, &BackendHostSetting{
				HostName:  strings.TrimLeft(setting, "backend_"),
				HostPort:  backendHostPort,
				Username:  username,
				Password:  password,
				Database:  database,
				ProxyPort: proxyPort,
				Capacity:  DEFAULT_CAPACITY,
			})
		}
	}
}

func GetConfig() RockyProxySettings {
	return c

}

func GetBackendHosts() []*BackendHostSetting {
	return c.BackendHosts
}

func GetBackendHost(hostName string) *BackendHostSetting {
	for _, backend := range c.BackendHosts {
		if backend.HostName == hostName {
			return backend
		}
	}
	return nil
}
