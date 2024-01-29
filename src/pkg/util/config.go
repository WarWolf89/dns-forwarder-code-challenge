package util

import (
	"fmt"
	"log/slog"

	"github.com/spf13/viper"
)

type AppConfig struct {
	ServerAddr string `yaml:"serverAddr`
	ServerPort int    `yaml:"serverPort"`
}

func LoadConfig(name string) (*AppConfig, error) {

	var ac AppConfig

	// Set default values
	viper.SetDefault("ServerPort", 1053)

	// Set the name of the config file (without extension)
	viper.SetConfigName(name)

	// Add paths to search for the config file
	viper.AddConfigPath("./config")

	// Read the config file
	err := viper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		slog.Warn("No config file not found. Using default values.")
	} else if err != nil { // Handle other errors that occurred while reading the config file
		return nil, fmt.Errorf("fatal error while reading the config file: %s", err)
	}

	// Bind environment variables with Viper
	viper.AutomaticEnv()

	// Unmarshal the configuration into a Config struct
	if err := viper.Unmarshal(&ac); err != nil {
		return nil, fmt.Errorf("failed marshalling config error: %v", err)
	}
	slog.Info("Config values", "config", ac)
	return &ac, nil
}
