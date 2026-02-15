package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

func LoadDotEnv(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}

		if _, exists := os.LookupEnv(key); exists {
			continue
		}

		if len(value) >= 2 {
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
				value = strings.Trim(value, "\"")
			} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
				value = strings.Trim(value, "'")
			}
		}

		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set env %s (line %d): %w", key, lineNumber, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", filePath, err)
	}

	return nil
}
