package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

var commandFormatFlagWrite bool

func format() error {
	optionsList, err := readConfig()
	if err != nil {
		return err
	}
	stdout := os.Stdout
	stderr := os.Stderr
	for _, optionsEntry := range optionsList {
		optionsEntry.options, err = badjson.Omitempty(globalCtx, optionsEntry.options)
		if err != nil {
			return err
		}
		buffer := new(bytes.Buffer)
		encoder := json.NewEncoder(buffer)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(optionsEntry.options)
		if err != nil {
			return E.Cause(err, "encode config")
		}
		outputPath, _ := filepath.Abs(optionsEntry.path)
		if !commandFormatFlagWrite {
			if len(optionsList) > 1 {
				if _, err = io.WriteString(stdout, outputPath+"\n"); err != nil {
					return E.Cause(err, "write output path")
				}
			}
			if _, err = stdout.Write(buffer.Bytes()); err != nil {
				return E.Cause(err, "write output")
			}
			continue
		}
		if bytes.Equal(optionsEntry.content, buffer.Bytes()) {
			continue
		}
		if err = writeFileAtomic(optionsEntry.path, buffer.Bytes()); err != nil {
			return E.Cause(err, "write output")
		}
		if _, err = io.WriteString(stderr, outputPath+"\n"); err != nil {
			return E.Cause(err, "write output path")
		}
	}
	return nil
}

func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".srsc-format-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if _, err = file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
