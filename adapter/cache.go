package adapter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

type Cache interface {
	Start() error
	Close() error
	LoadBinary(tag string) (*SavedBinary, error)
	SaveBinary(tag string, binary *SavedBinary) error
}

type SavedBinary struct {
	Content     []byte
	LastUpdated time.Time
	LastEtag    string
}

const savedBinaryVersion = 1
const maxUint32 = uint64(^uint32(0))

func (s *SavedBinary) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.Grow(1 + 8 + len(s.Content) + 8 + 4 + len(s.LastEtag))
	if err := buffer.WriteByte(savedBinaryVersion); err != nil {
		return nil, err
	}
	if err := writeBytes(&buffer, s.Content); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix()); err != nil {
		return nil, err
	}
	if err := writeString(&buffer, s.LastEtag); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (s *SavedBinary) UnmarshalBinary(data []byte) error {
	reader := bytes.NewReader(data)
	var version uint8
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return err
	}
	if version != savedBinaryVersion {
		return fmt.Errorf("unknown saved binary version: %d", version)
	}
	content, err := readBytes(reader)
	if err != nil {
		return err
	}
	s.Content = content
	var lastUpdated int64
	if err := binary.Read(reader, binary.BigEndian, &lastUpdated); err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdated, 0)
	s.LastEtag, err = readString(reader)
	if err != nil {
		return err
	}
	return nil
}

func writeBytes(buffer *bytes.Buffer, value []byte) error {
	if uint64(len(value)) > maxUint32 {
		return errors.New("byte slice too large")
	}
	if err := binary.Write(buffer, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	if len(value) == 0 {
		return nil
	}
	_, err := buffer.Write(value)
	return err
}

func readBytes(reader *bytes.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if uint64(size) > uint64(reader.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	if size == 0 {
		return nil, nil
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	return value, nil
}

func writeString(buffer *bytes.Buffer, value string) error {
	if uint64(len(value)) > maxUint32 {
		return errors.New("string too large")
	}
	if err := binary.Write(buffer, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	if len(value) == 0 {
		return nil
	}
	_, err := buffer.WriteString(value)
	return err
}

func readString(reader *bytes.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if uint64(size) > uint64(reader.Len()) {
		return "", io.ErrUnexpectedEOF
	}
	if size == 0 {
		return "", nil
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	return string(value), nil
}
