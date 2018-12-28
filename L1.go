package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/fullsailor/pkcs7"
	"github.com/yaml-2"
)

var crtLocation string = "./new.cer"
var keyLocation string = "./new.key"
var SZipName string = "./szip.szp"

func main() {
	var hash, mode, destination, source string
	flag.StringVar(&mode, "mode", "3", "application mode: Zip, eXtract, Info")
	flag.StringVar(&hash, "hash", "UNDEF", "hash")
	flag.StringVar(&destination, "d", "./unszipped/", "destination to extract to")
	flag.StringVar(&source, "s", ".", "source of the archive")
	flag.Parse()

	switch mode {
	case "1":
		err := PrepareSzp(source)
		if err != nil {
			fmt.Printf("Error! %s\nReason is here:\n%s", err, debug.Stack())
			return
		}
		fmt.Println("Archive's been created")

	case "2":
		fmt.Println("Information:")
		err := info(hash)
		if err != nil {
			fmt.Printf("Error! %s\nReason is here:\n%s", err, debug.Stack())
			return
		}

	case "3":
		err := Extract(destination, hash)
		if err != nil {
			fmt.Printf("Error occured: %s\nReason is here:\n%s", err, debug.Stack())
			return
		}
		fmt.Println(filepath.Join("Extraction's been comleted", destination))

	default:
		fmt.Println("Uknown command. Please read manual and restart the application")
	}
}

func signData(data []byte) (sighed []byte, err error) {
	var signedData *pkcs7.SignedData
	if signedData, err = pkcs7.NewSignedData(data); err != nil {
		return
	}
	var cert tls.Certificate
	if cert, err = tls.LoadX509KeyPair("./new.cer", "./new.key"); err != nil {
		return
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("Не удалось загрузить сертификат")
	}
	rsaKey := cert.PrivateKey
	var rsaCert *x509.Certificate
	if rsaCert, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return
	}
	if err = signedData.AddSigner(rsaCert, rsaKey, pkcs7.SignerInfoConfig{}); err != nil {
		return
	}
	return signedData.Finish()
}

func PrepareSzp(source string) (err error) {
	var yML, metaZip, zipData []byte
	collector := NewFileCollector()
	if err = collector.WalkFiles(source); err != nil {
		return err
	}

	if yML, err = yaml.Marshal(collector.MetaData); err != nil {
		return err
	}

	metaCollector := NewFileCollector()
	if err = metaCollector.PackFile("meta.yaml", bytes.NewReader(yML)); err != nil {
		return
	}

	if metaZip, err = metaCollector.zipData(); err != nil {
		return
	}

	if zipData, err = collector.zipData(); err != nil {
		return
	}

	return makeSzip(metaZip, zipData)
}

func makeSzip(metaZip, dataZip []byte) (err error) {
	resultBuf := new(bytes.Buffer)

	if err = binary.Write(resultBuf, binary.LittleEndian, uint32(len(metaZip))); err != nil {
		return
	}

	if _, err = resultBuf.Write(metaZip); err != nil {
		return
	}

	if _, err = resultBuf.Write(dataZip); err != nil {
		return
	}

	var signedData []byte
	if signedData, err = signData(resultBuf.Bytes()); err != nil {
		return
	}

	if err = ioutil.WriteFile(SZipName, signedData, 0644); err != nil {
		return
	}
	return
}

//------------------------------------------------------------------------------------

//Единица передачи метаданных файла
type FileMeta struct {
	Name           string   `yaml:"name"`
	OriginalSize   uint32   `yaml:"size"`
	CompressedSize uint32   `yaml:"compressed_size"`
	ModTime        string   `yaml:"modify"`
	Sha1Hash       [20]byte `yaml:"hash"`
}

//------------------------------------------------------------------------------------

//Для сбора итогового файла
type FileCollector struct {
	ZipBuf   *bytes.Buffer
	Zip      *zip.Writer
	MetaData []*FileMeta
}

//------------------------------------------------------------------------------------

//Конструктор по умолчанию
func NewFileCollector() *FileCollector {
	buf := new(bytes.Buffer)

	return &FileCollector{
		ZipBuf:   buf,
		Zip:      zip.NewWriter(buf),
		MetaData: make([]*FileMeta, 0, 100),
	}
}

//------------------------------------------------------------------------------------

func (f *FileCollector) WalkFiles(path string) (err error) {
	var files []os.FileInfo
	var fileReader *os.File

	if files, err = ioutil.ReadDir(path); err != nil {
		return err
	}

	for _, file := range files {
		fullPath := filepath.Join(path, "/", file.Name())

		if file.IsDir() {
			if err = f.WalkFiles(fullPath); err != nil {
				return err
			}

		} else {
			header, err := zip.FileInfoHeader(file)
			if err != nil {
				fmt.Println("Couldn't get file's header")
				return err
			}

			fileBytes, err := ioutil.ReadFile(fullPath)
			if err != nil {
				fmt.Println("Unable to obtain bytes from a file")
				return err
			}

			f.AddMeta(header, fullPath, fileBytes)
			if fileReader, err = os.Open(fullPath); err != nil {
				return err
			}

			if err = f.PackFile(fullPath, fileReader); err != nil {
				return err
			}
		}
	}
	return err
}

//------------------------------------------------------------------------------------

func (f *FileCollector) AddMeta(header *zip.FileHeader, fullPath string, fileBytes []byte) {
	f.MetaData = append(f.MetaData, &FileMeta{
		Name:           fullPath,
		OriginalSize:   header.UncompressedSize,
		CompressedSize: header.CompressedSize,
		ModTime:        header.Modified.Format("Mon Jan 2 15:04:05 MST 2006"),
		Sha1Hash:       sha1.Sum(fileBytes)})
	return
}

//------------------------------------------------------------------------------------

func (f *FileCollector) PackFile(filename string, fileReader io.Reader) (err error) {
	var fileWriter io.Writer
	if fileWriter, err = f.Zip.Create(filename); err != nil {
		return err
	}

	if _, err = io.Copy(fileWriter, fileReader); err != nil {
		return err
	}
	return nil
}

//------------------------------------------------------------------------------------

func (f *FileCollector) zipData() (data []byte, err error) {
	if err = f.Zip.Close(); err != nil {
		return
	}

	data = f.ZipBuf.Bytes()
	return
}

//------------------------------------------------------------------------------------

func CheckSzp(szpLocation string, hash string) (error, *pkcs7.PKCS7) {
	szp, err := ioutil.ReadFile(szpLocation)
	if err != nil {
		return err, nil
	}

	sign, err := pkcs7.Parse(szp)
	if err != nil {
		return err, nil
	}

	err = sign.Verify()
	if err != nil {
		return err, nil
	}

	signer := sign.GetOnlySigner()
	if signer == nil {
		return errors.New("Unable to obtain a single signer"), nil
	}

	if hash != "UNDEF" {
		if hash != fmt.Sprintf("%x", sha1.Sum(signer.Raw)) {
			fmt.Println(fmt.Sprintf("%x", sha1.Sum(signer.Raw)))
			return errors.New("ERROR: Certificate hash is corrupted"), nil
		}
	}

	crt, err := tls.LoadX509KeyPair(crtLocation, keyLocation)
	if err != nil {
		return err, nil
	}

	parsedCrt, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return err, nil
	}

	if bytes.Compare(parsedCrt.Raw, signer.Raw) != 0 {
		return errors.New("Certificates don't match"), nil
	}
	return nil, sign
}

//------------------------------------------------------------------------------------

func info(hash string) error {
	err, sign := CheckSzp(SZipName, hash)
	if err != nil {
		return err
	}

	fileMetas, err := GetMeta(sign)
	if err != nil {
		//fmt.Println("ошибка 1")
		return err
	}

	fmt.Println(len(fileMetas))

	for _, file := range fileMetas {
		fmt.Println(file)
	}

	return err
}

//------------------------------------------------------------------------------------

func GetMeta(p *pkcs7.PKCS7) ([]FileMeta, error) {
	//Read meta
	metaSize := int32(binary.LittleEndian.Uint32(p.Content[:4]))
	fmt.Println(metaSize)
	bytedMeta := bytes.NewReader(p.Content[4 : metaSize+4])

	readableMeta, err := zip.NewReader(bytedMeta, bytedMeta.Size())
	if err != nil {
		//fmt.Println("ошибка 2")
		return nil, err
	}

	if len(readableMeta.File) < 1 {
		return nil, errors.New("File doesn't have meta")
	}

	metaCompressed := readableMeta.File[0] //meta.xml

	metaUncompressed, err := metaCompressed.Open()
	if err != nil {
		//fmt.Println("ошибка 3")
		return nil, err
	}
	defer metaUncompressed.Close()

	var fileMetas []FileMeta
	metaUncompressedBody, err := ioutil.ReadAll(metaUncompressed)
	if err != nil {
		//fmt.Println("ошибка 4")
		return nil, err
	}
	err = yaml.Unmarshal(metaUncompressedBody, &fileMetas)
	if err != nil {
		//fmt.Println("ошибка 4")
		return nil, err
	}

	return fileMetas, err
}

//------------------------------------------------------------------------------------

func Extract(destination string, hash string) error {
	err, sign := CheckSzp(SZipName, hash)

	if err != nil {
		return err
	}

	fileMetas, err := GetMeta(sign)
	if err != nil {
		return err
	}

	metaSize := int32(binary.LittleEndian.Uint32(sign.Content[:4]))

	archivedFiles := bytes.NewReader(sign.Content[4+metaSize:])

	err = UnarchiveFiles(archivedFiles, fileMetas, destination)
	if err != nil {
		return err
	}
	return nil
}

//------------------------------------------------------------------------------------

func UnarchiveFiles(archive *bytes.Reader, fileMetas []FileMeta, destination string) error {
	zipReader, err := zip.NewReader(archive, archive.Size())
	if err != nil {
		return err
	}

	// Creating folder to extract to
	if err = os.MkdirAll(destination, 077); err != nil {
		fmt.Println("Couldn't create a folder to extract to")
		return err
	}

	for _, file := range zipReader.File {
		fileInfo := file.FileInfo()
		dirName, _ := filepath.Split(fileInfo.Name())

		if dirName != "" {
			if err = os.MkdirAll(filepath.Join(destination, "/", dirName), 077); err != nil {
				fmt.Println("Couldn't extract a folder")
				return err
			}
		}

		accessFile, err := file.Open() // gives io.ReadCloser
		if err != nil {
			fmt.Println("Unable to access a file")
			return err
		}

		fileGuts, err := ioutil.ReadAll(accessFile) // read file's bytes to buffer
		if err != nil {
			fmt.Println("Unable to read a file")
			return err
		}

		// Verifying hash for each file
		for _, metaData := range fileMetas {
			if metaData.Name == fileInfo.Name() {
				if metaData.Sha1Hash != sha1.Sum(fileGuts) {
					return errors.New(filepath.Join(file.Name, "'s hash is corrupted. The archive can't be fully unszipped"))
				}
			}
		}

		if err = ioutil.WriteFile(filepath.Join(destination, "/", fileInfo.Name()), fileGuts, 077); err != nil {
			return err
		}
	}

	return nil
}
