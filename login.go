package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	AccountsFile = "accounts.txt"
	ServerIP     = "185.255.92.10:4754"
	LocalKey     = "MySuperSecretLocalKeyForEncryption" // 32 bytes for AES-256
)

type Account struct {
	Alias    string
	Username string
	Password string // Encrypted
}

// AES-GCM Şifreleme (Yerel depolama için)
func encryptLocal(plaintext string) (string, error) {
	key := sha256.Sum256([]byte(LocalKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptLocal(ciphertextB64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(LocalKey))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("şifreli metin çok kısa")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func readAccounts(filename string) ([]Account, error) {
	cwd, _ := os.Getwd()
	absPath := filepath.Join(cwd, filename)

	file, err := os.Open(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []Account{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var accounts []Account
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^([^;]+);\s*username:\s*"([^"]+)"\s*password:\s*"([^"]+)"`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			accounts = append(accounts, Account{
				Alias:    matches[1],
				Username: matches[2],
				Password: matches[3],
			})
		}
	}
	return accounts, scanner.Err()
}

func saveAccounts(filename string, accounts []Account) error {
	file, err := os.Create(filename) // Üzerine yazar
	if err != nil {
		return err
	}
	defer file.Close()

	for _, acc := range accounts {
		line := fmt.Sprintf("%s; username: \"%s\" password: \"%s\"\n", acc.Alias, acc.Username, acc.Password)
		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}
	return nil
}

func callCreateHashs(user, pass string) (string, error) {
	cwd, _ := os.Getwd()
	binPath := filepath.Join(cwd, "create_hashs")
	if _, err := os.Stat(binPath); err == nil {
		cmd := exec.Command(binPath, "-u", user, "-p", pass)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", err
		}
		return strings.TrimSpace(out.String()), nil
	}

	scriptPath := filepath.Join(cwd, "create_hashs.go")
	cmd := exec.Command("go", "run", scriptPath, "-u", user, "-p", pass)
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("komut hatası: %v, stderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func sendNettyPacket(conn net.Conn, jsonPayload string) error {
	payloadBytes := []byte(jsonPayload)
	strLen := len(payloadBytes)

	// Paket Yapısı (Netty Object Serialization / Custom)
	packetLen := 4 + strLen

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(packetLen >> 24))
	buf.WriteByte(byte(packetLen >> 16))
	buf.WriteByte(byte(packetLen >> 8))
	buf.WriteByte(byte(packetLen))

	buf.WriteByte(0x05)
	buf.WriteByte(0x74)

	buf.WriteByte(byte(strLen >> 8))
	buf.WriteByte(byte(strLen))

	buf.Write(payloadBytes)
	_, err := conn.Write(buf.Bytes())
	return err
}

func sendLoginFlow(conn net.Conn, jsonPayload string) {
	// ---------------------------------------------------------
	// ADIM 1: 'getHashs' Handshake Gönderimi
	// ---------------------------------------------------------
	fmt.Println("Handshake başlatılıyor...")
	handshakeJson := `{"messageType":"getHashs"}`
	if err := sendNettyPacket(conn, handshakeJson); err != nil {
		fmt.Println("Handshake gönderme hatası:", err)
		return
	}

	// Handshake Cevabını Oku (Büyük veriyi tamamen temizle)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	totalHandshakeBytes := 0
	tempBuf := make([]byte, 65535)

	n, err := conn.Read(tempBuf)
	if err != nil {
		fmt.Println("Handshake ilk okuma başarısız:", err)
	} else {
		totalHandshakeBytes += n
		for {
			conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, err := conn.Read(tempBuf)
			if n > 0 {
				totalHandshakeBytes += n
			}
			if err != nil {
				break
			}
		}
	}
	// Handshake tamamlandı mesajını kaldırdık veya sadeleştirdik
	// fmt.Printf("Handshake tamamlandı (%d bayt alındı)\n", totalHandshakeBytes)

	// ---------------------------------------------------------
	// ADIM 2: 'tryLogin' Gönderimi
	// ---------------------------------------------------------
	fmt.Println("Giriş yapılıyor...")

	// Payload'a yeni satır ekle
	jsonPayload = jsonPayload + "\n"

	if err := sendNettyPacket(conn, jsonPayload); err != nil {
		fmt.Println("Login gönderme hatası:", err)
		return
	}

	response := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err = conn.Read(response)
	if err != nil {
		fmt.Println("Sunucu cevabı okunamadı (veya zaman aşımı):", err)
	}

	if n > 0 {
		rawResp := string(response[:n])
		jsonStart := strings.Index(rawResp, "{")
		jsonEnd := strings.LastIndex(rawResp, "}")

		if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
			jsonStr := rawResp[jsonStart : jsonEnd+1]

			reHash := regexp.MustCompile(`"globalSessionHash":\s*"([^"]+)"`)
			matchesHash := reHash.FindStringSubmatch(jsonStr)

			if len(matchesHash) > 1 {
				fmt.Println("Sunucuya giriş yapıldı.")
				fmt.Printf("Session Hash: %s\n", matchesHash[1]) // Keeping this as it's the result
			} else if strings.Contains(jsonStr, `"message":"4"`) || strings.Contains(jsonStr, `"message":"3"`) {
				fmt.Println("Şifre veya kullanıcı adı yanlış.")
			} else {
				fmt.Println("Bilinmeyen sunucu cevabı.")
			}
		} else {
			fmt.Println("Cevap içinde geçerli JSON bulunamadı.")
		}
	} else {
		fmt.Println("Sunucudan veri gelmedi.")
	}
}

func sendLoginPacket(jsonPayload string) {
	fmt.Println("Sunucuya bağlanılıyor:", ServerIP)
	conn, err := net.DialTimeout("tcp", ServerIP, 30*time.Second)
	if err != nil {
		fmt.Println("Bağlantı hatası:", err)
		return
	}
	defer conn.Close()

	sendLoginFlow(conn, jsonPayload)
}

func main() {
	newFlag := flag.Bool("yeni", false, "Yeni hesap ekle")
	userFlag := flag.String("kullanici", "", "Yeni hesap için kullanıcı adı")
	passFlag := flag.String("sifre", "", "Yeni hesap için şifre")
	flag.Parse()

	accounts, err := readAccounts(AccountsFile)
	if err != nil {
		fmt.Println("Hesaplar okunamadı:", err)
		return
	}

	if *newFlag {
		if *userFlag == "" || *passFlag == "" {
			fmt.Println("Hata: -yeni parametresiyle birlikte -kullanici ve -sifre gereklidir.")
			return
		}

		alias := *userFlag
		encryptedPass, err := encryptLocal(*passFlag)
		if err != nil {
			fmt.Println("Şifreleme hatası:", err)
			return
		}

		found := false
		for i, acc := range accounts {
			if acc.Username == *userFlag {
				accounts[i].Password = encryptedPass
				fmt.Printf("%s hesabı güncellendi.\n", *userFlag)
				found = true
				break
			}
		}

		if !found {
			accounts = append(accounts, Account{
				Alias:    alias,
				Username: *userFlag,
				Password: encryptedPass,
			})
			fmt.Printf("Yeni hesap eklendi: %s\n", *userFlag)
		}

		if err := saveAccounts(AccountsFile, accounts); err != nil {
			fmt.Println("Hesaplar kaydedilirken hata oluştu:", err)
		}
		return
	}

	if len(accounts) == 0 {
		fmt.Println("Kayıtlı hesap bulunamadı. Eklemek için: ./login -yeni -kullanici <ad> -sifre <parola>")
		return
	}

	fmt.Println("Lütfen giriş yapılacak hesabı seçin:")
	for i, acc := range accounts {
		fmt.Printf("%d. %s\n", i+1, acc.Username)
	}

	var choice int
	fmt.Print("Seçiminiz: ")
	_, err = fmt.Scanln(&choice)
	if err != nil || choice < 1 || choice > len(accounts) {
		fmt.Println("Geçersiz seçim.")
		return
	}

	selected := accounts[choice-1]

	realPass, err := decryptLocal(selected.Password)
	if err != nil {
		fmt.Println("Şifre çözme hatası:", err)
		return
	}

	fmt.Println("Giriş protokolü oluşturuluyor...")
	payload, err := callCreateHashs(selected.Username, realPass)
	if err != nil {
		fmt.Println("Payload oluşturma hatası:", err)
		return
	}

	sendLoginPacket(payload)
}
