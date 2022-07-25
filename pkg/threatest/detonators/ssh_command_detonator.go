package detonators

import (
	"fmt"
	"github.com/hashicorp/go-uuid"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type SSHCommandExecutor struct {
	SSHHostname   string
	SSHUsername   string
	SSHKeyFile    string
	SSHConnection *ssh.Client
}

func NewSSHCommandExecutor(hostname string, username string, keyFile string) (*SSHCommandExecutor, error) {
	executor := &SSHCommandExecutor{
		SSHHostname: hostname,
		SSHUsername: username,
		SSHKeyFile:  keyFile,
	}
	if err := executor.init(); err != nil {
		return nil, err
	}
	return executor, nil
}

func (m *SSHCommandExecutor) init() error {
	var realHostname = m.SSHHostname
	if hostname := ssh_config.Get(m.SSHHostname, "HostName"); hostname != "" && hostname != m.SSHHostname {
		realHostname = hostname
	}

	var sshUser = m.SSHUsername
	if sshUser == "" {
		sshUser = ssh_config.Get(m.SSHHostname, "User")
	}

	var sshKey = m.SSHKeyFile
	if sshKey == "" {
		sshKey = ssh_config.Get(m.SSHHostname, "IdentityFile")
	}

	var sshPort = 22
	if port := ssh_config.Get(m.SSHHostname, "Port"); port != "" {
		sshPort, _ = strconv.Atoi(port)
	}

	sshKey, err := resolveSSHKeyPath(sshKey)
	if err != nil {
		return fmt.Errorf("unable to resolve path of private key at %s: %v", sshKey, err)
	}

	pemBytes, err := ioutil.ReadFile(sshKey)
	if err != nil {
		return fmt.Errorf("unable to read private key file at %s: %v", sshKey, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return fmt.Errorf("unable to parse private key file at %s: %v", sshKey, err)
	}

	var config = &ssh.ClientConfig{
		Config:          ssh.Config{},
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
		Timeout:         10 * time.Second,
	}
	
	fmt.Println("Connecting over SSH")
	sshAddress := net.JoinHostPort(realHostname, strconv.Itoa(sshPort))
	conn, err := ssh.Dial("tcp", sshAddress, config)
	if err != nil {
		return fmt.Errorf("unable to establish SSH connection to %s: %v", sshAddress, err)
	}

	fmt.Println("Connection succeeded")

	m.SSHConnection = conn
	return nil
}

func (m *SSHCommandExecutor) RunCommand(command string) (string, error) {

	session, err := m.SSHConnection.NewSession()
	defer session.Close()
	if err != nil {
		return "", err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", err
	}

	id, _ := uuid.GenerateUUID()
	finalCommand := FormatCommand(command, id)
	println("Running remote command: " + finalCommand)
	if err := session.Run(finalCommand); err != nil {
		return "", err
	}

	return id, nil
}

func resolveSSHKeyPath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		path = filepath.Join(usr.HomeDir, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}
