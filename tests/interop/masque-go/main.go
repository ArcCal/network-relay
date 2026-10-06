// Interoperability check of a running network-relay against independent
// HTTP/3 implementations: quic-go (classic CONNECT, RFC 9114 §4.4) and
// masque-go (CONNECT-UDP, RFC 9298). It starts its own TCP and UDP echo
// services on 127.0.0.1, so the relay must allow that destination
// (`blocked_destinations = []`, `block_own_addresses = false`).
//
//	go run . -relay 127.0.0.1:8443 -name relay.test -ca ca.pem -user alice -password ...
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

var (
	relay    = flag.String("relay", "127.0.0.1:8443", "relay address")
	name     = flag.String("name", "relay.test", "relay host name, as in its certificate")
	caFile   = flag.String("ca", "", "CA certificate (default: system roots)")
	user     = flag.String("user", "alice", "user name")
	password = flag.String("password", "", "password")
)

var failures int

func check(what string, ok bool, detail string) {
	result := "PASS"
	if !ok {
		result = "FAIL"
		failures++
	}
	fmt.Printf("%s %s: %s\n", result, what, detail)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func authorization(pw string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(*user+":"+pw))
}

func tlsConfig() *tls.Config {
	conf := &tls.Config{ServerName: *name, NextProtos: []string{http3.NextProtoH3}}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		must(err)
		conf.RootCAs = x509.NewCertPool()
		conf.RootCAs.AppendCertsFromPEM(pem)
	}
	return conf
}

func echoServers() (udpAddr, tcpAddr string) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	must(err)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], from)
		}
	}()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return udp.LocalAddr().String(), tcp.Addr().String()
}

// CONNECT-UDP with masque-go: datagrams of several sizes come back unchanged.
func udpFlow(ctx context.Context, cc *http3.ClientConn, target, pw string, sizes []int) {
	_, port, _ := net.SplitHostPort(*relay)
	tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s:%s/.well-known/masque/udp/{target_host}/{target_port}/", *name, port))
	req, err := masque.NewRequest(ctx, tmpl, target)
	must(err)
	req.Header().Set("Authorization", authorization(pw))
	conn, rsp, err := masque.NewClientConn(cc).Dial(req)
	if pw != *password {
		check("CONNECT-UDP with a wrong password", err != nil && rsp != nil && rsp.StatusCode == 404, fmt.Sprint(err))
		return
	}
	if err != nil {
		check("CONNECT-UDP", false, err.Error())
		return
	}
	defer conn.Close()
	check("CONNECT-UDP response", rsp.StatusCode == 200 && rsp.Header.Get("Capsule-Protocol") == "?1", rsp.Status)
	for _, size := range sizes {
		echoed := 0
		for i := 0; i < 50; i++ {
			msg := bytes.Repeat([]byte{byte(i)}, size)
			if _, err := conn.WriteTo(msg, nil); err != nil {
				break
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 70000)
			n, _, err := conn.ReadFrom(buf)
			if err == nil && bytes.Equal(buf[:n], msg) {
				echoed++
			}
		}
		check(fmt.Sprintf("CONNECT-UDP %d-byte datagrams", size), echoed >= 45, fmt.Sprintf("%d/50 echoed", echoed))
	}
}

// Classic CONNECT with quic-go: 1 MiB each way, then half-close.
func tcpTunnel(ctx context.Context, cc *http3.ClientConn, target, pw string) {
	str, err := cc.OpenRequestStream(ctx)
	must(err)
	req := &http.Request{Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target}, Header: http.Header{}}
	req.Header.Set("Authorization", authorization(pw))
	must(str.SendRequestHeader(req))
	rsp, err := str.ReadResponse()
	if err != nil {
		check("CONNECT", false, err.Error())
		return
	}
	if pw != *password {
		check("CONNECT with a wrong password", rsp.StatusCode == 404, rsp.Status)
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return
	}
	check("CONNECT response", rsp.StatusCode == 200, rsp.Status)
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	go func() {
		str.Write(payload)
		str.Close()
	}()
	got, err := io.ReadAll(str)
	check("CONNECT 1 MiB echo and half-close", err == nil && bytes.Equal(got, payload), fmt.Sprintf("%d bytes, error %v", len(got), err))
}

// A refused CONNECT: the status and Proxy-Status (RFC 9209) the relay gives.
func refused(ctx context.Context, cc *http3.ClientConn, target string, want int, errorType string) {
	str, err := cc.OpenRequestStream(ctx)
	must(err)
	req := &http.Request{Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target}, Header: http.Header{}}
	req.Header.Set("Authorization", authorization(*password))
	must(str.SendRequestHeader(req))
	rsp, err := str.ReadResponse()
	if err != nil {
		check("refused CONNECT "+target, false, err.Error())
		return
	}
	status := rsp.Header.Get("Proxy-Status")
	ok := rsp.StatusCode == want && bytes.Contains([]byte(status), []byte("error="+errorType))
	check("refused CONNECT "+target, ok, rsp.Status+", Proxy-Status: "+status)
	str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	str.Close()
}

func main() {
	flag.Parse()
	if *password == "" {
		must(fmt.Errorf("-password is required"))
	}
	udpEcho, tcpEcho := echoServers()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, *relay, tlsConfig(), &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	must(err)
	defer qconn.CloseWithError(0, "")
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qconn)

	udpFlow(ctx, cc, udpEcho, *password, []int{1, 60, 1200, 1300})
	udpFlow(ctx, cc, udpEcho, "wrong password", nil)
	tcpTunnel(ctx, cc, tcpEcho, *password)
	tcpTunnel(ctx, cc, tcpEcho, "wrong password")
	refused(ctx, cc, "127.0.0.1:25", 403, "http_request_denied")
	refused(ctx, cc, "127.0.0.1:1", 502, "connection_refused")
	refused(ctx, cc, "nonexistent.invalid:80", 502, "dns_error")

	fmt.Printf("%d failed\n", failures)
	if failures > 0 {
		os.Exit(1)
	}
}
