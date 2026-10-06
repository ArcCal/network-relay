// Interoperability check of a running network-relay against independent
// HTTP/3 implementations: quic-go (classic CONNECT, RFC 9114 §4.4) and
// masque-go (CONNECT-UDP, RFC 9298). It starts its own TCP and UDP echo
// services on 127.0.0.1, so the relay must allow that destination
// (`blocked_destinations = []`, `block_own_addresses = false`).
//
//	RELAY_TEST_PASSWORD=... go run . -relay 127.0.0.1:8443 -name relay.test -ca ca.pem -user alice
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
	password = flag.String("password", os.Getenv("RELAY_TEST_PASSWORD"), "password (or RELAY_TEST_PASSWORD)")
	dataOnly = flag.Bool("data-only", false, "compare data paths against a reference server with different authentication/policy")
	echoHost = flag.String("echo-host", "127.0.0.1", "local echo address (use ::1 to test IPv6 destinations)")
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
		if !conf.RootCAs.AppendCertsFromPEM(pem) {
			must(fmt.Errorf("CA file contains no certificates"))
		}
	}
	return conf
}

func echoServers() (udpAddr, tcpAddr string, closeServers func()) {
	udp, err := net.ListenPacket("udp", net.JoinHostPort(*echoHost, "0"))
	must(err)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := udp.WriteTo(buf[:n], from); err != nil {
				return
			}
		}
	}()
	tcp, err := net.Listen("tcp", net.JoinHostPort(*echoHost, "0"))
	must(err)
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if c.SetDeadline(time.Now().Add(10*time.Second)) != nil {
					return
				}
				if _, err := io.Copy(c, c); err == nil {
					if err := c.(*net.TCPConn).CloseWrite(); err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}
			}()
		}
	}()
	return udp.LocalAddr().String(), tcp.Addr().String(), func() { udp.Close(); tcp.Close() }
}

// CONNECT-UDP with masque-go: datagrams of several sizes come back unchanged.
func udpFlow(ctx context.Context, cc *http3.ClientConn, target, pw string, sizes []int) {
	_, port, _ := net.SplitHostPort(*relay)
	tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s:%s/.well-known/masque/udp/{target_host}/{target_port}/", *name, port))
	req, err := masque.NewRequest(ctx, tmpl, target)
	must(err)
	req.Header().Set("Authorization", authorization(pw))
	conn, rsp, err := masque.NewClientConn(cc).Dial(req)
	if conn != nil {
		defer conn.Close()
	}
	if pw != *password {
		check("CONNECT-UDP with a wrong password", err != nil && rsp != nil && rsp.StatusCode == 404, fmt.Sprint(err))
		return
	}
	if err != nil {
		check("CONNECT-UDP", false, err.Error())
		return
	}
	check("CONNECT-UDP response", rsp.StatusCode == 200 && rsp.Header.Get("Capsule-Protocol") == "?1", rsp.Status)
	// Two simultaneous flows on the same connection must not exchange replies.
	second, _, err := masque.NewClientConn(cc).Dial(req)
	if err != nil {
		check("second CONNECT-UDP flow", false, err.Error())
		return
	}
	defer second.Close()
	conns := []*masque.Conn{conn, second}
	for _, size := range sizes {
		echoed := 0
		for i := 0; i < 50; i++ {
			for flow, c := range conns {
				msg := bytes.Repeat([]byte{byte(i + 64*flow)}, size)
				must(c.SetReadDeadline(time.Now().Add(2 * time.Second)))
				if n, err := c.WriteTo(msg, nil); err != nil || n != len(msg) {
					check("UDP write", false, fmt.Sprint(n, err))
					return
				}
				buf := make([]byte, 70000)
				n, _, err := c.ReadFrom(buf)
				if err == nil {
					if !bytes.Equal(buf[:n], msg) {
						check("UDP integrity / flow isolation", false, fmt.Sprintf("flow %d packet %d size %d", flow, i, size))
						return
					}
					echoed++
				} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					check("UDP read", false, err.Error())
					return
				}
			}
		}
		check(fmt.Sprintf("CONNECT-UDP %d-byte datagrams, two flows", size), echoed >= 90, fmt.Sprintf("%d/100 echoed", echoed))
	}
}

// Classic CONNECT with quic-go: 1 MiB each way, then half-close.
func tcpTunnel(ctx context.Context, cc *http3.ClientConn, target, pw string) {
	str, err := cc.OpenRequestStream(ctx)
	must(err)
	defer str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	defer str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	must(str.SetDeadline(time.Now().Add(10 * time.Second)))
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
	if rsp.StatusCode != 200 {
		return
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	written := make(chan error, 1)
	go func() {
		n, err := str.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		if closeErr := str.Close(); err == nil {
			err = closeErr
		}
		written <- err
	}()
	got, err := io.ReadAll(io.LimitReader(str, int64(len(payload)+1)))
	writeErr := <-written
	check("CONNECT 1 MiB echo and half-close", err == nil && writeErr == nil && bytes.Equal(got, payload), fmt.Sprintf("%d bytes, read %v, write %v", len(got), err, writeErr))
}

// A refused CONNECT: the status and Proxy-Status (RFC 9209) the relay gives.
func refused(ctx context.Context, cc *http3.ClientConn, target string, expected map[int]string) {
	str, err := cc.OpenRequestStream(ctx)
	must(err)
	defer str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	defer str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	must(str.SetDeadline(time.Now().Add(10 * time.Second)))
	req := &http.Request{Method: http.MethodConnect, Host: target, URL: &url.URL{Host: target}, Header: http.Header{}}
	req.Header.Set("Authorization", authorization(*password))
	must(str.SendRequestHeader(req))
	rsp, err := str.ReadResponse()
	if err != nil {
		check("refused CONNECT "+target, false, err.Error())
		return
	}
	status := rsp.Header.Get("Proxy-Status")
	errorType, known := expected[rsp.StatusCode]
	ok := known && bytes.Contains([]byte(status), []byte("error="+errorType))
	check("refused CONNECT "+target, ok, rsp.Status+", Proxy-Status: "+status)
	str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	str.Close()
}

func run() int {
	flag.Parse()
	if *password == "" {
		must(fmt.Errorf("-password is required"))
	}
	udpEcho, tcpEcho, closeServers := echoServers()
	defer closeServers()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, *relay, tlsConfig(), &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	must(err)
	defer qconn.CloseWithError(0, "")
	stop := context.AfterFunc(ctx, func() { qconn.CloseWithError(0, "test deadline") })
	defer stop()
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(qconn)

	udpFlow(ctx, cc, udpEcho, *password, []int{0, 1, 60, 1200, 1300})
	tcpTunnel(ctx, cc, tcpEcho, *password)
	if *dataOnly {
		if failures > 0 {
			return 1
		}
		return 0
	}
	udpFlow(ctx, cc, udpEcho, "wrong password", nil)
	tcpTunnel(ctx, cc, tcpEcho, "wrong password")
	refused(ctx, cc, "127.0.0.1:25", map[int]string{403: "http_request_denied"})
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	must(err)
	closedAddr := closed.Addr().String()
	must(closed.Close())
	refused(ctx, cc, closedAddr, map[int]string{502: "connection_refused"})
	// An uncontrolled system resolver may return a negative answer or time
	// out. Require the matching status/error pair, rather than infer its
	// future behaviour from a separate lookup (which can warm its cache).
	refused(ctx, cc, "nonexistent.invalid:80", map[int]string{502: "dns_error", 504: "dns_timeout"})

	fmt.Printf("%d failed\n", failures)
	if failures > 0 {
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
