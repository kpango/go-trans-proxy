package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"
)

const (
	HttpPort    = ":3128"
	HttpsPort   = ":3130"
	SSLCertFile = "./cert.pem"
	SSLKeyFile  = "./key.pem"
)

type MemoryCache struct {
	mu    sync.RWMutex
	cache map[string]PageData
}

type Cache interface {
	Get(string) (PageData, bool)
	Set(string, PageData) error
	Delete(string)
}

type PageData struct {
	time    time.Time
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

func (c *MemoryCache) passthrough(w http.ResponseWriter, r *http.Request) {

	defer r.Body.Close()

	w.Header().Add("Cache-Control", "max-age=200, must-revalidate, proxy-revalidate")

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		val, ok := c.Get(r.UserAgent() + r.URL.String())
		if ok {
			c.addCacheHeader(w)
			copyHeader(w, val.header)
			for _, cookie := range val.cookies {
				http.SetCookie(w, cookie)
			}
			w.Write(val.body)
			log.Println("cache response")
			return
		}
	}

	r.Header.Del("Accept-Encoding")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil || resp == nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 {
		// TODO redirect処理を入れる
		log.Println("\n\n" + resp.Header["Location"][0] + "\n\n")
		log.Println(resp.Request.URL.String())
		log.Println(resp)
	}

	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Println(err)
		return
	}

	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Headers", "Origin, Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow -Methods", "POST, GET, OPTIONS, PUT, DELETE")

	copyHeader(w, resp.Header)

	for _, cookie := range resp.Cookies() {
		http.SetCookie(w, cookie)
	}

	w.WriteHeader(resp.StatusCode)

	w.Write(contents)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.Set(r.UserAgent()+r.URL.String(), PageData{
			time:    time.Now(),
			status:  resp.StatusCode,
			header:  w.Header(),
			body:    contents,
			cookies: resp.Cookies(),
		})
	}

}

func copyHeader(writer http.ResponseWriter, header http.Header) {
	for key, values := range header {
		writer.Header().Del(key)
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
}

func (c *MemoryCache) addCacheHeader(writer http.ResponseWriter) {
	writer.Header().Set("X-From-Cache", "1")
}

func (c *MemoryCache) Get(key string) (PageData, bool) {
	c.mu.RLock()
	resp, ok := c.cache[key]
	c.mu.RUnlock()
	return resp, ok
}

func (c *MemoryCache) Set(key string, resp PageData) {
	c.mu.Lock()
	c.cache[key] = resp
	c.mu.Unlock()
}

func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	delete(c.cache, key)
	c.mu.Unlock()
}

func (c *MemoryCache) MonitorData(second time.Duration) {
	for {
		go func() {
			for key, value := range c.cache {
				if value.CheckPageExpire() {
					log.Println("cache deleted! key: " + key)
					c.Delete(key)
				}
			}
		}()
		time.Sleep(second * time.Second)
	}
}

func (p *PageData) CheckPageExpire() bool {
	return int(time.Since(p.time).Seconds()) >= 45
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Println("go-trans-proxy server running")

	c := new(MemoryCache)

	if c.cache == nil {
		c.cache = make(map[string]PageData)
	}

	go c.MonitorData(20)

	go func() {
		cert, err := tls.LoadX509KeyPair(SSLCertFile, SSLKeyFile)
		if err != nil {
			log.Println("cetrification Error")
			return
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		httpsServer := &http.Server{
			Addr:      HttpsPort,
			TLSConfig: tlsConfig,
			Handler:   http.HandlerFunc(c.passthrough),
		}
		log.Fatalln(httpsServer.ListenAndServeTLS(SSLCertFile, SSLKeyFile))
	}()

	httpServer := &http.Server{
		Addr:    HttpPort,
		Handler: http.HandlerFunc(c.passthrough),
	}
	log.Fatalln(httpServer.ListenAndServe())
}
