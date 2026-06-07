package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ContactForm struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Service string `json:"service"`
	Message string `json:"message"`
}

type ResendEmail struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Html    string   `json:"html"`
	ReplyTo string   `json:"reply_to,omitempty"`
}

type IncomingEmailWebhook struct {
	Type string `json:"type"`
	Data struct {
		From      string   `json:"from"`
		To        []string `json:"to"`
		Subject   string   `json:"subject"`
		Text      string   `json:"text"`
		Html      string   `json:"html"`
		CreatedAt string   `json:"created_at"`
	} `json:"data"`
}

func handleContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	form := ContactForm{
		Name:    r.FormValue("name"),
		Email:   r.FormValue("email"),
		Company: r.FormValue("company"),
		Service: r.FormValue("service"),
		Message: r.FormValue("message"),
	}

	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Println("RESEND_API_KEY not set")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	company := form.Company
	if company == "" {
		company = "Not specified"
	}

	htmlBody := fmt.Sprintf(`
		<h2>New quote request</h2>
		<p><strong>Name:</strong> %s</p>
		<p><strong>Email:</strong> %s</p>
		<p><strong>Company:</strong> %s</p>
		<p><strong>Project type:</strong> %s</p>
		<p><strong>Message:</strong></p>
		<p>%s</p>
	`, form.Name, form.Email, company, form.Service, form.Message)

	email := ResendEmail{
		From:    "Menta Systems <contact@mentasystems.com>",
		To:      []string{"hello@mentasystems.com"},
		Subject: fmt.Sprintf("New request: %s - %s", form.Service, form.Name),
		Html:    htmlBody,
	}

	jsonData, err := json.Marshal(email)
	if err != nil {
		log.Printf("Error marshaling email: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		http.Error(w, "Error sending message", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("Resend API error: %d", resp.StatusCode)
		http.Error(w, "Error sending message", http.StatusInternalServerError)
		return
	}

	// Redirect back to the page with success
	http.Redirect(w, r, "/?sent=1#contact", http.StatusSeeOther)
}

func verifyWebhookSignature(body []byte, msgId, signature, timestamp, secret string) bool {
	// Svix signature format: msgId.timestamp.body
	signedContent := fmt.Sprintf("%s.%s.%s", msgId, timestamp, string(body))

	// Secret is base64 encoded after "whsec_" prefix
	secretBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		log.Printf("Error decoding secret: %v", err)
		return false
	}

	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(signedContent))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Signature header contains multiple signatures like "v1,sig1 v1,sig2"
	for _, sig := range strings.Split(signature, " ") {
		parts := strings.SplitN(sig, ",", 2)
		if len(parts) == 2 && parts[1] == expectedSig {
			return true
		}
	}
	return false
}

func handleIncomingEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify webhook signature
	webhookSecret := os.Getenv("RESEND_WEBHOOK_SECRET")
	if webhookSecret != "" {
		svixId := r.Header.Get("svix-id")
		svixTimestamp := r.Header.Get("svix-timestamp")
		svixSignature := r.Header.Get("svix-signature")

		if svixId == "" || svixTimestamp == "" || svixSignature == "" {
			log.Printf("Missing svix headers")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !verifyWebhookSignature(body, svixId, svixSignature, svixTimestamp, webhookSecret) {
			log.Printf("Invalid webhook signature")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var webhook IncomingEmailWebhook
	if unmarshalErr := json.Unmarshal(body, &webhook); unmarshalErr != nil {
		log.Printf("Error parsing webhook: %v", unmarshalErr)
		http.Error(w, "Error parsing webhook", http.StatusBadRequest)
		return
	}

	if webhook.Type != "email.received" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("Received email from %s to %v: %s", webhook.Data.From, webhook.Data.To, webhook.Data.Subject)

	apiKey := os.Getenv("RESEND_API_KEY")
	if apiKey == "" {
		log.Println("RESEND_API_KEY not set")
		http.Error(w, "Server configuration error", http.StatusInternalServerError)
		return
	}

	toAddresses := ""
	for i, addr := range webhook.Data.To {
		if i > 0 {
			toAddresses += ", "
		}
		toAddresses += addr
	}

	htmlBody := webhook.Data.Html
	if htmlBody == "" {
		htmlBody = fmt.Sprintf("<pre>%s</pre>", webhook.Data.Text)
	}

	forwardedHtml := fmt.Sprintf(`
		<div style="background: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 5px;">
			<p><strong>Email forwarded from Menta Systems</strong></p>
			<p><strong>From:</strong> %s</p>
			<p><strong>To:</strong> %s</p>
			<p><strong>Date:</strong> %s</p>
		</div>
		<hr>
		%s
	`, webhook.Data.From, toAddresses, webhook.Data.CreatedAt, htmlBody)

	email := ResendEmail{
		From:    "Menta Systems <contact@mentasystems.com>",
		To:      []string{"kidandcat@gmail.com"},
		Subject: fmt.Sprintf("[Menta Systems] %s", webhook.Data.Subject),
		Html:    forwardedHtml,
		ReplyTo: webhook.Data.From,
	}

	jsonData, err := json.Marshal(email)
	if err != nil {
		log.Printf("Error marshaling email: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error forwarding email: %v", err)
		http.Error(w, "Error forwarding email", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("Resend API error forwarding: %d", resp.StatusCode)
		http.Error(w, "Error forwarding email", http.StatusInternalServerError)
		return
	}

	log.Printf("Email forwarded successfully to kidandcat@gmail.com")
	w.WriteHeader(http.StatusOK)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/api/contact", handleContact)
	http.HandleFunc("/api/webhook/email", handleIncomingEmail)

	fs := http.FileServer(http.Dir("."))
	http.HandleFunc("/gox", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "gox.html")
	})
	http.HandleFunc("/gox.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/gox", http.StatusMovedPermanently)
	})
	http.HandleFunc("/colmena", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "colmena.html")
	})
	http.HandleFunc("/colmena.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/colmena", http.StatusMovedPermanently)
	})
	http.HandleFunc("/fragua", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "fragua.html")
	})
	http.HandleFunc("/fragua.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fragua", http.StatusMovedPermanently)
	})
	// Home automation catalog — intentionally not linked from the root index.
	http.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "home.html")
	})
	http.HandleFunc("/home.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusMovedPermanently)
	})
	http.Handle("/", fs)

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
