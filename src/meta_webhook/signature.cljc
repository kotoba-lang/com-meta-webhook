(ns meta-webhook.signature
  "JVM-only (see `meta-webhook.async-signature` for the Cloudflare
  Workers/browser counterpart — same sync-vs-async platform split
  `line-messaging.signature`/`async-signature` documents, Web Crypto's
  `subtle.sign` is inherently async).

  Verifies the `X-Hub-Signature-256` header Meta sends on every webhook POST
  — shared verbatim across the WhatsApp Business Cloud API, Messenger
  Platform, and Instagram Messaging (all Meta Graph API products use the
  identical scheme: `sha256=` + hex(HMAC-SHA256(app-secret, raw-body))).
  The raw body bytes (pre-JSON-parse) are required — re-serializing a parsed
  body can reorder keys / change whitespace and silently break
  verification."
  #?(:clj (:import [javax.crypto Mac]
                    [javax.crypto.spec SecretKeySpec])))

#?(:clj
   (defn- bytes->hex [bs]
     (apply str (map (fn [b]
                        (let [h (Integer/toHexString (bit-and (int b) 0xff))]
                          (if (= 1 (count h)) (str "0" h) h)))
                      bs))))

#?(:clj
   (defn hmac-sha256-hex
     "hex(HMAC-SHA256(secret, raw-body)) -- the value after `sha256=` in
     `X-Hub-Signature-256`. `raw-body` is the request body as a String
     (UTF-8)."
     [secret raw-body]
     (let [mac (Mac/getInstance "HmacSHA256")]
       (.init mac (SecretKeySpec. (.getBytes (str secret) "UTF-8") "HmacSHA256"))
       (bytes->hex (.doFinal mac (.getBytes (str raw-body) "UTF-8"))))))

#?(:clj
   (defn valid-signature?
     "`app-secret` (Meta App dashboard → Settings → Basic → App Secret) +
     the raw webhook request body + the `X-Hub-Signature-256` header value
     (INCLUDING the `sha256=` prefix) -- true iff they match. Plain equality,
     not constant-time (same posture/rationale as
     `line-messaging.signature/valid-signature?`'s docstring)."
     [app-secret raw-body x-hub-signature-256]
     (= (str "sha256=" (hmac-sha256-hex app-secret raw-body))
        (str x-hub-signature-256))))
