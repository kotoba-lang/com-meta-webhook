(ns meta-webhook.async-signature
  "Cloudflare Workers / browser counterpart to `meta-webhook.signature` — see
  that ns's docstring for the shared-across-Meta-products `X-Hub-Signature-256`
  scheme this verifies, and `line-messaging.async-signature` for why this is
  a plain `.cljs` namespace (Web Crypto's `SubtleCrypto.sign` is
  Promise-based).

  `raw-body` MUST be the exact bytes Meta sent (pre-JSON-parse) — on a
  Cloudflare Worker that means reading `request.text()` BEFORE any
  `request.json()` call (a Request body stream can only be consumed once)."
  )

(defn- ->key [secret]
  (.importKey js/crypto.subtle
              "raw"
              (.encode (js/TextEncoder.) secret)
              #js {:name "HMAC" :hash "SHA-256"}
              false
              #js ["sign"]))

(defn- bytes->hex [^js buf]
  (let [arr (js/Uint8Array. buf)]
    (apply str (map (fn [b] (let [h (.toString b 16)]
                              (if (= 1 (.-length h)) (str "0" h) h)))
                     (array-seq arr)))))

(defn hmac-sha256-hex
  "hex(HMAC-SHA256(secret, raw-body)) -- returns a `js/Promise<string>`."
  [secret raw-body]
  (-> (->key secret)
      (.then (fn [key] (.sign js/crypto.subtle "HMAC" key (.encode (js/TextEncoder.) raw-body))))
      (.then bytes->hex)))

(defn valid-signature?
  "Same contract as `meta-webhook.signature/valid-signature?`, async:
  returns a `js/Promise<boolean>`."
  [app-secret raw-body x-hub-signature-256]
  (-> (hmac-sha256-hex app-secret raw-body)
      (.then (fn [hex] (= (str "sha256=" hex) (str x-hub-signature-256))))))
