Java.perform(() => {
    var PlatformClass = Java.use("com.android.org.conscrypt.Platform");
    PlatformClass.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function() {
        console.log("checkSeverTrusted has been called.")
    }
})

console.log("SSL Pinning Script has been loaded")