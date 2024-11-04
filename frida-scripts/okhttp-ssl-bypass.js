Java.perform(() => {
    var BuilderClass = Java.use("okhttp3.OkHttpClient$Builder");
    BuilderClass.certificatePinner.implementation = function() {
        console.log("okhttp3 certificate pinner called - bypassing!");
        return this;
    }
})

console.log("OKHTTP3 SSL Pinning Script has been loaded")