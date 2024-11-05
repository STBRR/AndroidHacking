let methods = Java.enumerateMethods("*Platform!*checkServerTrusted*");
console.log(JSON.stringify(methods, null, 2));