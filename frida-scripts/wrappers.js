var string_class = Java.use("java.lang.String");

string_class.charAt.implementation = (c) => {
    console.log("chatAt has been overridden!");
    return "X";
}

var string_instance = string_class.$new("I am a Java String!");

console.log(string_instance.toString());
console.log(string_instance.charAt(0));