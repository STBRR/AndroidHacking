# HexTree.io | Dynamic Instrumentation

- Provides a way of conducting dynamic analysis on applications as they're running
- We can modify and intercept the execution flow of applications
- We'll use [Frida](https://frida.re/) for this
	- Frida will inject an Agent into the application
	- Allows us to Trace and Analyse
	- Replace function, modify arguments, return values etc.
- The best way to conduct reverse engineering research is to combine dyamic and static analysis

# Setup

## Installing Frida & Objection

Frida and Objection are both awesome tools that can allow us to tinker with Android applications.
- Frida Installation: `pip3 install frida-tools`
- Objection Installation: `pip3 install objection`

## Patching APKs with Frida

For us to use Frida on an application we can patch the APK with Objection.
Objection will extract, re-pack, align and sign the application, so it is a very fast and easy way to get Frida running.

We can patch an APK and install it onto our device with. The APK for this example can be found [here](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/android-dynamic-instrumentation/FridaTarget.apk)


```
$ objection patchapk -s /path/to/<apk_name>.apk && adb install /path/to/<apk_name>.objection.apk
```


_Note: The application will hang on a blank screen until we launch Frida to connect to it.

```
frida -U ApplicationName
```

We use `-U` here to specify that we want to connect via. USB and once connected the application will load as normal.

```
$ frida -U FridaTarget
     ____
    / _  |   Frida 16.4.10 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4 XL (id=99061FFBA00CJ9)

[Pixel 4 XL::FridaTarget ]->
```

## Running The Frida Sever

An alternative to keep having to patch APKs individually is to run Frida Server on the device via. `adb shell`
This does require a rooted device so keep that in mind. If the device/emulator isn't rooted then you will have to patch the APK

You can obtain `frida-server` from [here](https://github.com/frida/frida/releases)

_Be sure to download the version of Frida Server that matches the same version installed on your machine_

1. Obtain a copy of `frida-server`
2. Unzip the `.xz` package with `xz -d frida-server.xz`
3. Push the executable to the device: `adb push frida-server /data/local/tmp/` - We choose `/tmp` as other areas such as `/sdcard` are commonly mounted as no-exec.
4. Spawn a shell on the device `adb root`
5. Make the file executable and run: `cd /data/local/tmp && chmod +x frida-server && ./frida-server`
6. Connect to the application with `frida -U FridaTarget`

# The Frida REPL & Frida Scripts


## The Frida REPL

The Frida REPL (Read-Eval-Print-Loop) is a JavaScript interpreter, and so we can directly run JavaScript statements.

```javascript
for(var i=0; i<5; i++) { console.log(i); }
```

For multi-line statements, suffix each line with `\` backslash.

```javascript
for(var=0; i<5; i++) {\
	console.log(i);\
}
```

The full JavaScript API documentation for Frida can be found [here](https://frida.re/docs/examples/javascript/)

## Writing Frida Scripts

Most of the time rather than using the REPL. We'll write Frida scripts that are regular JavaScript files that we can load into Frida to help automate tasks.

Scripts can be loaded into Frida with: `frida -U -l script.js <ApplicationName>` but we can also enable/disable auto-reloading on the CLI with `%autoreload on/off`
to manually reload all scripts we can run `%reload` in the REPL.

The following script will parse the current android version on the device and display some output if the `androidVersion` is larger than 10.

```javascript
console.log("Hello from the script");

var androidVersion = parseInt(Java.androidVersion)

if(androidVersion > 10) {
        console.log("You're running a version that is newer than 10");
} else {
        console.log("You're running an older version version of Android");
}
```

```
$ frida -U -l frida-scripts/hello.js FridaTarget
     ____
    / _  |   Frida 16.4.10 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4 XL (id=99061FFBA00CJ9)
Attaching...
Hello from the script
You're running a version that is newer than 10
[Pixel 4 XL::FridaTarget ]->
```

## Instantiating Objects and Calling Methods

One of the available functions on the Java object is `Java.use()` with this we can get a JavaScript wrapper for a Java class.
This wrapper allows us to create instances of that class.

Frida has two fancy methods for creating and disposing of instances with `$new()` and `$dispose()` however the latter is almost
never required as the Garbage Collector should collect any unused instances.

Here is an example of using the REPL to instantiate an object.

```
[Pixel 4 XL::FridaTarget ]-> var string_class = Java.use("java.lang.String")
[Pixel 4 XL::FridaTarget ]-> var string_instance = string_class.$new("I am a string!")
[Pixel 4 XL::FridaTarget ]-> console.log(string_instance)
I am a string!
[Pixel 4 XL::FridaTarget ]-> string_instance.charAt(0)
"I"
[Pixel 4 XL::FridaTarget ]-> string_instance.charAt(5)
"a"
[Pixel 4 XL::FridaTarget ]-> string_instance.charAt(7)
"s"
[Pixel 4 XL::FridaTarget ]-> string_instance.charAt(8)
"t"
```

But this can also be done within a Frida Script.

```javascript
var string_class = Java.use("java.lang.String");
var string_instance = string_class.$new("I am a Java String!");

console.log(string_instance.toString());
console.log(string_instance.charAt(0));
```

If we want to know which classes are actually available that we can use. We can use

1. `Java.enumerateLoadedClassses(callbacks)` - This will call a callback for each class that is loaded
2. `Java.enumerateLoadedClassesSync()` - Will return an array of all the classes that are loaded.

If we decide to use `Java.enumerateLoadedClassesSync()` we will get a really long list of classes.

We can also **replace** the implementation of a method by overwiting it on the class.

```javascript
var string_class = Java.use("java.lang.String");

string_class.charAt.implementation = (c) => {
    console.log("chatAt has been overridden!");
    return "X";
}
```

So that when `.charAt()` gets called. It'll always return `X`

```
$ frida -U -l frida-scripts/wrappers.js FridaTarget
     ____
    / _  |   Frida 16.4.10 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4 XL (id=99061FFBA00CJ9)
Attaching...
I am a Java String!
chatAt has been overridden!
X
```

## Mixing Static and Dynamic Analysis & Java.perform.

Frida is most-powerful when mixed with static analysis techniques. JADX works great with Frida as we can right-click
classes within `jadx-gui` and copy them as a Frida snippet. However using this directly will give us an error saying that the
class cannot be found. This is due to the way our Frida to Java bridge works.

The code that we execute in the REPL and within the Frida command line does not run within the same thread as our application.
The `Java.perform()` function can be used to ensure that the code we want to run is ran inside of the applications thread.

When analysing the application with `jadx-gui` we can see the following ExampleClass

```java
package io.hextree.fridatarget;

/* loaded from: classes6.dex */
public class ExampleClass {
    public String returnDecryptedString() {
        return FlagCryptor.decodeFlag("ViBueiBpcmVsIGZycGhlcnlsIHJhcGVsY2dycSE=");
    }

    public String returnDecryptedStringIfPasswordCorrect(String password) {
        if (password.equals("VerySecret")) {
            return FlagCryptor.decodeFlag("WWhweHZ5bCBWIGpuZiBjbmZmamJlcSBjZWJncnBncnEh");
        }
        return null;
    }
}
```

With a Frida script we can use `Java.perform()` to create an instance of this class and call these methods directly
within the thread of the application.

```javascript
Java.perform(() => {
    let ExampleClass = Java.use("io.hextree.fridatarget.ExampleClass");
    let ExampleInstance = ExampleClass.$new()

    console.log(ExampleInstance.returnDecryptedString());
    console.log(ExampleInstance.returnDecryptedStringIfPasswordCorrect("VerySecret"));

})
```

### Challenge

For this challenge, We need to view the 'FlagClass' and call the methods with Frida to obtain the flags. Given what we know
so far. We can write a Frida script to create a new instance of the class and call the methods:

```javascript
Java.perform(() => {
    let FlagClass = Java.use("io.hextree.fridatarget.FlagClass");
    let FlagInstance = FlagClass.$new()

    // staticMethod
    let staticMethod = FlagInstance.flagFromStaticMethod();
    console.log("First Flag: " + staticMethod);

    // instanceMethod
    let instanceMethod = FlagInstance.flagFromInstanceMethod();
    console.log("Second Flag " + instanceMethod);

    // flagIfYouCallMeWithSesame
    let sesameMethod = FlagInstance.flagIfYouCallMeWithSesame("sesame");
    console.log("Third Flag: " + sesameMethod);
})
```

We can execute this script and obtain the flags

```
$ frida -U -l frida-scripts/first-challenge.js FridaTarget
     ____
    / _  |   Frida 16.4.10 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Pixel 4 XL (id=99061FFBA00CJ9)
Attaching...
First Flag: HXT{REDACTED}
Second Flag HXT{REDACTED}
Third Flag: HXT{REDACTED}
[Pixel 4 XL::FridaTarget ]->
```

## Tracing Activites

It can be helpful during the research process to understand exactly which activity we are interacting with.
Frida can be used to 'hook' into the `android.app.Activity' class to output which activity we are currently using.

```javascript
Java.perform(() => {
    let ActivityClass = Java.use("android.app.Activity");
    ActivityClass.onResume.implementation = function() {
        console.log("Activity resumed:", this.getClass().getName());
        // Call original onResume method
        this.onResume();
    }
})
```

This code snipped will overwrite the `onResume` implementation within the `android.app.Activity` class and log the current name of the activity to the console
then return to the original `onResume` with `this.onResume()` 

We notice when we click around that our script does not update but only shows 'MainActivity'.
