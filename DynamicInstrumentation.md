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
Frida can be used to 'hook' into the `android.app.Activity` class to output which activity we are currently using.

```javascript
Java.perform(() => {
    let ActivityClass = Java.use("android.app.Activity");
    ActivityClass.onResume.implementation = function() {
        console.log("Activity resumed:", this.getClass().getName());
        this.onResume();
    }
})
```

This code snipped will overwrite the `onResume` implementation within the `android.app.Activity` class and log the current name of the activity to the console
then return to the original `onResume` with `this.onResume()` 

We notice when we click around that our script does not update but only shows 'MainActivity'.
This is because we need to trace the fragments that are in our application.

A fragment by definition is a reusable portion of your app's UI so when we are navigating around it can
be helpful to trace these calls to.

```javascript
Java.perform(() => {
    let FragmentClass = Java.use("androidx.fragment.app.Fragment");
    FragmentClass.onStart.implementation = function() {
        console.log("[*] Fragment Started:", this.getClass().getName());
        this.onStart();
    }
})
```

Here we override the implementation of the `Fragment.onStart()` method to console. 

# Tracing with Frida

## Frida-Trace

- `frida-trace` allows us to directly trace function calls within Applications
- This needs to instrument each function so we need to tell Frida which functions we are interested in.

We can tell Frida which functions we want to trace with the following syntax:

```
classname!methodname
```

Frida supports Wildcars so we can use the following to match all methods in all classes within the application.

```
io.hextree.*!*
```

This in action would look like

```
$ frida-trace -U -j 'io.hextree.*!*' FridaTarget
```

With the command we can see that it will start tracing X amount of functions. Even though we navigate around the 
app, some functions will not be traced. This is because the functions were not loaded when we initiated `frida-trace`. By exiting Frida and re-running the command. We'll be able to trace more functions and see what happens.

Within the 'Tracing' fragment. If we click a button with `frida-trace` open we can get the following output in our console.

```
  3323 ms  TraceButtonFragment$1.onClick("<instance: android.view.View, $className: com.google.android.material.button.MaterialButton>")
  3323 ms     | TraceButtonFragment.button_handler_6()
  3324 ms     |    | FlagCryptor.decodeFlag("VUtHe1YtZ254ci1xYmJlLTZ9")
  3324 ms     |    |    | FlagCryptor.decode("VUtHe1YtZ254ci1xYmJlLTZ9")
  3324 ms     |    |    | <= "UKG{V-gnxr-qbbe-6}"
  3324 ms     |    |    | FlagCryptor.rot13("UKG{V-gnxr-qbbe-6}")
  3324 ms     |    |    | <= "HXT{REDACTED}"
  3324 ms     |    | <= "HXT{REDACTED}"
```

This is very useful for when we want to trace a function to see what a button does within an application.

`frida-trace` also allows us to exclude certain classes and methods with the same syntax. Here is an example
with using the `-J` flag.

```
$ frida-trace -U -j 'io.hextree.*!*' -J '*AnnoyingClass*!*' FridaTarget
```

```
  1832 ms  TraceButtonFragment$2.onClick("<instance: android.view.View, $className: com.google.android.material.button.MaterialButton>")
  1832 ms     | TraceButtonFragment.button_handler_5()
  1833 ms     |    | FlagCryptor.decodeFlag("VUtHe1YtZ254ci1xYmJlLTV9")
  1833 ms     |    |    | FlagCryptor.decode("VUtHe1YtZ254ci1xYmJlLTV9")
  1833 ms     |    |    | <= "UKG{V-gnxr-qbbe-5}"
  1833 ms     |    |    | FlagCryptor.rot13("UKG{V-gnxr-qbbe-5}")
  1833 ms     |    |    | <= "HXT{REDACTED}"
  1833 ms     |    | <= "HXT{REDACTED}
```
## Tracing into JNI

- `frida-trace` allows us to trace into native objects by specifying the `-I` option.

This _can_ take some time as Frida will have to instrument all of the methods that are inside of the native library.


Example

```
$ frida-trace -U -I 'libhextree.so' -j 'io.hextree.*!*' FridaTarget
```

```
Started tracing 304 functions. Press Ctrl+C to stop. 
```

```
135523 ms  TraceButtonFragment$4.onClick("<instance: android.view.View, $className: com.google.android.material.button.MaterialButton>")
135524 ms     | TraceButtonFragment.native_call()
135524 ms     |    | NativeLib.$init()
135524 ms     |    | NativeLib.stringFromJNI()
135525 ms     |    |    | Java_io_hextree_NativeLib_stringFromJNI()
135525 ms     |    |    |    | _ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2IDnEEPKc()
135525 ms     |    |    |    |    | _ZNSt6__ndk117__compressed_pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5__repES5_EC2INS_18__default_init_tagESA_EEOT_OT0_()
135525 ms     |    |    |    |    | _ZNSt6__ndk111char_traitsIcE6lengthEPKc()
135525 ms     |    |    |    |    | _ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm()
135525 ms     |    |    |    |    |    | _Znwm()
135525 ms     |    |    |    | _ZN7_JNIEnv12NewStringUTFEPKc()
135525 ms     |    |    |    | _ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev()
135525 ms     |    |    |    |    | _ZdlPv()
135525 ms     |    | <= "HXT{REDACTED}"
135525 ms     | <= "HXT{REDACTED}"
```

## Frida Interception Basics

As we briefly covered previously. Frida can be used to override the implementation of methods and modify return values. This technique is commonly used to bypass SSL pinning in applications.

By using `Java.perform()` we can create an instance of a class and bypass the interception of return values for 
called methods.

In this case our target [APK](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/android-dynamic-instrumentation/FridaTarget.apk) has a Fragment for testing such cases.

```javascript
Java.perform(() => {
    var InterceptionFragment = Java.use("io.hextree.fridatarget.ui.InterceptionFragment");
    InterceptionFragment.function_to_intercept.implementation = function(argument) {
        console.log("Function called with:", argument)
        this.function_to_intercept(argument);
        return "pwnage";
    }
})
```

We change the `.implementation` of the method and change the return value to anything we choose.

There are two License Key checks that need to be solved for this part of the module and these can be found below.

### License Check 1

We can recover the source code via. `jadx-gui` and rewrite the implementation in a Frida script.


```java
public static boolean isLicenseValid() {
    return false;
}
```

```javascript
Java.perform(()=> {
    let LicenseManager = Java.use("io.hextree.fridatarget.LicenseManager");
    LicenseManager.isLicenseValid.implementation = function() {
        console.log("Function has been called.")
        return true;
    }
})

console.log("License Check Bypass #1 Script Loaded.")
```

### License Check 2

```java
public static void isLicenseStillValid(Context context, long unixTimestamp) {
    AlertDialog.Builder builder = new AlertDialog.Builder(context);
    if (unixTimestamp > 1672531261) {
        Log.d("LicenseManager", "The license expired on 01.01.2023.");
        builder.setMessage("License expired.");
    } else {
        builder.setMessage(FlagCryptor.decode("REDACTED"));
    }
    builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
        @Override
        public void onClick(DialogInterface dialog, int id) {
        }
    });
    AlertDialog dialog = builder.create();
    dialog.show();
}
```

```javascript
Java.perform(() => {
    let LicenseManager = Java.use("io.hextree.fridatarget.LicenseManager");
    LicenseManager["isLicenseStillValid"].implementation = function (context, unixTimestamp) {
    console.log(`LicenseManager.isLicenseStillValid is called: context=${context}, unixTimestamp=${unixTimestamp}`);
    return this["isLicenseStillValid"](context, 1672531260);
    };
})

console.log("License Check Bypass #2 Script Loaded.")
```

## The Dice Game

In order for us to win the game we need to roll 5 sixes. Given what we know. 
We can use `frida-trace` along with a frida script to overwrite the return value for the `randomDice()` method.

```java
    public int randomDice() {
        Random random = new Random();
        int randomNumber = random.nextInt(6);
        return randomNumber;
    }

    public void rollDice() {
        boolean won = true;
        for (int i = 0; i < 5; i++) {
            TextView v = (TextView) getView().findViewById(this.diceViewMapping[i]);
            int dice = randomDice();
            if (dice != 5) {
                won = false;
            }
            v.setText(this.diceMapping[dice]);
        }
        if (won) {
            Log.d("DiceGameFragment", "You won!");
            ((TextView) getView().findViewById(R.id.text_dice_winning_status)).setText("You won!");
            ((TextView) getView().findViewById(R.id.text_dice_winning_status)).setTextColor(Color.rgb(0, 255, 0));
            ((TextView) getView().findViewById(R.id.text_dice_flag)).setText(FlagCryptor.decodeFlag("REDACTED"));
            return;
        }
        Log.d("DiceGameFragment", "You lost!!");
        ((TextView) getView().findViewById(R.id.text_dice_winning_status)).setText("You lost!");
        ((TextView) getView().findViewById(R.id.text_dice_winning_status)).setTextColor(Color.rgb(255, 0, 0));
        ((TextView) getView().findViewById(R.id.text_dice_flag)).setText(HttpUrl.FRAGMENT_ENCODE_SET);
    }
```

As `randomDice()` returns a random number. It is trivial to bypass by right clicking the method in `jadx-gui`
and copying as a Frida snippet as seen below. We can modify the implementation and ensure that we will roll
5 sixes.

```javascript
Java.perform(() => {
    let DiceGameFragment = Java.use("io.hextree.fridatarget.ui.DiceGameFragment");
    DiceGameFragment["randomDice"].implementation = function() {
        this["randomDice"]();
        return 5;
    };
})

console.log("Roll Dice Bypass Script has been loaded.")
```

# SSL Validation Bypasses

## SSLContext & Network-Security-Config Bypass

- With Frida we can disable SSL validation or disable SSL pinning. For example to bypass Network Security Config and SSLContext based on cerficiate pinning.

The way we can bypass SSL validation and certificate pinning in Android all depends on how it is implemented. This can be as trivial as modifying the implementation of the method and therefore just disabling it.

Within Android Applications it is common to see the application using `X509TrustManager` for validation SSL certificates.

The demo [application](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/android-dynamic-instrumentation/FridaTarget.apk) that we've been provided has 3 small challenges for us to tackle that surround bypassing SSL Validation and Certificate Pinning.

If we are able to bypassthe SSL validation. The buttons that we press will turn 'Green' to indiciate we have bypassed any validations.

`frida-trace` can be used to check for `checkServerTrust` calls that we can follow to understand what is happening under the hood when we tap the button 
'SSLContext Pinning'


```
$ frida-trace -U -j '*!*checkServerTrusted*' FridaTarget
Instrumenting...
... 
3801 ms  Platform.checkServerTrusted("<instance: javax.net.ssl.X509TrustManager, $className: com.android.org.conscrypt.ConscryptEngineSocket$2>", ["<instance: java.security.cert.X509Certificate, $className: com.android.org.conscrypt.OpenSSLX509Certificate>","<instance: java.security.cert.X509Certificate, $className: com.android.org.conscrypt.OpenSSLX509Certificate>","<instance: java.security.cert.X509Certificate, $className: com.android.org.conscrypt.OpenSSLX509Certificate>"], "GENERIC", "<instance: com.android.org.conscrypt.ConscryptEngine>")
```

We can see that `Platform.checkServerTrusted` is being called but we are not able to see a package name in order for us to use this within a Frida script.
The Frida REPL can be used to use `Java.enumerateMethods()` directory or we can write a small Frida script. The choice is yours.

```javascript
let methods = Java.enumerateMethods("*Platform!*checkServerTrusted*");
console.log(JSON.stringify(methods, null, 2));
```

Yes! - We have obtained the full package name for the method that gets called within the application.

```json
[
  {
    "loader": null,
    "classes": [
      {
        "name": "com.android.org.conscrypt.Platform",
        "methods": [
          "checkServerTrusted"
        ]
      }
    ]
  }
]
```

The final step for bypassing the SSLContext validation is to override the implementation of this function.

```javascript
Java.perform(() => {
    var PlatformClass = Java.use("com.android.org.conscrypt.Platform");
    PlatformClass.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.ConscryptEngine').implementation = function() {
        console.log("checkServerTrusted has been called. - bypassing!")
    }
})

console.log("SSL Pinning Script has been loaded")
```

## OKHTTP3 Bypass

Similar to the previous section. We can use `frida-trace` to trace the function calls and override the implementation of `okhttp3.OkHttpClient$Builder`

```javascript
Java.perform(() => {
    var BuilderClass = Java.use("okhttp3.OkHttpClient$Builder");
    BuilderClass.certificatePinner.implementation = function() {
        console.log("Certificate pinner called");
        return this;
    }
})
```

## Bypassing SSL Pinning with Objection

Objection makes bypassing SSL pinning very simple with a simple command.

We can load up `objection` with 

```
$ objection --gadget io.hextree.fridatarget explore
Using USB device `Android Emulator 5554`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
io.hextree.fridatarget on (google: 13) [usb] #
```

By using the command `android sslpinning disable` we can automatically override the return value for common methods use for SSL pinning and validation.

```
io.hextree.fridatarget on (google: 13) [usb] # android sslpinning disable
(agent) Custom TrustManager ready, overriding SSLContext.init()
(agent) Found okhttp3.CertificatePinner, overriding CertificatePinner.check()
(agent) Found okhttp3.CertificatePinner, overriding CertificatePinner.check$okhttp()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.verifyChain()
(agent) Found com.android.org.conscrypt.TrustManagerImpl, overriding TrustManagerImpl.checkTrustedRecursive()
(agent) Registering job 545414. Type: android-sslpinning-disable
io.hextree.fridatarget on (google: 13) [usb] # (agent) [545414] Called SSLContext.init(), overriding TrustManager with empty one.
(agent) [545414] Called (Android 7+) TrustManagerImpl.checkTrustedRecursive(), not throwing an exception.
(agent) [545414] Called SSLContext.init(), overriding TrustManager with empty one.
(agent) [545414] Called (Android 7+) TrustManagerImpl.checkTrustedRecursive(), not throwing an exception.
(agent) [545414] Called SSLContext.init(), overriding TrustManager with empty one.
```

# 2048

For this exercise we will target a simple '2048' game. The objective of this game is to slide tiles that are the same value in order to reach
the next value. 2,4,8,16,32,64 etc.. until we combine two 1024 tiles.

Our objective is to beat the game by using some Frida wizardy. The first step for this is to patch our APK with `objection`

_Note: This will not need to be done if you're running `frida-server` on the device or if the device is rooted; `magisk_frida`_

```
$ frida-trace -U -j 'io.hextree.*!*' HT2048
 ...
 20128 ms     |    |    | GameActivity.addNumber() 
 20128 ms     |    |    |    | GameActivity.generateNumber()                                                                                                 20128 ms     |    |    |    | <= 2                                      
 20128 ms     |    |    |    | Element.setNumber(2)                                                             
 20128 ms     |    |    |    | Element.drawItem()   
```

We can see that the function `GameActivity.generateNumber()` is called when a new number shows on the screen for us to double.

Let's review this function within `jadx-gui` and see how this is implemented and how we can bypass it with a Frida script.

```java
    public int generateNumber() {
        if (Math.random() <= 0.9d) {
            return 2;
        }
        return 4;
    }
```

The `generateNumber()` method will generate a number and if the number is less than `0.9` then the function will return 2 if not. It'll return 4.
Let's write a Frida script and modify this return value to return `1024` to the game and obtain the flag by combining two `1024` blocks to obtain a `2048` block.

```javascript
Java.perform(() => {
    let GameActivity = Java.use("io.hextree.privacyfriendly2048.activities.GameActivity");
    GameActivity.generateNumber.implementation = function(){
        console.log('generateNumber is called');
        let ret = this.generateNumber();
        console.log('generateNumber ret value is ' + ret);
        return 1024;
    };
})
```