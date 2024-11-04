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

