# HexTree.io | Reverse Engineering Android Apps

- We'll learn the basics of reversing Android applications.
- Fetch APKs from device, decompilation, patching etc.

# Working with APKs and apktool

- This will cover: Extracting, Patching, Repacking and Decompiling Android applications.


## What is an APK

- Most native Android applications are written in either Java or Kotlin.
- This is then compiled to Java Bytecode by using either `javac` or `kotlinc` compiler
- `javac` and `kotlinc` compile into `.class` file but then `d8` compiles this class file into `classes.dex`
- `classes.dex` contains Davlik bytecode
	- On previous versions of Android this was convered into native code using the Dalvik VM
	- On newer versions of Android this is handled by ART - _Android runtime_
- APKs are really just `.zip` files but contain the following:
	1. `classes.dex`
	2. `AndroidManifest.xml`
	3. Resources - _strings, images, etc._
	4. Signature

## Getting APKs from a Device

First we will find the name of the package that we want to pull off the device. This can be acheived using `adb`
By running `adb shell pm list packages -3` we'll get a list of all third-party/non-Google packages.

We'll obtain the path to the APK on the device: `adb shell pm path <package_name>`

Now we can pull the APK to our machine with: `adb pull /path/to/apk`

## APKTool

- This is one of the best tools for extracting APK tools
- Provides functionalty for re-packing an APK once we've patched it

Installation of APKTool is straight forward but installation instructions can be found [here](https://apktool.org/docs/install/)

For MacOS and Linux you can pull it down from the repositories.

```
sudo apt -y install apktook
or
brew install apktool
```

- Usage: `apktool d /path/to/apk` to decompile an application.
- Note: apktool will also "baksmali" (disassemble) the embedded classes into smali bytecode

Once this process is completed a directory will be created with the name of the package specified.
Within this directory will be the `AndroidManifest.xml` along with a collection of directories.

The **best** place to start looking whne reversing an Android application is the `AndroidManifest.xml`. The first place to check
is all of the 'exported' activities as these can be started with other apps or via. `adb`. Sometimes they can be used
to bypass access controls of Android applications.

### Challenge

- Challenge Question: _Find and start the secret activity_
- Challenge Solution:
	1. Decompile the provided APK with `apktool`
	2. Review the exported activities within `AndroidManifest.xml
	3. Trigger the activity with `adb shell am start -n <package_name/<activity_name>`

## Patching and re-packing APKs with APKTool

- We'll learn about Packing APKs
- Creating a Keystore
- Signing an APK with `jarsigner`
- Troubleshooting Install Errors

What if we want to modify an APK?, such as export an activty ourselves or patch out some checks?

These can be done by editing the code and re-building the application with `apktool b` when inside of the directory
containing all of the decompiled files and directories. This will re-pack our application and be will be written into
the `./dist` folder. However our APK will not be signed so we will need to sign it before we can install it on our device.

```
$ apktool b
I: Using Apktool 2.9.3
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether sources has changed...
I: Smaling smali_classes3 folder into classes3.dex...
I: Checking whether sources has changed...
I: Smaling smali_classes4 folder into classes4.dex...
I: Checking whether sources has changed...
I: Smaling smali_classes5 folder into classes5.dex...
I: Checking whether sources has changed...
I: Smaling smali_classes2 folder into classes2.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Copying libs... (/lib)
I: Copying libs... (/kotlin)
I: Copying libs... (/META-INF/services)
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: ./dist/io.hextree.reversingexample.apk
```

Now that our application is rebuit. Let's attempt to install this directly onto our device.

```
$ adb install dist/io.hextree.reversingexample.apk
Performing Streamed Install
adb: failed to install dist/io.hextree.reversingexample.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Failed to collect certificates from /data/app/vmdl800147236.tmp/base.apk: Attempt to get length of null array]
```

As expected. The installation fails as we need our application to be signed befoe we can install and run it.

- All Android applications needs to be Cryptographically signed so that only the developer and provide updates.
- APKTool re-builds our patched application but does not sign it for us.
- This is where `keytool` comes to our rescuee. - _This is included in the Java JDK_

We'll create a keystore file that will contain our signing key. This will prompt us to set a passowrd for the key
and provide some details, which we can leave blank and just confirm 'yes' at the end.

```
$ keytool -genkey -v -keystore research.keystore -alias research_key -keyalg RSA -keysize 2048 -validity 10000
Enter keystore password:
Re-enter new password:
What is your first and last name?
  [Unknown]:
What is the name of your organizational unit?
  [Unknown]:
What is the name of your organization?
  [Unknown]:
What is the name of your City or Locality?
  [Unknown]:
What is the name of your State or Province?
  [Unknown]:
What is the two-letter country code for this unit?
  [Unknown]:
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
  [no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,000 days
        for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
[Storing research.keystore]
```

Now that we've got:
- A re-packaged APK
- A keystore with our signing key

We can move onto signing the APK with a tool called `jarsigner`

```
$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore research.keystore dist/io.hextree.reversingexample.apk research_key
  [...SNIPPED...]
  signing: classes5.dex
  signing: classes4.dex
  signing: DebugProbesKt.bin

>>> Signer
    X.509, CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    [trusted certificate]

jar signed.

Warning:
The signer's certificate is self-signed.
```

Our APK is now signed so we _should_ be good to install this onto our mobile device.

### Troubleshooting Installation Errors

- **INSTALL_PARSE_FAILED_NO_CERTIFICATES** - There is something wrong with the signature. Maybe you tried to install an unsigned APK or the chosen algorithm (e.g SHA1) gets rejected.
	- Use `jarsigner -verbose -keystore research.keystore app.apk research_key` which will use the default `-sigalg` rather than us specifying one

- **INSTALL_FAILED_INVALID_APK** - This failed to extract the native libraries
	- This error occurs in some versions of `apktool` if the app contains native-libraries. This can be fixed by:
		1. Editing the `AndroidManifest.xml` so that `extractNativeLibs` is set to `true`
		2. Repack with `apktool b` and resign the app with `jarsigner`
- **INSTALL_FAILED_UPDATE_INCOMPATIBLE** - The package signatures do not match.
	- You'll get this message if a version of the app is signed with a different key. Simple solution is to delete the existing app.
- **Failed parse during InstallPackageLI** - This happens on newer apps
	- (Version 30 and above) requires `resources.arsc` to be uncompressed and aligned on a 4-byte boundry
	- Ensure to use the binaries that are within the build tools directory.
	- Run the following: `[...]/build-tools/34.0.0/zipalign -p -f -v 4 ./dist/<apktool_build>.apk aligned.apk`
	- Run the following: `[...]/build-tools/34.0.0/apksigner sign --ks ./research.keystore ./aligned.apk`

# Decompiling Android Applications

## Introduction to Decompiling

Because of features such as reflection. Java applications generally retain all their symbols.

Also because the Dalvik bytecode is relatively high-level, it contains a lot of information on the structure and control
flow of classes. This means that we can get a very good results when decompiling Android applications.

However for this reason it is also very popular for developers to **obfuscate** Android applications, so you will often see
obfuscated apps in the wild.

## Installing JADX

This can be installed via. the GitHub [repo](https://github.com/skylot/jadx?tab=readme-ov-file#download)

## Getting started with JADX

We'll mainly use the `jadx-gui` which can directly import APKs so that we do **not** need to extract the APK with `apktool` first.

JADX directly decompiles into Java and makes navigation through the application very easy. To find the entry-point into
an application we can double-click the class in the `AndroidManifest.xml` to follow its declaration.

### Challenge

- Challenge Question: _Can you find the first password required to unlock the application?_
- Challenge Solution:
	1. Open the `.apk` in `jadx-gui`
	2. View `AndroidManifest.xml`
	3. Examine the code in `MainActivity`

## Resolving String Resources

Strings in Android applications are often not hard-coded, but instead packed into resources. When reviewing if you see code
such as `R.id` or `R.string` it means that a resource is loaded from the resource directory or the `resources.asrc` file

The best way to find the resource is by using the powerful global search of JADX.

## JNI - Java Native Interface

Some Android applications will use functions implemented in native shared objects. You can identify calls into such functions by
the keyword `native`.

This functionality is called JNI - _Java Native Interface_. JADX does not let us decompilee shared objects, instead we need
to use other reverse engineering tools such as Binary Ninja or Ghidra. Command line utilities such as `strings` can also reveal
information on the shared object.

## Saving JADX Projects & Working with the CLI

- JADX projects are saved as `.jadx` file format which contains all of the decompiled sources.
- Great for collaborating as everything is saved in a single file and can be sent to another researcher.
- You can also save all of the decompiled sources to a folder to work with other tools.
- JADX provides exporting the project as a Gradle Project so that you can import this into Android Stuido

JADX also has a powerful CLI that can be used to decompile APKs headless. All documentation for the JADX CLI
can be found [here](https://github.com/skylot/jadx?tab=readme-ov-file#usage)

# Case Study: A Weather App

- A nice, small set of hacking challenges compiled into a single application.
- Let's practice everything that has been learned so far by reversing an example application.
- The APK in-scope for this segment can be found [here](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/reverse-android-apps/biz.binarysolutions.weatherusa.apk)

## Define Research Goals

When doing reverse engineering it is important to define clear research goals to prevent getting lost when exploring.

- Why are you reverse engineer?
- Define your goals for what you want to achieve - In this case:
	- _Where is the data being pulled from?_
	- _What is the purpose of the application?_

> **Focus on your goal, not the code**. If you know you are looking for a specific functionality it is often best to 
search for that functionality instead of trying to understand the overall code and structure of the application.