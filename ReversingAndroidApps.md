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

We'll obtain the path to the APK on the device with: `adb shell pm path <package_name`

Now we can pull the APK to our machine with: `adb pull /path/to/apk`

## APKTool

Installation of APKTool is straight forward but installation instructions can be found [here](https://apktool.org/docs/install/)

For MacOS and Linux you can pull it down from the repositories.

```
sudo apt -y install apktook
or
brew install apktool
```




