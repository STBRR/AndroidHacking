# Hextree.io | Research Device & Emulator Setup

# Physical Device

- Developer Mode & USB Debugging needs to be enabled before we can debug applications on our device
- Enable this by going into Settings -> About Phone -> Software Information and tapping the build number several times.
- Connect to the PC/Mac via. USB and accept the USB Debugging prompt that is shown on the Android Device.

# Android Emulator

- Included within [Android Studio](https://developer.android.com/studio).
- QEMU Based - Emulates the actual device architecture
- Google Play images do not have root by default, but do have the Google Play Store installed like a real phone
- You can choose between different Android versions, depending on the API level you want to test for.
- Emulating a device can be much slower than running the code directly on a physical device

## Creating an Android Virtual Device (AVD)

When launching Android Studio. Click 'More Actions' and then 'Virtual Device Manager'. You can then create a new virtual device based on real Android phones.
You can download both Google Images along with base Android Images without any Google services installed.

- Google Play Images come with everything that you'd expect a real Android Phone to have
- Google APIs ATD come with all of the standard Google APIs but without the Google Play Store
- It is best to stick to the 'Recommended' images tab and download them there as there can be some incompatibilities between versions and hardware.

# Android Debug Bridge (ADB)

- ADB provides us a gateway to interact and debug a device
- Consists of a client, a server and a daemon (adbd)
- Client and Server run on our PC/Mac whilst the daemon runs on our Android Device
- ADB comes pre-installed with Android Studio, however it can also be installed standalone on Windows & Mac

## Windows

ADB can be found in `C:\Users\USERNAME\AppData\Local\Android\Sdk\platform-tools`
It may be worth adding this to your Environment Variables so that you haven't got to go to this location each time you want to run it

## MacOS

MacOS is much easier as ADB can be installed with: `brew install adb`
Alternatively. The location for the version of ADB that comes bundled with Android Studio can be found at: `~/Library/Android/sdk/platform-tools`

This directory can be added to your PATH variable with: `export PATH="~/Library/Android/sdk/platform-tools:$PATH`
You can put this line in either your `~/.bashrc` or `~/.zshrc` depending on what shell you use.

Running `adb version` can verify which version is installed along with the PATH to the binary.

```
[liam@hades ~]$ adb version
Android Debug Bridge version 1.0.41
Version 33.0.0-8141338
Installed as /usr/local/bin/adb
```

## Useful Commands

The command `adb devices` will give us a list of devices. If there are multiple devices, such as multiple emulators, physical etc..

- `-s` can be specificed to choose the device: `adb -s emulator-1337 shell`
- `-d` can be specified to use a USB device: `adb -d shell`

Using `adb shell` will drop you into a regular Linux shell on the device.

## Transferring Files

Both `adb push` and `adb pull` can be used to push files onto the device and pull used to get files from the device.

```
adb push ~/Desktop/test.txt /sdcard/Downloads/
```

An entire directory can be pulled off the device by specifying the directory in the command. This command will pull the entire contents of Downloads to the current working directory

```
adb pull /sdcard/Downloads
```

## Android Device Explorer

Within Android Studio. It is possible to browse the file system of the device in a nice UI and drag and drop files


## Managing Applications

- Install an application: `adb install /path/to/app.apk`
- List all Installed Packages - Including System Packages: `adb shell pm list packages`
- List only third party Packages: `adb shell pm list packages -3`
- Clear the application data without removing the application: `adb shell pm clear <package_name>`
- List Information such as activities and permissions of a package: `adb shell dumpsys package <package_name>`
- Manually starts the Activity of a specified package: `adb shell am start <package_name>/<activity_name>`
- Uninstalls the specified application: `adb uninstall <package_name>`

More information for `pm` can be found [here](https://developer.android.com/tools/adb#pm)
