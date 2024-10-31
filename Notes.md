# HexTree.io Android Notes

# Android Studio

- Used to develop proof of concept apps for the apps that we want to attack.
- Good to understand the process and perspective of Android Development.
- We don't need to know a lot about app development but it aids in the process of reverse engineering other android apps.
- The official Android Documentation is an excellent resource for a attackers as it can give a developers perspective.

## Creating an Android Project

- Empty Views Project - _Android Studio will automatically download all the required libraries needed for the project_
- Java and Kotlin can both be used to develop the app but historically Android applications were developed in Java.
- Can either use a physical device to run/debug the application or use an AVD within Android Studio

## Application Layout / Structure

- User Interfaces within Android are called 'layouts'
- Android Studio comes with a Graphical layout editor to make changes
- Under the hood these interfacs are just `.xml` files
- Every application has a `AndroidManifest.xml` file that documents the details of the application
	- Label
	- Theme
	- Activities
	- Intents
	- Permissions
- Resources are found in the `res/` directory within the directory structure.

## Graphical Layout View

- Contents of these `.xml` files can be edited as code if you wish.
- Android Studio has a nice layout functionality for positioning components and changing text values etc.

## LogCat

- This is Android's logging system.
- Using `Log.i("tag","text")` can be used to log an _Informational_ event to to LogCat
- Pretty much used to log and see what is happening if the app is logging data.

## Android Resources

- Localization gives developers flexibilty when it comes to providing additional language support
- The default application text can be found in `res/values/strings.xml` - This is the default that the developer expects the language to be
	- `res/values-fr/strings.xml` for French
	- `res/values-ja/strings.xml` for Japanese
- This is not really required during development of our attacks apps but when reverse engineering a target app and see `strings.xml` we can check here for application strings.

# Special Android Features

## Running Applications on a Physical Device
- Running applications from within Android Studio works good enough but we can run them on Physical Devices too!
- This requires the phone to have 'Developer Mode' enabled
        - Tap the 'Build Number' several times. Located in the Settings to enable
        - Connect phone via. USB and Select 'Allow USB Debugging'
- As long as the Applications SDK version if compatible with the Android Version installed on the device. The application will run.
- Within Android Studio the device will be recognised!
        - You can switch between the Emulated and Physical Devices at the top of the Windows

## Intents & Activities
- These are fundamental concept of Android and how applications work
- Intents can be used to interact with other apps, which makes them one of the most important attack surfaces
- An 'Activity' is a single, focused thing that the user can do. Almost all activites interact with the user.
















