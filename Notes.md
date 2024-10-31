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

```java
Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://hextree.io/"));
startActivity(browserIntent);
```

The above code example declares our 'Intention' (Intent) to 'View' (ACTION_VIEW) to the URL: 'https://hextree.io'
If we hand over this Intent object to the Android Operating System, It will figure out which app can handle this. This means that intents can be used to interact with other apps.

- Our Intention to view the URL automatically loads up Google Chrome but how does the Android Operating system know this?
- This again comes down to `AndroidManifest.xml`


```xml
<activity-alias android:name="com.google.android.apps.chrome.Main"
            android:targetActivity="org.chromium.chrome.browser.document.ChromeLauncherActivity"
            android:exported="true">
			...
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                {% if channel in ['stable', 'default'] %}<data android:scheme="googlechrome" />{% endif %}
                <data android:scheme="http" />
                <data android:scheme="https" />
                <data android:scheme="about" />
                <data android:scheme="javascript" />
            </intent-filter>
			...
</activity-alias>
```

Here we can see that in the `AndroidManifest.xml` within Google Chrome. There is an activity-alias with an intent-filter for `android.intent.action.VIEW` along with a set of schemas.
The Android Operating system will automatically search all applications to see if the conditions of our intention match, If so. The application will launch. Displaying our URL.

### Hacking Apps with Intents

In order to hack a target we need to be able to interact with it.

- We want to send malicious input to apps.
- Android Intents are the malicious input that we can send to other apps.

## Receiving Intents

- In order for an application to receive Intents the Activity would need to be 'Exposed'. This is done from within the `AndroidManifest.xml`
- Be sure to check for Exposed/Exported activity when reverse engineering target applications.
- If an activity has been Exported. This means that it is callable and we could interact with it.

Example:

```xml #3,5-7
        <activity
            android:name=".SecretActivity"
            android:exported="true" >
            <intent-filter>
                <action android:name="android.intent.action.SEND" />
                <data android:mimeType="text/plain" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
```

For us to be able to receive this intent. We write the following code that will call `getIntent()` and specify the type of `EXTRA_TEXT`.
This is essentially providing functionality to our application so that we can share text to it and whatever text is passed to it from another application will
be displayed in this activity and also logged with LogCat.

- Why would an application send an intent to us?

Because in our `AndroidManifest.xml` document. We specified the category within our Activity as `android.intent.category.DEFAULT` meaning that our Proof of Concept
application will show in the list of Applications when we highlight some text and choose the 'Share' option. 
With `android.intent.action.SEND` we tell the Android OS that our application can be used to handle text sharing.

```java
public class SecretActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secret);

        Intent receivedIntent = getIntent();
        String sharedText = receivedIntent.getStringExtra(Intent.EXTRA_TEXT);

        if(sharedText != null) {
            TextView debugText = findViewById(R.id.debug_text);
            debugText.setText(String.format("Shared: %s", sharedText));
            Log.i("SharedText", sharedText);
        }
    }
}
```

If this Activty handles the intent badly, we could have a vulnerability?. Be sure to think abut how applications handle Intents coming from other applications and their input.

## Decompiling Our Application

- Android applications using decompiled using a tool called [JADX](https://github.com/skylot/jadx)
- JADX is a powerful tool that can allow us to recover the source code, make changes and help us in the process of patching applications for further analysis
- We can build our application using 'Build' -> 'Build Bundle(s) / APK(s) -> 'Build APK(s)
- Signed Bundles for the Play Store compile into an `.aab` rather than a standard `.apk`
- Once the application has been built. This can be dragged into the JADX UI and the decompilation process will start


The first point of interest during the decompilation process will be the `AndroidManifest.xml` file. This gives us a general overview of the application including:
- Activies
- Permissions
- Intent Filters
- Resourse Locations - `strings.xml` etc..

This is the very first step and introduction into reverse engineering Android Applications.


## Debugging with Android Studio

- When creating Android Applications, especially when more complex steps are involved. It makes sense to learn about tools for proper debugging.
- Android Studio debugger is a great first step and can help a lot.
- When debugging you can set breakpoints and then launch the Application in 'Debug' mode for this to take effect.

Once a breakpoint has been hit within Android Studio. We have access to all of the debugging tools such as:

- Stop Debugging (F2)
- Step Over (F8)
- Step Into (F7) - _Allows us to dive into a function call and follow the code path_
- Step Out (SHIFT + F8) - _Allows us to step out of a function that we have stepped into and go back to the original code path_
- Mute Breakpoints - _Ignore any breakpoints temporarily_

When debugging we can alter variable values and tweak other values within the applications memory. This can be useful when troubleshooting issues.

## Sharing App Code via. Git

- Android Studio has integrated support for Git, so we can easily manage our project and upload our code to sites such as GitHub or GitLab
- We can also import Git projects directly into Android Studio for easy debugging.
- To import a project: File -> New -> Project from Version Control -> URL to Project

It may take some time for the project to be imported into Android Studio and the environment set up. Gradle will build the application and pull any dependencies that are required.

Challenge URL: https://github.com/hextreeio/android-challenge1
Challenge Question: _Setup the repository in Android Studio and find the hidden flag_




















