# HexTree.io | Network Interception

- An essential technique for proxying traffic between the application (client) and the server
- Bypassing SSL/Certificate pinning and validation
- Understanding [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- Application Permissions.
- Intercepting Network Requests also includes testing the APIs that applications use for sending and receiving data.
- Special tricks like (ab)using Android VPN features.
- Check out [Your First Android App](YourFirstAndroidApp.md) before proceeding with this module.

# Android Networking Basics

## The 'Internet' Permission

Let's play around with Android networking using the Proof of Concept application that we developed earlier.

In this example we'll attempt to send a HTTP request to 'https://android.com'

The code for performing such an action is shown below.

```java
package com.hextree.networkinterception;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        TextView homeText = findViewById(R.id.home_text);
        homeText.setText("Network Interception ftw.");

        Button homeButton = findViewById(R.id.button);
        homeButton.setText("Send Request");

        homeButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ExecutorService executor = Executors.newSingleThreadExecutor();
                executor.execute(() -> {
                    try {
                        URL url = new URL("https://android.com/");
                        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                        InputStream in = new BufferedInputStream(urlConnection.getInputStream());
                        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line).append('\n');
                        }
                        String result = sb.toString();
                        runOnUiThread(() -> homeText.setText(result));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        });
    }
}
```

By default Android will now permit the usage of a HTTP request as both the 'INTERNET' permission and `usesCleartextTraffic` need to be allowed within the `AndroidManifest.xml` if we do not declare these. We'll get the following exception thrown in Logcat:

```
java.io.IOException: Cleartext HTTP traffic to www.sxpre.me not permitted
```

By changing `http://` to `https://` we get the following error:

```
java.lang.SecurityException: Permission denied (missing INTERNET permission?)
```

This is a fundamental lesson to learn as Android applications need to explicity ask for the permission to access the Internet. If we are researching an application and review the `AndroidManifest.xml` and there is no INTERNET permission provided then we can not waste time in trying to dive further into it.

By adding the 'Internet' permission to our Manifest and adding `usesCleartextTraffic=true` we'll be able to issue the HTTP request.

Re-issuing the HTTP request via. `http://` shows the `HTTP 301` response that wants to redirect us to `https://android.com`

A developer could use TCP sockets to send cleartext traffic without having to allow it in the `AndroidManifest.xml` as 
`usesClearTextTraffic` is an Application-level permission. However an application is not able to use TCP sockets if the INTERNET is not in the Manifest.

It is quite common for Application developers to use a Network Security Config to specify which IP addresses and Domains that the applications are allowed to talk to. Commonly this can be found within the source code of the application at `xml/network_security_config.xml`

## Packet Logging with `tcpdump`

- We'll use Wireshark to analyze the traffic being sent to/from the device.
- TCPDump can be used to capture the traffic into a `.pcap` file
  - TCPDump can be used via. an emulator with the `emulator` binary that comes with the `build-tools`
  - If we have a Physical device we can also use `tcpdump` but will have to 'push' the binary to the device with `adb` and pull the capture file back to our machine for analysis.

Let's start by analyzing the traffic being sent from our emulated device to `https://android.com`.

In order to capture packets we need to obtain the AVD ID of the emulator. With `emulator`.
The AVD Id can be found within the details of the Virtual Device in Android Studio.

Firstly. We'll shutdown our emulator within Android Studio as we are going to start the emulator manually from the command line. The `emulator` binary is found in the PATH where the `build-tools` are installed.

On Windows the binary can be found at:

```
C:\Users\Liam\AppData\Local\Android\Sdk\emulator
```

We can start our AVD with `emulator` and capture traffic with the following command:

```
.\emulator.exe -tcpdump emulator.cap -avd Pixel_4_XL_-_Emulator -noaudio -no-boot-anim
```

The file `emulator.cap` will contain all raw packets sent and received by the Emulator which also includes our application traffic as well.

> In some cases tcpdump does not capture the Wi-Fi interface. If the emulator's packaet capture does not include any HTTP traffic. Try to disable the phone's Wi-Fi.

We are provided with an example APK that makes some network requests. The objective here to to find the Flag value that is in the clear-text response. The application can be downloaded [here](https://storage.googleapis.com/hextree_prod_image_uploads/media/uploads/network-interception/pockethexmap.apk?28572428)

## HTTP Proxy Tool Setup

- There are a range of proxy tools that can be used to intercept traffic. Such as:
  - Burp Suite
  - mitmproxy
  - Fiddler
  - Charles Proxy
  - Caido
  - Proxyman
  - ZAP
  - HTTP Toolit
  
Proxying clear-text HTTP traffic through the mobile device is as simple as modifying the Wi-Fi settings on the device and pointing the proxy to your HTTP listener on your machine.
Be sure to listen on an interface that the mobile device can communicate with.

Most applications will accept a proxy because it is a feature that developers will use to test:
- HTTP Requests
- Libraries that honor the proxy
- Some corporate networks require a proxy for security monitoring purposes.

**What if the Proxy Fails?**

When applications do ignore the proxy settings then we have to use other techniques:
- Patching with `apktool`
- Dynamic Instrumentation

# SSL Interception

## Installing Certificate in User Store

In order for us to be able to intercept TLS/SSL communication, we need the certificate of our proxy tool to be trusted by the device. Via the Android Settings we can easily install a certificate into the "user" CA store.

User certificates are only trusted by apps when:
- The application targets Android 6 (API Level 23) or lower.
- The applications Network Security Config specifically includes "user" certificates

**Example Security Config**
```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
        <certificates src="user" />
    </trust-anchors>
</base-config>
```

**Threat Model Notes**

If an application sends clear-text `http://` traffic we can probably consider this as a security issue. However traffic that can only
be intercepted with a purposely installed certificate is not an issue. By installing a CA we are intentionally "weakening" the security of the device to allow us to decrypt traffic.

## Installing Certificate in System Store

Due to the default Network Security Config rules, most applications only trust "System" certificates. This is the default configuration for applications targeting Android 9 (API 28) and higher is as follows:

```xml
<base-config cleartextTrafficPermitted="false">
    <trust-anchors>
        <certificates src="system" />
    </trust-anchors>
</base-config>
```

In order to install our certificate into the system store, root access is required such as a Rooted Phyical Phone or Rooted Emulator.

On a rooted device we can spawn a root shell with `adb root` or `adb shell` and execute the following to install our Burp Certificate as a 'System' certificate.

```
# Backup the existing system certificates to the user certs folder
cp /system/etc/security/cacerts/* /data/misc/user/0/cacerts-added/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# copy all system certs and our user cert into the tmpfs system certs folder
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Fix any permissions & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

## Android 14 CA System Store Changes
- This method also required root access.
- One-click Solution with [HTTP Toolkit](https://httptoolkit.com/docs/guides/android/#the-android-app).

If we want to do this manually we can run the following script within an `adb shell`

```bash
# Create a separate temp directory, to hold the current certificates
# Otherwise, when we add the mount we can't read the current certs anymore.
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

# Copy out the existing certificates
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Copy the existing certs back into the tmpfs, so we keep trusting them
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Copy our new cert in, so we trust that too
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Update the perms & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Deal with the APEX overrides, which need injecting into each namespace:

# First we get the Zygote process(es), which launch each app
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
# N.b. some devices appear to have both!

# Apps inherit the Zygote's mounts at startup, so we inject here to ensure
# all newly started apps will see these certs straight away:
for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Then we inject the mount into all already running apps, so they
# too see these CA certs immediately:

# Get the PID of every process whose parent is one of the Zygotes:
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
    xargs -n1 ps -o 'PID' -P | \
    grep -v PID
)

# Inject into the mount namespace of each of those apps:
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait # Launched in parallel - wait for completion here

echo "System certificate injected"
```



