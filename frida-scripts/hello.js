console.log("Hello from the script");
console.log("Test");

console.log(1);

var androidVersion = parseInt(Java.androidVersion);

if (androidVersion > 10) {
  console.log("You're running a version that is newer than 10");
} else {
  console.log("You're running an older version version of Android");
}
