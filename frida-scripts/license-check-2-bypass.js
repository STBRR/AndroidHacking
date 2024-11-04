Java.perform(() => {
    let LicenseManager = Java.use("io.hextree.fridatarget.LicenseManager");
    LicenseManager["isLicenseStillValid"].implementation = function (context, unixTimestamp) {
    console.log(`LicenseManager.isLicenseStillValid is called: context=${context}, unixTimestamp=${unixTimestamp}`);
    return this["isLicenseStillValid"](context, 1672531260);
    };
})

console.log("License Check Bypass #2 Script Loaded.")