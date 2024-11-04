Java.perform(()=> {
    let LicenseManager = Java.use("io.hextree.fridatarget.LicenseManager");
    LicenseManager.isLicenseValid.implementation = function() {
        console.log("Function has been called.")
        return true;
    }
})

console.log("License Check Bypass #1 Script Loaded.")

