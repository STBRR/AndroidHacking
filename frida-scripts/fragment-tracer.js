Java.perform(() => {
    let FragmentClass = Java.use("androidx.fragment.app.Fragment");
    FragmentClass.onStart.implementation = function() {
        console.log("[*] Fragment Started:", this.getClass().getName());
        // Call original onResume method
        this.onStart();
    }
})