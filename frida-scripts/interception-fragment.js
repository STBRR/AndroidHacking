Java.perform(() => {
    var InterceptionFragment = Java.use("io.hextree.fridatarget.ui.InterceptionFragment");
    InterceptionFragment.function_to_intercept.implementation = function(argument) {
        console.log("Function called with:", argument)
        this.function_to_intercept(argument);
        return "pwnage";
    }
})