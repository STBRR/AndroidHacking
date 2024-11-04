Java.perform(() => {
    let FlagClass = Java.use("io.hextree.fridatarget.FlagClass");
    let FlagInstance = FlagClass.$new()

    // staticMethod
    let staticMethod = FlagInstance.flagFromStaticMethod();
    console.log("First Flag: " + staticMethod);

    // instanceMethod
    let instanceMethod = FlagInstance.flagFromInstanceMethod();
    console.log("Second Flag " + instanceMethod);

    // flagIfYouCallMeWithSesame
    let sesameMethod = FlagInstance.flagIfYouCallMeWithSesame("sesame");
    console.log("Third Flag: " + sesameMethod);
})