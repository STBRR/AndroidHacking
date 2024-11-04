Java.perform(() => {
    let ExampleClass = Java.use("io.hextree.fridatarget.ExampleClass");
    let ExampleInstance = ExampleClass.$new()

    console.log(ExampleInstance.returnDecryptedString());
    console.log(ExampleInstance.returnDecryptedStringIfPasswordCorrect("VerySecret"));

})