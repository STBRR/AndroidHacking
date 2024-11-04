Java.perform(() => {
    let DiceGameFragment = Java.use("io.hextree.fridatarget.ui.DiceGameFragment");
    DiceGameFragment["randomDice"].implementation = function() {
        let result = this["randomDice"]();
        console.log(`randomDice() has been called with ${result}. Overwritting return value`)
        return 5;
    };
})

console.log("Roll Dice Bypass Script has been loaded.")