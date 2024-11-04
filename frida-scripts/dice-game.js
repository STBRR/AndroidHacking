Java.perform(() => {
    let DiceGameFragment = Java.use("io.hextree.fridatarget.ui.DiceGameFragment");
    DiceGameFragment["randomDice"].implementation = function() {
        this["randomDice"]();
        return 5;
    };
})

console.log("Roll Dice Bypass Script has been loaded.")