Java.perform(() => {
    let GameActivity = Java.use("io.hextree.privacyfriendly2048.activities.GameActivity");
    GameActivity.generateNumber.implementation = function(){
        console.log('generateNumber is called');
        let ret = this.generateNumber();
        console.log('generateNumber ret value is ' + ret);
        return 1024;
};
})