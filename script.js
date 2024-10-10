📦
494 /test1.js
✄
Java.perform(() => {
    let StartActivity = Java.use("com.rstgames.durak.StartActivity");
    StartActivity["p"].implementation = function (click_handler, header, positive, negative, cancelable) {
        if (click_handler.$className == "com.rstgames.durak.StartActivity$b") {
            header = "Способ входа:";
            negative = "Токен";
            positive = "Гугл";
        }
        this["p"](click_handler, header, positive, negative, cancelable);
    };
});
