Java.perform(function() {
	console.log("[Lab4] script is running");
	
	var pinFragment = Java.use("com.su.lab4.fragments.PinBypassFragment");
    for (var i = 0; i < 1000000; i++) {
        var pin = i.toString();
        if (pinFragment.checkPin(pin)) {
			console.log(pin);
			break;
        }
    }
	console.log("[Lab4] task1 is solved");
})