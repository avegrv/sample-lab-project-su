Java.perform(function() {
	send("script is running");
	var pinFragment = Java.use("com.su.lab4.fragments.PinBypassFragment");
    for (var i = 0; i < 1000000; i++) {
        var pin = i.toString();
        if (pinFragment.checkPin(pin)) {
			send(pin);
			break;
        }
    }
}) 