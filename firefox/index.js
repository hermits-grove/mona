var nativePort = browser.runtime.connectNative("mona_the_gitdb_cooperative");
var popupPort;

var model = {
  state: "logged_out"
};

function newPopup(port) {
  popupPort = port;
  popupPort.onMessage.addListener(function(msg) {
    console.log("background-script received message");
    if (msg.action === "login") {
      nativePort.postMessage({
	"Login": { "pass": msg.pass }
      });
    } else if (msg.action === "fresh_model") {
      popupPort.postMessage({"action": "updated_model", "model": model});
    } else {
      console.log("unknown action", msg);
    }
  });
}

browser.runtime.onConnect.addListener(newPopup);

/*
Listen for messages from the mona cli.
*/
nativePort.onMessage.addListener((response) => {
  console.log("Received: ", response);
  if (response.Login) {
    if (response.Login.success) {
      model = {
	state: "logged_in"
      };
    } else {
      model = {
	state: "failed_login"
      };
    }
  } else if (response.UnknownError) {
    console.log("something has gone horribly wrong in mona-cli app");
  } else {
    console.log("unkown response varient", response);
  }

  if (popupPort) {
    popupPort.postMessage({action: "received_response"});
  }
});
