var nativePort = browser.runtime.connectNative("mona_the_gitdb_cooperative");
var popupPort;

var model = {
  state: "logged_out"
};

function newPopup(port) {
  popupPort = port;
  popupPort.onMessage.addListener(function(msg) {
    console.log("background-script received message", msg);
    if (msg.action === "login") {
      nativePort.postMessage({
	"Login": { "pass": msg.pass }
      });
    } else if (msg.action === "fresh_model") {
      popupPort.postMessage({"action": "updated_model", "model": model});
    } else if (msg.action === "account_query") {
      nativePort.postMessage({
	"AccountQuery": { "query": msg.query }
      });
    } else if (msg.action === "get_account") {
      nativePort.postMessage({
	"GetAccount": { "account": msg.account }
      });
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
  console.log("Received from app");
  if (response.Login) {
    if (response.Login.success) {
      model = {
	state: "logged_in",
	query: "",
	accounts: []
      };
    } else {
      model = {
	state: "failed_login"
      };
    }
    if (popupPort) popupPort.postMessage({action: "received_response"});
  } else if (response.AccountQuery) {
    if (model.state != "logged_in") {
      console.log("received account query results but I am not logged in");
    } else {
      model.query = response.AccountQuery.query;
      model.accounts = response.AccountQuery.results;
    }
    if (popupPort) popupPort.postMessage({action: "received_query_response"});
  } else if (response.GetAccount) {
    if (popupPort) {
      popupPort.postMessage({
	action: "recieved_get_account",
	account_name: response.GetAccount.account,
	account_creds: response.GetAccount.creds
      });
    }
  } else if (response.UnknownError) {
    console.log("something has gone horribly wrong in mona-cli app");
  } else {
    console.log("unkown response varient", response);
  }
});
