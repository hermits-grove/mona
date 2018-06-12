var current_model = null;
var backgroundPort = browser.runtime.connect();


function render_logged_out() {
  console.log("render logged out");
}

function render_failed_login() {
  console.log("render failed login");
  document.querySelector("#loginform")
    .classList.add("wiggle");
  document.querySelector("#loginform  .passinput")
    .classList.add("bad_input");
  setTimeout(() => {
    document.querySelector("#loginform")
      .classList.remove("wiggle");
  }, 500); // 500 comes from mona.css
}

function render_logged_in() {
  console.log("render logged in");
  document.querySelector(".logged_out_prompt")
    .classList.add("animate_away");
  document.querySelector(".image")
    .classList.add("animate_blur");
  document.querySelector(".logged_in_main")
    .classList.add("animate_in");
  document.querySelector(".logged_in_main")
    .classList.remove("hidden");
}

function render() {
  if (current_model === null || current_model.state == "logged_out") {
    render_logged_out();
  } else if (current_model.state == "logged_in") {
    render_logged_in();
  } else if (current_model.state == "failed_login") {
    render_failed_login();
  } else {
    console.log("Unknown state", current_model.state);
  }
}

backgroundPort.onMessage.addListener(function(m) {
  console.log("popup script received a message from background script", m);
  if (m.action === "received_response") {
    backgroundPort.postMessage({action: "fresh_model"});
  } else if (m.action === "updated_model") {
    if (current_model != m.model) {
      current_model = m.model;
      render();
    }
  } else {
    console.log("unknown action", m);
  }
});

backgroundPort.postMessage({action: "fresh_model"});

function login(e) {
  let pass = document.querySelector(".passinput").value;
  backgroundPort.postMessage({"action": "login", "pass": pass});
  e.preventDefault();
};

document
  .querySelector("#loginform")
  .addEventListener("submit", login);
