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

  // wiggle animation is 500ms, we remove it after done
  // so that we can add it back if the user enters another bad password
  setTimeout(() => {
    document.querySelector("#loginform")
      .classList.remove("wiggle");
  }, 500);
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

  let input = document.getElementById('queryinput');
  let bounceTime = new Date().getTime();
  input.addEventListener('input', (e) => {
    bounceTime = new Date().getTime();
    let startTime = bounceTime;
    setTimeout(() => {
      if (bounceTime == startTime) {
	backgroundPort.postMessage({action: "account_query", "query": e.target.value});
      }
    }, 500);
  });

  let account_list = document.querySelector("#account_list");
  account_list.innerHTML = ""; // clear the account_list and rebuild it
  for (var account_name of current_model.accounts) {
    let account = document.createElement('div');
    account.classList.add('account');

    let account_thumb =  document.createElement("img");
    account_thumb.classList.add('account_thumbnail');
    account_thumb.setAttribute('src', encodeURI('https://logo.clearbit.com/' + account_name + "?size=48"));
    account_thumb.onerror = function() {
      account_thumb.setAttribute('src', "../icons/mona-48.png");
    };
    account.appendChild(account_thumb);
    account.insertAdjacentHTML(
      'beforeend',
      '<div class="account_name">' + account_name + '</div>'
    );
    let account_state = {
      name: account_name,
      expanded: false
    };

    account.addEventListener('click', function() {
      if (account_state.expanded) {
	account
	  .removeChild(account.querySelector('.account_inner'));
	account_state.expanded = false;
	return;
      }

      let account_inner = document.createElement('div');
      account_inner.setAttribute('id', account_state.name);
      account_inner.classList.add('account_inner');
      account_inner.classList.add('waiting');
      
      backgroundPort.postMessage({
	action: "get_account",
	account: account_state.name
      });
      account.appendChild(account_inner);
      account_state.expanded = true;
    });

    account_list.appendChild(account);
  }
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
      console.log("got updated model", current_model, m.model);
      if ((current_model == null || current_model.state != "logged_in")
	  && m.model.state == "logged_in"
	  && m.model.accounts.length == 0) {
	// query for all accounts
	backgroundPort.postMessage({action: "account_query", "query": ""});
      }
      current_model = m.model;
      render();
    }
  } else if (m.action === "get_account") {
    let account_inner = document.getElementById(m.account_name);
    if (account_inner == null) return;
    account_inner.innerHtml = "";
    account_inner.classList.remove('waiting');
    for (var cred of m.account_creds) {
      let cred_div = document.createElement('div');
      cred_div.classList.add('account_cred');
      cred_div.addEventListener('click', (e) => e.stopPropagation());

      let cred_user = document.createElement('span');
      cred_user.classList.add('account_cred_user');
      cred_user.insertAdjacentHTML('beforeend', '<div class="cred_label">user:</div>');
      cred_user.insertAdjacentHTML('beforeend', '<div class="cred_val">' + cred.user + '</div>');
      cred_div.appendChild(cred_user);

      cred_div.appendChild(document.createElement('br'));
      
      let cred_pass = document.createElement('span');
      cred_pass.classList.add('account_cred_pass');
      cred_pass.insertAdjacentHTML('beforeend', '<div class="cred_label">pass:</div>');
      cred_pass.insertAdjacentHTML('beforeend', '<div class="cred_val">' + cred.pass + '</div>');
      cred_div.appendChild(cred_pass);
      
      account_inner.appendChild(cred_div);
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

document
  .querySelector("#queryform")
  .addEventListener("submit", (e) => e.preventDefault());
