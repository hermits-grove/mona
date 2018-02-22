//document.body.style.border = "5px solid red";
// 
 var openpgp = require('openpgp'); // use as CommonJS, AMD, ES6 module or via window.openpgp
// 
 openpgp.initWorker({ path:'openpgp.worker.js' }); // set the relative web worker path
// 
var options = {
    data: 'password', // input as Uint8Array (or String)
    passwords: ['secret stuff'],              // multiple passwords possible
    armor: true                              // don't ASCII armor (for Uint8Array output)
};

openpgp.encrypt(options).then(function(ciphertext) {
  // get raw encrypted packets as Uint8Array
  console.log(JSON.stringify(ciphertext));;
  return ciphertext.data;
}).then((encrypted) =>{
  console.log(encrypted);
  options = {
    message: openpgp.message.readArmored(encrypted), // parse encrypted bytes
    password: 'secret stuff',                 // decrypt with password
    format: 'utf8'
  };

  openpgp.decrypt(options).then(function(plaintext) {
    console.log(plaintext.data);
  });
});

//var modes = require('js-git/lib/modes');
//var repo = {};
//
//require('js-git/mixins/mem-db')(repo);

