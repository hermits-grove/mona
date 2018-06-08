# sketch

#### onboarding

```
~ mona <any arg besides --help, init and init-from-remote>
!! Tried to load data from mona's home at ~/.mona but had issues.
!!
!! Are you new to mona? to get started run:
!!   `mona init`
!!
!! If you already setup mona elsewhere and you are syncing with git, run:
!!   `mona init-from-remote <git-repo-url>`
```

```
~ mona init
!! Welcome to mona!
!! initializing at ~/.mona, ok? (Y/n): y
!!
!! Pick your master pass-phrase. This phrase will protect
!! all data stored with mona. Make sure it's strong!
!!
!! enter your secret phrase: ******************
!! enter the phrase once more: ******************
!!
!! All set!
!!
!! One last thing.
!! You know have this file in your mona directory:
!!   ~/.mona/entropy_file
!!
!! This file stores some random bits which are mixed
!! with your master passphrase to strengthen your
!! encryption key.
!! 1. This file is stored in plaintext on your device,
!! 2. It's NOT tracked in Git
!! 3. It's up to you to keep it safe
!!
!! The entropy file is here to protect you from nefarious
!! people getting access to the servers storing your data.
!! It gives you an extra 256 bits of entropy on top of
!! the entropy you provide from your master passphrase.
!!
!! Attackers need to know both the entropy file and your
!! master passphrase to decrypt your files.
!!
!! Alright, that's it. Enjoy :)
```

```
~ mona init-from-remote https://github.com/davidrusu/my-private-mona-repo.git
!! remote username: davidrusu
!! remote password: *******************
!! pulling data.... done
!! 
!! Now all that's left is to get your entropy file
!! onto this device. This can be done in a few ways:
!! 1. Copy it to this device via USB or some other trusted medium
!! 2. coming soon: use asymetric encryption to forward the entropy file
```

#### query

``` 
~ mona ls
!! secret phrase: ****
!! checking... nope :( try again
!! secret phrase: ******************
!! checking... yep!
!!!! mona-bash: session key stored in env: MONA_SESSION
news.ycombinator.com
└── davidrusu
file
└── scuttlebutt
    ├── main persona
    └── hacker person
work
└── pagerduty.com
    └── drusu
```

``` 
# subsequent calls from the same bash session use the session_key
> mona news.ycom
news.ycombinator.com/davidrusu
├── user: davidrusu
└── pass: L2yTx7wkPh4x
```

``` 
> mona scutle
!! found multiple entries
file/scuttlebutt/main persona
file/scuttlebutt/hacker persona
> mona scutlemain
file/scuttlebutt/main persona
└── pass: L2yTx7wkPh4x
```

``` 
~ mona cat scutlemaindata > ~/.ssb/secret
~ cat ~/.ssb/secret
# this is your SECRET name.
# this name gives you magical powers.
# with it you can mark your messages so that your friends can verify
# that they really did come from you.
# ...
```

#### write

```
> mona new reddit.com
user: davidrusu
pass: eyH042QTQ6bI
extra fields? (enter to skip): 

> mona reddit
reddit.com
├── user: davidrusu
└── pass: eyH042QTQ6bI

> mona store file/plans/evil.md ~/evil.md
stored 80237 bytes at file/plans/evil.md
```

