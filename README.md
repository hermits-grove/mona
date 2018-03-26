# Mona - a transparently secure password manager

## _raison d’être_

Why are we trusting third parties with our secrets!? There's no need for trust, we can do better.

First of all, a password manager must be open source. Companies can publish whitepapers on their gigabit length AES keys till the cows come home, I ain't buying! GIVE US CODE! (and reproducible builds pls.)

Second, we've got to figure out sync. If your using an open source password manager and you've created some adhoc sync implementation with rsync that's pretty cool.. but nobodies got time for that. There's got to be something less painful to set up that works for non-techies.

UI. give us something usable

## Enter `Mona`

Mona is a thin layer on top of Git.

_Why Git?_

### We have no need for a custum backend

Open Source and Servers are a bit tricky. If someone dumps a pile of source code on your lap and tells you this is what's running behind this url, who's to know any better? We have to _trust_ this silicon valley cowboy and hope for the best.

There's another way, we don't need a custom backend, passwords are small and modified infrequently, if we store em in little encrypted blob's they'll take up kilobytes. Git'll work fine for us, plus we get decentralized synced storage for free.

### Git is everywhere

Mona is BYOB(ackend). You can host a private git server and tell Mona to use that, or you can point it at one of the many private git hosting services. As long as it speaks Git, Mona don't care.

