# programDatabase
Installation: On hiatus 

In the creation of this is totally just used whatever was on my system to make things automated, pushed to a database,
user notifications for changes, and repeatable/automatable. So installation will be a little interesting issue

![alt text](https://raw.githubusercontent.com/RyanLongVA/programDatabase/master/messingWithDatabase/screenshots/databaseScreen.png)

This is how I enumerate through the list domains
  It starts off with the general information like the count so far in the list, the domain value, and other useful information (Some still being worked on). Then we have our prompt which works with... 
    
    > next(n) // next in the list/count
    > info // display the information --> in case it's no longer visible
    > nc {integer} // connect to a tcp port on that domain with a socket
    > go {integer} // If I need to jump the counter this is what I use
    > checkInt // Checks the internet connection
