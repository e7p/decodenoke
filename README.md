decodenoke
==========

This script is able to decode data dumps out of bluetooth LE sniffs, which
are in somewhat like the following format:

> 01bd41ef9564fdc79bafdea1da064742
> d5298a7bb219f081c52522a9f96db16400
> a4fd46f750c37b7bf55d3144e3f09193
> c606d3f9f770b9857778f7e7dfccd02600

This program is free to use. It requires python 3 and the module `python-crypto`.

Usage
-----

`python3 decodenoke.py <file.txt>`

Supplying a text file containing hex-formatted dumps like stated above.
Note, that only the first 16 hex-bytes in each line will be used.

License
-------

Free to use, licensed under the WTFPL. Here is the full license text:

>            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
>                    Version 2, December 2004
> 
> Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
> 
> Everyone is permitted to copy and distribute verbatim or modified
> copies of this license document, and changing it is allowed as long
> as the name is changed.
> 
>            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
>   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
> 
>  0. You just DO WHAT THE FUCK YOU WANT TO.