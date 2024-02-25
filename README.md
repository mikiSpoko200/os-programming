# os-programming
Various pieces of software that utilize OS APIs directly and do not neatly fit into other repositories.

## Malloc

My implementation of `malloc` API for unix systems. It's a general purpose allocator, it's performance is by no means stellar and there is a lot of room for future improvments.

Current implementation uses segregated fit strategy which divides blocks into categories based on their size, and performs bookkeeping on per catagory basis.
