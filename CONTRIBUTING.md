# Contributing

Patches are welcome: bugs, translations, panel configs that are not here yet.

## Rights to the code you send

By sending changes you agree that you pass them to the author of the project
with the right to use and license them on any terms, including terms other
than the license of this repository.

That sounds strict, and the reason is simple. The server is under the AGPL by
deliberate choice: whoever runs it for their clients and improves it publishes
those improvements. Hardware manufacturers cannot work on such terms, and they
are dealt with separately. While the rights to all of the code belong to one
author, such a deal is possible; once the project contains someone else's code
on different terms, it can no longer be relicensed, and the second license
becomes impossible for everyone.

Your changes still stay under the AGPL along with the rest of the code: the
right to issue a second license does not revoke the first one.

## Worth knowing before you edit

The database schema ships whole in `sql/01-schema.sql`, and on start the
server brings an existing database up to it, adding missing tables and
columns. That is why there are no separate migration files in the project:
when the schema changes, the dump changes.

The server part has only three pages; everything else goes through `api/` and
the websocket worker. Page texts live in the dictionaries under `dist/lang/`,
with English serving as the key: editing an English string breaks it in every
other language.

## A note on language

Documentation is English. Comments in the code are still Russian in places —
the distribution is generated from the author's working sources, and they are
being translated gradually. A patch that translates a file's comments without
changing its behaviour is a welcome patch.
