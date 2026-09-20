"""The restricted plan language: a Python subset parsed with ``ast``, checked against a node
whitelist, and executed by an interpreter that propagates labels (explicit and implicit flows).

Nothing in this package ever calls ``eval``, ``exec`` or ``compile``: plans are walked as
syntax trees, so a plan can only do what the interpreter implements.
"""
