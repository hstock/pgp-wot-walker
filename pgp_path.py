#!/usr/bin/env python3

from urllib.parse import quote
import string
import requests
import gnupg
import sys
from collections import namedtuple

server = "https://pgp.cs.uu.nl"
urltemplate = string.Template(server + "/paths/${from_}/to/${to_}.json")


class KeyInfo(object):
    "class representing some information about a key"

    def __init__(self, key_properties):
        ":param key_properties: a python-gnupg list-keys response entry"
        self.__key_properties = key_properties

    @property
    def valid(self):
        "we trust that this key belongs to the user as indicated by its uid"
        return self.__key_properties["trust"] == "f"

    @property
    def fully_trusted(self):
        "key valid and has full ownertrust"
        return self.valid and self.__key_properties["ownertrust"] == "f"


def from_to_url(from_key, to_key):
    return urltemplate.safe_substitute(from_=quote(from_key), to_=quote(to_key))


def get_present_keys():
    gpg = gnupg.GPG()
    return dict(((key["keyid"].lower(), KeyInfo(key)) for key in gpg.list_keys()))


class WOTGraphWalker(object):

    def __init__(self, from_key, marginals_needed, present_keys):
        self.__fkey = from_key.lower()
        self.__marginals = marginals_needed
        self.__present = present_keys
        self.__future_signers = set()
        self.__invalid_keys = set()

    def get_keys_needed(self, to_key, visited):
        from_key = self.__fkey
        marginals_needed = self.__marginals
        present_keys = self.__present
        invalid_keys = self.__invalid_keys
        future_signers = self.__future_signers

        if to_key.lower() in present_keys and present_keys[to_key.lower()].valid:
            return []

        r = requests.get(from_to_url(from_key, to_key))
        r.raise_for_status()
        res = r.json()
        print("TO: {0}".format(res["TO"]["uid"]), file=sys.stderr)
        paths = res["xpaths"]  # an array of paths
        needed_keys = []
        if len(paths) < 3:
            print("Not enough paths from \"{0}\" to \"{1}\"".format(res["FROM"]["uid"], res["TO"]["uid"]), file=sys.stderr)
            return None
        valid_paths = 0
        for path in paths:
            potential_signer = path[-2]["kid"].lower()
            if potential_signer in invalid_keys or potential_signer in visited:
                continue
            if potential_signer == from_key.lower():
                # from self to self always works
                return []
            if potential_signer in present_keys:
                keyinfo = present_keys[potential_signer]
                if keyinfo.fully_trusted:
                    # we can immediately trust this key
                    return [to_key]
                elif keyinfo.valid:
                    # if the potential_signer is valid, we have a valid path
                    valid_paths += 1
                    continue
            if potential_signer in future_signers:
                # if we already have marginals_needed paths to this key, we do not need
                # more keys for this one and we have a valid path
                valid_paths += 1
                continue
            if valid_paths >= marginals_needed:
                break
            needed = self.get_keys_needed(potential_signer, visited.union((to_key,)))
            if(needed is not None):
                # we can use this key when we import the needed keys
                needed_keys.extend(needed)
                valid_paths += 1
                if valid_paths >= marginals_needed:
                    break
            else:
                invalid_keys.add(potential_signer)

        if valid_paths >= marginals_needed:
            future_signers.add(to_key)
            if not to_key in present_keys:
                needed_keys.append(to_key)
            print("Needed keys from \"{0}\" to \"{1}\": {2}".format(res["FROM"]["uid"], res["TO"]["uid"], len(needed_keys)), file=sys.stderr)
            return needed_keys
        else:
            print("Not enough paths from \"{0}\" to \"{1}\"".format(res["FROM"]["uid"], res["TO"]["uid"]), file=sys.stderr)
            return None


def main():
    keys = WOTGraphWalker("9c5a87fcfd375565", 3, get_present_keys()).get_keys_needed("dc80f2a6d5327cb9", frozenset())
    sys.stdout.write("\n".join(keys))

if __name__ == '__main__':
    main()