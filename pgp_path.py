#!/usr/bin/env python3

from urllib.parse import quote
import string
import requests
import gnupg
import sys
from collections import namedtuple
from threading import Lock
from enum import Enum

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

    class WalkerContext(object):
        def __init__(self):
            self.__future_signers = set()
            self.__invalid_keys = set()
            self.__lock = Lock()

        def add_invalid(self, item):
            with self.__lock:
                self.__invalid_keys.add(item)

        def add_signer(self, item):
            with self.__lock:
                self.__future_signers.add(item)

        def in_invalid(self, item):
            with self.__lock:
                return item in self.__invalid_keys

        def in_signers(self, item):
            with self.__lock:
                return item in self.__future_signers

    class SubpathState(Enum):
        UNKNOWN = 0
        VALID = 1
        INVALID = 2
        SUFFICIENT = 3

    def __init__(self, from_key, marginals_needed, present_keys):
        self.__fkey = from_key.lower()
        self.__marginals = marginals_needed
        self.__present = present_keys
        self.__context = self.WalkerContext()

    def check_key_state(self, potential_signer, visited):
        from_key = self.__fkey
        present_keys = self.__present
        SubpathState = self.SubpathState
        continuation_state = (SubpathState.UNKNOWN, None)
        
        if self.__context.in_signers(potential_signer):
            # if we already have marginals_needed paths to this key, we do not need
            # more keys for this one and we have a valid path
            continuation_state = (SubpathState.VALID, [])
        elif self.__context.in_invalid(potential_signer) or potential_signer in visited:
            continuation_state = (SubpathState.INVALID, None)
        elif potential_signer == from_key.lower():
            # from self to self always works
            continuation_state = (SubpathState.SUFFICIENT, [])
        elif potential_signer in present_keys:
            keyinfo = present_keys[potential_signer]
            if keyinfo.fully_trusted:
                # we can immediately trust this to_key
                continuation_state = (SubpathState.SUFFICIENT, [])
            elif keyinfo.valid:
                # if the potential_signer is valid, we have a valid path
                continuation_state = (SubpathState.VALID, [])
        return continuation_state

    def get_pathinfos(self, to_key):
        from_key = self.__fkey
        r = requests.get(from_to_url(from_key, to_key))
        r.raise_for_status()
        res = r.json()
        print("Requesting paths for: {0}".format(res["TO"]["uid"]), file=sys.stderr)
        return res

    def get_keys_needed(self, to_key, visited):
        return self._get_keys_needed(to_key, visited, self.get_pathinfos(to_key))

    def walk_sub_path(self, potential_signer, visited):
        needed = self.get_keys_needed(potential_signer, visited)
        if(needed is not None):
            # we can use this key when we import the needed keys
            continuation_state = (self.SubpathState.VALID, needed)
        else:
            continuation_state = (self.SubpathState.INVALID, None)
            self.__context.add_invalid(potential_signer)
        return continuation_state

    def _validation_loop(self, potentials_signers, needed_keys_, valid_paths_, check_fun):
        marginals_needed = self.__marginals
        SubpathState = self.SubpathState

        valid_paths = valid_paths_
        needed_keys = needed_keys_.copy()
        full_trust_encountered = False
        unresolved_paths = potentials_signers.copy()
        for potential_signer in potentials_signers:
            if valid_paths >= marginals_needed:
                break

            continuation_state = check_fun(potential_signer)

            if continuation_state[0] is SubpathState.VALID:
                valid_paths += 1
                needed_keys.update(continuation_state[1])
                unresolved_paths.remove(potential_signer)
            elif continuation_state[0] is SubpathState.SUFFICIENT:
                needed_keys.update(continuation_state[1])
                full_trust_encountered = True

        return full_trust_encountered, needed_keys, valid_paths, unresolved_paths

    def _prepare_success(self, needed_keys, serverresponse, to_key):
        self.__context.add_signer(to_key)
        if not to_key in self.__present:
            needed_keys.add(to_key)
        print("Needed keys from \"{0}\" to \"{1}\": {2}".format(serverresponse["FROM"]["uid"], serverresponse["TO"]["uid"], len(needed_keys)), file=sys.stderr)

    def _get_keys_needed(self, to_key, visited, serverresponse):
        from_key = self.__fkey
        marginals_needed = self.__marginals
        present_keys = self.__present
        SubpathState = self.SubpathState
        visited = visited.union((to_key,))

        if to_key.lower() in present_keys and present_keys[to_key.lower()].valid:
            return []  # to_key is already in keyring and valid

        paths = serverresponse["xpaths"]  # an array of paths

        if len(paths) < marginals_needed:
            print("Not enough paths from \"{0}\" to \"{1}\"".format(serverresponse["FROM"]["uid"], serverresponse["TO"]["uid"]), file=sys.stderr)
            return None

        potentials_signers = [path[-2]["kid"].lower() for path in paths]

        # --- Pre-Check without needing online information ---
        full_trust_encountered, needed_keys, valid_paths, unresolved_paths = self._validation_loop(
            potentials_signers,
            set(),
            0,
            lambda key: self.check_key_state(key, visited))

        if full_trust_encountered or valid_paths >= marginals_needed:
            self._prepare_success(needed_keys, serverresponse, to_key)
            return needed_keys

        # --- full check getting information for unresolved paths ---
        full_trust_encountered, needed_keys, valid_paths, unresolved_paths = self._validation_loop(
            unresolved_paths,
            needed_keys,
            valid_paths,
            lambda key: self.walk_sub_path(key, visited))

        if full_trust_encountered or valid_paths >= marginals_needed:
            self._prepare_success(needed_keys, serverresponse, to_key)
            return needed_keys
        else:
            print("Not enough paths from \"{0}\" to \"{1}\"".format(serverresponse["FROM"]["uid"], serverresponse["TO"]["uid"]), file=sys.stderr)
            return None


def main():
    keys = WOTGraphWalker("9c5a87fcfd375565", 3, get_present_keys()).get_keys_needed("dc80f2a6d5327cb9", frozenset())
    sys.stdout.write("\n".join(keys))

if __name__ == '__main__':
    main()