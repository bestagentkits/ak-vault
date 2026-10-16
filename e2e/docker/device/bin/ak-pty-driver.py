#!/usr/bin/env python3
"""Drive the real `ak` CLI through a pseudo-terminal, the way a person would.

Several `ak` steps are deliberately interactive: the file backend reads its
passphrase only from a terminal, `ak login --email` reads the OTP from a
terminal, `ak secrets get --reveal` asks for confirmation, and
`ak secrets devices approve` shows the 6-digit code and waits for y/N. This
driver gives the CLI a real pty, answers those prompts, and never changes the
CLI's behaviour. It is the e2e stand-in for the person at the keyboard.

Subcommands:
  run [--tty-stdout] [--mark REGEX=PATH]... [--timeout S] -- ARGV...
      Run ARGV with stdin and stderr on a pty (stdout too with --tty-stdout,
      otherwise stdout passes through for JSON). Answers passphrase prompts.
      --mark touches PATH the first time REGEX appears in the pty output.
  login EMAIL
      `ak login --email EMAIL`, typing the OTP from fake-akweb's test inbox.
  reveal REF
      `ak secrets get REF --reveal`; prints only "sha256:<hex>" of the value.
  approve JOIN_CODE STATE_DIR
      `ak secrets devices approve`; writes STATE_DIR/offer and STATE_DIR/sas
      when the CLI shows them, then waits for STATE_DIR/answer ("y" or "n")
      and types it.

The passphrase comes from E2E_PASSPHRASE_FILE. It is typed only once the
terminal has echo turned off, and is redacted from any transcript printed on
failure. A revealed value is never printed.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import urllib.parse
import urllib.request

PASSPHRASE_PROMPT = re.compile(rb"passphrase \(input hidden")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]")
REGISTRY = os.environ.get("AGENTKIT_REGISTRY_URL", "http://127.0.0.1:8788")
# A secret ref as the e2e names them; refs on a command line are redacted
# from any transcript this driver prints.
REF_LIKE = re.compile(r"^[A-Z][A-Z0-9_]{5,}$")


def die(msg, code=2):
    print(f"ak-pty-driver: {msg}", file=sys.stderr)
    sys.exit(code)


def read_passphrase():
    path = os.environ.get("E2E_PASSPHRASE_FILE", "/run/e2e/passphrase")
    try:
        with open(path, "rb") as f:
            value = f.read().strip()
    except OSError as exc:
        die(f"cannot read the synthetic passphrase file: {exc.strerror}")
    if not value:
        die("the synthetic passphrase file is empty")
    return value


class Session:
    """One child process on a pty, with prompt rules."""

    def __init__(self, argv, tty_stdout, timeout):
        self.master, self.slave = os.openpty()
        # A wide terminal keeps long codes on one line.
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 400, 0, 0))
        env = dict(os.environ, NO_COLOR="1", TERM="dumb")
        self.proc = subprocess.Popen(
            argv,
            stdin=self.slave,
            stdout=self.slave if tty_stdout else None,
            stderr=self.slave,
            env=env,
            start_new_session=True,
            preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0),
            close_fds=True,
        )
        self.buf = b""
        self.scan_from = 0
        self.deadline = time.monotonic() + timeout
        self.secrets = []

    def echo_off(self):
        """Wait until the CLI has turned terminal echo off (a hidden prompt)."""
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if not termios.tcgetattr(self.slave)[3] & termios.ECHO:
                return True
            time.sleep(0.02)
        return False

    def send(self, data, hidden=False):
        if hidden:
            if not self.echo_off():
                self.kill()
                die("the CLI asked for hidden input but left echo on; refusing to type it")
            self.secrets.append(data)
        os.write(self.master, data + b"\n")

    def pump(self, on_output):
        """Read until the child exits; on_output(session) handles prompts."""
        while True:
            if time.monotonic() > self.deadline:
                self.kill()
                return 124
            ready, _, _ = select.select([self.master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    chunk = b""
                if chunk:
                    self.buf += chunk
                    on_output(self)
                    continue
            code = self.proc.poll()
            if code is not None:
                # Drain what is left, then stop.
                while select.select([self.master], [], [], 0.05)[0]:
                    try:
                        chunk = os.read(self.master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    self.buf += chunk
                    on_output(self)
                os.close(self.master)
                os.close(self.slave)
                return code

    def pending(self):
        return self.buf[self.scan_from:]

    def consume(self):
        self.scan_from = len(self.buf)

    def kill(self):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def text(self):
        out = ANSI.sub(b"", self.buf)
        for s in self.secrets:
            out = out.replace(s, b"[redacted]")
        return out.decode("utf-8", "replace").replace("\r", "")

    def tail(self, lines=25):
        return "\n".join(self.text().strip().splitlines()[-lines:])


def answer_passphrase(session, passphrase):
    if PASSPHRASE_PROMPT.search(session.pending()):
        session.consume()
        session.send(passphrase, hidden=True)
        return True
    return False


def cmd_run(args):
    passphrase = read_passphrase()
    marks = []
    for m in args.mark or []:
        pattern, _, path = m.partition("=")
        if not pattern or not path:
            die("--mark takes REGEX=PATH")
        marks.append([re.compile(pattern.encode()), path, False])
    session = Session(args.argv, args.tty_stdout, args.timeout)
    session.secrets += [a.encode() for a in args.argv if REF_LIKE.match(a)]

    # Stopping the driver stops the CLI the way Ctrl-C would.
    def forward(signum, _frame):
        try:
            os.killpg(session.proc.pid, signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    def on_output(s):
        answer_passphrase(s, passphrase)
        for mark in marks:
            if not mark[2] and mark[0].search(s.buf):
                mark[2] = True
                with open(mark[1], "w") as f:
                    f.write(str(int(time.time() * 1000)))

    code = session.pump(on_output)
    if args.echo or code != 0:
        print(session.tail(), file=sys.stderr)
    return code


def cmd_login(args):
    otp_prompt = re.compile(rb"Enter OTP code:")
    session = Session(["ak", "login", "--email", args.email], True, args.timeout)

    def on_output(s):
        if otp_prompt.search(s.pending()):
            s.consume()
            url = f"{REGISTRY}/__e2e/otp?email={urllib.parse.quote(args.email)}"
            with urllib.request.urlopen(url, timeout=5) as resp:
                code = json.load(resp)["code"]
            s.send(code.encode(), hidden=False)
            s.secrets.append(code.encode())

    code = session.pump(on_output)
    print(session.tail(), file=sys.stderr if code else sys.stdout)
    return code


def cmd_reveal(args):
    passphrase = read_passphrase()
    confirm = re.compile(rb"Reveal the value of .*\[y/N\]:")
    session = Session(["ak", "secrets", "get", args.ref, "--reveal"], True, args.timeout)
    session.secrets.append(args.ref.encode())
    state = {"confirmed_at": None}

    def on_output(s):
        if answer_passphrase(s, passphrase):
            return
        if state["confirmed_at"] is None and confirm.search(s.pending()):
            s.consume()
            state["confirmed_at"] = len(s.buf)
            s.send(b"y")

    code = session.pump(on_output)
    if code != 0 or state["confirmed_at"] is None:
        # Error text never carries a value; it may say the ref is unknown.
        text = ANSI.sub(b"", session.buf[: state["confirmed_at"] or len(session.buf)]).decode("utf-8", "replace")
        if "not found" in text.lower():
            return 3
        # Only what the CLI printed before the confirmation: after it, the
        # output may hold the value.
        for secret in session.secrets:
            text = text.replace(secret.decode("utf-8", "replace"), "[redacted]")
        print("\n".join(text.replace("\r", "").strip().splitlines()[-25:]), file=sys.stderr)
        return code or 1
    after = ANSI.sub(b"", session.buf[state["confirmed_at"]:]).decode("utf-8", "replace").replace("\r", "")
    match = re.search(r"^" + re.escape(args.ref) + r": (.*)$", after, re.MULTILINE)
    if not match:
        print("ak-pty-driver: the revealed output did not contain the value line", file=sys.stderr)
        return 1
    print("sha256:" + hashlib.sha256(match.group(1).encode()).hexdigest())
    return 0


def cmd_approve(args):
    passphrase = read_passphrase()
    offer_re = re.compile(rb"Give it this offer code \(not secret\):\s*\r?\n(\S+)\r?\n")
    sas_re = re.compile(rb"Does the other device show (\d{6})\? \[y/N\]")
    os.makedirs(args.state_dir, exist_ok=True)
    session = Session(["ak", "secrets", "devices", "approve", args.join_code], True, args.timeout)
    state = {"answered": False}

    def publish(name, value):
        tmp = os.path.join(args.state_dir, name + ".tmp")
        with open(tmp, "w") as f:
            f.write(value)
        os.rename(tmp, os.path.join(args.state_dir, name))

    def on_output(s):
        if answer_passphrase(s, passphrase):
            return
        if state["answered"]:
            return
        sas = sas_re.search(s.buf)
        offer = offer_re.search(s.buf)
        if not (sas and offer):
            return
        s.consume()
        publish("offer", offer.group(1).decode())
        publish("sas", sas.group(1).decode())
        answer_path = os.path.join(args.state_dir, "answer")
        while not os.path.exists(answer_path):
            if time.monotonic() > s.deadline:
                s.kill()
                return
            time.sleep(0.2)
        with open(answer_path) as f:
            answer = f.read().strip()
        state["answered"] = True
        s.send(answer.encode())

    code = session.pump(on_output)
    print(session.tail(), file=sys.stderr if code else sys.stdout)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--tty-stdout", action="store_true")
    p.add_argument("--echo", action="store_true", help="print the pty transcript even on success")
    p.add_argument("--mark", action="append")
    p.add_argument("--timeout", type=float, default=300)
    p.add_argument("argv", nargs=argparse.REMAINDER)
    p = sub.add_parser("login")
    p.add_argument("email")
    p.add_argument("--timeout", type=float, default=60)
    p = sub.add_parser("reveal")
    p.add_argument("ref")
    p.add_argument("--timeout", type=float, default=60)
    p = sub.add_parser("approve")
    p.add_argument("join_code")
    p.add_argument("state_dir")
    p.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    if args.cmd == "run":
        if args.argv and args.argv[0] == "--":
            args.argv = args.argv[1:]
        if not args.argv:
            die("run needs a command after --")
        return cmd_run(args)
    return {"login": cmd_login, "reveal": cmd_reveal, "approve": cmd_approve}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
