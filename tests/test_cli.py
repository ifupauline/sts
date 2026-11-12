#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Runs real sts processes against a local mosquitto and checks what they
print: messages, private messages, file transfers, nick changes, leaving,
connection loss, and the full screen interface (with pyte, if installed).

usage: test_cli.py STS MOSQUITTO
"""
import fcntl
import os
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

SKIP = 77
failures = 0
checks = 0


def check(cond, what):
    global failures, checks
    checks += 1
    if not cond:
        failures += 1
        print(f"CHECK failed: {what}", file=sys.stderr)
    return cond


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Client:
    """sts in plain mode, fed through a pipe"""

    def __init__(self, sts, work, name, args=None):
        self.out = open(os.path.join(work, name + ".out"), "wb")
        if args is None:
            args = ["-c", name + ".conf"]
        self.proc = subprocess.Popen(
            [sts, *args], cwd=work,
            stdin=subprocess.PIPE, stdout=self.out, stderr=subprocess.STDOUT)
        self.path = self.out.name

    def say(self, line):
        self.proc.stdin.write(line.encode() + b"\n")
        self.proc.stdin.flush()

    def text(self):
        with open(self.path, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def wait_for(self, needle, timeout=8):
        end = time.time() + timeout
        while time.time() < end:
            if needle in self.text():
                return True
            time.sleep(0.05)
        return False

    def quit(self):
        try:
            self.say("/quit")
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            return self.proc.wait(10)
        finally:
            self.out.close()


class Terminal:
    """sts on a pseudo terminal, for what asks on /dev/tty"""

    def __init__(self, sts, work, args):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(work)
            os.execv(sts, [sts, *args])
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", 30, 100, 0, 0))
        self.out = b""
        self.pos = 0  # what was already answered

    def read(self, secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    return False
                if not data:
                    return False
                self.out += data
        return True

    def expect(self, needle, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            i = self.out.find(needle.encode(), self.pos)
            if i >= 0:
                self.pos = i + len(needle)
                return True
            if not self.read(0.05):
                break
        i = self.out.find(needle.encode(), self.pos)
        if i >= 0:
            self.pos = i + len(needle)
        return i >= 0

    def answer(self, needle, line):
        ok = self.expect(needle)
        time.sleep(0.05)
        os.write(self.fd, line.encode() + b"\r")
        return ok

    def text(self):
        return self.out.decode("utf-8", "replace")

    def wait(self, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            self.read(0.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                os.close(self.fd)
                return os.waitstatus_to_exitcode(status)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        os.close(self.fd)
        return -1


def write_conf(work, port, name, extra=""):
    with open(os.path.join(work, name + ".conf"), "w") as f:
        f.write(f"""# test
broker = 127.0.0.1
port = {port}
topic_prefix = sts-test
nick = {name}
identity = {name}.key
known_peers = {name}.peers
room = neotokyo
{extra}""")


def test_chat(sts, work, port):
    for n in ("alice", "bob", "carol"):
        write_conf(work, port, n)

    alice = Client(sts, work, "alice")
    check(alice.wait_for("joined #neotokyo"), "alice connects")
    bob = Client(sts, work, "bob")
    check(bob.wait_for("alice [") and alice.wait_for("bob ["),
          "alice and bob see each other")
    carol = Client(sts, work, "carol")
    # no configuration file: everything on the command line
    mallory = Client(sts, work, "mallory", [
        "-b", "127.0.0.1", "-p", str(port), "-t", "sts-test",
        "-n", "mallory", "-i", "mallory.key", "-k", "mallory.peers",
        "-r", "neotokyo:wrong-password"])
    check(carol.wait_for("alice [") and carol.wait_for("bob ["),
          "carol sees everyone")

    alice.say("hello from alice")
    check(bob.wait_for("<alice> hello from alice"), "bob gets the message")
    check(carol.wait_for("<alice> hello from alice"), "carol gets it")
    bob.say("/me waves")
    check(alice.wait_for("* bob waves"), "action")
    bob.say("/msg carol only for you")
    check(carol.wait_for("(private) <bob> only for you"), "private message")
    check(bob.wait_for("(private to carol) <bob> only for you"),
          "private message echo")
    time.sleep(0.5)
    check("only for you" not in alice.text(), "alice doesn't get it")
    carol.say("/nick caroline")
    check(alice.wait_for("carol is now known as caroline"), "nick change")
    alice.say("/who")
    check(alice.wait_for("3 in #neotokyo:"), "/who")
    alice.say("/status")
    check(alice.wait_for("MQTT topic sts-test/"), "/status shows the topic")

    # a file from alice to bob, end to end
    data = os.urandom(150000)
    with open(os.path.join(work, "report.pdf"), "wb") as f:
        f.write(data)
    os.mkdir(os.path.join(work, "inbox"))
    alice.say("/send bob " + os.path.join(work, "report.pdf"))
    check(bob.wait_for("alice wants to send you report.pdf (146.5 KB)"),
          "file offer")
    bob.say("/accept 1 " + os.path.join(work, "inbox"))
    check(bob.wait_for("received report.pdf from alice"), "file received")
    check(alice.wait_for("bob received report.pdf"), "sender told")
    saved = os.path.join(work, "inbox", "report.pdf")
    check(os.path.exists(saved) and open(saved, "rb").read() == data,
          "same file")
    alice.say("/send caroline " + os.path.join(work, "report.pdf"))
    check(carol.wait_for("wants to send you report.pdf"), "second offer")
    carol.say("/refuse")
    check(alice.wait_for("caroline refused report.pdf"), "refused")
    alice.say("/msg nobody hi")
    check(alice.wait_for("no nobody in #neotokyo"), "unknown nick")
    alice.say("/bogus")
    check(alice.wait_for("unknown command /bogus"), "unknown command")

    # another password: another room, nobody there
    time.sleep(0.5)
    text = mallory.text()
    check("joined #neotokyo" in text and "alice" not in text
          and "hello" not in text, "wrong password sees nothing")

    # carol's connection dies, then bob leaves properly
    carol.proc.send_signal(signal.SIGKILL)
    check(alice.wait_for("caroline lost the connection"), "will message")
    check(bob.quit() == 0, "bob exits cleanly")
    check(alice.wait_for("bob left"), "leave message")

    alice.say("/part")
    check(alice.wait_for("left #neotokyo"), "/part")
    check(alice.quit() == 0, "alice exits cleanly")
    mallory.quit()
    carol.out.close()


def test_errors(sts, work, port):
    run = lambda *a: subprocess.run([sts, *a], cwd=work, capture_output=True,
                                    text=True, timeout=10)
    r = run()
    check(r.returncode != 0 and "give a configuration file or a broker"
          in r.stderr, "-c or -b/-p required")
    write_conf(work, port, "zoe")
    r = run("-c", "zoe.conf", "-n", "zed")
    check(r.returncode != 0 and "can't be combined with -n" in r.stderr,
          "-c is exclusive")
    r = run("-b", "127.0.0.1")
    check(r.returncode != 0 and "-b HOST and -p PORT" in r.stderr,
          "-b needs -p")
    r = run("-c", "missing.conf")
    check(r.returncode != 0 and "cannot open" in r.stderr, "missing file")
    with open(os.path.join(work, "bad.conf"), "w") as f:
        f.write("broker = 127.0.0.1\nport = 1\n")
    r = run("-c", "bad.conf")
    check(r.returncode != 0 and "is not set" in r.stderr, "incomplete file")
    r = run("--version")
    check(r.returncode == 0 and r.stdout.startswith("sts "), "--version")


def test_extras(sts, work, port):
    """room names ignore case, max_file_size, the chat log"""
    write_conf(work, port, "dave", "log = yes\nlog_dir = davelogs\n")
    write_conf(work, port, "erin", "max_file_size = 1K\n")
    with open(os.path.join(work, "erin.conf")) as f:
        conf = f.read().replace("room = neotokyo", "room = NeoTokyo")
    with open(os.path.join(work, "erin.conf"), "w") as f:
        f.write(conf)

    dave = Client(sts, work, "dave")
    erin = Client(sts, work, "erin")
    check(erin.wait_for("dave [") and dave.wait_for("erin ["),
          "NeoTokyo and neotokyo are one room")
    erin.say("hi dave")
    check(dave.wait_for("<erin> hi dave"), "mention")
    erin.say("/msg dave between us")
    check(dave.wait_for("(private) <erin> between us"), "private")

    with open(os.path.join(work, "big.bin"), "wb") as f:
        f.write(os.urandom(5000))
    dave.say("/send erin " + os.path.join(work, "big.bin"))
    check(erin.wait_for("bigger than your max_file_size (1.0 KB): refused"),
          "too big for the receiver")
    check(dave.wait_for("bigger than what they accept"), "sender told why")
    erin.say("/send dave " + os.path.join(work, "big.bin"))
    check(erin.wait_for("bigger than max_file_size"), "too big to send")

    check(dave.quit() == 0, "dave exits")
    erin.quit()
    log = os.path.join(work, "davelogs", "neotokyo.log")
    try:
        with open(log) as f:
            text = f.read()
        mode = os.stat(log).st_mode & 0o777
        dmode = os.stat(os.path.dirname(log)).st_mode & 0o777
    except OSError:
        text, mode, dmode = "", 0, 0
    check("---- #neotokyo, as dave ----" in text, "log header")
    check("<erin> hi dave" in text and "(private) <erin> between us" in text,
          "messages logged")
    check("\033" not in text, "no escape sequences in the log")
    if os.environ.get("STS_SHOW_LOG"):
        print(text)
    check(mode == 0o600 and dmode == 0o700, "log readable by its owner only")


def test_setup(sts, work, port):
    """--init, then a passphrase protected identity"""
    t = Terminal(sts, work, ["--init"])
    ok = (t.answer("Your nick", "frank") and
          t.answer("Room to join", "") and
          t.answer("Room password", "") and
          t.answer("MQTT broker", "127.0.0.1") and
          t.answer("Use TLS to the broker", "") and
          t.answer("Port", str(port)) and
          t.answer("Topic prefix", "sts-test") and
          t.answer("Identity key file", "frank.key") and
          t.answer("New passphrase", "open sesame") and
          t.answer("The same again", "open sesame") and
          t.answer("Save the configuration as", "frank.conf"))
    code = t.wait()
    check(ok and code == 0 and "Saved" in t.text(), "--init writes a file")
    conf = os.path.join(work, "frank.conf")
    try:
        with open(conf) as f:
            text = f.read()
        mode = os.stat(conf).st_mode & 0o777
    except OSError:
        text, mode = "", 0
    check("nick = frank" in text and "room = lobby" in text and
          f"port = {port}" in text and mode == 0o600, "--init content")
    with open(os.path.join(work, "frank.key")) as f:
        check(f.read().startswith("sts-key-v1:"), "key is protected")

    r = subprocess.run([sts, "-c", "frank.conf"], cwd=work,
                       capture_output=True, text=True, timeout=10,
                       start_new_session=True, stdin=subprocess.DEVNULL)
    check(r.returncode != 0 and "start sts on a terminal" in r.stderr,
          "no terminal, no passphrase")

    t = Terminal(sts, work, ["-c", "frank.conf"])
    t.answer("Passphrase of", "wrong")
    check(t.expect("wrong passphrase"), "wrong passphrase refused")
    t.answer("Passphrase of", "open sesame")
    check(t.expect("joined #lobby", 15), "starts with the passphrase")
    os.write(t.fd, b"/quit\r")
    check(t.wait() == 0, "frank exits")

    t = Terminal(sts, work, ["--passphrase", "frank.key"])
    t.answer("Passphrase of", "open sesame")
    t.answer("New passphrase", "")
    t.answer("The same again", "")
    check(t.wait() == 0 and "no longer protected" in t.text(),
          "passphrase removed")
    with open(os.path.join(work, "frank.key")) as f:
        check(not f.read().startswith("sts-key-v1:"), "key in clear again")


def test_tui(sts, work, port):
    try:
        import pyte
    except ImportError:
        print("pyte not installed: full screen check skipped")
        return

    rows, cols = 24, 100
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    write_conf(work, port, "dave")
    write_conf(work, port, "erin")

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(work)
        os.environ["TERM"] = "xterm-256color"
        os.execv(sts, [sts, "-c", "dave.conf"])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    raw = []  # everything sts wrote

    def feed(data):
        raw.append(data)
        stream.feed(data)

    def pump(secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    feed(os.read(fd, 65536))
                except OSError:
                    return

    def shown(needle):
        return any(needle in line for line in screen.display)

    def settle():
        """read until the screen stops changing: no half drawn frame"""
        end = time.time() + 10
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.7)
            if not r:
                return
            try:
                feed(os.read(fd, 65536))
            except OSError:
                return

    pump(1.5)
    erin = Client(sts, work, "erin")
    pump(3)
    check(shown("2 people"), "nick list header")
    check(any(line.rstrip().endswith("erin") for line in screen.display),
          "erin in the nick list")
    check(shown("#neotokyo - 2 people"), "title bar")
    check(shown("2:#neotokyo"), "window list")

    # fay shares erin's key, as instances started with -b -p do:
    # everyone still gets their own color
    write_conf(work, port, "fay")
    with open(os.path.join(work, "fay.conf")) as f:
        conf = f.read().replace("identity = fay.key", "identity = erin.key")
    with open(os.path.join(work, "fay.conf"), "w") as f:
        f.write(conf)
    fay = Client(sts, work, "fay")
    end = time.time() + 15
    while time.time() < end and not shown("fay (2)"):
        pump(0.3)
    settle()

    def nick_color(nick):
        """the color code sts last wrote @nick with, as "35" or "95"

        From the bytes rather than pyte's colors: older pyte (0.8.0, in
        Ubuntu) names "\\033[95m" magenta like "\\033[35m".
        """
        found = re.findall(rb"\x1b\[(\d+)m" + re.escape(nick.encode()) +
                           rb"(?=[\x1b ])", b"".join(raw))
        return found[-1].decode() if found else None

    colors = [nick_color(n) for n in ("dave", "erin", "fay")]
    if not check(None not in colors and len(set(colors)) == 3,
                 f"a different color for each person {colors}"):
        print("\n".join(screen.display))
    fay.quit()
    pump(1)
    erin.say("hi dave")
    pump(0.7)
    check(shown("<erin> hi dave"), "message shown")
    os.write(fd, b"hello\x7fo erin\r")      # backspace
    pump(0.7)
    check(shown("<dave> hello erin"), "line editing")
    check(erin.wait_for("<dave> hello erin"), "sent from the TUI")
    os.write(fd, b"/whois er\t\r")         # completion
    pump(0.7)
    check(shown("fingerprint"), "tab completion + /whois")
    os.write(fd, b"\x1b1")                  # Alt-1: status window
    pump(0.5)
    check(shown("[sts]"), "window switch")
    erin.say("while you were away")
    pump(0.7)
    os.write(fd, b"\x1b2")                  # back to #neotokyo
    pump(0.5)
    lines = [line.rstrip() for line in screen.display]
    mark = [i for i, line in enumerate(lines) if "new messages" in line]
    check(len(mark) == 1 and "<erin> while you were away" in lines[mark[0] + 1]
          and "hello erin" in "".join(lines[:mark[0]]),
          "new messages marker above the first unread line")
    os.write(fd, b"\x1b1\x1b2")
    pump(0.5)
    check(not shown("new messages"), "marker gone once read")
    os.write(fd, b"/quit\r")
    pump(3)
    _, status = os.waitpid(pid, 0)
    check(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "TUI exits")
    erin.quit()


def main():
    if len(sys.argv) != 3 or not os.access(sys.argv[2], os.X_OK):
        print("usage: test_cli.py STS MOSQUITTO (skipped)")
        return SKIP
    sts = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="sts-cli-")
    port = free_port()
    with open(os.path.join(work, "mosquitto.conf"), "w") as f:
        f.write(f"listener {port} 127.0.0.1\nallow_anonymous true\n"
                "persistence false\n")
        if os.getuid() == 0:
            import pwd
            f.write(f"user {pwd.getpwuid(0).pw_name}\n")
    log = open(os.path.join(work, "mosquitto.log"), "wb")
    broker = subprocess.Popen([sys.argv[2], "-c", "mosquitto.conf"],
                              cwd=work, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), 0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            log.close()
            with open(log.name, "rb") as f:
                print("mosquitto didn't start, its output:\n" +
                      f.read().decode(errors="replace"))
            return 1
        for t in (test_errors, test_chat, test_extras, test_setup, test_tui):
            before = failures
            t(sts, work, port)
            print(f"{t.__name__:52} {'ok' if failures == before else 'FAIL'}")
    finally:
        broker.terminate()
        broker.wait()
    if failures:
        print(f"output kept in {work}")
    else:
        shutil.rmtree(work)
    print(f"{checks} checks, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
