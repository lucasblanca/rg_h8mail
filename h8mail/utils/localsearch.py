#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import signal
import subprocess

from multiprocessing import Pool
from itertools import takewhile, repeat
from .classes import local_breach_target
from .colors import colors as c


def local_to_targets(targets, local_results, user_args):
    """
    Appends data from local_breach_target objects using existing list of targets.
    Finds corresponding email in dest object list, and adds data to the t.data object variable.
    Full output line is stored in t.data[1] and original found data in t.data[2]

    """
    for t in targets:
        for l in local_results:
            if l.target == t.target:
                t.data.append(
                    (
                        "LOCALSEARCH",
                        f"[{os.path.basename(l.filepath)}] Line {l.line}: {l.content}".strip(),
                        l.content.strip(),
                    )
                )
                t.pwned += 1
                if user_args.debug:
                    c.debug_news(f"DEBUG: Found following content matching {t.target.target}")
                    l.target.dump()
    return targets


def raw_in_count(filename):
    """
    StackOverflow trick to rapidly count lines in big files.
    Returns total line number.
    """
    c.info_news("Identifying total line number...")
    f = open(filename, "rb")
    bufgen = takewhile(lambda x: x, (f.raw.read(1024 * 1024) for _ in repeat(None)))
    return sum(buf.count(b"\n") for buf in bufgen)


def worker(filepath, target_list):
    """
    Searches for every email from target_list in every line of filepath using ripgrep.
    """
    found_list = []
    try:
        for t in target_list:
            try:
                result = subprocess.run(
                    ["rg", "-n", "-H", "--color", "never", "--text", t, filepath],
                    capture_output=True,
                    text=True,
                    check=True
                )
                for line in result.stdout.splitlines():
                    try:
                        # Split the line into filename, line number, and content
                        parts = line.split(":", 2)
                        if len(parts) < 3:
                            raise ValueError(f"Unexpected format: {line}")
                        _, line_number, content = parts
                        line_number = int(line_number)
                        found_list.append(
                            local_breach_target(t, filepath, line_number, content)
                        )
                        c.good_news(
                            f"Found occurrence [{filepath}] Line {line_number}: {content}"
                        )
                    except ValueError as ve:
                        c.bad_news(f"Error parsing line: {line} - {ve}")
            except subprocess.CalledProcessError:
                # No matches found, continue to the next target
                c.info_news(f"No matches found for {t} in {filepath}")
                continue
    except Exception as e:
        c.bad_news(f"Something went wrong with worker: {e}")
        print(e)
    return found_list


def local_search(files_to_parse, target_list):
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = Pool()
    found_list = []
    signal.signal(signal.SIGINT, original_sigint_handler)
    try:
        async_results = [
            pool.apply_async(worker, args=(f, target_list))
            for i, f in enumerate(files_to_parse)
        ]
        for r in async_results:
            if r.get() is not None:
                found_list.extend(r.get(60))
    except KeyboardInterrupt:
        c.bad_news("Caught KeyboardInterrupt, terminating workers")
        pool.terminate()
    else:
        c.info_news("Terminating worker pool")
        pool.close()
    pool.join()
    return found_list


def progress(count, total, status=""):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = "=" * filled_len + "-" * (bar_len - filled_len)

    sys.stdout.write("[%s] %s%s ...%s\r" % (bar, percents, "%", status))
    sys.stdout.write("\033[K")


sys.stdout.flush()


def local_search_single(files_to_parse, target_list):
    found_list = []
    for file_to_parse in files_to_parse:
        with open(file_to_parse, "rb") as fp:
            size = os.stat(file_to_parse).st_size
            lines_no = raw_in_count(file_to_parse)
            c.info_news(
                f"Searching for targets in {file_to_parse} ({size} bytes, {lines_no} lines)"
            )
            for cnt, line in enumerate(fp):
                lines_left = lines_no - cnt
                progress(
                    cnt, lines_no, f"{cnt} lines checked - {lines_left} lines left"
                )
                for t in target_list:
                    if t in str(line):
                        try:
                            decoded = str(line, "cp437")
                            found_list.append(
                                local_breach_target(t, file_to_parse, cnt, decoded)
                            )
                            c.good_news(
                                f"Found occurrence [{file_to_parse}] Line {cnt}: {decoded}"
                            )
                        except:
                            c.bad_news(
                                f"Got a decoding error line {cnt} - file: {file_to_parse}"
                            )
                            c.good_news(
                                f"Found occurrence [{file_to_parse}] Line {cnt}: {line}"
                            )
                            found_list.append(
                                local_breach_target(t, file_to_parse, cnt, str(line))
                            )
    return found_list
