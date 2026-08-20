import argparse
import logging
import multiprocessing
import sys
import time
from argparse import Namespace
from pathlib import Path


def synthetic_spiderling(target, parent):
    from man_spider.lib.spiderling import SpiderlingMessage

    logging.getLogger("manspider").info(f"{target}: synthetic child console message")
    parent.spiderling_queue.put(SpiderlingMessage("a", target, False))
    time.sleep(0.5)


def make_options(loot_dir, targets=None, content=None):
    return Namespace(
        targets=targets or ["testhost-one", "testhost-two"],
        threads=2,
        maxdepth=1,
        quiet=True,
        username="testuser",
        password="dummy-password",
        domain="TESTDOMAIN",
        hash="",
        kerberos=False,
        aes_key=None,
        dc_ip=None,
        max_failed_logons=None,
        max_filesize=1024,
        sharenames=["testshare"],
        exclude_sharenames=[],
        dirnames=[],
        exclude_dirnames=[],
        no_download=True,
        or_logic=False,
        exclude_extensions=[],
        extensions=[],
        filenames=[],
        content=content or [],
        loot_dir=str(loot_dir),
        modified_after=None,
        modified_before=None,
        verbose=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("start_method")
    parser.add_argument("loot_dir")
    args = parser.parse_args()

    multiprocessing.set_start_method(args.start_method, force=True)

    from man_spider.lib import spider as spider_module
    from man_spider.lib.logger import CustomQueueListener, console
    from man_spider.manspider import go

    logging.getLogger("manspider").setLevel(logging.INFO)
    sys.argv = ["manspider", "testhost"]

    test_root = Path(args.loot_dir).parent
    targets = [test_root / "target-one", test_root / "target-two"]
    for target in targets:
        target.mkdir()
        (target / "example.txt").write_text("synthetic-content", encoding="utf-8")

    ctx = multiprocessing.get_context()
    log_queue = ctx.Queue()
    logging_process = ctx.Process(
        target=go,
        args=(
            make_options(args.loot_dir, targets=targets, content=["synthetic-content"]),
            log_queue,
        ),
    )
    logging_process.start()
    listener = CustomQueueListener(log_queue, console)
    listener.start()
    logging_process.join(10)
    listener.stop()
    log_queue.close()
    log_queue.join_thread()
    if logging_process.exitcode != 0:
        raise SystemExit(logging_process.exitcode)

    spider_module.Spiderling = synthetic_spiderling

    controller = spider_module.MANSPIDER(make_options(args.loot_dir))
    controller.start()
    print(f"processed messages: {controller.failed_logons}")


if __name__ == "__main__":
    main()
