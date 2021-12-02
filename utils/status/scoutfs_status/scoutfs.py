#!/usr/bin/env python3
#
# Copyright (c) 2021 Versity Software, Inc. All rights reserved.
#

import sys
import click
import logging
import logging.handlers
import os
import pwd
import traceback

import util as cliutil


class ScoutfsCLI(click.MultiCommand):
    def list_commands(self, ctx):
        ret = []
        for filename in os.listdir(os.path.dirname(os.path.realpath(__file__))):
            if filename.endswith('.py') and filename.startswith('cmd_'):
                ret.append(filename[4:-3])
        ret.sort()
        return ret

    def get_command(self, ctx, name):
        module = None
        try:
            module = __import__("cmd_" + name, fromlist=["sfcli"])
        except ImportError:
            raise click.BadArgumentUsage("Invalid Command Provided")
        return module.sfcli


@click.command(cls=ScoutfsCLI)
@click.option("--json", is_flag=True, help="Show output in JSON format.")
@click.option("--summary", is_flag=True, help="Show output in Table format.")
@click.option("--detail", is_flag=True, help="Show output in Multiline format. (Default)")
@cliutil.pass_context
def sfcli(ctx, json, summary, detail):
    ctx.json = json
    ctx.summary = summary
    ctx.detail = detail


if __name__ == "__main__":

    logging.captureWarnings(True)
    logger = logging.getLogger("scoutfs")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.WatchedFileHandler("/tmp/scoutfs.log")
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s pid-%(process)d %(name)s    %(message)s'))
    logger.addHandler(handler)
    logger = logging.getLogger("scoutfs.cli")
    logger.info("CLI process started: %s")

    try:
        sfcli()
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("CLI process failed with internal error")
        click.echo("ERROR: " + e.__class__.__name__ + ": " + str(e), err=True)
        sys.exit(1)
