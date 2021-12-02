#!/usr/bin/env python3
#
# Copyright (c) 2021 Versity Software, Inc. All rights reserved.
#

import click
import logging

import util as cliutil

logger = logging.getLogger("scoutfs.cli")


@click.group(help="Information about Scoutfs Quorum")
@cliutil.pass_context
def sfcli(ctx, **kwargs):
    pass


@sfcli.command(help="Status of Quorum")
@cliutil.pass_context
def status(ctx, **kwargs):
    pass
