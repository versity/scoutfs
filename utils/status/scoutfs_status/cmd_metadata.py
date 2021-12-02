#!/usr/bin/env python3
#
# Copyright (c) 2021 Versity Software, Inc. All rights reserved.
#

import click
import logging

import core
import util as cliutil

logger = logging.getLogger("scoutfs.cli")


@click.group(help="Information about Scoutfs Metadata")
@cliutil.pass_context
def sfcli(ctx, **kwargs):
    pass


@sfcli.command(help="Metadata Device Path")
@cliutil.pass_context
def show(ctx, **kwargs):
    path = core.meta_get_path()
    cliutil.display_output(path, ctx, "systems")
