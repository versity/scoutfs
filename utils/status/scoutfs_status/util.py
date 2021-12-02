#
# Copyright (c) 2021 Versity Software, Inc. All rights reserved.
#

import click
import core


class Context():
    def __init__(self):
        self.json = False
        self.summary = False
        self.detail = False


pass_context = click.make_pass_decorator(Context, ensure=True)


def display_output(outval, ctx, typename):
    if isinstance(outval, list):
        # For lists, default view is summary
        if ctx.json:
            output = {}
            output['total'] = len(outval)
            output[typename] = outval
            click.echo(core.to_json(output))
        elif ctx.detail:
            click.echo("TOTAL: %s" % str(len(outval)))
            for elem in outval:
                click.echo(core.to_detail_string(elem))
        else:
            click.echo(core.to_table_string(outval))
    else:
        # For single objects, default view is detail
        if ctx.json:
            click.echo(core.to_json(outval))
        elif ctx.summary:
            click.echo(core.to_table_string(outval))
        else:
            click.echo(core.to_detail_string(outval))


def display_string(value):
    if hasattr(value, "_show_dict"):
        return re.sub("'", "", str(value.__dict__))
    elif value is None:
        return "N/A"
    return str(value)
