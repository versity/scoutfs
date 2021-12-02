import os
import json
import logging
import pwd
import re
import glob

import util
from collections import OrderedDict
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

META_PATH = "meta_path"


class ScoutfsType:
    def __init__(self):
        pass

    def _show_dict(self):
        clsname = self.__class__.__name__
        output = {}
        if clsname not in display_detail_attrs:
            raise Exception(
                "Cannot display object: no display_detail_attrs defined for %s" % clsname)
        for attr in display_detail_attrs[clsname]:
            value = getattr(self, attr)
            if isinstance(value, dict):
                output[attr] = {}
                for key in value:
                    output[attr][key] = to_dict(value[key])
            elif isinstance(value, list):
                output[attr] = []
                for element in value:
                    output[attr].append(to_dict(element))
            elif isinstance(value, ObjectId):
                output[attr] = str(value)
            elif hasattr(value, "_show_dict"):
                output[attr] = value._show_dict()
            else:
                output[attr] = value
        return output


class ScoutfsDisplayEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "_show_dict"):
            return o._show_dict()
        else:
            return json.JSONEncoder.default(self, o)


def to_dict(o):
    if hasattr(o, "_show_dict"):
        return o._show_dict()
    else:
        return o


def to_json(o):
    return json.dumps(o, indent=4, cls=ScoutfsDisplayEncoder, sort_keys=True)


def to_detail_string(o):
    clsname = o.__class__.__name__
    if clsname not in display_detail_attrs:
        raise Exception(
            "Cannot display object: no display_detail_attrs defined for %s" % clsname)
    output = "\n"
    for attr in display_detail_attrs[clsname]:
        value = getattr(o, attr)
        value = util.display_string(value)
        output += "%s: %s\n" % (display_detail_attrs[clsname][attr], value)
    return output


def to_table_string(olist):
    if not isinstance(olist, list):
        olist = [olist]
    if len(olist) < 1:
        return ""
    separator = " | "
    clsname = olist[0].__class__.__name__
    if clsname not in display_detail_attrs:
        raise Exception(
            "Cannot display object: no display_detail_attrs defined for %s" % clsname)
    col_width = {}
    for attr in display_table_attrs[clsname]:
        col_width[attr] = len(display_table_attrs[clsname][attr])
        for o in olist:
            value = getattr(o, attr)
            value = util.display_string(value)
            setattr(o, attr, value)
            vlen = len(value)
            if vlen > col_width[attr]:
                col_width[attr] = vlen
    output = ""
    # Display heading
    line = []
    for attr in display_table_attrs[clsname]:
        line.append(display_table_attrs[clsname][attr].ljust(col_width[attr]))
    output += separator.join(line)
    output += "\n" + "-" * len(output) + "\n"
    # Display rows
    for o in olist:
        line = []
        for attr in display_table_attrs[clsname]:
            line.append(getattr(o, attr).ljust(col_width[attr]))
        output += separator.join(line) + "\n"
    return output


TYPE_INT = "integer"
TYPE_STR = "string"
TYPE_FLOAT = "float"
TYPE_BOOL = "boolean"


def parse_value(value_str, value_type, value_name):
    if value_str is None:
        return None
    elif value_type == TYPE_STR:
        return value_str
    elif value_type == TYPE_INT:
        return util.to_int(value_str, value_name)
    elif value_type == TYPE_FLOAT:
        return util.to_float(value_str, value_name)
    elif value_type == TYPE_BOOL:
        return util.to_bool(value_str, value_name)
    else:
        raise TypeError("Only STR/INT/FLOAT/BOOL are allowed")


display_table_attrs = {}
display_detail_attrs = {}

display_table_attrs['MetaInfo'] = OrderedDict([
    ("meta_path", "METADATA PATH"),
])

display_detail_attrs['MetaInfo'] = OrderedDict([
    ("meta_path", "METADATA PATH"),
])


class MetaInfo(ScoutfsType):
    def __init__(self):
        super().__init__()
        self.type = "Unknown"
        self.path = "Unknown"


def meta_get_path(**kwargs):
    pathinfo = MetaInfo()
    first_line = None
    for file in glob.iglob('/sys/fs/scoutfs/f.*/mount_options/metadev_path'):
        with open(file) as f:
            first_line = f.readline()
    pathinfo.meta_path = first_line
    return pathinfo
