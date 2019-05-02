#!/usr/bin/env python2.7
# coding: UTF-8

import idaapi
import ida_kernwin
import ida_nalt
import idc

class PatchManager(object):

    def __init__(self):
        self.patched_bytes = []
        self.prev_addr = None

    def generate(self):
        idaapi.visit_patched_bytes(0, idaapi.BADADDR, self.get_patch_byte)
        print self.patched_bytes
        path = get_input_file_path() + '_patch.py'
        print path
        with open(path, "w") as f:
            f.write("some string")

        ida_kernwin.info('Successfully generated patch to %s from Patched Bytes' % path)

    # callback in 3rd argument of idaapi.visit_patched_bytes
    def get_patch_byte(self, ea, fpos, org_val, patched_val):
        org_byte = "%02x" % org_val
        patched_byte = "%02x" % patched_val

        if self.prev_addr is None or ea != (self.prev_addr + 1):
            name = idc.SegName(ea)
            if idc.GetFunctionName(ea) or idc.Name(ea):
                name += ": %s" % idc.GetFunctionName(ea) or idc.Name(ea)

            comment = idc.Comment(ea) or idc.RptCmt(ea) or ""

            self.patched_bytes.append({'name': name, 'begin_addr': ea, 'original': org_byte, 'patched': patched_byte, 'comment': comment})

        else:
            self.patched_bytes[-1]['original'] += org_byte
            self.patched_bytes[-1]['patched'] += patched_byte

        self.prev_addr = ea

        return 0


class genpatch_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_KEEP
    comment = 'generate patch from patched bytes'
    help = ''
    wanted_name = "genpatch"
    wanted_hotkey = ""

    def init(self):  
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        p = PatchManager()
        p.generate()

    def term(self):
        return None


def PLUGIN_ENTRY():
    return genpatch_t()
