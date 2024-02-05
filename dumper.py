import idaapi
import idc
import ida_bytes

def debug_out(str):
    print ("[dumper]: %s" % str)

class MyForm(idaapi.Form):
    def __init__(self):
        super(MyForm, self).__init__(r"""STARTITEM 0
        Enter Information
        <##Start address(hex):{start_addr}>
        <##End address(hex):{end_addr}>
        <##Length(hex):{length}>
        <##File path:{file_path}>
        """, {
            'start_addr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
            'end_addr': idaapi.Form.NumericInput(tp=idaapi.Form.FT_ADDR),
            'length': idaapi.Form.NumericInput(tp=idaapi.Form.FT_DEC),
            'file_path': idaapi.Form.FileInput(save=True),
        })

class DumpPlugin(idaapi.plugin_t):
    flags = 0
    comment = "This is a plugin to dump memory"
    help = "Help"
    wanted_name = "dumper"

    def init(self):
        debug_out(" initialized")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        f = MyForm()
        f.Compile()
        ok = f.Execute()
        if ok == 1:
            start_addr = f.start_addr.value
            end_addr = f.end_addr.value
            length = int('0x' + str(f.length.value), 16)
            file_path = f.file_path.value

            if start_addr is not None and file_path is not None:
                if length is not None:
                    data = ida_bytes.get_bytes(start_addr, length)
                    end_addr = start_addr + length
                elif end_addr is not None:
                    data = ida_bytes.get_bytes(start_addr, end_addr - start_addr)
                    length = end_addr - start_addr
                else:
                    debug_out("Invalid input")
                    return

                if data is not None:
                    with open(file_path, "wb") as f:
                        f.write(data)
                    debug_out(f"Data ({start_addr:#x}-{end_addr:#x} [{length:#x}]) has been saved to {file_path}")
                else:
                    debug_out("Failed to get data from memory")
            else:
                debug_out("Invalid input")

    def term(self):
        debug_out("DumpPlugin terminated\n")

def PLUGIN_ENTRY():
    return DumpPlugin()
