import struct
import traceback

from binaryninja import Architecture, BinaryView, SegmentFlag, log_error

header_sig_const = bytearray([0x1b, 0x4c, 0x75, 0x61])
header_block_len = 12  #Header block is always 12 bytes in size

header_block = None


#-------------------------------------------------------------
#4 bytes Header signature: ESC, "Lua" or 0x1B4C7561
#   Binary chunk is recognized by checking for this signature
#1 byte Version number, 0x51 (81 decimal) for Lua 5.1
#   High hex digit is major version number
#   Low hex digit is minor version number
#1 byte Format version, 0=official version
#1 byte Endianness flag (default 1)
#   0=big endian, 1=little endian
#1 byte Size of int (in bytes) (default 4)
#1 byte Size of size_t (in bytes) (default 4)
#1 byte Size of Instruction (in bytes) (default 4)
#1 byte Size of lua_Number (in bytes) (default 8)
#1 byte Integral flag (default 0)
#   0=floating-point, 1=integral number type
#--------------------------------------------------------------
def parse_header_block(start, reader):
    header_block = {}
    addr = start
    header_sig = struct.unpack('<L', reader.read(addr, 4))
    addr += 4

    version, format_version, endianness_flag, int_size, size_t_size, instruction_size, lua_number_size, integral_flag = struct.unpack(
        '<8B', reader.read(addr, 8))

    header_block = {
        'header_sig': header_sig,
        'version': version,
        'format_version': format_version,
        'endianness_flag': endianness_flag,
        'int_size': int_size,
        'size_t_size': size_t_size,
        'instruction_size': instruction_size,
        'lua_number_size': lua_number_size,
        'integral_flag': integral_flag
    }
    return header_block, header_block_len


#-----------------------------------------------------------
#String source name
#Integer line defined
#Integer last line defined
#1 byte number of upvalues
#1 byte number of parameters
#1 byte is_vararg flag (see explanation further below)
#   1=VARARG_HASARG
#   2=VARARG_ISVARARG
#   4=VARARG_NEEDSARG
#1 byte maximum stack size (number of registers used)
#List list of instructions (code)
#List list of constants
#List list of function prototypes
#List source line positions (optional debug data)
#List list of locals (optional debug data)
#List list of upvalues (optional debug data)
#------------------------------------------------------------
def parse_function_block(start, reader):
    instruction_size = 4

    addr = start

    fmt_string = ''

    if header.size_t_size == 4:
        fmt_string = '<L'
    elif header.size_t_size == 8:
        fmt_string = '<Q'
    source_name_len = struct.unpack(fmt_string,
                                    reader.read(addr, header.size_t_size))[0]
    addr += 4
    source_name = reader.read(addr, source_name_len)[0]
    addr += source_name_len
    line_defined, last_line_defined = struct.unpack('<2L', reader.read(
        addr, 8))
    addr += 8
    num_upvalues, num_params, is_vararg, max_stack_size = struct.unpack(
        '<4B', reader.read(addr, 4))
    addr += 4

    code_size = struct.unpack('<L', reader.read(addr, 4))[0]
    addr += 4

    func_object = {}
    code = func_object['code'] = {}
    code['start'] = addr
    code['size'] = code_size * instruction_size

    return func_object


class LuaBytecodeBinaryView(BinaryView):
    name = "luabytecodebinaryview"
    long_name = "luabytecodebinaryview"
    header_block = None

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def init(self):
        try:
            self.platform = Architecture['luabytecodearch'].standalone_platform
            self.arch = Architecture['luabytecodearch']
            header_block = parse_header_block(0, self.raw)
            self.store_metadata('header_block', header_block)
            top_level_func = parse_function_block(header_block_len, self.raw)
            self.entry_addr = top_level_func['code']['start']

            self.add_entry_point(self.entry_addr)

            self.add_auto_segment(
                self.entry_addr, top_level_func['code']['size'],
                self.entry_addr, top_level_func['code']['size'],
                SegmentFlag.SegmentExecutable | SegmentFlag.SegmentReadable)
        except:
            log_error(traceback.format_exc())
            return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_addr


LuaBytecodeBinaryView.register()
