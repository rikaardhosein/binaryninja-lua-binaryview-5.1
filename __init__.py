import struct
import traceback
from collections import namedtuple

from binaryninja import Architecture, BinaryView, SegmentFlag, log_error
from namedlist import namedlist

header_sig_const = bytearray([0x1b, 0x4c, 0x75, 0x61])
header_block_len = 12  #Header block is always 12 bytes in size

LUA_LITTLE_ENDIAN = 1
LUA_BIG_ENDIAN = 0

LUA_TNIL = 0
LUA_TBOOLEAN = 1
LUA_TNUMBER = 3
LUA_TSTRING = 4

header_block = None


def prep_fmt(fc):
    global header_block
    fmt = ''
    endianness = header_block['endianness_flag']
    assert (endianness == LUA_LITTLE_ENDIAN
            or endianness == LUA_BIG_ENDIAN), "Unknown endianness"
    if endianness == LUA_LITTLE_ENDIAN:
        fmt += '<'
    elif endianness == LUA_BIG_ENDIAN:
        fmt += '>'

    fmt += fc
    return fmt


def load_string(addr, reader):
    global header_block
    size_t_size = header_block['size_t_size']

    fmt = prep_fmt('L')
    if size_t_size == 8:
        fmt = prep_fmt('Q')

    slen = struct.unpack(fmt, reader.read(addr, size_t_size))[0]
    addr += size_t_size
    s = struct.unpack('@%ds' % slen, reader.read(addr, slen))[0]
    s = s[:-1]
    addr += slen
    return s, addr


def load_byte(addr, reader):
    b = struct.unpack('@B', reader.read(addr, 1))[0]
    addr += 1
    return b, addr


def load_int(addr, reader):
    global header_block
    int_size = header_block['int_size']
    fmt = prep_fmt('L')
    if int_size == 8:
        fmt = prep_fmt('Q')
    i = struct.unpack(fmt, reader.read(addr, int_size))[0]
    addr += int_size
    return i, addr


def load_number(addr, reader):
    #TODO: Does not consider if integral flag is set.
    global header_block
    number_size = header_block['number_size']
    fmt = prep_fmt('d')
    n = struct.unpack(fmt, reader.read(addr, number_size))[0]
    addr += number_size
    return n, addr


def load_boolean(addr, reader):
    fmt = prep_fmt('_Bool')
    b = struct.unpack(fmt, reader.read(addr, boolean_size))[0]
    addr += boolean_size
    return b, addr


def load_byte(addr, reader):
    fmt = prep_fmt('B')
    b = struct.unpack(fmt, reader.read(addr, 1))[0]
    addr += 1
    return b, addr


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
        'number_size': lua_number_size,
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
def load_function_block(start, reader):
    instruction_size = 4
    addr = start

    FunctionBlock = namedlist('func_block', ' '.join([
        'source_name', 'line_defined', 'last_line_defined', 'num_upvalues',
        'num_params', 'is_vararg', 'max_stack_size', 'code_size', 'code_addr',
        'num_constants', 'constants', 'num_functions', 'func_blocks',
        'num_source_line_pos', 'source_line_pos', 'num_locals', 'locals',
        'num_upvalue_names', 'upvalue_names'
    ]))

    func_block = FunctionBlock(*([None] * 19))

    func_block.source_name, addr = load_string(addr, reader)
    func_block.line_defined, addr = load_int(addr, reader)
    func_block.last_line_defined, addr = load_int(addr, reader)

    func_block.num_upvalues, addr = load_byte(addr, reader)
    func_block.num_params, addr = load_byte(addr, reader)
    func_block.is_vararg, addr = load_byte(addr, reader)
    func_block.max_stack_size, addr = load_byte(addr, reader)

    func_block.code_size, addr = load_int(addr, reader)
    func_block.code_size *= instruction_size
    func_block.code_addr = addr
    addr += (instruction_size + func_block.code_size)

    func_block.num_constants, addr = load_int(addr, reader)
    func_block.constants = []
    for i in range(0, func_block.num_constants):
        c, constant_type, addr = load_constant(addr, reader)
        func_block.constants.append((constant_type, c))

    func_block.num_functions, addr = load_int(addr, reader)
    func_block.func_blocks = []
    for i in range(0, func_block.num_functions):
        func_block, addr = load_function_block(addr, reader)
        func_block.func_blocks.append(func_block)

    func_block.num_source_line_pos = load_int(addr, reader)
    func_block.source_line_pos = []
    for i in range(0, func_block.num_source_line_pos):
        source_line_pos, addr = load_int(addr, reader)
        func_block.source_line_pos.append(source_line_pos)

    func_block.num_locals = load_int(addr, reader)
    func_block.locals = []
    for i in range(0, func_block.num_locals):
        varname, addr = load_string(addr, reader)
        startpc, addr = load_int(addr, reader)
        endpc, addr = load_int(addr, reader)
        func_block.locals.append((varname, startpc, endpc))

    func_block.upvalues = []
    func_block.num_upvalue_names = load_int(addr, reader)
    for i in range(0, func_block.num_upvalue_names):
        upvalue_name, addr = load_string(addr, reader)
        func_block.upvalue_names.append(upvalue_name)

    return func_block, addr


def load_constant(addr, reader):
    prev_addr = addr
    constant_type, addr = load_byte(addr, reader)
    c = None
    if constant_type == LUA_TNIL:
        c = None
    elif constant_type == LUA_TNUMBER:
        c, addr = load_number(addr, reader)
    elif constant_type == LUA_TSTRING:
        c, addr = load_string(addr, reader)
    elif constant_type == LUA_TBOOLEAN:
        c, addr = load_boolean(addr, reader)
    else:
        raise ValueError('Unknown constant type %d @ %x\n' % (constant_type,
                                                              addr))
    print "Addr: %x\nConstant type: %d\nConstant: " % (prev_addr, constant_type)
    return c, constant_type, addr


class LuaBytecodeBinaryView(BinaryView):
    name = "luabytecodebinaryview"
    long_name = "luabytecodebinaryview"

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        return True

    def init(self):
        global header_block
        try:
            self.platform = Architecture['luabytecodearch'].standalone_platform
            self.arch = Architecture['luabytecodearch']
            header_block, header_block_len = parse_header_block(0, self.raw)
            top_level_func, addr = load_function_block(header_block_len,
                                                       self.raw)

            print top_level_func
            self.entry_addr = top_level_func.code_addr

            self.add_entry_point(self.entry_addr)

            self.add_auto_segment(
                self.entry_addr, top_level_func.code_size, self.entry_addr,
                top_level_func.code_size,
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
