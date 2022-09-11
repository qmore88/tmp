#!/bin/env python
import os
import sys

# ==========================================================
#  get reg list                                    tart#{{{
# ==========================================================
def get_reg_list(file_name):
  #try:
    with open(file_name, "r") as f:
      data_str = f.readlines()
      data_str = "".join(data_str)

      _locals = locals()
      exec(data_str, globals(), _locals)
      data = _locals[file_name]

      return data
  #except:
  #  print("open file %s err" % file_name)
  #  sys.exit(1)
# ==========================================================
#  get reg list                                      end#}}}
# ==========================================================

# ==========================================================
#  add default                                     start#{{{
# ==========================================================
def add_default(data):
  def_addr  = 0x0000
  def_type  = "RW"
  def_value = 0x0

  for reg in data:
    # add default addr
    try:
      def_addr = reg["addr"] + 4
    except:
      reg["addr"] = def_addr
      def_addr = reg["addr"] + 4

    # add default type
    try:
      reg["type"]
    except:
      reg["type"] = def_type

    for bit in reg["bit"]:
      # add default range
      if len(bit[1]) == 1:
        bit[1] = [bit[1][0],bit[1][0]]

      # add default value
      try:
        bit[2]
      except:
        bit.append(def_value)
# ==========================================================
#  add default                                       end#}}}
# ==========================================================

# ==========================================================
#  check overlap                                   start#{{{
# ==========================================================
def check_overlap(data):
  err = 0

  # addr overlap check
  addr_list = []
  for reg in data:
    addr_list.append(reg["addr"])
  set_addr_list = list(set(addr_list))
  if len(addr_list) != len(set_addr_list):
    overlap_addr = [ addr for addr in set_addr_list if addr_list.count(addr) > 1]
    for addr in overlap_addr:
      print("Err  : 0x%08x addr overlap !!!" % addr)
      err = 1

  # bit overlap check
  for reg in data:
    bit_list = []
    for bit in reg["bit"]:
      bit_start = bit[1][1]
      bit_end   = bit[1][0]
      bit_list += range(bit_start,bit_end+1)
    set_bit_list = list(set(bit_list))
    if len([bit for bit in set_bit_list if bit >= 32]) > 0:
      print("Err  : reg %s addr 0x%08x bit out range !!!" % (reg['name'], reg['addr']))
      err = 1

    if len(bit_list) != len(set_bit_list):
      overlap_bit = [ bit for bit in set_bit_list if bit_list.count(bit) > 1]
      print("Err  : 0x%08x bit %s overlap !!!" % (reg['addr'], str(overlap_bit)))
      err = 1

  if err:
    sys.exit(1)
# ==========================================================
#  check overlap                                     end#}}}
# ==========================================================

# ==========================================================
#  gen io port                                     start#{{{
# ==========================================================
def gen_io_port(data):
  io_str = []
  rw_list = [ reg for reg in data if reg['type'] == 'RW']
  ro_list = [ reg for reg in data if reg['type'] == 'RO']
  wc_list = [ reg for reg in data if reg['type'] == 'WC']

  # output port
  io_str.append("  // output port\n")
  for reg in rw_list:
    for bit in reg['bit']:
      bit_range = bit[1]
      bit_len   = bit_range[0] - bit_range[1]

      if bit_len != 0:
        range_str = "[%d:0]" % bit_len
      else:
        range_str = ""

      #bit_name_str = "o_sw_%s" % bit[0]
      bit_name_str = "%s_o" % bit[0]

      io_str.append("  ,output %-17s %s\n" % (range_str, bit_name_str,))
  io_str.append("\n");

  # input port
  io_str.append("  // input port\n")
  for reg in ro_list:
    for bit in reg['bit']:
      bit_range = bit[1]
      bit_len   = bit_range[0] - bit_range[1]

      if bit_len != 0:
        range_str = "[%d:0]" % bit_len
      else:
        range_str = ""

      #bit_name_str = "i_ro_%s" % bit[0]
      bit_name_str = "%s_i" % bit[0]

      io_str.append("  ,input  %-17s %s\n" % (range_str, bit_name_str,))
  io_str.append("\n");

  # write clear output port
  io_str.append("  //write clear output port\n")
  for reg in wc_list:
    for bit in reg['bit']:
      bit_range = bit[1]
      bit_len   = bit_range[0] - bit_range[1]

      if bit_len != 0:
        range_str = "[%d:0]" % bit_len
      else:
        range_str = ""

      bit_name_str = "%s_o" % bit[0]

      io_str.append("  ,output  %-17s %s\n" % (range_str, bit_name_str,))
  io_str.append("\n");


  return io_str

# ==========================================================
#  gen io port                                       end#}}}
# ==========================================================

# ==========================================================
#  gen localparam                                  start#{{{
# ==========================================================
def gen_localparam(data):
  localparam_str = []
  for reg in data:
    addr_name = "ADDR_%s" % reg['name'].upper()
    addr_str  = "16'h%04x" % reg['addr']

    localparam_str.append("localparam %-36s = %s ;\n" % (addr_name, addr_str,))

  return localparam_str

# ==========================================================
#  gen localparam                                    end#}}}
# ==========================================================

# ==========================================================
#  gen reg wire                                    start#{{{
# ==========================================================
def gen_reg_wire(data):
  reg_wire_str = []
  rw_list = [ reg for reg in data if (reg['type'] == 'RW' or reg['type'] == 'WC') ]

  reg_wire_str.append("\n")
  # write signal
  #reg_wire_str.append("// write signal\n")
  #for reg in rw_list:
  #  wire_name = "write_%s" % reg['name']

  #  reg_wire_str.append("wire        %-47s;\n" % wire_name)
  #reg_wire_str.append("\n")

  # reg
  #reg_wire_str.append("// registers declare \n")
  for reg in rw_list:
    reg_name = "reg_%s" % reg['name']

    reg_wire_str.append("reg  [31:0] %-47s;\n" % reg_name)
  #reg_wire_str.append("\n")

  # read data
  #reg_wire_str.append("// register read data\n")
  #for reg in data:
  #  wire_name = "rdata_%s_w" % reg['name']

  #  reg_wire_str.append("wire [31:0] %-47s;\n" % wire_name)
  #reg_wire_str.append("\n")

  return reg_wire_str

# ==========================================================
#  gen write signal                                start#{{{
# ==========================================================
def gen_write_signal(data):
  write_signal_str = []
  rw_list = [ reg for reg in data if (reg['type'] == 'RW' or reg['type'] == 'WC') ]

  for reg in rw_list:
    wire_name = "write_%s" % reg['name']
    addr_name = "ADDR_%s" % reg['name'].upper()

    #write_signal_str.append("assign %-20s = wr & (addr == %-14s);\n" % (wire_name, addr_name,))
    write_signal_str.append("wire %-20s = wr & (addr == %-14s);\n" % (wire_name, addr_name,))

  return write_signal_str

# ==========================================================
#  gen reg
# ==========================================================
def gen_reg(data):
  reg_str = []
  for reg in data:
    reg_str.append("//==========================================================\n")
    reg_str.append("// register %-44s \n" % reg['name'])
    reg_str.append("//==========================================================\n")

    reg_name       = "reg_%s"     % reg['name']
    value_bit_name = "%s_VALID_BIT" % reg['name'].upper()
    default_name   = "%s_RSTN_DEFAULT"   % reg['name'].upper()
    write_name     = "write_%s"      % reg['name']
    rdata_name     = "rdata_%s"   % reg['name']
    if reg['type'] == 'RW':
      # localparam
      value_bit = 0
      default   = 0
      for bit in reg['bit']:
        bit_range = bit[1]
        bit_def   = bit[2]
        bit_start = bit_range[1]
        bit_end   = bit_range[0]
        bit_len   = bit_end - bit_start + 1
        value_bit |= (((2**bit_len) - 1) << bit_start)
        default   |= bit_def << bit_start

      value_bit_str = "%08x" % value_bit
      default_str   = "%08x" % default

      value_bit_str = "_".join([ value_bit_str[i*2:i*2+2] for i in range(4)])
      default_str   = "_".join([ default_str[i*2:i*2+2] for i in range(4)])

      reg_str.append("localparam %-30s = 32'h%s;\n" % (value_bit_name, value_bit_str))
      reg_str.append("localparam %-30s = 32'h%s;\n" % (default_name, default_str))
      reg_str.append("\n")

      # reg function
      reg_str.append("always@(posedge clk or negedge rstn) begin\n" )
      reg_str.append("  if(~rstn) \n"  )
      reg_str.append("    %s <= %s;\n"                % (reg_name, default_name,))
#      reg_str.append("  end\n"                        )
      reg_str.append("  else if(%s) \n"          % write_name)
      reg_str.append("    %s <= wdata & %s;\n"        % (reg_name, value_bit_name,))
#      reg_str.append("  end\n"                        )
      reg_str.append("end\n"                          )
      reg_str.append("\n"                             )

      # output
      for bit in reg['bit']:
        #output_name = "o_sw_%s" % bit[0]
        output_name = "%s_o" % bit[0]
        bit_range   = bit[1]
        bit_start   = bit_range[1]
        bit_end     = bit_range[0]
        bit_len     = bit_end - bit_start + 1

        if bit_len > 1:
          bit_range_str = "[%d:%d]" % (bit_end, bit_start)
        else:
          bit_range_str = "[%d]" % bit_start

        reg_str.append("assign %-16s = %s%s;\n" % (output_name, reg_name, bit_range_str,))
      reg_str.append("\n")

    # rdata
    bit_index  = 0
    rdata_list = []
    for bit in reg['bit']:
      bit_range   = bit[1]
      bit_start   = bit_range[1]
      bit_end     = bit_range[0]

      if bit_index != bit_start:
        rdata_list.append("%d'd0" % (bit_start - bit_index))
      if reg['type'] == "RW":
        rdata_list.append("%s_o" % bit[0])
      elif reg['type'] == "RO":
        rdata_list.append("%s_i" % bit[0])
      bit_index = bit_end + 1
    if bit_index != 32:
      rdata_list.append("%d'd0" % (32 - bit_index))

    if (reg['type'] == "RW" or reg['type'] == "RO"):
      reg_str.append("wire [31:0] %s = {" % rdata_name)
      reg_str.append(" ,".join(rdata_list[::-1]) )
      reg_str.append("};\n")

  return reg_str

# ==========================================================
#  gen write clear signal (by Anderson) 
# ==========================================================
def gen_wc_sig(data):
  wc_str = []
  for reg in data:
    if reg['type'] == 'WC':
      wc_str.append("//==========================================================\n")
      wc_str.append("// Write Clear Signal %-44s \n" % reg['name'])
      wc_str.append("//==========================================================\n")

      reg_name       = "reg_%s"     % reg['name']
      value_bit_name = "%s_VALID_BIT" % reg['name'].upper()
      #default_name   = "%s_RSTN_DEFAULT"   % reg['name'].upper()
      write_name     = "write_%s"   % reg['name']
      rdata_name     = "rdata_%s"   % reg['name']
      # localparam
      value_bit = 0
      default   = 0
      for bit in reg['bit']:
        bit_range = bit[1]
        bit_def   = bit[2]
        bit_start = bit_range[1]
        bit_end   = bit_range[0]
        bit_len   = bit_end - bit_start + 1
        value_bit |= (((2**bit_len) - 1) << bit_start)
        default   |= bit_def << bit_start

      value_bit_str = "%08x" % value_bit
      default_str   = "%08x" % default

      value_bit_str = "_".join([ value_bit_str[i*2:i*2+2] for i in range(4)])
      default_str   = "_".join([ default_str[i*2:i*2+2] for i in range(4)])

      wc_str.append("localparam %-30s = 32'h%s;\n" % (value_bit_name, value_bit_str))
      wc_str.append("\n")

      # reg function
      wc_str.append("always@(posedge clk or negedge rstn) begin\n"             )
      wc_str.append("  if(~rstn) \n"                                           )
      wc_str.append("    %s <= 'd0;\n"           % (reg_name,   ) )
      wc_str.append("  else if(%s) \n"          % write_name                   )
      wc_str.append("    %s <= wdata & %s;\n"   % (reg_name, value_bit_name, ) )
      wc_str.append("  else  \n"                                               )
      wc_str.append("    %s <= 'd0;\n"            % (reg_name,                 ) )
      wc_str.append("end\n"                                                    )
      wc_str.append("\n"                                                       )


      #wc_str.append("assign %s = %s & wdata & %s;\n"   % (reg_name, write_name, value_bit_name,))



      # output
      for bit in reg['bit']:
        output_name = "%s_o" % bit[0]
        bit_range   = bit[1]
        bit_start   = bit_range[1]
        bit_end     = bit_range[0]
        bit_len     = bit_end - bit_start + 1

        if bit_len > 1:
          bit_range_str = "[%d:%d]" % (bit_end, bit_start)
        else:
          bit_range_str = "[%d]" % bit_start

        wc_str.append("assign %-16s = %s%s;\n" % (output_name, reg_name, bit_range_str,))
      wc_str.append("\n")

  return wc_str
# ==========================================================
#  gen rdata
# ==========================================================
def gen_rdata(data):
  rdata_str = []
#  for reg in data:
  for reg in data :
    if (reg['type'] == 'RW' or reg['type'] == 'RO'): 
      addr_name  = "ADDR_%s"    % reg['name'].upper()
      rdata_name = "rdata_%s" % reg['name']
      rdata_str.append("      %-22s : rdata <= %-21s;\n" % (addr_name, rdata_name,))

  return rdata_str
# ==========================================================
#  gen rdata                                         end#}}}
# ==========================================================

# ==========================================================
#  gen reg file                                    start#{{{
# ==========================================================
def gen_reg_file(
    module_name,
    io_str,
    localparam_str,
    reg_wire_str,
    write_signal_str,
    reg_str,
    wc_str,
    rdata_str,
    ):
#  with open("../reg_file/%s_reg_cfg.v" % module_name, "w") as f:
  with open("%s_cfg.v" % module_name, "w") as f:
    f.write("module %s_cfg\n" % module_name                              )
    f.write("(\n"                                                           )
    f.write("   input                    clk\n"                           )
    f.write("  ,input                    rstn\n"                         )
    f.write("  // apb port\n"                                               )
    f.write("  ,input                    psel_i\n"                          )
    f.write("  ,input  [15:0]            paddr_i\n"                         )
    f.write("  ,input                    penable_i\n"                       )
    f.write("  ,input                    pwrite_i\n"                        )
    f.write("  ,input  [31:0]            pwdata_i\n"                        )
    f.write("  ,output [31:0]            prdata_o\n"                        )
    f.write("  ,output                   pready_o\n"                        )
    f.write("\n"                                                            )
    f.write("".join(io_str))
    f.write(");\n"                                                          )
    f.write("//==========================================================\n")
    f.write("// apb bus ctrl                                             \n")
    f.write("//==========================================================\n")
    f.write("wire        wr    ;\n")
    f.write("wire        rd    ;\n")
    f.write("wire [15:0] addr  ;\n")
    f.write("wire [31:0] wdata ;\n")
    f.write("reg  [31:0] rdata ;\n")
    f.write("\n"                                                            )
    f.write("assign wr       = psel_i &  penable_i &  pwrite_i;\n")
    f.write("assign rd       = psel_i &  penable_i & ~pwrite_i;\n")
    f.write("assign addr     = {4'b0,paddr_i[11:0]}           ;\n")
    f.write("assign wdata    = pwdata_i                       ;\n")
    f.write("assign prdata_o = rdata                          ;\n")
    f.write("assign pready_o = 1'b1                           ;\n")
    f.write("\n"                                                            )
    f.write("//==========================================================\n")
    f.write("// Register Base Address \n")
    f.write("//==========================================================\n")
    f.write("".join(localparam_str))
    f.write("\n"                                                            )
    f.write("//==========================================================\n")
    f.write("// Registers declartion                                             \n")
    f.write("//==========================================================\n")
    f.write("".join(reg_wire_str))
    f.write("\n"                                                            )
    f.write("//==========================================================\n")
    f.write("// write signal gen                                         \n")
    f.write("//==========================================================\n")
    f.write("".join(write_signal_str))
    f.write("\n"                                                            )
    f.write("".join(reg_str))
    f.write("//==========================================================\n")
    f.write("// Write Clear Block                                        \n")
    f.write("//==========================================================\n")
    f.write("".join(wc_str))
    f.write("//==========================================================\n")
    f.write("// rdata                                                    \n")
    f.write("//==========================================================\n")
#    f.write("always@(posedge clk or negedge rstn) begin\n"                                )
#    f.write("  if(~rstn) \n"                                 )
#    f.write("    rdata <= 32'd0;\n"                                         )
#    f.write("  end\n"                                                       )
#    f.write("  else if(rd) begin\n"                                         )
    f.write("always_comb begin\n"                                )
    f.write("    case(addr)\n"                                              )
    f.write("".join(rdata_str))
    f.write("    default                  : rdata <= 32'd0                ;\n")
    f.write("    endcase\n"                                                 )
#    f.write("  else\n"                                                )
#    f.write("    rdata <= rdata;\n"                                         )
    f.write("end\n"                                                         )
    f.write("\n"                                                            )
    f.write("endmodule\n"                                                   )

    f.close()

if __name__ == '__main__':
  if(len(sys.argv) < 2):
    print("not have input file")
    print("    %s reg_list" % sys.argv[0])
    sys.exit(0)
  file_name = sys.argv[1]

  module_name = file_name.split("_")[0]

  data = get_reg_list(file_name)
  add_default(data)
  check_overlap(data)

  io_str           = gen_io_port(data)
  localparam_str   = gen_localparam(data)
  reg_wire_str     = gen_reg_wire(data)
  write_signal_str = gen_write_signal(data)
  reg_str          = gen_reg(data)
  wc_str           = gen_wc_sig(data) 
  rdata_str        = gen_rdata(data)

  gen_reg_file(
    module_name,
    io_str,
    localparam_str,
    reg_wire_str,
    write_signal_str,
    reg_str,
    wc_str,           
    rdata_str,
  )
