import idaapi
import ida_bytes

def align(ea):
    while(ea % 4) != 0:
        ea = idc.next_addr(ea)
    return ea

count = 64
ea = idaapi.get_screen_ea()
ea = align(ea)

for i in range(count):
    idaapi.jumpto(ea)
    idc.create_dword(ea)
    ea = align(ea+1)    