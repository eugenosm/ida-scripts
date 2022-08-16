import idaapi
import ida_bytes


def align(ea):
    while(ea % 4) != 0 and ida_bytes.get_byte(ea) == 0:
        ea = idc.next_addr(ea)
    return ea

def find_next(ea):	
    ea = idaapi.find_unknown(ea, idaapi.SEARCH_DOWN | idaapi.SEARCH_NEXT)
    ea = align(ea)            
    idaapi.jumpto(ea)
    return ea

ea = idaapi.get_screen_ea()
next = True
while next:
    ea = find_next(ea)
    flags = ida_bytes.get_flags(ea)
    b = ida_bytes.get_byte(ea)  
    next = (b >= 0x20) and (b < 0x7f) or b in [10, 13, 9]
    if next:
        idc.create_strlit(ea, BADADDR)
