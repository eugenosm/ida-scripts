import ida_bytes
import idaapi
import idautils
import idc

aut_make_funcs = False


class CodeRange:
    start: int
    end: int

    def __init__(self, start, end):
        self.start = start
        self.end = end


marked_ranges: list = list()


def add_func(start: int, end: int) -> bool:
    global marked_ranges
    for i,r in enumerate(marked_ranges):
        if r.end == start - 1:
            r.end = end
            marked_ranges[i] = r
            return True
        if r.start == end + 1:
            r.start = start
            marked_ranges[i] = r
            return True
    
    marked_ranges.append(CodeRange(start, end))
    return False	


def finding(ea: int) -> None:
    prange = CodeRange(-1, -1)
    for r in marked_ranges:
        if r.start > ea:
            rea = prange.end
            while rea < r.start:
                flag = ida_bytes.get_flags(rea)
                if ida_bytes.is_code(flag):
                    idaapi.jumpto(rea)

                    idaapi.auto_make_proc(rea)
                    idaapi.auto_wait()
                    chunks = [t for t in idautils.Chunks(rea)]
                    if len(chunks) != 1 :
                        print("fragmented function created or not created. possible need of manual correction .")
                        return
                    (fstart, fend) = chunks[0]
                    rea = fend
                    if not aut_make_funcs:
                        yn = idc.ask_yn(0, "continue?")
                        if yn == -1 or yn == 0:
                            return
                rea = idc.next_addr(rea)    
                    
            ea = idc.next_addr(r.end)
            idaapi.jumpto(ea)
        prange = r
    print("end address reached.")


print("starting...");
print("preparing metadata...");

for segea in idautils.Segments():
    for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
        for (startea, endea) in idautils.Chunks(funcea):
            add_func(startea, endea)

print(f"sorting metadata{len(marked_ranges)} code fragments)...");

marked_ranges.sort(key=lambda x: x.start)

print("searching unattached code...");
        
ea = idaapi.get_screen_ea()
finding(ea)
print("done.")
