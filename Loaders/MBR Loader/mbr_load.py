import idaapi
import ida_idp
import ida_struct
import idc
import ida_bytes
import os

#************************#
#   IDA Loader for MBR   #
#   By Noam Afergan      #
#************************#

FormatName = "MBR loader"

def accept_file(li, neflags: int):
    """
    This function check if the format of given binary match the MBR binary format,
    if it maches it will be accepted to load by the MBR loader.
    """

    file_size = li.size() #get file size

    #MBR need minimum size of '512 bytes'
    if file_size < 512:
        return 0
    
    li.seek(510, os.SEEK_SET) #get MBR signature
    mbr_sign = li.read(2)

    #check MBR signature
    if mbr_sign[0] != ord('\x55') or mbr_sign[1] != ord('\xaa'):
        return 0
    
    #return MBR loader name
    return FormatName

def load_file(li, neflags: int, format: str) -> int:
    """
    This function load the binary by its format and set all its necessary info structures.
    """

    #when the given loader name isnt mach to the current loader name
    if format != FormatName:
        print(("[*] Wrong loader '%s' (current loader is '%s')") % (format, FormatName))
        return 0
    
    #set the ida processor type of this binary
    idaapi.set_processor_type("metapc", ida_idp.SETPROC_LOADER)

    #get the binary data into raw buffer
    li.seek(0, os.SEEK_SET)
    buf = li.read(li.size())

    mbr_start = 0x7C00 #start of MBR
    mbr_size = len(buf) #the len of the mbr raw bytes
    mbr_end = mbr_start + mbr_size #end of MBR

    #set the code segment metadata
    seg = idaapi.segment_t()
    seg.start_ea = mbr_start #start addr
    seg.end_ea = mbr_end #end addr
    seg.bitness = 0 #16 bit format

    #create code segment
    idaapi.add_segm_ex(seg, "seg0", "CODE", 0) #
    idaapi.mem2base(buf, mbr_start, mbr_end)
    idaapi.add_entry(mbr_start, mbr_start, "start", 1)

    # partition table data
    partition_table_start_offset = 0x1BE
    partition_size = 16

    #setup the Partition Table and its 4 entrys
    for partition_ctr in range(4):
        entry_address = mbr_start + partition_table_start_offset + (partition_ctr * partition_size)
        set_partiotion_entry(entry_address)

    signature_address = mbr_start + 510  # Offset for the mbr signature

    # Add a comment at the signature address
    ida_bytes.set_cmt(signature_address, "MBR Signature: 0x55AA", 0)

    # Optionally, ensure the bytes are displayed as meaningful data
    ida_bytes.create_word(signature_address, 2)

    return 1

def define_partition_entry_struct() -> int:
    """
    This function defines the partitions entry structre.
    """

    #partiotion entry structure name
    struct_name = "PARTITION_TABLE_ENTRY"

    #check if the structure already exists, if its exists return its SID
    sid_partition_entry = ida_struct.get_struc_id(struct_name)
    if sid_partition_entry != idaapi.BADADDR:
        return sid_partition_entry  

    #add new structure named by the partition entry sruct and get its SID
    sid_partition_entry = ida_struct.add_struc(-1, struct_name, 0)

    #check if the structure generated successfully
    if sid_partition_entry == idaapi.BADADDR:
        print(f"Failed to create structure '{struct_name}'")
        return None

    #get the structure object by its SID
    struct_obj = ida_struct.get_struc(sid_partition_entry)

    #***************************************************************************#
    #   Structure Members (Credit for https://wiki.osdev.org/Partition_Table)   #
    #***************************************************************************#

    #Boot indicator bit flag: 0 = no, 0x80 = bootable (or "active")
    ida_struct.add_struc_member(struct_obj, "boot_indicator", 0x00, idc.FF_BYTE, None, 1)                
    #Starting head
    ida_struct.add_struc_member(struct_obj, "starting_head", 0x01, idc.FF_BYTE, None, 1)                
    #Starting sector (Bits 6-7 are the upper two bits for the Starting Cylinder field.)
    ida_struct.add_struc_member(struct_obj, "starting_sector", 0x02, idc.FF_BYTE, None, 1)             
    #Starting Cylinder
    ida_struct.add_struc_member(struct_obj, "starting_cylinder", 0x03, idc.FF_BYTE, None, 1)           
    #System ID
    ida_struct.add_struc_member(struct_obj, "partition_type", 0x04, idc.FF_BYTE, None, 1)         
    #Ending Head
    ida_struct.add_struc_member(struct_obj, "ending_head", 0x05, idc.FF_BYTE, None, 1)                 
    #Ending Sector (Bits 6-7 are the upper two bits for the ending cylinder field)
    ida_struct.add_struc_member(struct_obj, "ending_sector", 0x06, idc.FF_BYTE, None, 1)             
    #Ending Cylinder
    ida_struct.add_struc_member(struct_obj, "ending_cylinder", 0x07, idc.FF_BYTE, None, 1)             
    #Relative Sector (to start of partition -- also equals the partition's starting LBA value)
    ida_struct.add_struc_member(struct_obj, "starting_lba", 0x08, idc.FF_DWORD, None, 4)      
    #Total Sectors in partition
    ida_struct.add_struc_member(struct_obj, "total_sectors", 0x0C, idc.FF_DWORD, None, 4)               


    #log msg
    print(f"[+] Structure '{struct_name}' defined.")

    return sid_partition_entry


def set_partiotion_entry(address: int) -> None:
    """
    This function set the partiotion entry structure on given Binary address.
    address: the entry address for setting.
    """

    #get the partition entry structure
    sid_partition_entry = define_partition_entry_struct()

    #check if the structure created successfully
    if sid_partition_entry is None:
        print("[*] Faild while creating partition entry")
        return

    #clean items
    ida_bytes.del_items(address, ida_bytes.DELIT_SIMPLE, 16)

    #set structure on given address
    if ida_bytes.create_struct(address, 16, sid_partition_entry):
        print(f"[+] Structure applied at address 0x{address:X}")
    else:
        print(f"[*] Failed to apply structure at address 0x{address:X}")
        