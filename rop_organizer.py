import re
import sys
import argparse
import struct

def get_address_bytes(address_str):
    try:
        addr_int = int(address_str, 16)
        return struct.pack('<I', addr_int)
    except ValueError:
        return None

def has_badchars(address_str, bad_chars):
    if not bad_chars:
        return False
    addr_bytes = get_address_bytes(address_str)
    if not addr_bytes:
        return False
    for byte in addr_bytes:
        if byte in bad_chars:
            return True
    return False

def parse_gadgets(file_path, bad_chars=None):
    
    gadgets = {
        "Stack_Pivot": [],        
        "ESP_Transfer": [],      
        "Dereference_Read": [],   
        "Dereference_Write": [],  
        "Arithmetic": [],         
        "Logic": [],              
        "Pop_Ret": [],            
        "Data_Movement": [],      # MOV, LEA, and XCHG
    }

    # Regex Patterns
    patterns = {
        # 1. Stack Pivots (Highest Priority) - Catch ESP exchanges here first
        "Stack_Pivot": re.compile(r"(xchg\s+e..,\s*esp|xchg\s+esp,\s*e..|mov\s+esp,\s*e..|add\s+esp,\s*0x[0-9a-fA-F]+|sub\s+esp,\s*0x[0-9a-fA-F]+)", re.IGNORECASE),
        
        # 2. ESP Saving (LEA/MOV/PUSH)
        "ESP_Transfer": re.compile(r"(mov\s+e..,\s*esp|lea\s+e..,\s*.*\[esp.*\]|push\s+esp.*pop\s+e..)", re.IGNORECASE),
        
        # 3. Memory Operations
        "Dereference_Read": re.compile(r"mov\s+e..,\s*.*\[e..\]", re.IGNORECASE),
        "Dereference_Write": re.compile(r"mov\s+.*\[e..\],\s*e..", re.IGNORECASE),
        
        # 4. Math/Logic
        "Arithmetic": re.compile(r"\b(add|sub|inc|dec|neg)\s+(?!esp)", re.IGNORECASE),
        "Logic": re.compile(r"\b(xor|and|or|not)\s", re.IGNORECASE),
        
        # 5. Clean Pops
        "Pop_Ret": re.compile(r"^0x[0-9a-fA-F]+:\s*pop\s+e..(\s*;\s*pop\s+e..)*\s*;\s*ret", re.IGNORECASE),
        
        # 6. Data Movement (MOV, LEA, XCHG)
        # Matches: "mov r,r", "xchg r,r", "lea r, [anything]"
        "Data_Movement": re.compile(r"(mov\s+e..,\s*e..|xchg\s+e..,\s*e..|lea\s+e..,\s*.*\[.*\])", re.IGNORECASE)
    }

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
        sys.exit(1)

    print(f"[*] Analyzing {len(lines)} lines...")
    if bad_chars:
        print(f"[*] Filtering out gadgets containing: {[hex(b) for b in bad_chars]}")

    for line in lines:
        line = line.strip()
        if not line or "ret" not in line:
            continue

        match_addr = re.match(r"(0x[0-9a-fA-F]+):", line)
        if not match_addr:
            continue
            
        address_str = match_addr.group(1)
        if bad_chars and has_badchars(address_str, bad_chars):
            continue

        classified = False

        # Priority 1: Stack Pivots
        if patterns["Stack_Pivot"].search(line):
            gadgets["Stack_Pivot"].append(line)
            classified = True

        # Priority 2: ESP Transfers
        if patterns["ESP_Transfer"].search(line):
            if "mov esp" not in line and "xchg esp" not in line:
                gadgets["ESP_Transfer"].append(line)
                classified = True

        # Priority 3: Write-What-Where
        if patterns["Dereference_Write"].search(line):
            gadgets["Dereference_Write"].append(line)
            classified = True
        elif patterns["Dereference_Read"].search(line):
            gadgets["Dereference_Read"].append(line)
            classified = True

        if not classified:
            if patterns["Arithmetic"].search(line):
                gadgets["Arithmetic"].append(line)
                classified = True
            elif patterns["Logic"].search(line):
                gadgets["Logic"].append(line)
                classified = True

        if not classified and patterns["Pop_Ret"].search(line):
            gadgets["Pop_Ret"].append(line)
            classified = True
            
        # Priority 4: Data Movement (MOV, LEA, XCHG)
        if not classified and patterns["Data_Movement"].search(line):
            gadgets["Data_Movement"].append(line)
            classified = True

    return gadgets

def print_category(name, gadget_list):
    if not gadget_list:
        return
    print(f"\n{'='*60}")
    print(f" [+] {name} ({len(gadget_list)} found)")
    print(f"{'='*60}")
    gadget_list.sort(key=len)
    for g in gadget_list:
        print(f"  {g}")

def main():
    parser = argparse.ArgumentParser(description="Organize rp++ gadgets for OSED.")
    parser.add_argument("file", help="The output file from rp++")
    parser.add_argument("--badchars", help="Hex string of bad characters (e.g. 000a0d)", default=None)
    args = parser.parse_args()
    
    bad_chars_bytes = None
    if args.badchars:
        try:
            bad_chars_bytes = bytes.fromhex(args.badchars)
        except ValueError:
            print("[!] Error: --badchars must be a valid hex string (e.g., 000a)")
            sys.exit(1)

    organized_gadgets = parse_gadgets(args.file, bad_chars_bytes)

    print_category("Stack_Pivots (Control ESP)", organized_gadgets["Stack_Pivot"])
    print_category("ESP_Transfers (Save ESP -> Reg)", organized_gadgets["ESP_Transfer"])
    print_category("Write-What-Where (mov [dst], src)", organized_gadgets["Dereference_Write"])
    print_category("Read Memory (mov dst, [src])", organized_gadgets["Dereference_Read"])
    print_category("Arithmetic", organized_gadgets["Arithmetic"])
    print_category("Logic", organized_gadgets["Logic"])
    print_category("Clean Pops", organized_gadgets["Pop_Ret"])
    
    # Updated Category
    print_category("Data Movement (MOV / LEA / XCHG)", organized_gadgets["Data_Movement"])

if __name__ == "__main__":
    main()
