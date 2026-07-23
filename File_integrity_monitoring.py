import os
import hashlib
import json
from datetime import datetime  # used to timestamp baseline creation and integrity checks

BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hashes.json")

def clear_screen():
    """Clears the terminal screen regardless of the Operating System."""
    os.system('cls' if os.name == 'nt' else 'clear')
def file_hash_calc(file_path, algorithm):
    """Calculates the cryptographic hash of a file or returns an error message string."""
    hasher = hashlib.new(algorithm)
    block_size = 65536
    try:
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(block_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest() , None

    except FileNotFoundError:
        return None , "File not found!"
    except PermissionError:
        return None, "Permission denied"
def build_file_hashes(target_dir):
    """Builds a list of file hashes based on the target directory."""
    dictionary = dict()
    errors = dict()
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            full_path = os.path.join(root, file)
            # BUG FIX: skip our own baseline file so it never shows up as
            # NEW/DELETED/MODIFIED in future scans just because it didn't
            # exist (or its contents changed) during the previous run.
            if os.path.abspath(full_path) == BASELINE_FILE:
                continue
            digest , error = file_hash_calc(full_path,"sha256")
            if error is None:
                dictionary[full_path] = digest
            else:
                errors[full_path] = error
    return dictionary , errors
def load_all_baselines(output_file):
    """Loads the full baseline store (all directories) from disk.
    Returns an empty dict if the file doesn't exist yet or is empty/corrupt."""
    if not os.path.exists(output_file):
        return {}
    try:
        with open(output_file, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, ValueError):
        return {}
def save_baseline(target_dir, dictionary, timestamp, output_file):
    """Saves/updates the baseline for ONE directory without wiping out
    baselines already stored for other directories."""
    all_baselines = load_all_baselines(output_file)
    key = os.path.abspath(target_dir)
    all_baselines[key] = {
        "timestamp": timestamp,
        "hashes": dictionary
    }
    with open(output_file , "w") as file:
        json.dump(all_baselines, file, indent=4)
def load_baseline_for_dir(target_dir, output_file):
    """Returns (hashes_dict, timestamp) for one directory's stored baseline,
    or (None, None) if no baseline exists yet for that directory."""
    all_baselines = load_all_baselines(output_file)
    key = os.path.abspath(target_dir)
    entry = all_baselines.get(key)
    if entry is None:
        return None, None
    return entry["hashes"], entry["timestamp"]
def compare(common,dict1,dict2):
    modified = []
    for key in common:
        if dict1[key] != dict2[key]:
            modified.append(key)
    return modified

while True:
    clear_screen()
    print("\nFile Integrity Monitoring\n")
    print("1. Baseline scan.\n2. Integrity Check \n3. Exit\n")
    choice = input("Enter your choice: ").strip()
    # Input validation: reject anything that isn't 1/2/3 instead of
    # silently falling through to the exit branch below.
    if choice not in ("1", "2", "3"):
        print("[X] Invalid choice. Please enter 1, 2, or 3.")
        input("Press enter to continue...")
        continue
    if choice == "1":
        clear_screen()
        # Timestamp marks exactly when this baseline snapshot was taken,
        # useful later for correlating with logs/SIEM events.
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        path = input("Enter the root directory path: ").strip()
        # Input validation: make sure the path actually exists and is a
        # directory before wasting time walking it.
        if not os.path.isdir(path):
            print(f"[X] Error: '{path}' is not a valid directory.")
            input("Press enter to continue...")
            continue
        file_hashes, errors = build_file_hashes(path)
        # Saves/updates only THIS directory's entry - baselines already
        # stored for other directories are left untouched.
        save_baseline(path, file_hashes, scan_time, BASELINE_FILE)
        print(f"[+] Baseline saved to {BASELINE_FILE} - {len(file_hashes)} file(s) recorded.")
        print(f"[i] Baseline timestamp: {scan_time}")
        if errors:
            print(f"[x] ERRORS: {len(errors)}")
            for filepath,reason in errors.items():
                print(f"    x {filepath} ({reason})\n")
        input("Press enter to continue...")

    elif choice == "2":
        clear_screen()
        path = input("Enter the root directory path: ").strip()
        # Input validation: make sure the path actually exists and is a
        # directory before wasting time walking it.
        if not os.path.isdir(path):
            print(f"[X] Error: '{path}' is not a valid directory.")
            input("Press enter to continue...")
            continue
        # Look up the baseline for THIS specific directory only - no need
        # to re-baseline every other directory just to check one of them.
        old_hashes, baseline_time = load_baseline_for_dir(path, BASELINE_FILE)
        if old_hashes is None:
            print(f"[X] Error: No baseline found for '{path}'. Run option 1 for this directory first!\n")
            input("Press Enter to continue...")
            continue

        # Timestamp marks exactly when this integrity check was run.
        check_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_hashes , errors = build_file_hashes(path)
        old_set = set(old_hashes.keys())
        new_set = set(new_hashes.keys())
        deleted_files = old_set - new_set
        new_files = new_set - old_set
        common_files = new_set  & old_set
        modified_files = compare(common_files,old_hashes,new_hashes)

        print(f"[i] Baseline taken at: {baseline_time}")
        print(f"[i] Integrity check run at: {check_time}\n")

        if deleted_files:
            print(f"[-] DELETED: {len(deleted_files)}")
            for file in deleted_files:
                print(f"    - {file}\n")
        else:
            print("[-] DELETED: None")
        if new_files:
            print(f"[+] NEW: {len(new_files)}")
            for file in new_files:
                print(f"    + {file}\n")
        else:
            print("[+] NEW: None")
        if modified_files:
            print(f"[*] MODIFIED: {len(modified_files)}")
            for file in modified_files:
                if file == BASELINE_FILE:
                    continue
                print(f"    * {file}\n")
        else:
            print("[*] MODIFIED: None")

        if errors:
            print(f"[x] ERRORS: {len(errors)}")
            for filepath, reason in errors.items():
                print(f"    x {filepath} ({reason})\n")
        input("Press enter to continue...")

    else:
        print("Thanks for using the file integrity monitoring tool!")
        input("Press Enter to continue...")
        break